// Package mail sends plain-text notification email (console invites).
//
// The SMTP sender speaks implicit TLS (port 465) or requires STARTTLS
// unless the server is on localhost, uses
// PLAIN auth only when a username is set, and refuses CR or LF in the
// recipient and subject so callers cannot inject headers.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Sender delivers one plain-text message.
type Sender interface {
	Send(ctx context.Context, to, subject, textBody string) error
}

// ErrDisabled is returned by Nop: no mail server is configured.
var ErrDisabled = errors.New("mail: not configured")

// ErrInvalid is returned for a bad address or a header containing CR or LF.
var ErrInvalid = errors.New("mail: invalid address or header")

// Nop is the sender used when SMTP is not configured. It sends nothing and
// returns ErrDisabled so callers can tell "not sent" from "sent".
type Nop struct{}

// Send implements Sender.
func (Nop) Send(context.Context, string, string, string) error { return ErrDisabled }

// Config configures an SMTP sender.
type Config struct {
	Host     string
	Port     int // default 587
	Username string
	Password string
	From     string // bare address or "Name <addr>"
	// TLS is TLSStartTLS or TLSImplicit. Empty: implicit on port 465,
	// STARTTLS otherwise.
	TLS string
}

// TLS modes.
const (
	TLSStartTLS = "starttls"
	TLSImplicit = "implicit"
)

// Timeout bounds a whole delivery: dial, TLS, auth and data.
const Timeout = 10 * time.Second

// SMTP sends through an SMTP submission server.
type SMTP struct {
	cfg  Config
	from *mail.Address

	// Test hooks.
	dial      func(ctx context.Context, addr string) (net.Conn, error)
	tlsConfig *tls.Config
}

// NewSMTP validates cfg and returns a sender.
func NewSMTP(cfg Config) (*SMTP, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" || strings.ContainsAny(cfg.Host, "\r\n/ ") {
		return nil, errors.New("mail: SMTP host required")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, errors.New("mail: bad SMTP port")
	}
	switch cfg.TLS {
	case "":
		cfg.TLS = TLSStartTLS
		if cfg.Port == 465 {
			cfg.TLS = TLSImplicit
		}
	case TLSStartTLS, TLSImplicit:
	default:
		return nil, errors.New("mail: TLS must be implicit or starttls")
	}
	from, err := ParseFrom(cfg.From)
	if err != nil {
		return nil, err
	}
	s := &SMTP{cfg: cfg, from: from}
	s.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: Timeout}).DialContext(ctx, "tcp", addr)
	}
	return s, nil
}

// ParseFrom validates a From value: a bare address or "Name <addr>".
func ParseFrom(v string) (*mail.Address, error) {
	if strings.ContainsAny(v, "\r\n") {
		return nil, ErrInvalid
	}
	a, err := mail.ParseAddress(v)
	if err != nil || !strings.Contains(a.Address, "@") {
		return nil, fmt.Errorf("%w: from address", ErrInvalid)
	}
	return a, nil
}

// validRecipient accepts a bare address only.
func validRecipient(to string) bool {
	if to == "" || len(to) > 254 || strings.ContainsAny(to, "\r\n<>,; \t") {
		return false
	}
	a, err := mail.ParseAddress(to)
	return err == nil && a.Address == to && a.Name == ""
}

// SendError is a failed delivery: the protocol stage that failed and the
// underlying error. Stage is safe to log and store; Err may echo addresses.
type SendError struct {
	Stage string // dial, tls, greeting, hello, starttls, auth, mail, rcpt, data
	Err   error
}

func (e *SendError) Error() string { return "mail: " + e.Stage + ": " + e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

func stageErr(stage string, err error) error { return &SendError{Stage: stage, Err: err} }

// ErrorCode is a short, address-free label for a send error, for logs and
// the outbox: "invalid", "disabled", "timeout", or the failed stage, with
// the SMTP reply code when there is one (for example "rcpt_550").
func ErrorCode(err error) string {
	var se *SendError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrDisabled):
		return "disabled"
	case !errors.As(err, &se):
		return "other"
	}
	var tp *textproto.Error
	if errors.As(err, &tp) {
		return se.Stage + "_" + strconv.Itoa(tp.Code)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return se.Stage + "_timeout"
	}
	return se.Stage
}

// Permanent reports whether retrying err cannot help: a rejected address or
// header, or a 5xx reply to MAIL, RCPT or DATA.
func Permanent(err error) bool {
	if errors.Is(err, ErrInvalid) {
		return true
	}
	var se *SendError
	var tp *textproto.Error
	if errors.As(err, &se) && errors.As(err, &tp) && tp.Code >= 500 {
		return se.Stage == "mail" || se.Stage == "rcpt" || se.Stage == "data"
	}
	return false
}

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Send implements Sender.
func (s *SMTP) Send(ctx context.Context, to, subject, textBody string) error {
	if !validRecipient(to) || strings.ContainsAny(subject, "\r\n") {
		return ErrInvalid
	}
	msg, err := s.build(to, subject, textBody)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	conn, err := s.dial(ctx, net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return stageErr("dial", err)
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	// Cancelling ctx (for example shutdown) aborts the exchange.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	implicit := s.cfg.TLS == TLSImplicit
	if implicit {
		tc := tls.Client(conn, s.tlsFor())
		if err := tc.HandshakeContext(ctx); err != nil {
			return stageErr("tls", err)
		}
		// smtp.NewClient sees the *tls.Conn and treats the session as
		// encrypted, so PlainAuth will send credentials.
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return stageErr("greeting", err)
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return stageErr("hello", err)
	}
	if !implicit {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(s.tlsFor()); err != nil {
				return stageErr("starttls", err)
			}
		} else if !isLocal(s.cfg.Host) {
			return stageErr("starttls", errors.New("server does not offer STARTTLS"))
		}
	}
	if s.cfg.Username != "" {
		// PlainAuth itself refuses to send credentials over an unencrypted
		// connection to anything but localhost.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return stageErr("auth", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return stageErr("mail", err)
	}
	if err := c.Rcpt(to); err != nil {
		return stageErr("rcpt", err)
	}
	wc, err := c.Data()
	if err != nil {
		return stageErr("data", err)
	}
	if _, err := wc.Write(msg); err != nil {
		wc.Close()
		return stageErr("data", err)
	}
	if err := wc.Close(); err != nil {
		return stageErr("data", err)
	}
	// The message is accepted once DATA ends; a failed QUIT is not a
	// failed delivery (and must not cause a duplicate on retry).
	c.Quit()
	return nil
}

func (s *SMTP) tlsFor() *tls.Config {
	if s.tlsConfig != nil {
		return s.tlsConfig
	}
	return &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
}

func (s *SMTP) build(to, subject, body string) ([]byte, error) {
	var b bytes.Buffer
	id := make([]byte, 12)
	rand.Read(id)
	domain := s.from.Address[strings.LastIndex(s.from.Address, "@")+1:]
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", s.from.String())
	hdr("To", to)
	hdr("Subject", mime.QEncoding.Encode("utf-8", subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", `text/plain; charset="utf-8"`)
	hdr("Content-Transfer-Encoding", "quoted-printable")
	hdr("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(body, "\r\n", "\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
