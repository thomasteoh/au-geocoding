package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server: EHLO, optional STARTTLS, AUTH PLAIN,
// MAIL, RCPT, DATA, QUIT.
type fakeSMTP struct {
	ln       net.Listener
	tls      *tls.Config // non-nil: offer STARTTLS
	implicit bool        // TLS from the first byte (port 465 style)
	rcptCode string      // reply to RCPT; "" = 250
	mu       sync.Mutex
	from, to string
	data     string
	auth     string // decoded AUTH PLAIN payload
	usedTLS  bool
}

func newFakeSMTP(t *testing.T, tc *tls.Config) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tls: tc}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	secure := false
	f.mu.Lock()
	implicit := f.implicit
	f.mu.Unlock()
	if implicit {
		tc := tls.Server(c, f.tls)
		if err := tc.Handshake(); err != nil {
			return
		}
		c, secure = tc, true
		f.mu.Lock()
		f.usedTLS = true
		f.mu.Unlock()
	}
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch cmd {
		case "EHLO":
			if f.tls != nil && !secure {
				say("250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN")
			} else {
				say("250-fake\r\n250 AUTH PLAIN")
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tls)
			if err := tc.Handshake(); err != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
			f.mu.Lock()
			f.usedTLS = true
			f.mu.Unlock()
		case "AUTH":
			parts := strings.Fields(line)
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f.mu.Lock()
			f.auth = string(raw)
			f.mu.Unlock()
			say("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from = line
			f.mu.Unlock()
			say("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.to = line
			code := f.rcptCode
			f.mu.Unlock()
			if code != "" {
				say(code + " 5.1.1 <someone@example.com>: mailbox unavailable")
				continue
			}
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 no")
		}
	}
}

func (f *fakeSMTP) sender(t *testing.T, host string, cfg Config) *SMTP {
	t.Helper()
	cfg.Host = host
	if cfg.From == "" {
		cfg.From = "Geocoder <noreply@geo.example>"
	}
	s, err := NewSMTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := f.ln.Addr().String()
	s.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	return s
}

func TestSendLocalhostPlain(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := f.sender(t, "localhost", Config{})
	body := "Hello.\nSign in: https://geo.example/auth/login\n.\nA long line " + strings.Repeat("x", 100)
	if err := s.Send(context.Background(), "ada@example.com", "Invitation to Ünïcode Org", body); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from != "MAIL FROM:<noreply@geo.example>" || f.to != "RCPT TO:<ada@example.com>" {
		t.Fatalf("envelope: %q %q", f.from, f.to)
	}
	for _, want := range []string{"To: ada@example.com\r\n", "Subject: =?utf-8?q?", "From: \"Geocoder\" <noreply@geo.example>\r\n",
		"Content-Type: text/plain", "https://geo.example/auth/login"} {
		if !strings.Contains(f.data, want) {
			t.Errorf("message lacks %q:\n%s", want, f.data)
		}
	}
	if f.auth != "" {
		t.Fatal("authenticated without a username")
	}
}

func TestSendRequiresSTARTTLSOffLocalhost(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := f.sender(t, "mail.example.com", Config{Username: "u", Password: "p"})
	err := s.Send(context.Background(), "ada@example.com", "hi", "body")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want STARTTLS error, got %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" || f.data != "" {
		t.Fatal("credentials or data sent without TLS")
	}
}

func TestSendSTARTTLSAndAuth(t *testing.T) {
	cert, pool := testCert(t, "mail.example.com")
	f := newFakeSMTP(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	s := f.sender(t, "mail.example.com", Config{Username: "user", Password: "pw", Port: 2525})
	s.tlsConfig = &tls.Config{ServerName: "mail.example.com", RootCAs: pool, MinVersion: tls.VersionTLS12}
	if err := s.Send(context.Background(), "ada@example.com", "hi", "body"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.usedTLS || f.auth != "\x00user\x00pw" || !strings.Contains(f.data, "body") {
		t.Fatalf("tls=%v auth=%q data=%q", f.usedTLS, f.auth, f.data)
	}
}

func TestSendRejectsInjectionAndBadAddresses(t *testing.T) {
	f := newFakeSMTP(t, nil)
	s := f.sender(t, "localhost", Config{})
	for _, c := range []struct{ to, subject string }{
		{"ada@example.com\r\nBcc: eve@example.com", "hi"},
		{"ada@example.com", "hi\r\nBcc: eve@example.com"},
		{"ada@example.com", "hi\nX: y"},
		{"Ada <ada@example.com>", "hi"},
		{"ada@example.com, eve@example.com", "hi"},
		{"not-an-address", "hi"},
		{"", "hi"},
	} {
		if err := s.Send(context.Background(), c.to, c.subject, "b"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q / %q: %v", c.to, c.subject, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.data != "" {
		t.Fatal("rejected message was sent")
	}
}

func TestNewSMTPValidation(t *testing.T) {
	for _, c := range []Config{
		{Host: "", From: "a@b.example"},
		{Host: "smtp.example", From: ""},
		{Host: "smtp.example", From: "nobody"},
		{Host: "smtp.example", From: "a@b.example\r\nBcc: x@y.example"},
		{Host: "smtp.example", From: "a@b.example", Port: 70000},
	} {
		if _, err := NewSMTP(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	s, err := NewSMTP(Config{Host: "smtp.example", From: "a@b.example"})
	if err != nil || s.cfg.Port != 587 {
		t.Fatalf("default port: %v %+v", err, s)
	}
}

func TestSendTimeout(t *testing.T) {
	// A server that accepts and never greets: Send must give up when the
	// context ends.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	s, _ := NewSMTP(Config{Host: "localhost", From: "a@b.example"})
	s.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Send(ctx, "ada@example.com", "hi", "b"); err == nil {
		t.Fatal("no error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not honour the deadline")
	}
}

func TestNop(t *testing.T) {
	if err := (Nop{}).Send(context.Background(), "a@b.example", "s", "b"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
}

func testCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestSendImplicitTLS(t *testing.T) {
	cert, pool := testCert(t, "mail.example.com")
	f := newFakeSMTP(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	f.mu.Lock()
	f.implicit = true
	f.mu.Unlock()
	s := f.sender(t, "mail.example.com", Config{Username: "user", Password: "pw", Port: 465})
	if s.cfg.TLS != TLSImplicit {
		t.Fatalf("port 465 should imply implicit TLS, got %q", s.cfg.TLS)
	}
	s.tlsConfig = &tls.Config{ServerName: "mail.example.com", RootCAs: pool, MinVersion: tls.VersionTLS12}
	if err := s.Send(context.Background(), "ada@example.com", "hi", "body"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if !f.usedTLS || f.auth != "\x00user\x00pw" || !strings.Contains(f.data, "body") {
		t.Fatalf("tls=%v auth=%q data=%q", f.usedTLS, f.auth, f.data)
	}
	f.mu.Unlock()

	// An untrusted certificate fails at the TLS stage, before any SMTP.
	s2 := f.sender(t, "mail.example.com", Config{Port: 2465, TLS: TLSImplicit})
	err := s2.Send(context.Background(), "ada@example.com", "hi", "body")
	if ErrorCode(err) != "tls" || Permanent(err) {
		t.Fatalf("untrusted cert: %v code=%q", err, ErrorCode(err))
	}

	// Explicit starttls on 465 is honoured; bad modes are refused.
	if s, err := NewSMTP(Config{Host: "smtp.example", From: "a@b.example", Port: 465, TLS: TLSStartTLS}); err != nil || s.cfg.TLS != TLSStartTLS {
		t.Fatalf("explicit starttls: %v", err)
	}
	if _, err := NewSMTP(Config{Host: "smtp.example", From: "a@b.example", TLS: "ssl"}); err == nil {
		t.Fatal("accepted TLS mode ssl")
	}
}

func TestErrorCodeAndPermanent(t *testing.T) {
	f := newFakeSMTP(t, nil)
	f.mu.Lock()
	f.rcptCode = "550"
	f.mu.Unlock()
	s := f.sender(t, "localhost", Config{})
	err := s.Send(context.Background(), "someone@example.com", "hi", "b")
	if ErrorCode(err) != "rcpt_550" || !Permanent(err) {
		t.Fatalf("code=%q permanent=%v err=%v", ErrorCode(err), Permanent(err), err)
	}
	if strings.Contains(ErrorCode(err), "@") {
		t.Fatal("code leaks an address")
	}
	if ErrorCode(ErrInvalid) != "invalid" || !Permanent(ErrInvalid) {
		t.Fatal("invalid")
	}
	if Permanent(&SendError{Stage: "dial", Err: errors.New("refused")}) {
		t.Fatal("dial failure is temporary")
	}
}
