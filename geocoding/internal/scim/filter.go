package scim

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"augeocoding/internal/identity"
)

// parseFilter parses the subset of RFC 7644 §3.4.2.2 filters IdPs send:
// "eq" comparisons joined by "and"/"or" with parentheses. Attribute names
// are case-insensitive and may carry the core schema URN.
func parseFilter(s string) (identity.SCIMCond, error) {
	toks, err := lexFilter(s)
	if err != nil {
		return identity.SCIMCond{}, err
	}
	p := &filterParser{toks: toks}
	c, err := p.or()
	if err != nil {
		return c, err
	}
	if p.i != len(p.toks) {
		return c, errors.New("unexpected " + p.toks[p.i].s)
	}
	return c, nil
}

type tok struct {
	s      string
	quoted bool
}

func lexFilter(s string) ([]tok, error) {
	var out []tok
	for i := 0; i < len(s); {
		switch ch := s[i]; {
		case ch == ' ' || ch == '\t':
			i++
		case ch == '(' || ch == ')':
			out = append(out, tok{s: string(ch)})
			i++
		case ch == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return nil, errors.New("unterminated string")
			}
			var v string
			if err := json.Unmarshal([]byte(s[i:j+1]), &v); err != nil {
				return nil, errors.New("bad string")
			}
			out = append(out, tok{s: v, quoted: true})
			i = j + 1
		default:
			j, depth, inq := i, 0, false
			for ; j < len(s); j++ {
				c := s[j]
				if inq {
					if c == '\\' {
						j++
					} else if c == '"' {
						inq = false
					}
					continue
				}
				if c == '"' && depth > 0 {
					inq = true
				} else if c == '[' {
					depth++
				} else if c == ']' {
					depth--
				} else if depth == 0 && (c == ' ' || c == '\t' || c == '(' || c == ')') {
					break
				}
			}
			if depth != 0 || inq {
				return nil, errors.New("unbalanced brackets")
			}
			out = append(out, tok{s: s[i:j]})
			i = j
		}
		if len(out) > 200 {
			return nil, errors.New("filter too complex")
		}
	}
	return out, nil
}

type filterParser struct {
	toks []tok
	i    int
}

func (p *filterParser) peekWord(w string) bool {
	return p.i < len(p.toks) && !p.toks[p.i].quoted && strings.EqualFold(p.toks[p.i].s, w)
}

func (p *filterParser) or() (identity.SCIMCond, error) {
	return p.chain("or", p.and)
}

func (p *filterParser) and() (identity.SCIMCond, error) {
	return p.chain("and", p.factor)
}

func (p *filterParser) chain(op string, next func() (identity.SCIMCond, error)) (identity.SCIMCond, error) {
	first, err := next()
	if err != nil {
		return first, err
	}
	subs := []identity.SCIMCond{first}
	for p.peekWord(op) {
		p.i++
		c, err := next()
		if err != nil {
			return c, err
		}
		subs = append(subs, c)
	}
	if len(subs) == 1 {
		return first, nil
	}
	return identity.SCIMCond{Op: op, Sub: subs}, nil
}

func (p *filterParser) factor() (identity.SCIMCond, error) {
	if p.peekWord("(") {
		p.i++
		c, err := p.or()
		if err != nil {
			return c, err
		}
		if !p.peekWord(")") {
			return c, errors.New("missing )")
		}
		p.i++
		return c, nil
	}
	if p.peekWord("not") {
		return identity.SCIMCond{}, errors.New("not is unsupported")
	}
	if p.i+3 > len(p.toks) {
		return identity.SCIMCond{}, errors.New("incomplete comparison")
	}
	attr, op, val := p.toks[p.i], p.toks[p.i+1], p.toks[p.i+2]
	if attr.quoted || op.quoted {
		return identity.SCIMCond{}, errors.New("bad comparison")
	}
	if !strings.EqualFold(op.s, "eq") {
		return identity.SCIMCond{}, errors.New("only the eq operator is supported")
	}
	a, err := filterAttr(attr.s)
	if err != nil {
		return identity.SCIMCond{}, err
	}
	if !val.quoted && (val.s == "(" || val.s == ")") {
		return identity.SCIMCond{}, errors.New("bad value")
	}
	p.i += 3
	return identity.SCIMCond{Op: "eq", Attr: a, Value: val.s}, nil
}

var workEmailRe = regexp.MustCompile(`(?i)^emails\[\s*type\s+eq\s+"work"\s*\]\.value$`)

func stripSchema(a string) string {
	for _, urn := range []string{schemaUser + ":", schemaGroup + ":"} {
		if len(a) > len(urn) && strings.EqualFold(a[:len(urn)], urn) {
			return a[len(urn):]
		}
	}
	return a
}

func filterAttr(a string) (string, error) {
	a = stripSchema(a)
	switch strings.ToLower(a) {
	case "id":
		return identity.SCIMAttrID, nil
	case "username":
		return identity.SCIMAttrUserName, nil
	case "externalid":
		return identity.SCIMAttrExternalID, nil
	case "emails", "emails.value":
		return identity.SCIMAttrEmail, nil
	case "displayname":
		return identity.SCIMAttrDisplayName, nil
	}
	if workEmailRe.MatchString(a) {
		return identity.SCIMAttrWorkEmail, nil
	}
	return "", errors.New("unsupported filter attribute " + a)
}
