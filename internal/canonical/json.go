// Package canonical implements the strict JSON reading and RFC 8785 (JCS)
// writing that federation-package/v1 requires.
//
// It exists because the standard library's decoder is deliberately lenient in
// three ways this format cannot tolerate:
//
//   - it keeps the last of two members with the same name, where other parsers
//     keep the first, so the same bytes become two different documents;
//   - it discards the source text of a number, so `1380.0` and `1380` become
//     indistinguishable after parsing;
//   - it substitutes U+FFFD for invalid UTF-8, silently changing the bytes a
//     signature was computed over.
//
// Nothing here decides anything about a package's meaning. It reads bytes into
// an ordered tree and writes that tree back out in one defined form, so that a
// signature can be checked against exactly what was signed.
package canonical

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind distinguishes the six JSON value kinds.
type Kind int

const (
	KindObject Kind = iota
	KindArray
	KindString
	KindNumber
	KindBool
	KindNull
)

// Value is a parsed JSON value. Object members keep their document order, which
// is not the canonical order; Write sorts them. Number keeps the source token
// because §4 tests the token as written, not the parsed value.
type Value struct {
	Kind    Kind
	Members []Member // KindObject
	Items   []*Value // KindArray
	Str     string   // KindString
	Num     string   // KindNumber, source token
	Bool    bool     // KindBool
}

// Member is one object member, in document order.
type Member struct {
	Name  string
	Value *Value
}

// Get returns the member with the given name, or nil. Duplicate names are
// refused at parse time, so at most one can match.
func (v *Value) Get(name string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for _, m := range v.Members {
		if m.Name == name {
			return m.Value
		}
	}
	return nil
}

// Names returns the member names in document order.
func (v *Value) Names() []string {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	out := make([]string, 0, len(v.Members))
	for _, m := range v.Members {
		out = append(out, m.Name)
	}
	return out
}

// Without returns a shallow copy of an object with one member removed. Used to
// build the signing input, which is the package minus `signature`.
func (v *Value) Without(name string) *Value {
	if v == nil || v.Kind != KindObject {
		return v
	}
	cp := &Value{Kind: KindObject}
	for _, m := range v.Members {
		if m.Name == name {
			continue
		}
		cp.Members = append(cp.Members, m)
	}
	return cp
}

// maxSafeInt is 2^53-1: the largest integer every mainstream runtime holds
// exactly. §4 bounds every integer to +/- this.
const maxSafeInt = 9007199254740991

type parser struct {
	src []byte
	i   int
}

// Parse reads one JSON document under the constraints of federation-package/v1
// §4. Trailing content after the value is an error.
func Parse(src []byte) (*Value, error) {
	if !utf8.Valid(src) {
		return nil, fmt.Errorf("document is not valid UTF-8")
	}
	p := &parser{src: src}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.src) {
		return nil, fmt.Errorf("trailing content at byte %d", p.i)
	}
	return v, nil
}

func (p *parser) ws() {
	for p.i < len(p.src) {
		switch p.src[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) errf(format string, args ...any) error {
	return fmt.Errorf("byte %d: %s", p.i, fmt.Sprintf(format, args...))
}

const maxDepth = 64

func (p *parser) value(depth int) (*Value, error) {
	if depth > maxDepth {
		return nil, p.errf("nesting deeper than %d", maxDepth)
	}
	if p.i >= len(p.src) {
		return nil, p.errf("unexpected end of document")
	}
	switch c := p.src[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.string()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't':
		if err := p.lit("true"); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: true}, nil
	case c == 'f':
		if err := p.lit("false"); err != nil {
			return nil, err
		}
		return &Value{Kind: KindBool, Bool: false}, nil
	case c == 'n':
		if err := p.lit("null"); err != nil {
			return nil, err
		}
		// A null parses. Structural validation refuses it: the canonicaliser
		// must be able to render a package containing one, so an operator can
		// be shown what was rejected.
		return &Value{Kind: KindNull}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errf("unexpected character %q", c)
	}
}

func (p *parser) lit(s string) error {
	if p.i+len(s) > len(p.src) || string(p.src[p.i:p.i+len(s)]) != s {
		return p.errf("expected %s", s)
	}
	p.i += len(s)
	return nil
}

func (p *parser) object(depth int) (*Value, error) {
	p.i++ // '{'
	v := &Value{Kind: KindObject}
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.src) && p.src[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		if p.i >= len(p.src) || p.src[p.i] != '"' {
			return nil, p.errf("expected a member name")
		}
		name, err := p.string()
		if err != nil {
			return nil, err
		}
		if seen[name] {
			// §4: a parser handed the same name twice must refuse, never
			// resolve. Go keeps the last and other parsers keep the first, so
			// resolving would make the document mean two different things.
			return nil, p.errf("duplicate member name %q", name)
		}
		seen[name] = true
		p.ws()
		if p.i >= len(p.src) || p.src[p.i] != ':' {
			return nil, p.errf("expected ':' after member name %q", name)
		}
		p.i++
		p.ws()
		mv, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Members = append(v.Members, Member{Name: name, Value: mv})
		p.ws()
		if p.i >= len(p.src) {
			return nil, p.errf("unexpected end of object")
		}
		switch p.src[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return v, nil
		default:
			return nil, p.errf("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (*Value, error) {
	p.i++ // '['
	v := &Value{Kind: KindArray, Items: []*Value{}}
	p.ws()
	if p.i < len(p.src) && p.src[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		item, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.Items = append(v.Items, item)
		p.ws()
		if p.i >= len(p.src) {
			return nil, p.errf("unexpected end of array")
		}
		switch p.src[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return v, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}

func (p *parser) string() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.src) {
			return "", p.errf("unterminated string")
		}
		c := p.src[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", p.errf("unescaped control character U+%04X in string", c)
		case c == '\\':
			p.i++
			if p.i >= len(p.src) {
				return "", p.errf("unterminated escape")
			}
			switch p.src[p.i] {
			case '"':
				sb.WriteByte('"')
				p.i++
			case '\\':
				sb.WriteByte('\\')
				p.i++
			case '/':
				sb.WriteByte('/')
				p.i++
			case 'b':
				sb.WriteByte('\b')
				p.i++
			case 'f':
				sb.WriteByte('\f')
				p.i++
			case 'n':
				sb.WriteByte('\n')
				p.i++
			case 'r':
				sb.WriteByte('\r')
				p.i++
			case 't':
				sb.WriteByte('\t')
				p.i++
			case 'u':
				r, err := p.unicodeEscape()
				if err != nil {
					return "", err
				}
				sb.WriteRune(r)
			default:
				return "", p.errf("unknown escape \\%c", p.src[p.i])
			}
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

// unicodeEscape reads \uXXXX, having consumed the backslash and pointing at the
// 'u'. An escape naming an unpaired surrogate denotes no Unicode scalar value
// and so has no UTF-8 encoding; §4 refuses it rather than substituting U+FFFD.
func (p *parser) unicodeEscape() (rune, error) {
	hi, err := p.hex4()
	if err != nil {
		return 0, err
	}
	if !utf16.IsSurrogate(rune(hi)) {
		return rune(hi), nil
	}
	if hi >= 0xDC00 {
		return 0, p.errf("unpaired low surrogate \\u%04X", hi)
	}
	if p.i+1 >= len(p.src) || p.src[p.i] != '\\' || p.src[p.i+1] != 'u' {
		return 0, p.errf("unpaired high surrogate \\u%04X", hi)
	}
	p.i++ // backslash
	lo, err := p.hex4()
	if err != nil {
		return 0, err
	}
	r := utf16.DecodeRune(rune(hi), rune(lo))
	if r == utf8.RuneError {
		return 0, p.errf("invalid surrogate pair \\u%04X\\u%04X", hi, lo)
	}
	return r, nil
}

// hex4 consumes 'u' plus four hex digits.
func (p *parser) hex4() (uint16, error) {
	if p.i >= len(p.src) || p.src[p.i] != 'u' {
		return 0, p.errf("expected \\u escape")
	}
	p.i++
	if p.i+4 > len(p.src) {
		return 0, p.errf("truncated \\u escape")
	}
	n, err := strconv.ParseUint(string(p.src[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, p.errf("malformed \\u escape")
	}
	p.i += 4
	return uint16(n), nil
}

// number reads an integer token. §4 refuses a fractional part, an exponent, a
// leading zero, a leading plus and negative zero, and bounds the value to
// +/- (2^53 - 1). The test is on the token as written, never on the parsed
// value, so that the set of accepted documents does not depend on how a given
// language widens numbers.
func (p *parser) number() (*Value, error) {
	start := p.i
	if p.src[p.i] == '-' {
		p.i++
	}
	digits := p.i
	for p.i < len(p.src) && p.src[p.i] >= '0' && p.src[p.i] <= '9' {
		p.i++
	}
	if p.i == digits {
		return nil, p.errf("number with no digits")
	}
	tok := string(p.src[start:p.i])
	// Anything the JSON grammar allows after the integer part is a fractional
	// part or an exponent, both refused. Naming the offending token in the
	// error is the point: "1380.0 is refused" sends a reader somewhere useful.
	if p.i < len(p.src) {
		if c := p.src[p.i]; c == '.' || c == 'e' || c == 'E' {
			for p.i < len(p.src) && strings.IndexByte(".eE+-0123456789", p.src[p.i]) >= 0 {
				p.i++
			}
			return nil, fmt.Errorf("number %q carries a fractional part or an exponent; integers only", string(p.src[start:p.i]))
		}
	}
	intPart := string(p.src[digits:p.i])
	if len(intPart) > 1 && intPart[0] == '0' {
		return nil, fmt.Errorf("number %q has a leading zero", tok)
	}
	if tok == "-0" {
		return nil, fmt.Errorf("number %q is negative zero; JCS emits it as 0, so the document is not in canonical form", tok)
	}
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return nil, fmt.Errorf("number %q is outside the range +/-(2^53-1)", tok)
	}
	return &Value{Kind: KindNumber, Num: tok}, nil
}
