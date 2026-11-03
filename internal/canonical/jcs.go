package canonical

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// Write serialises a Value in RFC 8785 canonical form: member names sorted by
// UTF-16 code unit, no insignificant whitespace, UTF-8 output.
//
// This is how a receiver reproduces bytes it did not produce, so it must render
// faithfully whatever it was given -- including a null. Refusing a null here
// would mean the one moment a faithful rendering is most wanted, showing an
// operator what was rejected, is the moment it cannot be produced. Structural
// validation refuses the null; this function writes it.
func Write(v *Value) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func write(buf *bytes.Buffer, v *Value) error {
	if v == nil {
		// A member with no value at all -- the "mtu":, case. There is nothing
		// to write, and emitting anything would produce output that parses
		// nowhere while carrying a clean digest.
		return fmt.Errorf("member present with no value")
	}
	switch v.Kind {
	case KindNull:
		buf.WriteString("null")
	case KindBool:
		if v.Bool {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindNumber:
		buf.WriteString(v.Num)
	case KindString:
		writeString(buf, v.Str)
	case KindArray:
		buf.WriteByte('[')
		for i, item := range v.Items {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case KindObject:
		members := make([]Member, len(v.Members))
		copy(members, v.Members)
		sort.SliceStable(members, func(i, j int) bool {
			return LessUTF16(members[i].Name, members[j].Name)
		})
		buf.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, m.Name)
			buf.WriteByte(':')
			if err := write(buf, m.Value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unknown value kind %d", v.Kind)
	}
	return nil
}

// LessUTF16 is the one ordering this format uses, for member names and for
// set-arrays alike: compare UTF-16 code units one at a time, shorter string
// first where one is a prefix of the other.
//
// Go's own sort.Strings compares bytes, which is code-point order, and that
// differs on exactly one thing: a character above the basic multilingual plane
// is a surrogate pair beginning D800-DBFF, so UTF-16 places it before
// U+E000-U+FFFF where a code-point comparison places it after. Do not replace
// this with strings.Compare.
func LessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeString emits a JSON string using JCS escaping: the two-character escapes
// where they exist, \u00XX for the remaining control characters, and the
// character itself otherwise.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// Indent renders a Value in canonical member order with two-space indentation.
// It is for showing a human what is stored. It is never what GET returns:
// pretty-printing stored package bytes would break every signature over them.
func Indent(v *Value) ([]byte, error) {
	var buf bytes.Buffer
	if err := indent(&buf, v, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func indent(buf *bytes.Buffer, v *Value, depth int) error {
	pad := strings.Repeat("  ", depth+1)
	closePad := strings.Repeat("  ", depth)
	switch {
	case v == nil:
		return fmt.Errorf("member present with no value")
	case v.Kind == KindObject && len(v.Members) > 0:
		members := make([]Member, len(v.Members))
		copy(members, v.Members)
		sort.SliceStable(members, func(i, j int) bool { return LessUTF16(members[i].Name, members[j].Name) })
		buf.WriteString("{\n")
		for i, m := range members {
			if i > 0 {
				buf.WriteString(",\n")
			}
			buf.WriteString(pad)
			writeString(buf, m.Name)
			buf.WriteString(": ")
			if err := indent(buf, m.Value, depth+1); err != nil {
				return err
			}
		}
		buf.WriteString("\n" + closePad + "}")
	case v.Kind == KindArray && len(v.Items) > 0:
		buf.WriteString("[\n")
		for i, item := range v.Items {
			if i > 0 {
				buf.WriteString(",\n")
			}
			buf.WriteString(pad)
			if err := indent(buf, item, depth+1); err != nil {
				return err
			}
		}
		buf.WriteString("\n" + closePad + "]")
	default:
		return write(buf, v)
	}
	return nil
}
