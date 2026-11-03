package canonical

import (
	"strings"
	"testing"
)

func TestParseRefusals(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"duplicate member", `{"expires":"2026-01-01","expires":"2027-01-01"}`, "duplicate member name"},
		{"duplicate nested", `{"a":{"b":1,"b":2}}`, "duplicate member name"},
		{"fractional", `{"mtu":1380.0}`, "fractional part or an exponent"},
		{"exponent", `{"mtu":1.38e3}`, "fractional part or an exponent"},
		{"trailing point", `{"mtu":1380.}`, "fractional part or an exponent"},
		{"leading zero", `{"mtu":01}`, "leading zero"},
		{"leading plus", `{"mtu":+1}`, "unexpected character"},
		{"negative zero", `{"mtu":-0}`, "negative zero"},
		{"too large", `{"n":9007199254740992}`, "outside the range"},
		{"too small", `{"n":-9007199254740992}`, "outside the range"},
		{"unpaired high surrogate", `{"s":"\ud800"}`, "unpaired high surrogate"},
		{"unpaired low surrogate", `{"s":"\udc00"}`, "unpaired low surrogate"},
		{"trailing content", `{"a":1} {"b":2}`, "trailing content"},
		{"raw control character", "{\"s\":\"a\tb\"}", "unescaped control character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("Parse(%s) accepted the document; want a refusal mentioning %q", tc.src, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse(%s) = %v; want an error mentioning %q", tc.src, err, tc.want)
			}
		})
	}
}

func TestParseRefusesInvalidUTF8(t *testing.T) {
	// A decoder that substitutes U+FFFD here has composed a document that was
	// never signed: the bytes change, so the digest changes, with nothing
	// reported and no field that differs.
	src := []byte("{\"s\":\"a\xffb\"}")
	if _, err := Parse(src); err == nil {
		t.Fatal("Parse accepted invalid UTF-8")
	}
}

func TestParseAcceptsBoundaryIntegers(t *testing.T) {
	for _, src := range []string{`{"n":9007199254740991}`, `{"n":-9007199254740991}`, `{"n":0}`} {
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("Parse(%s) = %v; want acceptance", src, err)
		}
	}
}

func TestParseAcceptsNullSoItCanBeRendered(t *testing.T) {
	// The canonicaliser must be able to render a package containing a null, so
	// an operator can be shown what was rejected. Refusing the null is
	// structural validation's job, in package pkgv1, and it is tested there.
	v, err := Parse([]byte(`{"cut":null}`))
	if err != nil {
		t.Fatalf("Parse = %v; the canonicaliser must render a null faithfully", err)
	}
	out, err := Write(v)
	if err != nil {
		t.Fatalf("Write = %v", err)
	}
	if string(out) != `{"cut":null}` {
		t.Fatalf("Write = %s; want {\"cut\":null}", out)
	}
}

func TestWriteSortsMembersAndPreservesArrayOrder(t *testing.T) {
	v, err := Parse([]byte(`{"b":1,"a":[3,1,2],"A":2}`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Write(v)
	if err != nil {
		t.Fatal(err)
	}
	// Members sort; array elements do not. A composer sorts set-arrays on the
	// way into an agreement, but a package is what it is and must not be
	// repaired -- the signature covers the bytes as signed.
	if want := `{"A":2,"a":[3,1,2],"b":1}`; string(out) != want {
		t.Fatalf("Write = %s; want %s", out, want)
	}
}

func TestWritePreservesIntegerTokens(t *testing.T) {
	v, err := Parse([]byte(`{"n":1380}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Write(v)
	if string(out) != `{"n":1380}` {
		t.Fatalf("Write = %s; want {\"n\":1380}", out)
	}
}

func TestLessUTF16OrdersSurrogatesBeforeHighBMP(t *testing.T) {
	// The one place UTF-16 code-unit order differs from Go's byte order: a
	// character above the basic multilingual plane is a surrogate pair
	// beginning D800-DBFF, so it sorts before U+E000-U+FFFF, where a byte or
	// code-point comparison puts it after.
	astral := "\U0001F600" // surrogate pair D83D DE00
	highBMP := "\uFFFD"    // single code unit FFFD
	if !LessUTF16(astral, highBMP) {
		t.Fatalf("LessUTF16(%q, %q) = false; UTF-16 order must place the surrogate pair first", astral, highBMP)
	}
	if astral < highBMP {
		t.Fatal("this test no longer distinguishes UTF-16 order from Go's byte order; pick another pair")
	}
}

func TestWriteEscapesPerJCS(t *testing.T) {
	v, err := Parse([]byte(`{"s":"a\"b\\c\nde"}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Write(v)
	if want := `{"s":"a\"b\\c\nde"}`; string(out) != want {
		t.Fatalf("Write = %s; want %s", out, want)
	}
}

func TestWithoutRemovesOnlyTheNamedMember(t *testing.T) {
	v, err := Parse([]byte(`{"a":1,"signature":"x","b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := Write(v.Without("signature"))
	if want := `{"a":1,"b":2}`; string(out) != want {
		t.Fatalf("Write = %s; want %s", out, want)
	}
	// The original is untouched: building a signing input must not mutate the
	// document the caller still holds.
	if v.Get("signature") == nil {
		t.Fatal("Without mutated the receiver")
	}
}
