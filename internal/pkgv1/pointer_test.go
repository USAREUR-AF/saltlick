package pkgv1_test

import (
	"strings"
	"testing"

	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/testsupport"
)

func TestPointerParsesAndVerifies(t *testing.T) {
	k := testsupport.NewKey(t, "pointer")
	p, err := pkgv1.Parse(testsupport.SignedPointer(t, k, "xaa", "2026-12-06"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec != pkgv1.PointerSpec || p.SovereignID != "xaa" || p.Expires != "2026-12-06" || p.Issued != "" {
		t.Fatalf("parsed %+v", p)
	}
	if err := p.VerifySignature(k.Pub); err != nil {
		t.Fatal(err)
	}
	if err := p.VerifySignature(testsupport.NewKey(t, "other").Pub); err == nil {
		t.Fatal("a pointer verified under a key that did not sign it")
	}
}

func TestPointerPackageURLMustBeHTTPSWithoutUserinfoOrFragment(t *testing.T) {
	k := testsupport.NewKey(t, "pointer-url")
	for url, want := range map[string]string{
		"http://xaa.example/p.json":                        "https://",
		"ftp://xaa.example/p.json":                         "https://",
		"/p.json":                                          "https://",
		"https:///p.json":                                  "no host",
		"https://user:pw@xaa.example/p.json":               "userinfo",
		"https://xaa.example/p.json#frag":                  "fragment",
		"https://xaa.example/" + strings.Repeat("a", 2048): "at most 2048",
	} {
		_, err := pkgv1.Parse(testsupport.Sign(t, k, testsupport.Pointer("xaa", url, "2026-12-06")))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("package_url %.40q: err = %v, want it to mention %q", url, err, want)
		}
	}
}

func TestPointerRefusesUnknownAndMissingMembers(t *testing.T) {
	k := testsupport.NewKey(t, "pointer-members")
	base := testsupport.Pointer("xaa", "https://xaa.example/p.json", "2026-12-06")

	extra := strings.Replace(base, `"expires"`, `"issued": "2026-09-06", "expires"`, 1)
	if _, err := pkgv1.Parse(testsupport.Sign(t, k, extra)); err == nil || !strings.Contains(err.Error(), "unknown top-level member") {
		t.Fatalf("unknown member: err = %v", err)
	}
	keyed := strings.Replace(base, `"expires"`, `"key": "pLgCyHH6SH7N02G9sFrWG1wODsv0PT434mlFj8H5X64=", "expires"`, 1)
	if _, err := pkgv1.Parse(testsupport.Sign(t, k, keyed)); err == nil {
		t.Fatal("a pointer carrying key material was accepted")
	}
	offer := strings.Replace(base, `"expires"`, `"transport_offer": {}, "expires"`, 1)
	if _, err := pkgv1.Parse(testsupport.Sign(t, k, offer)); err == nil || !strings.Contains(err.Error(), "never carries an offer") {
		t.Fatalf("offer in a pointer: err = %v", err)
	}
	missing := strings.Replace(base, `"package_sha256": "`+testsupport.TestDigest+`",`, "", 1)
	if _, err := pkgv1.Parse(testsupport.Sign(t, k, missing)); err == nil || !strings.Contains(err.Error(), "missing required member") {
		t.Fatalf("missing digest: err = %v", err)
	}
	upper := strings.Replace(base, testsupport.TestDigest, strings.ToUpper(testsupport.TestDigest[7:]), 1)
	if _, err := pkgv1.Parse(testsupport.Sign(t, k, upper)); err == nil || !strings.Contains(err.Error(), "package_sha256") {
		t.Fatalf("malformed digest: err = %v", err)
	}
}
