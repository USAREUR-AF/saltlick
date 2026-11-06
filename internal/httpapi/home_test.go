package httpapi_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// The root is a page for a person: it says what the directory is, that
// listing grants nothing, and lists what is published.
func TestHomePage(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"Listing grants nothing", "No parties are listed yet", "FED_DIRECTORY_URL", "/v1/parties"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("home page lacks %q", want)
		}
	}
}

// An unknown path is still a 404: the root route matches "/" exactly.
func TestUnknownPathStill404(t *testing.T) {
	h := newHarness(t)
	resp := h.get("/nope")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404", resp.StatusCode)
	}
}
