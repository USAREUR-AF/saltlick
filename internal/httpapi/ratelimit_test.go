package httpapi_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/store"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func mustRate(t *testing.T, s string) httpapi.Rate {
	t.Helper()
	r, err := httpapi.ParseRate(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// limited builds the real directory handler behind a limiter on a fake clock.
func limited(t *testing.T, cfg httpapi.LimitConfig) (http.Handler, *httpapi.Limiter, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "saltlick.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &clock{t: fixedNow}
	l := httpapi.NewLimiter(cfg, c.now)
	return l.Wrap(httpapi.New(st, nil, c.now).Handler()), l, c
}

func do(h http.Handler, method, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(nil))
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func defaults(t *testing.T) httpapi.LimitConfig {
	return httpapi.LimitConfig{
		Read: mustRate(t, "10/s"), ReadBurst: 3,
		Write: mustRate(t, "6/m"), WriteBurst: 2,
	}
}

func TestReadLimitFiresWith429AndRetryAfter(t *testing.T) {
	h, _, c := limited(t, defaults(t))
	for i := 0; i < 3; i++ {
		if rec := do(h, "GET", "/v1/parties", "192.0.2.1:4000", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d within the burst = %d", i, rec.Code)
		}
	}
	rec := do(h, "GET", "/v1/parties", "192.0.2.1:4000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("request past the burst = %d, want 429", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", rec.Header().Get("Retry-After"))
	}
	if rec.Header().Get(httpapi.HeaderAdvisory) == "" {
		t.Fatal("a 429 must carry the advisory like every other response")
	}

	// Another source is unaffected.
	if rec := do(h, "GET", "/v1/parties", "192.0.2.2:4000", nil); rec.Code != http.StatusOK {
		t.Fatalf("a different source = %d, want 200", rec.Code)
	}

	// The bucket refills at the sustained rate.
	c.advance(100 * time.Millisecond)
	if rec := do(h, "GET", "/v1/parties", "192.0.2.1:4000", nil); rec.Code != http.StatusOK {
		t.Fatalf("after one token's worth of time = %d, want 200", rec.Code)
	}
}

func TestWritesHaveTheirOwnStricterBudget(t *testing.T) {
	h, _, _ := limited(t, defaults(t))
	src := "192.0.2.10:5000"
	for i := 0; i < 2; i++ {
		if rec := do(h, "PUT", "/v1/parties/xaa", src, nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("write %d within the burst was limited", i)
		}
	}
	rec := do(h, "DELETE", "/v1/parties/xaa", src, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("write past the burst = %d, want 429", rec.Code)
	}
	// Ten seconds per write token at 6/m.
	if got := rec.Header().Get("Retry-After"); got != "10" {
		t.Fatalf("Retry-After = %q, want 10", got)
	}
	// Spending the write budget leaves the read budget whole.
	if rec := do(h, "GET", "/v1/parties", src, nil); rec.Code != http.StatusOK {
		t.Fatalf("read after exhausting writes = %d, want 200", rec.Code)
	}
}

func TestHealthzIsNeverLimited(t *testing.T) {
	h, l, _ := limited(t, defaults(t))
	for i := 0; i < 100; i++ {
		if rec := do(h, "GET", "/healthz", "192.0.2.20:6000", nil); rec.Code != http.StatusOK {
			t.Fatalf("healthz request %d = %d", i, rec.Code)
		}
	}
	if r, w := l.Sources(); r != 0 || w != 0 {
		t.Fatalf("healthz was tracked: read=%d write=%d", r, w)
	}
}

func TestForwardedForIgnoredUnlessPeerIsATrustedProxy(t *testing.T) {
	cfg := defaults(t)
	h, l, _ := limited(t, cfg)
	// No trusted proxy: a client rotating X-Forwarded-For still spends one budget.
	for i := 0; i < 3; i++ {
		do(h, "GET", "/v1/parties", "192.0.2.30:7000",
			map[string]string{"X-Forwarded-For": "198.51.100." + strconv.Itoa(i)})
	}
	rec := do(h, "GET", "/v1/parties", "192.0.2.30:7000",
		map[string]string{"X-Forwarded-For": "198.51.100.99"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed X-Forwarded-For escaped the limit: %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/v1/parties", nil)
	req.RemoteAddr = "192.0.2.30:7000"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := l.ClientKey(req); got != "192.0.2.30" {
		t.Fatalf("ClientKey = %q, want the peer address", got)
	}

	// Trusted proxy: the rightmost hop that is not a trusted proxy is the client,
	// whatever the client wrote to the left of it.
	cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	_, l, _ = limited(t, cfg)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.66, 198.51.100.7, 10.9.9.9")
	if got := l.ClientKey(req); got != "198.51.100.7" {
		t.Fatalf("ClientKey behind a trusted proxy = %q, want 198.51.100.7", got)
	}
	// A trusted proxy that sent no header is itself the source.
	req.Header.Del("X-Forwarded-For")
	if got := l.ClientKey(req); got != "10.1.2.3" {
		t.Fatalf("ClientKey without X-Forwarded-For = %q, want the proxy", got)
	}
	// An untrusted peer's header is ignored even when trusted proxies are set.
	req.RemoteAddr = "192.0.2.31:7000"
	req.Header.Set("X-Forwarded-For", "198.51.100.8")
	if got := l.ClientKey(req); got != "192.0.2.31" {
		t.Fatalf("ClientKey from an untrusted peer = %q, want the peer", got)
	}
}

func TestIPv6SourcesAreKeyedByTheir64(t *testing.T) {
	_, l, _ := limited(t, defaults(t))
	a := httptest.NewRequest("GET", "/v1/parties", nil)
	a.RemoteAddr = "[2001:db8:1:2::1]:443"
	b := httptest.NewRequest("GET", "/v1/parties", nil)
	b.RemoteAddr = "[2001:db8:1:2:ffff::9]:443"
	if l.ClientKey(a) != l.ClientKey(b) {
		t.Fatalf("addresses in one /64 got different keys: %q %q", l.ClientKey(a), l.ClientKey(b))
	}
}

func TestIdleSourcesAreEvicted(t *testing.T) {
	h, l, c := limited(t, defaults(t))
	for i := 0; i < 50; i++ {
		do(h, "GET", "/v1/parties", "192.0.2."+strconv.Itoa(i)+":1000", nil)
	}
	do(h, "PUT", "/v1/parties/xaa", "192.0.2.200:1000", nil)
	if r, w := l.Sources(); r != 50 || w != 1 {
		t.Fatalf("tracked read=%d write=%d, want 50 and 1", r, w)
	}
	// Past the sweep interval and the longest refill, every bucket is full again
	// and indistinguishable from a fresh one, so it is dropped.
	c.advance(2 * time.Minute)
	do(h, "GET", "/v1/parties", "198.51.100.1:1000", nil)
	do(h, "PUT", "/v1/parties/xaa", "198.51.100.1:1000", nil)
	if r, w := l.Sources(); r != 1 || w != 1 {
		t.Fatalf("after idling, tracked read=%d write=%d, want 1 and 1", r, w)
	}
}

func TestSourceTableIsBounded(t *testing.T) {
	cfg := defaults(t)
	cfg.MaxSources = 4
	h, l, _ := limited(t, cfg)
	for i := 0; i < 4; i++ {
		do(h, "GET", "/v1/parties", "192.0.2."+strconv.Itoa(i)+":1000", nil)
	}
	if rec := do(h, "GET", "/v1/parties", "192.0.2.99:1000", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a new source with the table full = %d, want 429", rec.Code)
	}
	if r, _ := l.Sources(); r != 4 {
		t.Fatalf("table grew past its bound: %d", r)
	}
	// A source already tracked is still served.
	if rec := do(h, "GET", "/v1/parties", "192.0.2.0:1000", nil); rec.Code != http.StatusOK {
		t.Fatalf("a tracked source with the table full = %d, want 200", rec.Code)
	}
}

func TestParseRate(t *testing.T) {
	for in, want := range map[string]float64{"10/s": 10, "6/m": 0.1, "360/h": 0.1, "0": 0, "off": 0} {
		r, err := httpapi.ParseRate(in)
		if err != nil || r.PerSecond != want {
			t.Errorf("ParseRate(%q) = %v, %v; want %v", in, r.PerSecond, err, want)
		}
	}
	for _, in := range []string{"10", "10/d", "x/s", "-1/s", ""} {
		if _, err := httpapi.ParseRate(in); err == nil {
			t.Errorf("ParseRate(%q) accepted", in)
		}
	}
}

func TestZeroRateDisablesTheLimit(t *testing.T) {
	h, _, _ := limited(t, httpapi.LimitConfig{ReadBurst: 1, WriteBurst: 1})
	for i := 0; i < 50; i++ {
		if rec := do(h, "GET", "/v1/parties", "192.0.2.1:1", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d with limits off = %d", i, rec.Code)
		}
	}
}
