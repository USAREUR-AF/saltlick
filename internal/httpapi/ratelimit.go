package httpapi

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate is a sustained request rate. The zero Rate disables the limit it is
// used for.
type Rate struct {
	PerSecond float64
}

// ParseRate reads "N/s", "N/m" or "N/h". "0" or "off" disables the limit.
func ParseRate(s string) (Rate, error) {
	s = strings.TrimSpace(s)
	if s == "0" || s == "off" {
		return Rate{}, nil
	}
	num, unit, ok := strings.Cut(s, "/")
	if !ok {
		return Rate{}, fmt.Errorf("rate %q: want N/s, N/m or N/h", s)
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n < 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return Rate{}, fmt.Errorf("rate %q: %q is not a non-negative number", s, num)
	}
	var per float64
	switch unit {
	case "s":
		per = 1
	case "m":
		per = 60
	case "h":
		per = 3600
	default:
		return Rate{}, fmt.Errorf("rate %q: unit must be s, m or h", s)
	}
	return Rate{PerSecond: n / per}, nil
}

// ParsePrefixes reads a comma-separated list of CIDRs or bare addresses. A bare
// address is taken as a single host.
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q is neither a CIDR nor an address", f)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// LimitConfig sets the per-source budgets.
//
// Reads (GET, HEAD) and writes (everything else) draw on separate buckets, so a
// client reading the catalogue does not spend its publish budget and a client
// hammering writes does not crowd out its own reads. /healthz draws on neither:
// a load balancer probing it must never be the thing that gets limited.
type LimitConfig struct {
	Read       Rate
	ReadBurst  int
	Write      Rate
	WriteBurst int

	// TrustedProxies are the addresses whose X-Forwarded-For is believed. A
	// request from anywhere else is keyed by its own address and its
	// X-Forwarded-For is ignored, because any client can write that header.
	TrustedProxies []netip.Prefix

	// MaxSources bounds how many sources each budget tracks at once. When the
	// table is full and nothing in it is idle, a request from a new source is
	// refused rather than the table growing. Zero means DefaultMaxSources.
	MaxSources int
}

// DefaultMaxSources bounds memory at a few megabytes per budget.
const DefaultMaxSources = 65536

// sweepEvery is how often idle buckets are dropped.
const sweepEvery = time.Minute

// Limiter applies per-source token buckets in front of a handler.
type Limiter struct {
	cfg   LimitConfig
	now   func() time.Time
	read  *bucketTable
	write *bucketTable
}

// NewLimiter builds a Limiter. now may be nil, in which case time.Now is used.
func NewLimiter(cfg LimitConfig, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if cfg.MaxSources <= 0 {
		cfg.MaxSources = DefaultMaxSources
	}
	return &Limiter{
		cfg:   cfg,
		now:   now,
		read:  newBucketTable(cfg.Read, cfg.ReadBurst, cfg.MaxSources),
		write: newBucketTable(cfg.Write, cfg.WriteBurst, cfg.MaxSources),
	}
}

// Wrap returns h behind the limiter.
func (l *Limiter) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			h.ServeHTTP(w, r)
			return
		}
		table := l.write
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			table = l.read
		}
		ok, wait := table.take(l.ClientKey(r), l.now())
		if !ok {
			secs := int(math.Ceil(wait.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(HeaderAdvisory, Advisory)
			w.WriteHeader(http.StatusTooManyRequests)
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{
				"error":    fmt.Sprintf("rate limit exceeded for this source; retry after %ds", secs),
				"advisory": Advisory,
			})
			return
		}
		h.ServeHTTP(w, r)
	})
}

// ClientKey is the source a request is charged to.
//
// It is the connection's peer address, unless that peer is a trusted proxy. In
// that case X-Forwarded-For is read from the right, skipping trusted proxies,
// and the first address that is not one is the client: every hop to the right
// of it was appended by infrastructure that is trusted, and everything to its
// left was written by the client and may be invented.
//
// IPv6 sources are keyed by their /64, the smallest block a single subscriber
// is commonly given, so one host cannot reset its budget by changing address
// within its own prefix.
func (l *Limiter) ClientKey(r *http.Request) string {
	peer, ok := remoteAddr(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	if l.trusted(peer) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break // a malformed hop: stop believing the header here
			}
			a = a.Unmap()
			if !l.trusted(a) {
				return sourceKey(a)
			}
		}
	}
	return sourceKey(peer)
}

func (l *Limiter) trusted(a netip.Addr) bool {
	for _, p := range l.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteAddr(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func sourceKey(a netip.Addr) string {
	a = a.WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// Sources reports how many sources the read and write budgets currently track.
func (l *Limiter) Sources() (read, write int) {
	return l.read.len(), l.write.len()
}

type bucket struct {
	tokens float64
	last   time.Time
}

type bucketTable struct {
	rate  float64 // tokens per second; 0 disables
	burst float64
	max   int
	// idle is how long a bucket takes to refill completely. A bucket idle that
	// long is indistinguishable from a fresh one, so dropping it loses nothing.
	idle time.Duration

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

func newBucketTable(r Rate, burst, max int) *bucketTable {
	if burst < 1 {
		burst = 1
	}
	t := &bucketTable{
		rate:    r.PerSecond,
		burst:   float64(burst),
		max:     max,
		buckets: make(map[string]*bucket),
	}
	if t.rate > 0 {
		t.idle = time.Duration(t.burst / t.rate * float64(time.Second))
	}
	return t
}

// take spends one token for key. When none is available it reports how long
// until one will be.
func (t *bucketTable) take(key string, now time.Time) (bool, time.Duration) {
	if t.rate <= 0 {
		return true, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if now.Sub(t.lastSweep) >= sweepEvery {
		t.sweep(now)
	}
	b, ok := t.buckets[key]
	if !ok {
		if len(t.buckets) >= t.max {
			t.sweep(now)
		}
		if len(t.buckets) >= t.max {
			return false, t.idle
		}
		b = &bucket{tokens: t.burst, last: now}
		t.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(t.burst, b.tokens+el*t.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / t.rate * float64(time.Second))
}

func (t *bucketTable) sweep(now time.Time) {
	for k, b := range t.buckets {
		if now.Sub(b.last) >= t.idle {
			delete(t.buckets, k)
		}
	}
	t.lastSweep = now
}

func (t *bucketTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}
