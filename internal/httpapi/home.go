package httpapi

import (
	"bytes"
	"html/template"
	"net/http"
)

// home is the page a person sees at "/": what this directory is, how a
// federation driver uses it, and the parties listed now. It reads the same
// catalogue as GET /v1/parties and adds nothing to it.
var homeTemplate = template.Must(template.New("home").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>saltlick: goatnet peering directory</title>
<style>
:root { --fg:#1c2430; --muted:#5b6876; --bg:#fff; --line:#d6dee8; --card:#f4f7fb; --accent:#12324f; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6edf3; --muted:#9aa6b2; --bg:#0d1117; --line:#30363d; --card:#161b22; --accent:#8ab4f8; } }
body { font: 16px/1.55 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: var(--fg); background: var(--bg); max-width: 860px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { color: var(--accent); margin: 0 0 4px; font-size: 1.7rem; }
h2 { color: var(--accent); font-size: 1.1rem; margin: 28px 0 8px; border-bottom: 1px solid var(--line); padding-bottom: 4px; }
.sub { color: var(--muted); margin: 0 0 16px; }
.lead { background: var(--card); border-left: 4px solid var(--accent); padding: 10px 14px; border-radius: 6px; }
table { border-collapse: collapse; width: 100%; font-size: 0.93rem; }
th, td { border: 1px solid var(--line); padding: 6px 9px; text-align: left; }
th { background: var(--card); }
code { font: 0.88em ui-monospace, Menlo, monospace; background: var(--card); padding: 1px 4px; border-radius: 4px; }
.expired { color: var(--muted); text-decoration: line-through; }
a { color: var(--accent); }
</style></head><body>
<h1>saltlick</h1>
<p class="sub">The peering directory for goatnets that federate with each other.</p>
<p class="lead"><strong>Listing grants nothing.</strong> Each party publishes a signed pointer: who it is, where its signed federation package can be fetched, the package's digest, and an expiry date. A party with no public host of its own keeps its package, its CA certificate and its SPIFFE trust bundle here, beside its entry, each served with the signature of the key that uploaded it. A counterparty's federation driver looks the party up, fetches the files, and checks the signatures, the digest and the CA fingerprint itself. This directory does not vouch for who published an entry; the two parties read each other's verifying key and CA fingerprint aloud once, by voice.</p>

<h2>Parties listed</h2>
{{if .Parties}}<table>
<tr><th>Party</th><th>Entry format</th><th>Expires</th><th>Hosted here</th></tr>
{{range .Parties}}<tr{{if .Expired}} class="expired"{{end}}><td><a href="/v1/parties/{{.SovereignID}}"><code>{{.SovereignID}}</code></a></td><td><code>{{.Spec}}</code></td><td>{{.Expires}}{{if .Expired}} (expired){{end}}</td><td>{{$sep := false}}{{if .Package}}<a href="{{.Package}}">package</a>{{$sep = true}}{{end}}{{if .CA}}{{if $sep}} · {{end}}<a href="{{.CA}}">CA</a>{{$sep = true}}{{end}}{{if .SPIFFEBundle}}{{if $sep}} · {{end}}<a href="{{.SPIFFEBundle}}">SPIFFE bundle</a>{{end}}</td></tr>
{{end}}</table>{{else}}<p>No parties are listed yet.</p>{{end}}

<h2>Using it</h2>
<p>Run the goatcore federation driver with <code>FED_DIRECTORY_URL</code> set to this address. In the package-exchange phase it uploads your package and CA certificate here (unless <code>FED_PACKAGE_URL</code> names your own host), publishes your pointer, fetches the counterparty's package and CA, and prints a compatibility report. Nothing else is required of either party.</p>

<h2>API</h2>
<table>
<tr><th>Request</th><th>Returns</th></tr>
<tr><td><code>GET /v1/parties</code></td><td>The list above, as JSON</td></tr>
<tr><td><code>GET /v1/parties/&lt;id&gt;</code></td><td>The stored entry, byte for byte</td></tr>
<tr><td><code>PUT /v1/parties/&lt;id&gt;</code></td><td>Publish or replace an entry; the first key to claim a name keeps it</td></tr>
<tr><td><code>DELETE /v1/parties/&lt;id&gt;</code></td><td>Remove an entry and the files it hosts, signed by its bound key</td></tr>
<tr><td><code>GET /v1/parties/&lt;id&gt;/package</code></td><td>The party's signed federation package, byte for byte</td></tr>
<tr><td><code>PUT /v1/parties/&lt;id&gt;/package</code></td><td>Host or replace the package, signed by the entry's bound key</td></tr>
<tr><td><code>GET /v1/parties/&lt;id&gt;/packages/&lt;counterparty&gt;</code></td><td>The package the party signed for one counterparty, byte for byte</td></tr>
<tr><td><code>PUT /v1/parties/&lt;id&gt;/packages/&lt;counterparty&gt;</code></td><td>Host or replace the package for one counterparty, signed by the entry's bound key; a party with several peerings keeps one per counterparty</td></tr>
<tr><td><code>DELETE /v1/parties/&lt;id&gt;/packages/&lt;counterparty&gt;</code></td><td>Withdraw the package for one counterparty, for good, when the peering ends; signed by the entry's bound key over that package's sha256</td></tr>
<tr><td><code>GET /v1/parties/&lt;id&gt;/ca</code></td><td>The party's CA certificate(s), PEM, byte for byte</td></tr>
<tr><td><code>PUT /v1/parties/&lt;id&gt;/ca</code></td><td>Host or replace the CA certificate(s), signed by the entry's bound key</td></tr>
<tr><td><code>GET /v1/parties/&lt;id&gt;/spiffe-bundle</code></td><td>The party's SPIFFE trust bundle, JSON, byte for byte</td></tr>
<tr><td><code>PUT /v1/parties/&lt;id&gt;/spiffe-bundle</code></td><td>Host or replace the SPIFFE trust bundle, signed by the entry's bound key</td></tr>
<tr><td><code>GET /v1/spec</code></td><td>The entry formats this instance accepts</td></tr>
<tr><td><code>GET /healthz</code></td><td>Liveness</td></tr>
</table>
<p class="sub">Source: <a href="https://github.com/USAREUR-AF/saltlick">github.com/USAREUR-AF/saltlick</a> · Apache-2.0</p>
</body></html>
`))

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	items, err := s.catalogue(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "listing entries: %v", err)
		return
	}
	var buf bytes.Buffer
	if err := homeTemplate.Execute(&buf, map[string]any{"Parties": items}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "rendering page: %v", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}
