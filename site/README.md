# site

The landing page published to GitHub Pages by `.github/workflows/pages.yml`.
One static page: no framework, no external requests, no web fonts.

## Files

| File | What it is |
|---|---|
| `index.html` | the page |
| `assets/site.css` | its styles, light and dark (`prefers-color-scheme`) |
| `assets/hero.js` | the copy buttons, and the hero: replays `assets/from-tree/session.json` and runs the reader's checks in the browser |
| `assets/icon.svg` | the page icon |
| `assets/from-tree/` | git-ignored; written by `build.py`: `session.json` and the README figure from `docs/figures/` |
| `fitcheck.py` | run by `build.py`: fails when a command box is cut off at 1440 or 390 px |
| `build.py` | builds saltlick, records the session, copies the figure and checks the page against the tree |

## Preview

Needs Go (the version in `go.mod`) and Python 3.

```sh
python3 -I site/build.py
python3 -m http.server 8000 --directory site    # then open http://127.0.0.1:8000/
```

## The hero

`build.py` builds `./cmd/saltlick`, starts it on a free local port with an
empty database, and makes six requests, recording each request and response:

| # | Request | Answer |
|---|---|---|
| 1 | `PUT /v1/parties/xaa` with `internal/pkgv1/testdata/full-offer-xaa.json`, which carries offers | 422 |
| 2 | `PUT /v1/parties/xaa`, a pointer record signed with `saltlick sign` | 201, key bound on first use |
| 3 | `PUT /v1/parties/xaa/package`, the package the pointer names | 201 |
| 4 | `PUT /v1/parties/xaa`, the same pointer signed by another key | 403 |
| 5 | `GET /v1/parties/xaa` | 200, the pointer's bytes |
| 6 | `GET /v1/parties/xaa/package` | 200, the package's bytes |

It fails if any answer differs or if the bytes served are not the bytes sent.
The key is the published conformance test key in `internal/pkgv1/testdata/`,
which is worthless on purpose; the second key is derived from a fixed string.
Ed25519 is deterministic, so the session is the same on every build. The page
shows the host as `directory.example`, the name the README uses.

The last screen of the hero is computed in the visitor's browser from the
bytes of steps 5 and 6: the SHA-256 of the package against the pointer's
`package_sha256`, and both Ed25519 signatures under the key read aloud (where
the browser supports Ed25519 in Web Crypto). With reduced motion the hero shows
only that screen.

## Where each number comes from

Every number is in an element with `data-measure="<key>"`; `build.py` measures
it and fails if the page says something else.

| Key | On the page | Measured as |
|---|---|---|
| `routes` | routes it serves | the length of `routes` in `GET /v1/version` from the instance the session ran |
| `cap` | largest body it accepts | `const MaxBodyBytes = N << 10` in `internal/httpapi/server.go` |
| `offers` | offer blocks refused with 422 | members of `offerMembers` in `internal/pkgv1/package.go` |
| `tests` | Go tests | functions starting `func Test` in every `*_test.go` |

## Command and output boxes

Every `<pre>` on the page is marked `data-box="command"` or `data-box="output"`. A command box shows the whole command at any width: it wraps at spaces, each line of it a `<span class="ln">` with a hanging indent, and Copy copies the exact text. An output box may scroll inside its box on a narrow screen, and its caption says so. `build.py` ends by running `fitcheck.py`, which loads the page in headless Chrome at 1440 and 390 px wide and fails when a box is cut off.
