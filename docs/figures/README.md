# Figures

`make-figures.py` draws every figure in this directory from the tree. Each
figure is written in a light and a dark variant for a `<picture>` element.
Standard library only.

```sh
python3 -I docs/figures/make-figures.py           # write the SVG files
python3 -I docs/figures/make-figures.py --check   # exit 1 if a committed file is out of date
```

| Figure | Shows | Data |
|---|---|---|
| `peering-directory` | the publishing party, the directory and the reading party: what a pointer record holds, what is refused, the reader's four steps, and the verifying key passing between the two parties outside the directory | pointer record members and the four steps from `README.md` §"The pointer record"; refused offer blocks from `offerMembers` and the pointer format from `PointerSpec` in `internal/pkgv1/package.go` |

The generator exits with an error if those sections change shape. Regenerate
after either source changes.

## Checks

Each figure was rendered in headless Chromium as an `<img>` at 830 px and at
400 px wide in both themes and inspected. Text is at least 13 units on an
880-unit canvas.
