# Design, motion, accessibility and technique register

The report page uses the Maak design system's "Inspection" language: a dark room, one amber lamp (`signal`), structure revealed by a sweep. Tokens in the page `:root` mirror the design system (`bg`, `surface`, `surface-raised`, `line`, `ink`, `ink-muted`, `signal`, `on-signal`, `trace`, `status-ok`, `status-error`); the dark and light values are the ones in the system's `tokens.json`.

## Behaviour

| Element | Behaviour |
| --- | --- |
| Header beam | One 1.6 s lamp sweep along the header rule on load, then still. |
| Server switches | Native checkboxes (24px, label click target at least 44px tall). Toggling recomputes the diagram, columns, flows and smallest fix instantly. |
| Diagram | Servers left, capabilities right; amber dashed lines mark servers and capabilities in an active *high* flow, and march slowly (1.2 s loop). The diagram is a convenience: the column lists and flow cards carry the same information as text. |
| Columns | Entries fade in over 500 ms when a toggle changes them. |
| Flow cards / fix box | "Untick these" applies the smallest fix to the switches; "Reset all servers" restores. |
| Status line | A visually hidden `aria-live="polite"` region announces "N flows active, M high severity." |

## Responsive

Single column up to ~800px with 16px gutters; columns wrap with `auto-fit` (min 190px); long package names wrap (`overflow-wrap:anywhere`); the SVG scales with its `viewBox`. Verified at 1280px and 390px: no horizontal overflow.

## Reduced motion and fallbacks

`prefers-reduced-motion: reduce` disables all animation and transitions. A visible "Pause motion" button does the same on demand (`data-motion="paused"`). Without JavaScript the page shows the header only, because the content is built from embedded data; the text and JSON CLI outputs are the no-JS alternative. No fonts or scripts are loaded from the network: the font stacks name Newsreader, Instrument Sans and JetBrains Mono if installed and fall back to Georgia, system-ui and ui-monospace.

## Security of the report

Config text is attacker-influenced. It is embedded as inert JSON (`<`, `>`, `&` escaped) and rendered only through `textContent` / `setAttribute`, never `innerHTML`. A test injects `</script><img onerror>` and asserts no `<` remains in the data block.

## Technique register

| Technique | Problem | Source | Cost | Fallback | Validation |
| --- | --- | --- | --- | --- | --- |
| Capability-combination ("toxic flow") analysis | Pattern matching is noisy; risk is in combinations | Prior art: Invariant Labs, see RESEARCH.md | Negligible (tiny set logic) | Findings list works without flows | 27 unit tests |
| Exact minimal removal set by subset search | Tell the user the smallest change | Original here; plain combinatorics | Exponential in relevant servers, capped at 20 then greedy | Greedy, labelled "not proven smallest" | Unit test; browser/Python parity |
| Same rules evaluated in Python and in the page | What-if without a server | Original here | None | CLI output | `tests/parity_browser.py`: 64 of 64 on/off states matched (Chromium via Playwright) |
| Inline SVG diagram, CSS `stroke-dashoffset` animation | Show reach at a glance | Standard SVG/CSS | Trivial | Column lists | Rendered and inspected at 2 widths, 2 themes |
| JSONC tolerant parse | VS Code configs may contain comments | Standard practice | Trivial | Error message with line number | Unit test |

## Verification performed (2026-10-26, lab only)

- 27 unit tests pass; one deliberate mutation (disabling the pin check) made a test fail, confirming the tests can fail.
- axe-core 4.10.2 (wcag2a, wcag2aa, wcag21aa, wcag22aa, best-practice): 0 violations at 1280px and 390px, dark and light. Automated checks cover only part of WCAG; no screen-reader or manual keyboard audit has been done.
- Rendered in headless Chromium: no console errors, no horizontal overflow at 390px.
- Not measured: Core Web Vitals, other browsers, real screen readers, Windows paths in `--discover`.
