# Contributing

- Run the tests: `python -m unittest discover -s tests`.
- Add a server to `src/mcp_lantern/catalog.json`: give the package or URL fragments in `match`, the capabilities you can justify, a `confidence` (`medium` only for servers whose purpose is documented), and a `note` saying why. Add a test that exercises it.
- Add a rule in `src/mcp_lantern/flows.py` (`RULES`). The report's browser code reads the same rule data, so no JavaScript change is needed. Run the parity check described in docs/DESIGN.md.
- Never put real credentials in fixtures. Build fake ones at runtime, as in `tests/test_lantern.py`.
