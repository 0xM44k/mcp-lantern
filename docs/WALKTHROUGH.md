# Three-minute walkthrough (script)

Record a screen capture yourself; nothing here is pre-recorded.

1. (0:00) State the problem in one sentence: MCP safety advice is checklists and noisy scanners; the real risk is combinations of servers.
2. (0:20) Run `mcp-lantern examples/risky.mcp.json` and read out the lethal-trifecta flow.
3. (0:50) Open the HTML report. Point at the diagram: amber lines are the servers in a high flow.
4. (1:20) Untick `github`. Show that the trifecta remains through `web` + `files`. Untick `web` too and show it clearing.
5. (2:00) Click "Untick these" to apply the smallest fix, then Reset.
6. (2:20) Show the limits section: inferred capabilities, unknown is not safe. Show `--annotate`.
7. (2:45) Show `--format sarif --fail-on high` in CI and the 27 tests.
