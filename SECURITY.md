# Security and intended use

Lantern reads configuration files you point it at. It never starts, connects to, or executes an MCP server, and it makes no network requests (the HTML report loads nothing external).

Use it on configuration you own or are authorised to review. It is a defensive review aid, not an exploitation tool, and contains no attack code.

Secret values found in configs are never printed, written to reports, or placed in SARIF output. If you find a case where one is, please report it privately to the maintainer before opening a public issue.

Please report vulnerabilities in Lantern itself to the maintainer by email: m11k.08k3@gmail.com.
