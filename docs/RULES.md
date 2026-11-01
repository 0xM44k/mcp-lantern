# Rules

## Flow rules (`src/mcp_lantern/flows.py`)

A rule fires when every role in it is provided by at least one enabled server. One server may provide several roles.

| ID | Name | Severity | Needs |
| --- | --- | --- | --- |
| LNT-F001 | Lethal trifecta | high | untrusted_input + private_data + egress |
| LNT-F002 | Injected text can run commands | high | untrusted_input + exec |
| LNT-F003 | Private data can leave | medium | private_data + egress |
| LNT-F004 | Injected text can change data | medium | untrusted_input + write |

"Smallest fix" is exact (tries removal sets by increasing size) for up to 20 relevant servers, otherwise greedy and labelled as such.

## Config checks (`src/mcp_lantern/checks.py`)

| ID | Checks | Severity |
| --- | --- | --- |
| LNT-C001 | Literal credentials in `env`, headers, args or URL query (known token formats, or a secret-like name with a non-reference value). Values are never shown. | high / medium |
| LNT-C002 | `npx`/`uvx`/`pnpm dlx`/... package not pinned; `@latest`; Docker image without tag or digest | medium |
| LNT-C003 | Launch through a shell string; `curl ... | sh` | medium / high |
| LNT-C004 | Remote server over plain HTTP (non-localhost) | high |
| LNT-C005 | Remote server with no credential header (may be OAuth) | low |
| LNT-C006 | Docker `--privileged`, socket mount, host root mount, host network | high / medium |
| LNT-C007 | File server rooted at a home/system directory or credentials folder | high |
| LNT-C008 | Server not in the catalog (capabilities unknown) | info |

## Adding or correcting servers

Edit `catalog.json` or pass `--annotate`. Allowed capabilities: `untrusted_input`, `private_data`, `egress`, `exec`, `write`.
