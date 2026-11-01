# Research record

Date: 2026-10-26. Method: web search plus page fetches through an automated tool. Search result pages gave titles and URLs only; the statements below come from pages that were actually fetched and summarised. I did not read Reddit threads directly (search surfaced only an aggregator snapshot), did not read GitHub repositories' source, and did not run any competing tool. Treat everything under "Inferred" as unverified.

## Observed in fetched pages

| Source | What it says | Used for |
| --- | --- | --- |
| [AppSec Santa, MCP server security audit 2026](https://appsecsanta.com/research/mcp-server-security-audit-2026) | 33 local MCP servers (433 tools) scanned with a pattern scanner: 27 detections, about 78% judged false positives after manual review. Genuine concerns were risky *capabilities* (filesystem search reaching `.ssh/` and `.aws/` plus code execution; arbitrary SQL) and open unauthenticated remote endpoints. Author calls for semantic analysis, least privilege and isolation. Small sample, public npm/GitHub servers only. | Decision to reason about capability combinations and report confidence, not match phrases |
| [Invariant Labs, Toxic flow analysis](https://invariantlabs.ai/blog/toxic-flow-analysis) | Models tools and their sequences; flags "toxic flows" such as the lethal trifecta (untrusted instructions, sensitive data, a way to leak). Preview via `uvx mcp-scan@latest`. Predictive, early preview, no published false-positive data. | Prior art. This project does **not** claim to invent the idea. |
| [CSA RiskRubric MCP Scanner draft spec](https://labs.cloudsecurityalliance.org/agentic/csa-research-note-riskrubric-mcp-scanner-spec-20260327/) | Draft client-side scanner spec with weighted domains and letter grades. Says existing tools lack standard scoring and auth/session coverage. | Chose *not* to use a single letter grade (a score hides which combination matters) |
| [Mailtrap, How to vet an MCP server](https://mailtrap.io/blog/mcp-server-security/) | Manual checklist: pin versions, keep tokens out of config files, least-privilege tokens, approval gates, restrict sensitive tools while processing untrusted content, watch capability drift. | Config-level checks |
| [FastMCP, MCP JSON configuration](https://gofastmcp.com/integrations/mcp-json-configuration) | stdio schema `mcpServers.<name>.{command,args,env}`; Claude Desktop and Cursor config locations. Did not document remote fields or VS Code's format. | Parser; remote and VS Code handling is therefore **inferred** and covered by tests I wrote, not by documentation |
| [Cloud Security Guy, portfolio projects](https://cloudsecurityguy.substack.com/p/stop-wasting-time-on-random-labs) | Author's opinion: projects tied to real job needs, with visible deliverables and a short walkthrough, beat generic labs. Not hiring-manager data. | Deliverables: README, report, walkthrough script |

## Gap this project targets

Existing tools either match text patterns (noisy), or require running a Python tool that inspects installed servers, or are vendor previews. A developer who just wants to know "given this exact config file, which combinations of my servers could let injected text lead to data leaving my machine, and what is the smallest change that stops it" has checklists, not an offline, deterministic answer. Lantern is that: config-only, no network, no code execution, explains each flow, and lets you try removals in a report before editing anything.

## Concept comparison (scored 1–5; my judgement, not measured)

| | Lantern (MCP config flow auditor) | Evidence locker (pentest report builder) | Repo secret-history auditor |
| --- | --- | --- | --- |
| Relevance to Maak (security, dev, MCP/agents) | 5 | 4 | 4 |
| Unmet need seen in research | 4 | 2 (PlexTrac, Dradis, Ghostwriter exist) | 2 (gitleaks, trufflehog exist) |
| Distinctiveness | 3 (toxic-flow prior art, offline what-if is the difference) | 2 | 1 |
| Safe to publish (defensive, own files only) | 5 | 4 | 4 |
| Buildable and testable here | 5 | 4 | 3 |
| Fits the "inspection" design language | 5 | 3 | 3 |

Decision: Lantern. Its main risk is catalog accuracy (see docs/LIMITATIONS in README).

## Inferred, not verified

- Whether mcp-scan sends data off the machine, and its exact false-positive rate.
- Whether the catalog's capability guesses match each server's real tool list. They are derived from package names and my general knowledge, and are labelled medium or low confidence.
