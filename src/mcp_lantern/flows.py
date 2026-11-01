"""Combine per-server capabilities into flows, and find the smallest fix.

A flow rule needs every one of its roles to be provided by at least one
enabled server. A single server may provide several roles. Rules are plain
data so the HTML report can recompute them in the browser from the same JSON.
"""
from __future__ import annotations

from itertools import combinations

RULES = [
    {"id": "LNT-F001", "name": "Lethal trifecta", "severity": "high",
     "roles": ["untrusted_input", "private_data", "egress"],
     "why": "Text written by a third party can reach the model, the model can read private data, and it can send data out. A prompt injection in that text could move your data to an attacker.",
     "fix": "Remove one leg: drop a server that supplies it, or run the sources of untrusted text in a separate profile from the sources of private data."},
    {"id": "LNT-F002", "name": "Injected text can run commands", "severity": "high",
     "roles": ["untrusted_input", "exec"],
     "why": "Text written by a third party can reach a model that can execute commands on this machine.",
     "fix": "Disable command execution while handling untrusted content, or require approval for every command."},
    {"id": "LNT-F003", "name": "Private data can leave", "severity": "medium",
     "roles": ["private_data", "egress"],
     "why": "The model can read private data and send data out. An attacker needs a way to give it instructions, which this pair alone does not provide, so the likelihood is lower.",
     "fix": "Scope the data servers to the narrowest paths and accounts, and require approval for outbound actions."},
    {"id": "LNT-F004", "name": "Injected text can change data", "severity": "medium",
     "roles": ["untrusted_input", "write"],
     "why": "Text written by a third party can reach a model that can modify or delete data.",
     "fix": "Use read-only credentials where possible and require approval for writes."},
]
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _providers(servers, enabled):
    roles = {}
    for s in servers:
        if s["id"] in enabled:
            for cap in s["caps"]:
                roles.setdefault(cap, []).append(s["id"])
    return roles


def compute_flows(servers, enabled=None):
    """servers: list of {"id", "caps"}. Returns active flows, most severe first."""
    enabled = {s["id"] for s in servers} if enabled is None else set(enabled)
    prov = _providers(servers, enabled)
    flows = []
    for rule in RULES:
        if all(prov.get(r) for r in rule["roles"]):
            flows.append({"rule": rule["id"], "name": rule["name"], "severity": rule["severity"],
                          "roles": {r: sorted(prov[r]) for r in rule["roles"]}})
    flows.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["rule"]))
    return flows


def smallest_fix(servers, severities=("high",), limit=20):
    """Smallest set of servers whose removal clears every flow of the given severities.

    Exact for up to `limit` relevant servers (tries subsets by increasing size);
    beyond that returns a greedy answer and says so. Returns (ids, exact).
    """
    def remaining(removed):
        en = {s["id"] for s in servers} - set(removed)
        return [f for f in compute_flows(servers, en) if f["severity"] in severities]

    if not remaining([]):
        return [], True
    relevant = sorted({sid for f in remaining([]) for ids in f["roles"].values() for sid in ids})
    if len(relevant) <= limit:
        for k in range(1, len(relevant) + 1):
            for combo in combinations(relevant, k):
                if not remaining(combo):
                    return list(combo), True
    chosen = []
    while remaining(chosen):
        counts = {}
        for f in remaining(chosen):
            for ids in f["roles"].values():
                for sid in ids:
                    counts[sid] = counts.get(sid, 0) + 1
        chosen.append(max(sorted(counts), key=lambda k: counts[k]))
    return chosen, False
