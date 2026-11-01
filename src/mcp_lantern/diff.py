"""Compare two analysis results and report what became riskier or safer.

The comparison is between two points in time for the same configuration (or
two configurations). Servers are matched by their name. Flows are matched by
rule id, findings by rule id and server, so a finding that merely moves to a
different line is not reported as new.
"""
from __future__ import annotations

from .flows import SEV_ORDER

CAP_LABEL = {"untrusted_input": "untrusted input", "private_data": "private data",
             "egress": "egress", "exec": "exec", "write": "write"}


def _finding_key(f):
    return (f["rule"], f["server"])


def compute_diff(old, new):
    """Return a JSON-ready dict describing the change from `old` to `new`."""
    old_servers = {s["name"]: s for s in old["servers"]}
    new_servers = {s["name"]: s for s in new["servers"]}
    added = sorted(set(new_servers) - set(old_servers))
    removed = sorted(set(old_servers) - set(new_servers))
    changed = []
    for name in sorted(set(old_servers) & set(new_servers)):
        o, n = old_servers[name], new_servers[name]
        gained = [c for c in n["caps"] if c not in o["caps"]]
        lost = [c for c in o["caps"] if c not in n["caps"]]
        if gained or lost or o["launch"] != n["launch"]:
            changed.append({"name": name, "gained_caps": gained, "lost_caps": lost,
                            "launch_before": o["launch"], "launch_after": n["launch"]})

    old_flows = {f["rule"]: f for f in old["flows"]}
    new_flows = {f["rule"]: f for f in new["flows"]}
    new_flow_list = [new_flows[k] for k in sorted(new_flows, key=lambda k: (SEV_ORDER[new_flows[k]["severity"]], k)) if k not in old_flows]
    cleared_flow_list = [old_flows[k] for k in sorted(old_flows, key=lambda k: (SEV_ORDER[old_flows[k]["severity"]], k)) if k not in new_flows]

    old_f = {_finding_key(f): f for f in old["findings"]}
    new_f = {_finding_key(f): f for f in new["findings"]}
    new_findings = sorted((new_f[k] for k in new_f if k not in old_f), key=lambda f: (SEV_ORDER[f["severity"]], f["rule"], f["server"]))
    resolved = sorted((old_f[k] for k in old_f if k not in new_f), key=lambda f: (SEV_ORDER[f["severity"]], f["rule"], f["server"]))

    return {"servers_added": added, "servers_removed": removed, "servers_changed": changed,
            "flows_introduced": new_flow_list, "flows_cleared": cleared_flow_list,
            "findings_introduced": new_findings, "findings_resolved": resolved}


def worst_new_severity(diff):
    """Most severe thing that is new in `diff`, or None. Used for --fail-on."""
    sevs = [f["severity"] for f in diff["flows_introduced"]] + [f["severity"] for f in diff["findings_introduced"]]
    return min(sevs, key=lambda s: SEV_ORDER[s]) if sevs else None


def is_empty(diff):
    return not any(diff[k] for k in diff)


def to_text(diff):
    out = ["Changes since baseline"]
    if is_empty(diff):
        out.append("  No differences in servers, flows or findings.")
        return "\n".join(out) + "\n"
    for name in diff["servers_added"]:
        out.append(f"  + server {name}")
    for name in diff["servers_removed"]:
        out.append(f"  - server {name}")
    for c in diff["servers_changed"]:
        bits = []
        if c["gained_caps"]:
            bits.append("gained " + ", ".join(CAP_LABEL[x] for x in c["gained_caps"]))
        if c["lost_caps"]:
            bits.append("lost " + ", ".join(CAP_LABEL[x] for x in c["lost_caps"]))
        if c["launch_before"] != c["launch_after"]:
            bits.append(f"launch changed: {c['launch_before']!r} -> {c['launch_after']!r}")
        out.append(f"  ~ server {c['name']}: " + "; ".join(bits))
    for f in diff["flows_introduced"]:
        out.append(f"  NEW   {f['severity'].upper():<6} {f['rule']} {f['name']}")
    for f in diff["flows_cleared"]:
        out.append(f"  CLEAR {f['severity'].upper():<6} {f['rule']} {f['name']}")
    for f in diff["findings_introduced"]:
        out.append(f"  NEW   {f['severity'].upper():<6} {f['rule']} {f['title']} [{f['server']}]")
    for f in diff["findings_resolved"]:
        out.append(f"  GONE  {f['severity'].upper():<6} {f['rule']} {f['title']} [{f['server']}]")
    return "\n".join(out) + "\n"
