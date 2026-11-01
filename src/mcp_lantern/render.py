"""Text, JSON and SARIF output."""
from __future__ import annotations

import json
import os

from . import __version__

SEV_MARK = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   ", "info": "INFO  "}
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
CAP_LABEL = {"untrusted_input": "untrusted input", "private_data": "private data", "egress": "egress", "exec": "exec", "write": "write"}


def to_json(result):
    return json.dumps(result, indent=2, sort_keys=False)


def to_text(result, color=False):
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s
    sev_col = {"high": "31;1", "medium": "33", "low": "36", "info": "2"}
    out = [c("1", "mcp-lantern"), result["scope"], ""]
    out.append(f"Servers ({len(result['servers'])})")
    for s in result["servers"]:
        caps = ", ".join(CAP_LABEL[x] for x in s["caps"]) or "none known"
        out.append(f"  {s['name']:<24} {caps}  [{s['basis']}, confidence {s['confidence']}]")
    out.append("")
    out.append(f"Flows ({len(result['flows'])})")
    if not result["flows"]:
        out.append("  No capability combination in the rules is complete. This is not a safety guarantee: unknown servers contribute nothing.")
    for f in result["flows"]:
        out.append("  " + c(sev_col[f["severity"]], SEV_MARK[f["severity"]]) + f" {f['rule']} {f['name']}")
        for role, ids in f["roles"].items():
            out.append(f"      {CAP_LABEL[role]:<16} <- {', '.join(ids)}")
    fx = result["smallest_fix_high"]
    if fx["remove"]:
        how = "smallest" if fx["exact"] else "a small (not proven smallest)"
        out.append(f"  Clearing every high flow needs {how} change: disable {', '.join(fx['remove'])}.")
    out.append("")
    out.append(f"Findings ({len(result['findings'])})")
    for f in result["findings"]:
        out.append("  " + c(sev_col[f["severity"]], SEV_MARK[f["severity"]]) + f" {f['rule']} {f['title']}  [{f['server']}, confidence {f['confidence']}]")
        out.append(f"      {f['detail']}")
        out.append(f"      Fix: {f['fix']}")
    return "\n".join(out) + "\n"


def to_sarif(result):
    rules, seen = [], set()
    def add_rule(rid, name, text, sev):
        if rid in seen:
            return
        seen.add(rid)
        rules.append({"id": rid, "name": name, "shortDescription": {"text": name}, "fullDescription": {"text": text},
                      "defaultConfiguration": {"level": SARIF_LEVEL[sev]}})
    for r in result["rules"]:
        add_rule(r["id"], r["name"], r["why"], r["severity"])
    results = []
    for f in result["findings"]:
        add_rule(f["rule"], f["title"].split(":")[0], f["detail"], f["severity"])
        path = f["location"].rsplit(" /", 1)[0] if " /" in f["location"] else f["location"]
        results.append({"ruleId": f["rule"], "level": SARIF_LEVEL[f["severity"]],
                        "message": {"text": f"{f['title']}. {f['detail']} Fix: {f['fix']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(path)}},
                                       "logicalLocations": [{"name": f["server"]}]}],
                        "properties": {"confidence": f["confidence"]}})
    for fl in result["flows"]:
        roles = "; ".join(f"{k}: {', '.join(v)}" for k, v in fl["roles"].items())
        srcs = sorted({s["source"] for s in result["servers"] if s["id"] in {i for v in fl["roles"].values() for i in v}})
        results.append({"ruleId": fl["rule"], "level": SARIF_LEVEL[fl["severity"]],
                        "message": {"text": f"{fl['name']} is complete across your enabled servers ({roles})."},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(p)}}} for p in srcs[:1]] or []})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "mcp-lantern", "version": __version__,
                                                    "rules": rules}}, "results": results}]}, indent=2)


def _uri(path):
    return os.path.normpath(path).replace("\\", "/")
