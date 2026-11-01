"""Turn parsed servers into a full analysis result (a plain dict, JSON-ready)."""
from __future__ import annotations

import json
import os

from . import __version__, checks
from .flows import RULES, SEV_ORDER, compute_flows, smallest_fix
from .parse import Server

CAP_ORDER = ["untrusted_input", "private_data", "egress", "exec", "write"]


def load_catalog():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "catalog.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_annotations(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("annotations must be a JSON object mapping server name to {\"caps\": [...]}")
    valid = set(CAP_ORDER)
    out = {}
    for name, spec in data.items():
        caps = spec.get("caps") if isinstance(spec, dict) else None
        if not isinstance(caps, list) or not set(caps) <= valid:
            raise ValueError(f"annotation for {name!r}: caps must be a list drawn from {sorted(valid)}")
        out[name] = {"caps": caps, "note": str(spec.get("note", "Declared by you in the annotations file."))}
    return out


def classify(server, catalog, annotations):
    if server.name in annotations:
        a = annotations[server.name]
        return {"caps": a["caps"], "basis": "annotation", "confidence": "high", "note": a["note"], "catalog_id": None}
    hay = server.haystack
    for entry in catalog["servers"]:
        if any(m in hay for m in entry["match"]):
            return {"caps": list(entry["caps"]), "basis": "catalog", "confidence": entry["confidence"],
                    "note": entry["note"], "catalog_id": entry["id"]}
    name_hay = f"{server.name.lower()} {hay}"
    for guess in catalog["keyword_guesses"]:
        if any(w in name_hay for w in guess["words"]):
            return {"caps": list(guess["caps"]), "basis": "keyword", "confidence": "low",
                    "note": "Guessed from words in the name or command; verify against the server's real tool list.", "catalog_id": None}
    return {"caps": [], "basis": "unknown", "confidence": "none",
            "note": "Not in the catalog. Capabilities are unknown, which is not the same as safe.", "catalog_id": None}


def analyze(servers, annotations=None):
    annotations = annotations or {}
    catalog = load_catalog()
    rows, findings = [], []
    _assign_ids(servers)
    for s in servers:
        info = classify(s, catalog, annotations)
        rows.append({"id": s.ident, "name": s.name, "source": s.source, "kind": s.kind,
                     "launch": _launch_text(s), **info})
        findings += checks.check_secrets(s) + checks.check_pinning(s) + checks.check_command_shape(s)
        findings += checks.check_remote(s) + checks.check_broad_paths(s, info["caps"])
        if info["basis"] == "unknown":
            findings.append({"rule": "LNT-C008", "severity": "info", "confidence": "high", "server": s.ident,
                             "title": "Server is not in the catalog", "detail": info["note"],
                             "fix": "Declare its capabilities with --annotate so flows can include it.",
                             "location": f"{s.source} {s.pointer}"})
    flow_input = [{"id": r["id"], "caps": r["caps"]} for r in rows]
    flows = compute_flows(flow_input)
    fix_ids, exact = smallest_fix(flow_input, ("high",))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["rule"], f["server"]))
    return {
        "tool": "mcp-lantern", "version": __version__,
        "scope": "Static analysis of configuration files only. No server was started, contacted or executed.",
        "servers": rows, "flows": flows, "findings": findings,
        "rules": [{k: r[k] for k in ("id", "name", "severity", "roles", "why", "fix")} for r in RULES],
        "role_help": catalog["roles"],
        "smallest_fix_high": {"remove": fix_ids, "exact": exact},
    }


def _assign_ids(servers):
    """Short ids: the bare name when unique, else file:name, else file:name#n."""
    names = [s.name for s in servers]
    for s in servers:
        s.uid = s.name if names.count(s.name) == 1 else f"{os.path.basename(s.source)}:{s.name}"
    seen = {}
    for s in servers:
        seen[s.uid] = seen.get(s.uid, 0) + 1
        if seen[s.uid] > 1:
            s.uid = f"{s.uid}#{seen[s.uid]}"


def _launch_text(s: Server) -> str:
    """Display text for how the server starts. Env values are never included."""
    if s.kind == "remote":
        return _strip_query(s.url)
    return " ".join([s.command, *[_hide(a) for a in s.args]]).strip()


def _strip_query(url):
    return url.split("?", 1)[0] + ("?…" if "?" in url else "")


def _hide(arg):
    return "[hidden]" if checks._secret_label(arg) else arg


def worst_severity(result):
    sevs = [f["severity"] for f in result["findings"]] + [f["severity"] for f in result["flows"]]
    return min(sevs, key=lambda s: SEV_ORDER[s]) if sevs else None
