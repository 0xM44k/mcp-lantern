from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .analyze import analyze, load_annotations, worst_severity
from .flows import SEV_ORDER
from . import diff as diffmod
from .htmlreport import to_html
from .parse import ConfigError, load_file
from .render import to_json, to_sarif, to_text

# Well-known per-client locations. Only read when --discover is passed.
def known_paths():
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    cands = [
        os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        os.path.join(appdata, "Claude", "claude_desktop_config.json") if appdata else "",
        os.path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        os.path.join(home, ".cursor", "mcp.json"),
        os.path.join(home, ".claude.json"),
        os.path.join(os.getcwd(), ".mcp.json"),
        os.path.join(os.getcwd(), ".vscode", "mcp.json"),
        os.path.join(os.getcwd(), ".cursor", "mcp.json"),
    ]
    return [p for p in cands if p and os.path.isfile(p)]


def build_parser():
    p = argparse.ArgumentParser(prog="mcp-lantern", description="Audit MCP client configuration files offline. Reads files only; never starts or contacts a server.")
    p.add_argument("files", nargs="*", help="config files to audit (mcp.json, claude_desktop_config.json, .vscode/mcp.json ...)")
    p.add_argument("--discover", action="store_true", help="also read the well-known config locations that exist on this machine")
    p.add_argument("--annotate", metavar="FILE", help="JSON file declaring capabilities for servers lantern does not know")
    p.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    p.add_argument("-o", "--output", metavar="PATH", help="write to a file instead of stdout (required for html)")
    p.add_argument("--baseline", metavar="FILE", action="append", default=[], help="earlier config to compare against (repeatable). Reports newly introduced risk; with --fail-on, only new flows and findings count")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never", help="exit 1 if any flow or finding is at least this severe")
    p.add_argument("--version", action="version", version=f"mcp-lantern {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    paths = list(args.files)
    if args.discover:
        paths += [p for p in known_paths() if p not in paths]
    if not paths:
        print("mcp-lantern: give at least one config file, or use --discover.", file=sys.stderr)
        return 2
    servers, errors = [], []
    for path in paths:
        try:
            servers += load_file(path)
        except ConfigError as e:
            errors.append(str(e))
    for e in errors:
        print(f"mcp-lantern: {e}", file=sys.stderr)
    if not servers:
        return 2
    try:
        annotations = load_annotations(args.annotate) if args.annotate else {}
    except (OSError, ValueError) as e:
        print(f"mcp-lantern: annotations: {e}", file=sys.stderr)
        return 2
    result = analyze(servers, annotations)
    change = None
    if args.baseline:
        if args.format in ("sarif", "html"):
            print("mcp-lantern: --baseline supports --format text or json only", file=sys.stderr)
            return 2
        base_servers = []
        for path in args.baseline:
            try:
                base_servers += load_file(path)
            except ConfigError as e:
                print(f"mcp-lantern: baseline: {e}", file=sys.stderr)
                return 2
        change = diffmod.compute_diff(analyze(base_servers, annotations), result)
        result["diff"] = change
    if args.format == "html":
        if not args.output:
            print("mcp-lantern: --format html needs -o PATH", file=sys.stderr)
            return 2
        body = to_html(result)
    elif args.format == "json":
        body = to_json(result)
    elif args.format == "sarif":
        body = to_sarif(result)
    else:
        body = to_text(result, color=sys.stdout.isatty() and not args.output)
        if change is not None:
            body += "\n" + diffmod.to_text(change)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"mcp-lantern: wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(body if body.endswith("\n") else body + "\n")
    if args.fail_on != "never":
        worst = diffmod.worst_new_severity(change) if change is not None else worst_severity(result)
        if worst and SEV_ORDER[worst] <= SEV_ORDER[args.fail_on]:
            return 1
    return 1 if errors else 0
