"""Optional: checks the report's browser flow logic against Python for every on/off combination.
Needs playwright (pip install playwright && playwright install chromium). Run from the repo root."""
import sys, os, json, itertools, tempfile
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
from mcp_lantern.htmlreport import to_html
from mcp_lantern.parse import load_file
from mcp_lantern.analyze import analyze
from mcp_lantern.flows import compute_flows, smallest_fix
from playwright.sync_api import sync_playwright
EX = os.path.join(ROOT, "examples", "risky.mcp.json")
r=analyze(load_file(EX))
REPORT = os.path.join(tempfile.mkdtemp(), "report.html")
open(REPORT, "w", encoding="utf-8").write(to_html(r))
ids=[s["id"] for s in r["servers"]]; fi=[{"id":s["id"],"caps":s["caps"]} for s in r["servers"]]
bad=0
with sync_playwright() as p:
    b=p.chromium.launch();pg=b.new_page();pg.goto("file://" + REPORT)
    for mask in itertools.product([0,1],repeat=len(ids)):
        en=[i for i,m in zip(ids,mask) if m]
        py=[(f["rule"],f["roles"]) for f in compute_flows(fi,set(en))]
        js=pg.evaluate("en=>{const e={};en.forEach(i=>e[i]=true);return window.__lantern.flowsFor(e).map(f=>[f.rule,f.roles])}",en)
        if py!=[(a,b2) for a,b2 in js]: bad+=1
print("states checked:",2**len(ids),"mismatches:",bad)
sys.exit(1 if bad else 0)
