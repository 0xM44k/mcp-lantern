"""Self-contained HTML report. No network requests, no external fonts or scripts."""
from __future__ import annotations

import json
import os


def to_html(result):
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "report_template.html"), "r", encoding="utf-8") as fh:
        tpl = fh.read()
    payload = json.dumps(result, ensure_ascii=True)
    # Keep the JSON inert inside a <script> block even if config text contains markup.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return tpl.replace("__DATA__", payload, 1)
