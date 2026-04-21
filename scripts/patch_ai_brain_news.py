#!/usr/bin/env python3
"""
SENTINEL APEX v134.0.0 - AI Brain + CDB_NEWS Permanent Patcher
Reads ai_brain_patch.js and injects it into index.html before </body>.
IDEMPOTENT - safe to call on every pipeline run.
Called by sentinel-blogger.yml AFTER update_embedded_intel.py
"""
import sys, os

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO    = os.path.dirname(SCRIPTS)
INDEX   = os.path.join(REPO, "index.html")
JS_TPL  = os.path.join(SCRIPTS, "ai_brain_patch.js")
MARKER  = "<!-- CDB-AI-BRAIN-INIT-v134 -->"
ENDMRK  = "<!-- /CDB-AI-BRAIN-INIT-v134 -->"

# ── Validate inputs ────────────────────────────────────────────────────────────
if not os.path.exists(INDEX):
    print("ERROR: index.html not found at " + INDEX)
    sys.exit(1)

if not os.path.exists(JS_TPL):
    print("ERROR: ai_brain_patch.js not found at " + JS_TPL)
    sys.exit(1)

# ── Read files ─────────────────────────────────────────────────────────────────
with open(INDEX,  "r", encoding="utf-8") as f:
    html = f.read()

with open(JS_TPL, "r", encoding="utf-8") as f:
    js = f.read()

# ── Idempotency: remove any previous injection ────────────────────────────────
if MARKER in html:
    s = html.find(MARKER)
    e = html.find(ENDMRK)
    if e != -1:
        e += len(ENDMRK)
        html = html[:s] + html[e:]
    else:
        html = html[:s]
    print("Refreshing existing patch block ...")
else:
    print("First-time patch ...")

if "</body>" not in html:
    print("ERROR: </body> not found in index.html")
    sys.exit(1)

# ── Build injection block ─────────────────────────────────────────────────────
BLOCK = (
    "\n"
    + MARKER + "\n"
    + "<script>\n"
    + js.strip()
    + "\n</script>\n"
    + ENDMRK + "\n"
)

# ── Inject + write ────────────────────────────────────────────────────────────
html = html.replace("</body>", BLOCK + "</body>", 1)

with open(INDEX, "w", encoding="utf-8") as f:
    f.write(html)

print("OK  index.html patched (" + str(len(html)) + " chars) -- AI Brain + CDB_NEWS live.")
