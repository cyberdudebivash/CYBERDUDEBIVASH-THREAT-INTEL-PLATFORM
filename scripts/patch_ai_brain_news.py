#!/usr/bin/env python3
"""
SENTINEL APEX v145.0.0 - AI Brain + CDB_NEWS Permanent Patcher
Reads ai_brain_patch.js and injects it into index.html before </body>.
IDEMPOTENT - safe to call on every pipeline run.
Called by sentinel-blogger.yml AFTER update_embedded_intel.py

v145.0.0 FIX: Use regex to strip ANY version of the CDB-AI-BRAIN-INIT
marker pair (start+end). Previously ENDMRK was hardcoded to v134 but the
HTML had /v150.1 -- when the end-marker was not found the else-branch did
html = html[:s] which silently truncated </body> and </html>.
"""
import re
import sys
import os

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO    = os.path.dirname(SCRIPTS)
INDEX   = os.path.join(REPO, "index.html")
JS_TPL  = os.path.join(SCRIPTS, "ai_brain_patch.js")

# Current version markers written by this script going forward
MARKER  = "<!-- CDB-AI-BRAIN-INIT-v145 -->"
ENDMRK  = "<!-- /CDB-AI-BRAIN-INIT-v145 -->"

# Regex that removes ANY version of the CDB-AI-BRAIN-INIT block from HTML.
# Matches start marker (any vXXX suffix) through matching end marker.
# re.DOTALL so '.' matches newlines inside the block.
_BLOCK_RE = re.compile(
    r"<!-- CDB-AI-BRAIN-INIT-v[\w.]+ -->"
    r".*?"
    r"<!-- /CDB-AI-BRAIN-INIT-v[\w.]+ -->",
    re.DOTALL,
)

# Validate inputs
if not os.path.exists(INDEX):
    print("ERROR: index.html not found at " + INDEX)
    sys.exit(1)

if not os.path.exists(JS_TPL):
    print("ERROR: ai_brain_patch.js not found at " + JS_TPL)
    sys.exit(1)

# Read files
with open(INDEX, "r", encoding="utf-8") as f:
    html = f.read()

with open(JS_TPL, "r", encoding="utf-8") as f:
    js = f.read()

# Idempotency: strip any existing injection block (any version)
_original_len = len(html)
html, _n_removed = _BLOCK_RE.subn("", html)
if _n_removed:
    print("Refreshing existing patch block (removed " + str(_n_removed) + " block(s)) ...")
else:
    print("First-time patch ...")

# Safety guard: </body> must still be present after stripping
if "</body>" not in html:
    print("ERROR: </body> not found in index.html after stripping old block")
    print("  Original length: " + str(_original_len))
    print("  Current length:  " + str(len(html)))
    print("  Blocks removed:  " + str(_n_removed))
    sys.exit(1)

# Build injection block with current v145 markers
BLOCK = (
    "\n"
    + MARKER + "\n"
    + "<script>\n"
    + js.strip()
    + "\n</script>\n"
    + ENDMRK + "\n"
)

# Inject before first </body>
html = html.replace("</body>", BLOCK + "</body>", 1)

with open(INDEX, "w", encoding="utf-8") as f:
    f.write(html)

print("OK  index.html patched (" + str(len(html)) + " chars) -- AI Brain + CDB_NEWS live.")
