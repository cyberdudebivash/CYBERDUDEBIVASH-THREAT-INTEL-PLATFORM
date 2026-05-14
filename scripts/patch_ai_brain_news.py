#!/usr/bin/env python3
"""
SENTINEL APEX v153.0.0 - AI Brain + CDB_NEWS Permanent Patcher
Reads ai_brain_patch.js and injects it into index.html before </body>.
IDEMPOTENT - safe to call on every pipeline run.
Called by sentinel-blogger.yml AFTER update_embedded_intel.py

v145.0.0 FIX: Use regex to strip ANY version of the CDB-AI-BRAIN-INIT
marker pair (start+end). Previously ENDMRK was hardcoded to v134 but the
HTML had /v150.1 -- when the end-marker was not found the else-branch did
html = html[:s] which silently truncated </body> and </html>.

v153.0.0 FIX (P0): Strip ORPHANED brain JS blocks that lack CDB-AI-BRAIN-INIT
markers. These orphaned blocks arise when a previous patcher run removes the
marker tags but leaves the raw JS content in the HTML — causing the browser to
render the JavaScript source code as visible plain text after the footer.
The _ORPHAN_RE regex fingerprints the block by its unique Micro-utilities
header and strips it (with its stray </script> closer if present) before the
fresh properly-wrapped injection is inserted. This makes the patcher fully
idempotent even against legacy marker-less residue.
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

# v153.0.0 P0 FIX: Regex that removes ORPHANED brain JS blocks - those that
# contain the AI Brain code (fingerprinted by the unique Micro-utilities header)
# but are NOT enclosed in CDB-AI-BRAIN-INIT markers. These blocks have no
# <script> opener and render as raw visible text in the browser.
# Strategy: protect legitimate marked blocks, strip orphans, restore protected.
_ORPHAN_RE = re.compile(
    r"[ \t]*/\*\s*\xe2\x94\x80{2,}\s*Micro-utilities.*?"
    r"(?:\}\)\(\);\s*</script>|\}\)\(\);\s*(?=\n))",
    re.DOTALL | re.MULTILINE,
)
_PROTECT_TOKEN = "__CDB_AI_BRAIN_PROTECTED_v153__"

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

_original_len = len(html)

# --- PASS 1: Remove any existing properly-marked injection block (any version) ---
html, _n_removed = _BLOCK_RE.subn("", html)
if _n_removed:
    print("Refreshing existing patch block (removed " + str(_n_removed) + " marked block(s)) ...")
else:
    print("First-time patch (no existing marked block found) ...")

# --- PASS 2: Remove orphaned brain JS blocks (no markers, causes raw-JS display) ---
# Temporarily protect any remaining marked blocks (shouldn't exist after Pass 1,
# but be defensive), then strip orphans, then restore.
marked_blocks = _BLOCK_RE.findall(html)
html_protected = _BLOCK_RE.sub(_PROTECT_TOKEN, html)

html_protected, _n_orphans = _ORPHAN_RE.subn("", html_protected)
if _n_orphans:
    print("P0 FIX v153: Removed " + str(_n_orphans) + " orphaned brain JS block(s) "
          "(raw-JS-after-footer bug eliminated).")

# Restore any protected blocks
for block in marked_blocks:
    html_protected = html_protected.replace(_PROTECT_TOKEN, block, 1)
html = html_protected

# Collapse excessive blank lines left by removal (>3 consecutive newlines -> 2)
html = re.sub(r'\n{4,}', '\n\n\n', html)

# Safety guard: </body> must still be present after stripping
if "</body>" not in html:
    print("ERROR: </body> not found in index.html after stripping old block")
    print("  Original length: " + str(_original_len))
    print("  Current length:  " + str(len(html)))
    print("  Marked blocks removed:  " + str(_n_removed))
    print("  Orphan blocks removed:  " + str(_n_orphans))
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
