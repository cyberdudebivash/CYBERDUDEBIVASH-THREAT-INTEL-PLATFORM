#!/usr/bin/env python3
"""
SENTINEL APEX — Add Enterprise Dashboard Link to Main Navigation
Injects a nav link to dashboard/enterprise_dashboard.html in index.html.

ZERO-REGRESSION: Only adds a single <a> tag after the existing nav links.
Does not modify any existing HTML elements, JavaScript, or CSS.

Run: python patches/add_enterprise_nav_link.py
"""

import os
import sys

TARGET = os.path.join(os.path.dirname(__file__), "..", "index.html")

# The existing nav section we're adding to
ANCHOR = '<a href="#contact" class="nav-chip">ENTERPRISE CONTACT</a>'

# The new link to add (after the existing nav items)
NEW_LINK = '''<a href="#contact" class="nav-chip">ENTERPRISE CONTACT</a>
                    <a href="dashboard/enterprise_dashboard.html" class="nav-chip" style="color:#a78bfa;border-color:rgba(167,139,250,0.4);background:rgba(167,139,250,0.06);">ENTERPRISE DASHBOARD</a>'''


def main():
    if not os.path.exists(TARGET):
        print(f"Target file not found: {TARGET}")
        sys.exit(1)

    with open(TARGET, "r", encoding="utf-8") as f:
        content = f.read()

    if "enterprise_dashboard.html" in content:
        print("Already patched — Enterprise Dashboard link exists.")
        sys.exit(0)

    if ANCHOR not in content:
        print("Could not find nav anchor point in index.html.")
        print("Manual fix: Add this after the ENTERPRISE CONTACT nav link:")
        print('  <a href="dashboard/enterprise_dashboard.html" class="nav-chip">ENTERPRISE DASHBOARD</a>')
        sys.exit(1)

    content = content.replace(ANCHOR, NEW_LINK)

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"✅ Enterprise Dashboard link added to index.html navigation")


if __name__ == "__main__":
    main()
