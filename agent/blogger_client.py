"""
Blogger API Client — Publish, update, and manage posts.
v55.0 FIX: HTML sanitization to prevent HttpError 400 from Blogger API.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import re
import logging
from typing import List, Optional, Dict

logger = logging.getLogger("CDB-BLOGGER")

# Maximum content size Blogger API accepts reliably (bytes)
_MAX_CONTENT_BYTES = 900_000  # ~900KB, well under 1MB API limit

# Tags that Blogger API rejects or renders incorrectly
_UNSUPPORTED_TAGS = [
    "script", "style", "iframe", "object", "embed", "form", "input",
    "textarea", "select", "button", "applet", "meta", "link",
]

# Tags to convert to safe alternatives (preserve content)
_CONVERT_TAGS = {
    "pre": "div style=\"font-family:monospace;white-space:pre-wrap;background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;font-size:13px;color:#e6edf3;border:1px solid #30363d\"",
    "code": "span style=\"font-family:monospace;background:#161b22;padding:2px 6px;border-radius:3px;font-size:13px;color:#e6edf3\"",
}


def sanitize_blogger_html(html: str) -> str:
    """
    Sanitize HTML content for safe Blogger API publishing.

    Fixes HttpError 400 by:
      1. Converting <pre>/<code> to styled <div>/<span> (preserves formatting)
      2. Stripping completely unsupported tags (<script>, <iframe>, etc.)
      3. Removing HTML comments
      4. Cleaning null bytes and control characters
      5. Truncating oversized payloads with a "continued on platform" footer

    This is ADDITIVE — does not alter the report generation pipeline.
    """
    if not html:
        return html

    # 1. Clean null bytes and control chars (except newline/tab)
    html = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', html)

    # 2. Remove HTML comments
    html = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)

    # 3. Convert <pre>/<code> to safe styled equivalents
    for tag, replacement in _CONVERT_TAGS.items():
        # Opening tag (with or without attributes)
        html = re.sub(
            rf'<{tag}(\s[^>]*)?>',
            f'<{replacement}>',
            html,
            flags=re.IGNORECASE,
        )
        # Closing tag — extract just the tag name from replacement
        close_tag = replacement.split()[0] if ' ' in replacement else replacement
        html = re.sub(
            rf'</{tag}\s*>',
            f'</{close_tag}>',
            html,
            flags=re.IGNORECASE,
        )

    # 4. Strip completely unsupported tags (and their content)
    for tag in _UNSUPPORTED_TAGS:
        html = re.sub(
            rf'<{tag}(\s[^>]*)?>.*?</{tag}\s*>',
            '',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        )
        # Self-closing variants
        html = re.sub(rf'<{tag}(\s[^>]*)?/?>', '', html, flags=re.IGNORECASE)

    # 5. Remove data: URIs in src/href (can cause 400)
    html = re.sub(r'(src|href)\s*=\s*["\']data:[^"\']*["\']', r'\1=""', html, flags=re.IGNORECASE)

    # 6. Truncate if oversized
    if len(html.encode('utf-8', errors='replace')) > _MAX_CONTENT_BYTES:
        truncation_notice = (
            '<div style="background:#1a1a2e;border:2px solid #f97316;border-radius:8px;'
            'padding:16px;margin-top:20px;text-align:center;">'
            '<p style="color:#f97316;font-weight:bold;margin:0;">⚠️ Advisory Truncated</p>'
            '<p style="color:#94a3b8;font-size:13px;margin:4px 0 0 0;">'
            'Full advisory available at '
            '<a href="https://intel.cyberdudebivash.com" style="color:#00d4aa;">'
            'intel.cyberdudebivash.com</a></p></div>'
        )
        # Find a safe cut point (end of a closing tag)
        cut_target = _MAX_CONTENT_BYTES - len(truncation_notice.encode('utf-8')) - 100
        encoded = html.encode('utf-8', errors='replace')
        if len(encoded) > cut_target:
            # Decode safely up to cut point
            truncated = encoded[:cut_target].decode('utf-8', errors='ignore')
            # Find last closing tag to avoid mid-tag truncation
            last_close = truncated.rfind('>')
            if last_close > len(truncated) * 0.5:
                truncated = truncated[:last_close + 1]
            html = truncated + truncation_notice
        logger.warning(f"Blogger content truncated from {len(encoded)} to ~{len(html.encode('utf-8'))} bytes")

    return html


def publish_post(
    service,
    blog_id: str,
    title: str,
    content: str,
    labels: Optional[List[str]] = None,
    is_draft: bool = False,
) -> Dict:
    """
    Publish a post to Blogger.

    v55.0: Sanitizes HTML before API call to prevent HttpError 400.

    Returns:
        dict with id, url, title, published keys
    """
    if not blog_id:
        raise ValueError("blog_id is required")
    if not title:
        raise ValueError("title is required")
    if not content:
        raise ValueError("content is required")

    # v55.0 FIX: Sanitize content to prevent Blogger API 400 errors
    safe_content = sanitize_blogger_html(content)

    post_body = {
        "kind": "blogger#post",
        "title": title,
        "content": safe_content,
        "labels": labels or [],
    }

    response = service.posts().insert(
        blogId=blog_id,
        body=post_body,
        isDraft=is_draft,
    ).execute()

    result = {
        "id": response.get("id"),
        "url": response.get("url"),
        "title": response.get("title"),
        "published": response.get("published"),
    }

    logger.info(f"Post published: {result['url']} (draft={is_draft})")
    return result
