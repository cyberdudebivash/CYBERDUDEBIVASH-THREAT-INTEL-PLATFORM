"""
CYBERDUDEBIVASH® SENTINEL APEX — Blogger API Client v69.0
Path: agent/blogger_client.py
Features: Technical HTML Sanitization, Style Injection, Payload Guard
"""

import re
import logging
from typing import Dict, Any, Optional

# Configure Elite Technical Logging
logger = logging.getLogger("CDB-BLOGGER")

def sanitize_for_blogger(html_body: str) -> str:
    """
    Hardens HTML for Blogger API compatibility while maintaining 
    elite technical dark-mode styling for technical reports.
    """
    if not html_body:
        return ""

    # Transform <pre> into professional dark-themed code windows
    # This prevents HttpError 400 caused by raw technical tags
    safe_html = html_body.replace("<pre>", 
        "<div style='font-family:Consolas,monaco,monospace; background:#0d1117; color:#c9d1d9; "
        "padding:20px; border-radius:8px; border:1px solid #30363d; margin:15px 0; "
        "overflow-x:auto; line-height:1.5;'>")
    safe_html = safe_html.replace("</pre>", "</div>")
    
    # Transform <code> into high-contrast inline spans
    safe_html = safe_html.replace("<code>", 
        "<span style='background:#21262d; color:#ff7b72; padding:3px 6px; "
        "border-radius:4px; font-weight:bold;'>")
    safe_html = safe_html.replace("</code>", "</span>")
    
    # Strip forbidden security tags (scripts/iframes) that trigger Blogger's firewall
    safe_html = re.sub(r'<(script|iframe|object|embed|form)[^>]*>.*?</\1>', '', 
                       safe_html, flags=re.IGNORECASE | re.DOTALL)
    
    # Enforce Blogger Payload Limit (Truncate if encoded size exceeds 900KB)
    # Blogger has a hard ~1MB limit per post
    if len(safe_html.encode('utf-8')) > 950000:
        logger.warning("Advisory exceeds 950KB; initiating sovereign truncation.")
        footer = ("<br><p style='color:#8b949e; font-style:italic;'><b>[INTEL TRUNCATED]</b> "
                  "Detailed technical analysis and STIX bundles are available on the "
                  "Sentinel APEX Premium Portal.</p>")
        safe_html = safe_html[:900000] + footer
        
    return safe_html

def publish_post(service, blog_id: str, title: str, content: str) -> Optional[Dict[str, Any]]:
    """
    Executes a sovereign publish command with integrated sanitization.
    """
    try:
        # Step 1: Apply v69.0 Technical Hardening
        safe_content = sanitize_for_blogger(content)
        
        # Step 2: Construct Sovereign Payload
        body = {
            "kind": "blogger#post",
            "title": f"🛡️ Sentinel APEX: {title}",
            "content": safe_content
        }
        
        # Step 3: Atomic Insert
        posts = service.posts()
        request = posts.insert(blogId=blog_id, body=body)
        result = request.execute()
        
        logger.info(f"[SUCCESS] Sovereign Intelligence Published: {title}")
        return result

    except Exception as e:
        logger.error(f"[CRITICAL] Blogger Client Logic Failure for {title}: {e}")
        return None

def update_post(service, blog_id: str, post_id: str, title: str, content: str) -> Optional[Dict[str, Any]]:
    """
    Updates an existing advisory with sanitized data.
    """
    try:
        safe_content = sanitize_for_blogger(content)
        body = {
            "title": f"🛡️ Sentinel APEX [UPDATED]: {title}",
            "content": safe_content
        }
        result = service.posts().patch(blogId=blog_id, postId=post_id, body=body).execute()
        return result
    except Exception as e:
        logger.error(f"Failed to patch advisory {post_id}: {e}")
        return None
