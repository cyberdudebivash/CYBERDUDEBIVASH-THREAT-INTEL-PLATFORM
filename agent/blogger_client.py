"""
Blogger API Client — Publish, update, and manage posts.
© 2026 CyberDudeBivash Pvt Ltd — All rights reserved.
"""

import logging
from typing import List, Optional, Dict

logger = logging.getLogger("CDB-BLOGGER")


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

    Returns:
        dict with id, url, title, published keys
    """
    if not blog_id:
        raise ValueError("blog_id is required")
    if not title:
        raise ValueError("title is required")
    if not content:
        raise ValueError("content is required")

    post_body = {
        "kind": "blogger#post",
        "title": title,
        "content": content,
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
