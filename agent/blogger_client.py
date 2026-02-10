from typing import List, Optional


def publish_post(
    service,
    blog_id: str,
    title: str,
    content: str,
    labels: Optional[List[str]] = None,
    is_draft: bool = False,
):
    """
    Publish a post to Blogger.

    Args:
        service: Authenticated Blogger API service
        blog_id (str): Blogger Blog ID
        title (str): Post title
        content (str): HTML content
        labels (list, optional): Blogger labels
        is_draft (bool): Publish as draft if True

    Returns:
        dict: Published post metadata
    """

    post_body = {
        "kind": "blogger#post",
        "title": title,
        "content": content,
        "labels": labels or [],
    }

    response = service.posts().insert(
        blogId=blog_id,
        body=post_body,
        isDraft=is_draft
    ).execute()

    return {
        "id": response.get("id"),
        "url": response.get("url"),
        "title": response.get("title"),
        "published": response.get("published"),
    }
