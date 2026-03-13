"""
CYBERDUDEBIVASH SENTINEL SYNDICATION ENGINE — State Manager
Tracks which blog posts have already been syndicated.
State persisted as JSON, committed back to repo by GitHub Actions.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Set, Dict, Any

log = logging.getLogger("StateManager")


class StateManager:
    def __init__(self, state_file: str = "data/syndication_state.json"):
        self.state_file = Path(state_file)
        self._state: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load state from JSON file. Returns empty state if not found."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                log.info(f"State loaded: {len(data.get('posted', {}))} items tracked")
                return data
            except (json.JSONDecodeError, IOError) as e:
                log.warning(f"Could not load state file: {e} — starting fresh")

        return {
            'posted': {},
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_updated': None,
            'total_posts_synced': 0,
        }

    def get_posted_guids(self) -> Set[str]:
        """Return the set of GUIDs already posted."""
        return set(self._state.get('posted', {}).keys())

    def mark_posted(self, item: Dict[str, Any]) -> None:
        """Mark an RSS item as successfully posted."""
        guid = item['guid']
        self._state.setdefault('posted', {})[guid] = {
            'title': item.get('title', ''),
            'link': item.get('link', ''),
            'posted_at': datetime.now(timezone.utc).isoformat(),
        }
        self._state['total_posts_synced'] = self._state.get('total_posts_synced', 0) + 1

    def save(self) -> None:
        """Persist state to JSON file."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state['last_updated'] = datetime.now(timezone.utc).isoformat()
        with open(self.state_file, 'w') as f:
            json.dump(self._state, f, indent=2)
        log.info(f"State saved: {self.state_file} ({len(self._state['posted'])} total items)")

    def get_stats(self) -> Dict[str, Any]:
        return {
            'total_tracked': len(self._state.get('posted', {})),
            'total_synced': self._state.get('total_posts_synced', 0),
            'last_updated': self._state.get('last_updated'),
        }
