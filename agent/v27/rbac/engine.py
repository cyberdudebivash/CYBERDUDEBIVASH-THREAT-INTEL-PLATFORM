"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — RBAC Engine
===================================================
Role-Based Access Control for enterprise deployments.

Features:
- Role management
- Fine-grained permissions
- Resource-level access control
- Audit trail integration
- SSO readiness

Permission Format:
    <action>:<resource>
    Examples:
        - read:threats
        - write:reports
        - admin:api_keys
        - export:stix
        - *:threats (all actions on threats)
        - read:* (read all resources)
        - * (superadmin)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Any
from enum import Enum

logger = logging.getLogger("CDB-RBAC")


class Action(Enum):
    """Standard RBAC actions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    EXPORT = "export"
    SHARE = "share"
    ALL = "*"


class Resource(Enum):
    """Platform resources"""
    THREATS = "threats"
    IOCS = "iocs"
    REPORTS = "reports"
    RULES = "rules"
    WATCHLIST = "watchlist"
    API_KEYS = "api_keys"
    USERS = "users"
    SETTINGS = "settings"
    AUDIT = "audit"
    ALL = "*"


@dataclass
class Permission:
    """Single permission definition"""
    action: str
    resource: str
    
    def __str__(self) -> str:
        return f"{self.action}:{self.resource}"
    
    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Parse permission from string format"""
        if ":" not in permission_str:
            if permission_str == "*":
                return cls("*", "*")
            raise ValueError(f"Invalid permission format: {permission_str}")
        
        parts = permission_str.split(":", 1)
        return cls(parts[0], parts[1])
    
    def matches(self, action: str, resource: str) -> bool:
        """Check if this permission grants access"""
        action_match = self.action == "*" or self.action == action
        resource_match = self.resource == "*" or self.resource == resource
        return action_match and resource_match


@dataclass
class Role:
    """RBAC Role definition"""
    name: str
    description: str
    permissions: List[Permission]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def has_permission(self, action: str, resource: str) -> bool:
        """Check if role has permission"""
        return any(p.matches(action, resource) for p in self.permissions)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "permissions": [str(p) for p in self.permissions],
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class User:
    """RBAC User"""
    user_id: str
    email: str
    roles: List[str]
    api_tier: str = "free"
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "roles": self.roles,
            "api_tier": self.api_tier,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


@dataclass
class AccessDecision:
    """Result of access check"""
    allowed: bool
    reason: str
    user_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RBACEngine:
    """
    Role-Based Access Control Engine.
    
    Manages roles, permissions, and access decisions.
    """
    
    # Default role definitions
    DEFAULT_ROLES = {
        "admin": Role(
            name="admin",
            description="Full administrative access",
            permissions=[Permission("*", "*")],
        ),
        "analyst": Role(
            name="analyst",
            description="Security analyst with read/write access",
            permissions=[
                Permission("read", "threats"),
                Permission("read", "iocs"),
                Permission("read", "reports"),
                Permission("write", "watchlist"),
                Permission("export", "stix"),
                Permission("export", "csv"),
            ],
        ),
        "viewer": Role(
            name="viewer",
            description="Read-only access",
            permissions=[
                Permission("read", "threats"),
                Permission("read", "reports"),
            ],
        ),
        "api_consumer": Role(
            name="api_consumer",
            description="API access only",
            permissions=[
                Permission("read", "threats"),
                Permission("read", "iocs"),
                Permission("export", "json"),
            ],
        ),
        "enterprise": Role(
            name="enterprise",
            description="Enterprise tier with full feature access",
            permissions=[
                Permission("*", "threats"),
                Permission("*", "iocs"),
                Permission("*", "reports"),
                Permission("*", "rules"),
                Permission("admin", "api_keys"),
                Permission("export", "*"),
            ],
        ),
    }
    
    def __init__(self):
        self._roles: Dict[str, Role] = {}
        self._users: Dict[str, User] = {}
        self._audit_log: List[Dict] = []
        
        # Initialize default roles
        for name, role in self.DEFAULT_ROLES.items():
            self._roles[name] = role
    
    # ══════════════════════════════════════════════════════════════════════════
    # ROLE MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════
    
    def add_role(self, role: Role):
        """Add a new role"""
        self._roles[role.name] = role
        self._audit("ROLE_CREATED", {"role": role.name})
        logger.info(f"Added role: {role.name}")
    
    def get_role(self, name: str) -> Optional[Role]:
        """Get role by name"""
        return self._roles.get(name)
    
    def list_roles(self) -> List[Role]:
        """List all roles"""
        return list(self._roles.values())
    
    def delete_role(self, name: str) -> bool:
        """Delete a role"""
        if name in self.DEFAULT_ROLES:
            logger.warning(f"Cannot delete default role: {name}")
            return False
        
        if name in self._roles:
            del self._roles[name]
            self._audit("ROLE_DELETED", {"role": name})
            return True
        return False
    
    # ══════════════════════════════════════════════════════════════════════════
    # USER MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════
    
    def add_user(self, user: User):
        """Add a new user"""
        self._users[user.user_id] = user
        self._audit("USER_CREATED", {"user_id": user.user_id, "email": user.email})
        logger.info(f"Added user: {user.user_id}")
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self._users.get(user_id)
    
    def assign_role(self, user_id: str, role_name: str) -> bool:
        """Assign a role to a user"""
        user = self._users.get(user_id)
        role = self._roles.get(role_name)
        
        if not user or not role:
            return False
        
        if role_name not in user.roles:
            user.roles.append(role_name)
            self._audit("ROLE_ASSIGNED", {
                "user_id": user_id,
                "role": role_name,
            })
        return True
    
    def revoke_role(self, user_id: str, role_name: str) -> bool:
        """Revoke a role from a user"""
        user = self._users.get(user_id)
        
        if not user or role_name not in user.roles:
            return False
        
        user.roles.remove(role_name)
        self._audit("ROLE_REVOKED", {
            "user_id": user_id,
            "role": role_name,
        })
        return True
    
    # ══════════════════════════════════════════════════════════════════════════
    # ACCESS CONTROL
    # ══════════════════════════════════════════════════════════════════════════
    
    def check_access(
        self,
        user_id: str,
        action: str,
        resource: str,
    ) -> AccessDecision:
        """
        Check if user has access to perform action on resource.
        
        Args:
            user_id: User identifier
            action: Action to perform (read, write, delete, etc.)
            resource: Resource being accessed
            
        Returns:
            AccessDecision with result and reason
        """
        user = self._users.get(user_id)
        
        if not user:
            decision = AccessDecision(
                allowed=False,
                reason="User not found",
                user_id=user_id,
            )
            self._audit("ACCESS_DENIED", {
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "reason": "User not found",
            })
            return decision
        
        if not user.is_active:
            decision = AccessDecision(
                allowed=False,
                reason="User account is disabled",
                user_id=user_id,
                roles=user.roles,
            )
            self._audit("ACCESS_DENIED", {
                "user_id": user_id,
                "action": action,
                "resource": resource,
                "reason": "Account disabled",
            })
            return decision
        
        # Check all user roles
        for role_name in user.roles:
            role = self._roles.get(role_name)
            if role and role.has_permission(action, resource):
                decision = AccessDecision(
                    allowed=True,
                    reason=f"Granted by role: {role_name}",
                    user_id=user_id,
                    roles=user.roles,
                )
                self._audit("ACCESS_GRANTED", {
                    "user_id": user_id,
                    "action": action,
                    "resource": resource,
                    "role": role_name,
                })
                return decision
        
        # No matching permission found
        decision = AccessDecision(
            allowed=False,
            reason="Insufficient permissions",
            user_id=user_id,
            roles=user.roles,
        )
        self._audit("ACCESS_DENIED", {
            "user_id": user_id,
            "action": action,
            "resource": resource,
            "reason": "Insufficient permissions",
        })
        return decision
    
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Get all permissions for a user"""
        user = self._users.get(user_id)
        if not user:
            return []
        
        permissions = set()
        for role_name in user.roles:
            role = self._roles.get(role_name)
            if role:
                for perm in role.permissions:
                    permissions.add(str(perm))
        
        return sorted(permissions)
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUDIT
    # ══════════════════════════════════════════════════════════════════════════
    
    def _audit(self, event_type: str, details: Dict[str, Any]):
        """Log an audit event"""
        entry = {
            "event_type": event_type,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._audit_log.append(entry)
        
        # Keep last 1000 entries
        if len(self._audit_log) > 1000:
            self._audit_log = self._audit_log[-1000:]
    
    def get_audit_log(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Dict]:
        """Get audit log entries"""
        entries = self._audit_log
        
        if event_type:
            entries = [e for e in entries if e["event_type"] == event_type]
        
        if user_id:
            entries = [
                e for e in entries
                if e.get("details", {}).get("user_id") == user_id
            ]
        
        return entries[-limit:]
    
    # ══════════════════════════════════════════════════════════════════════════
    # STATS
    # ══════════════════════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get RBAC statistics"""
        return {
            "total_roles": len(self._roles),
            "total_users": len(self._users),
            "active_users": sum(1 for u in self._users.values() if u.is_active),
            "audit_entries": len(self._audit_log),
            "roles": list(self._roles.keys()),
        }


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_rbac: Optional[RBACEngine] = None


def get_rbac() -> RBACEngine:
    """Get or create the global RBAC engine"""
    global _rbac
    if _rbac is None:
        _rbac = RBACEngine()
    return _rbac


__all__ = [
    "RBACEngine",
    "Role",
    "Permission",
    "User",
    "AccessDecision",
    "Action",
    "Resource",
    "get_rbac",
]
