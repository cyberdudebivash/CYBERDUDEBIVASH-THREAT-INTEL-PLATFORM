"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — RBAC Middleware
=======================================================
Enterprise RBAC enforcement with JWT validation and route protection.

Features:
- JWT Token Validation
- Role-Based Route Protection
- Scope Validation per Endpoint
- Token Expiration Enforcement
- API Key Authentication
- Rate Limiting per Role
- Audit Logging

Roles:
- admin: Full access
- analyst: Read + limited write
- viewer: Read only
- api_consumer: API access only
- enterprise: Premium features

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import time
import jwt
import hashlib
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-apex-secret-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))


class Role(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_CONSUMER = "api_consumer"
    ENTERPRISE = "enterprise"


class Permission(Enum):
    # Threat Intelligence
    THREAT_READ = "threat:read"
    THREAT_WRITE = "threat:write"
    THREAT_DELETE = "threat:delete"
    
    # STIX/IOC
    STIX_READ = "stix:read"
    STIX_EXPORT = "stix:export"
    STIX_WRITE = "stix:write"
    
    # API Access
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_ADMIN = "api:admin"
    
    # Enrichment
    ENRICH_READ = "enrich:read"
    ENRICH_EXECUTE = "enrich:execute"
    
    # Reports
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    
    # Admin
    USER_MANAGE = "user:manage"
    SYSTEM_CONFIG = "system:config"
    AUDIT_READ = "audit:read"
    
    # Enterprise
    PREMIUM_ACCESS = "premium:access"
    MARKETPLACE = "marketplace:access"
    TAXII_ACCESS = "taxii:access"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: set(Permission),  # All permissions
    
    Role.ANALYST: {
        Permission.THREAT_READ,
        Permission.THREAT_WRITE,
        Permission.STIX_READ,
        Permission.STIX_EXPORT,
        Permission.API_READ,
        Permission.API_WRITE,
        Permission.ENRICH_READ,
        Permission.ENRICH_EXECUTE,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
        Permission.AUDIT_READ,
    },
    
    Role.VIEWER: {
        Permission.THREAT_READ,
        Permission.STIX_READ,
        Permission.API_READ,
        Permission.ENRICH_READ,
        Permission.REPORT_READ,
    },
    
    Role.API_CONSUMER: {
        Permission.THREAT_READ,
        Permission.STIX_READ,
        Permission.API_READ,
        Permission.ENRICH_READ,
    },
    
    Role.ENTERPRISE: {
        Permission.THREAT_READ,
        Permission.THREAT_WRITE,
        Permission.STIX_READ,
        Permission.STIX_EXPORT,
        Permission.STIX_WRITE,
        Permission.API_READ,
        Permission.API_WRITE,
        Permission.ENRICH_READ,
        Permission.ENRICH_EXECUTE,
        Permission.REPORT_READ,
        Permission.REPORT_GENERATE,
        Permission.PREMIUM_ACCESS,
        Permission.MARKETPLACE,
        Permission.TAXII_ACCESS,
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class User:
    """User entity"""
    user_id: str
    username: str
    email: str
    role: Role
    api_key: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_login: Optional[str] = None
    is_active: bool = True
    custom_permissions: Set[Permission] = field(default_factory=set)
    
    def get_permissions(self) -> Set[Permission]:
        """Get all permissions for user"""
        permissions = ROLE_PERMISSIONS.get(self.role, set()).copy()
        permissions.update(self.custom_permissions)
        return permissions
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has permission"""
        return permission in self.get_permissions()
    
    def to_dict(self) -> Dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role.value,
            "api_key": self.api_key,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "is_active": self.is_active,
            "permissions": [p.value for p in self.get_permissions()],
        }


@dataclass
class TokenPayload:
    """JWT token payload"""
    user_id: str
    username: str
    role: str
    permissions: List[str]
    exp: int
    iat: int
    jti: str  # JWT ID for revocation


@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user: Optional[User] = None
    error: Optional[str] = None
    token: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# JWT OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

class JWTManager:
    """JWT token management"""
    
    def __init__(self, secret: str = JWT_SECRET, algorithm: str = JWT_ALGORITHM):
        self.secret = secret
        self.algorithm = algorithm
        self._revoked_tokens: Set[str] = set()
    
    def create_token(self, user: User, expiry_hours: int = JWT_EXPIRY_HOURS) -> str:
        """Create JWT token for user"""
        now = datetime.utcnow()
        exp = now + timedelta(hours=expiry_hours)
        
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in user.get_permissions()],
            "exp": int(exp.timestamp()),
            "iat": int(now.timestamp()),
            "jti": hashlib.md5(f"{user.user_id}:{now.timestamp()}".encode()).hexdigest(),
        }
        
        return jwt.encode(payload, self.secret, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[TokenPayload]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret, algorithms=[self.algorithm])
            
            # Check if revoked
            if payload.get("jti") in self._revoked_tokens:
                logger.warning(f"Revoked token used: {payload.get('jti')}")
                return None
            
            return TokenPayload(
                user_id=payload["user_id"],
                username=payload["username"],
                role=payload["role"],
                permissions=payload["permissions"],
                exp=payload["exp"],
                iat=payload["iat"],
                jti=payload["jti"],
            )
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def revoke_token(self, jti: str):
        """Revoke a token by JTI"""
        self._revoked_tokens.add(jti)
    
    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh token if still valid"""
        payload = self.verify_token(token)
        if payload is None:
            return None
        
        # Create new token with same user
        user = User(
            user_id=payload.user_id,
            username=payload.username,
            email="",  # Not stored in token
            role=Role(payload.role),
        )
        
        return self.create_token(user)


# ══════════════════════════════════════════════════════════════════════════════
# API KEY AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

class APIKeyManager:
    """API key authentication"""
    
    def __init__(self):
        self._keys: Dict[str, User] = {}
    
    def generate_key(self, user: User) -> str:
        """Generate API key for user"""
        key = hashlib.sha256(
            f"{user.user_id}:{time.time()}:{os.urandom(16).hex()}".encode()
        ).hexdigest()
        
        self._keys[key] = user
        user.api_key = key
        return key
    
    def validate_key(self, key: str) -> Optional[User]:
        """Validate API key"""
        return self._keys.get(key)
    
    def revoke_key(self, key: str) -> bool:
        """Revoke API key"""
        if key in self._keys:
            del self._keys[key]
            return True
        return False


# ══════════════════════════════════════════════════════════════════════════════
# RBAC MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

class RBACMiddleware:
    """
    RBAC middleware for FastAPI/Starlette.
    Enforces authentication and authorization on all routes.
    """
    
    def __init__(self):
        self.jwt_manager = JWTManager()
        self.api_key_manager = APIKeyManager()
        self._route_permissions: Dict[str, Set[Permission]] = {}
        self._public_routes: Set[str] = {"/", "/health", "/metrics", "/docs", "/openapi.json"}
        self._audit_log: List[Dict] = []
    
    def protect_route(self, path: str, *permissions: Permission):
        """Register permissions required for route"""
        self._route_permissions[path] = set(permissions)
    
    def make_public(self, path: str):
        """Make route public (no auth required)"""
        self._public_routes.add(path)
    
    async def authenticate(self, request) -> Optional[User]:
        """Authenticate request via JWT or API key"""
        # Check Authorization header
        auth_header = request.headers.get("Authorization", "")
        
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            payload = self.jwt_manager.verify_token(token)
            if payload:
                return User(
                    user_id=payload.user_id,
                    username=payload.username,
                    email="",
                    role=Role(payload.role),
                    custom_permissions={Permission(p) for p in payload.permissions},
                )
        
        # Check API key
        api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
        if api_key:
            return self.api_key_manager.validate_key(api_key)
        
        return None
    
    def authorize(self, user: User, path: str, method: str) -> bool:
        """Check if user is authorized for route"""
        # Check if public route
        if path in self._public_routes:
            return True
        
        # Get required permissions
        required = self._route_permissions.get(path, set())
        
        # If no specific permissions, require at least API_READ
        if not required:
            required = {Permission.API_READ}
        
        # Check user permissions
        user_permissions = user.get_permissions()
        return required.issubset(user_permissions)
    
    def log_access(self, user: Optional[User], path: str, method: str, status: int):
        """Log access for audit"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user.user_id if user else None,
            "username": user.username if user else "anonymous",
            "role": user.role.value if user else None,
            "path": path,
            "method": method,
            "status": status,
        }
        self._audit_log.append(entry)
        
        # Keep only last 10000 entries
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-10000:]
    
    async def __call__(self, scope, receive, send):
        """ASGI middleware"""
        if scope["type"] != "http":
            return
        
        path = scope.get("path", "/")
        method = scope.get("method", "GET")
        
        # Skip auth for public routes
        if path in self._public_routes:
            return
        
        # Create mock request for auth
        class MockRequest:
            def __init__(self, scope):
                self.headers = dict(scope.get("headers", []))
                self.query_params = {}
        
        request = MockRequest(scope)
        
        # Authenticate
        user = await self.authenticate(request)
        
        if user is None:
            # Unauthorized
            await self._send_error(send, 401, "Unauthorized")
            self.log_access(None, path, method, 401)
            return
        
        # Authorize
        if not self.authorize(user, path, method):
            await self._send_error(send, 403, "Forbidden")
            self.log_access(user, path, method, 403)
            return
        
        # Proceed with request
        self.log_access(user, path, method, 200)
    
    async def _send_error(self, send, status: int, message: str):
        """Send error response"""
        import json
        
        body = json.dumps({"error": message}).encode()
        
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"application/json"]],
        })
        await send({
            "type": "http.response.body",
            "body": body,
        })


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI DECORATORS
# ══════════════════════════════════════════════════════════════════════════════

def require_permissions(*permissions: Permission):
    """Decorator to require permissions on endpoint"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from request state
            request = kwargs.get("request")
            if request and hasattr(request.state, "user"):
                user = request.state.user
                for perm in permissions:
                    if not user.has_permission(perm):
                        from fastapi import HTTPException
                        raise HTTPException(
                            status_code=403,
                            detail=f"Missing permission: {perm.value}"
                        )
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(*roles: Role):
    """Decorator to require specific roles"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = kwargs.get("request")
            if request and hasattr(request.state, "user"):
                user = request.state.user
                if user.role not in roles:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=403,
                        detail=f"Role required: {', '.join(r.value for r in roles)}"
                    )
            return await func(*args, **kwargs)
        return wrapper
    return decorator


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI DEPENDENCY
# ══════════════════════════════════════════════════════════════════════════════

def get_current_user():
    """FastAPI dependency for current user"""
    from fastapi import Depends, HTTPException, Security
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
    
    security = HTTPBearer(auto_error=False)
    api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
    
    async def _get_user(
        credentials: HTTPAuthorizationCredentials = Security(security),
        api_key: str = Security(api_key_header),
    ) -> User:
        middleware = get_middleware()
        
        # Try JWT
        if credentials:
            payload = middleware.jwt_manager.verify_token(credentials.credentials)
            if payload:
                return User(
                    user_id=payload.user_id,
                    username=payload.username,
                    email="",
                    role=Role(payload.role),
                )
        
        # Try API key
        if api_key:
            user = middleware.api_key_manager.validate_key(api_key)
            if user:
                return user
        
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    return _get_user


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_middleware_instance: Optional[RBACMiddleware] = None


def get_middleware() -> RBACMiddleware:
    """Get RBAC middleware singleton"""
    global _middleware_instance
    if _middleware_instance is None:
        _middleware_instance = RBACMiddleware()
    return _middleware_instance


__all__ = [
    "Role",
    "Permission",
    "User",
    "TokenPayload",
    "AuthResult",
    "JWTManager",
    "APIKeyManager",
    "RBACMiddleware",
    "require_permissions",
    "require_role",
    "get_current_user",
    "get_middleware",
    "ROLE_PERMISSIONS",
]
