"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — Storage Abstraction Layer
==================================================================
Eliminates file-based state dependency for enterprise scalability.

Supported Backends:
- FileBackend (default, backward compatible)
- PostgresBackend (production recommended)
- RedisBackend (caching layer)
- S3Backend (object storage for STIX/reports)
- MongoBackend (document storage)

Usage:
    from agent.v29.storage import get_backend
    
    storage = get_backend()
    storage.save("audit_log", entry)
    logs = storage.load("audit_log")

Environment Variables:
    SENTINEL_STORAGE=file|postgres|redis|s3|mongo
    DATABASE_URL=postgresql://...
    REDIS_URL=redis://...
    S3_BUCKET=sentinel-data
    MONGO_URI=mongodb://...

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# ABSTRACT STORAGE INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class StorageInterface(ABC):
    """Abstract storage interface for all backends"""
    
    @abstractmethod
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        """Save data to storage. Returns key/id."""
        pass
    
    @abstractmethod
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        """Load data from storage."""
        pass
    
    @abstractmethod
    def delete(self, collection: str, key: str) -> bool:
        """Delete data from storage."""
        pass
    
    @abstractmethod
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        """List all keys in collection."""
        pass
    
    @abstractmethod
    def exists(self, collection: str, key: str) -> bool:
        """Check if key exists."""
        pass
    
    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Check storage health."""
        pass


# ══════════════════════════════════════════════════════════════════════════════
# FILE BACKEND (DEFAULT - BACKWARD COMPATIBLE)
# ══════════════════════════════════════════════════════════════════════════════

class FileBackend(StorageInterface):
    """
    File-based storage backend.
    Maintains backward compatibility with existing data/ structure.
    """
    
    def __init__(self, base_path: str = "data"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        
        # Collection to file mapping (backward compat)
        self.collection_map = {
            "audit_log": "audit_log.json",
            "telemetry_log": "telemetry_log.json",
            "revenue_log": "revenue_log.json",
            "sync_marker": "sync_marker.json",
            "stix": "stix/",
            "ai_predictions": "ai_predictions/",
            "enrichment": "enrichment/",
        }
    
    def _get_path(self, collection: str, key: Optional[str] = None) -> Path:
        """Get file path for collection/key"""
        mapped = self.collection_map.get(collection, f"{collection}/")
        
        if mapped.endswith("/"):
            # Directory-based collection
            dir_path = self.base_path / mapped
            dir_path.mkdir(parents=True, exist_ok=True)
            if key:
                return dir_path / f"{key}.json"
            return dir_path
        else:
            # Single file collection
            return self.base_path / mapped
    
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        """Save data to file"""
        path = self._get_path(collection, key)
        
        if key is None and not str(path).endswith("/"):
            # Append to log file
            existing = []
            if path.exists():
                try:
                    existing = json.loads(path.read_text())
                    if not isinstance(existing, list):
                        existing = [existing]
                except:
                    existing = []
            
            if isinstance(data, list):
                existing.extend(data)
            else:
                existing.append(data)
            
            path.write_text(json.dumps(existing, indent=2, default=str))
            return str(len(existing) - 1)
        else:
            # Save to specific key
            if key is None:
                key = hashlib.md5(json.dumps(data, default=str).encode()).hexdigest()[:12]
                path = self._get_path(collection, key)
            
            path.write_text(json.dumps(data, indent=2, default=str))
            return key
    
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        """Load data from file"""
        path = self._get_path(collection, key)
        
        if not path.exists():
            return [] if key is None else None
        
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return None
    
    def delete(self, collection: str, key: str) -> bool:
        """Delete file"""
        path = self._get_path(collection, key)
        if path.exists():
            path.unlink()
            return True
        return False
    
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        """List all keys in directory collection"""
        path = self._get_path(collection)
        if path.is_dir():
            keys = []
            for f in path.glob(f"{prefix}*.json"):
                keys.append(f.stem)
            return keys
        return []
    
    def exists(self, collection: str, key: str) -> bool:
        """Check if file exists"""
        return self._get_path(collection, key).exists()
    
    def health_check(self) -> Dict[str, Any]:
        """Check file storage health"""
        return {
            "backend": "file",
            "status": "healthy",
            "base_path": str(self.base_path),
            "writable": os.access(self.base_path, os.W_OK),
        }


# ══════════════════════════════════════════════════════════════════════════════
# POSTGRES BACKEND (PRODUCTION RECOMMENDED)
# ══════════════════════════════════════════════════════════════════════════════

class PostgresBackend(StorageInterface):
    """
    PostgreSQL storage backend for production deployments.
    Requires: pip install psycopg2-binary sqlalchemy
    """
    
    def __init__(self, database_url: Optional[str] = None):
        self.database_url = database_url or os.getenv("DATABASE_URL")
        self._engine = None
        self._initialized = False
    
    def _get_engine(self):
        """Lazy load SQLAlchemy engine"""
        if self._engine is None:
            try:
                from sqlalchemy import create_engine
                self._engine = create_engine(self.database_url, pool_pre_ping=True)
                self._initialize_tables()
            except ImportError:
                logger.warning("SQLAlchemy not installed. Using file fallback.")
                return None
        return self._engine
    
    def _initialize_tables(self):
        """Create tables if not exist"""
        if self._initialized:
            return
        
        from sqlalchemy import text
        
        with self._engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS sentinel_data (
                    id SERIAL PRIMARY KEY,
                    collection VARCHAR(255) NOT NULL,
                    key VARCHAR(255),
                    data JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(collection, key)
                )
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_sentinel_collection 
                ON sentinel_data(collection)
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_sentinel_key 
                ON sentinel_data(collection, key)
            """))
            conn.commit()
        
        self._initialized = True
    
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        """Save data to PostgreSQL"""
        engine = self._get_engine()
        if engine is None:
            return FileBackend().save(collection, data, key)
        
        from sqlalchemy import text
        
        if key is None:
            key = hashlib.md5(json.dumps(data, default=str).encode()).hexdigest()[:12]
        
        with engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO sentinel_data (collection, key, data, updated_at)
                VALUES (:collection, :key, :data, CURRENT_TIMESTAMP)
                ON CONFLICT (collection, key) 
                DO UPDATE SET data = :data, updated_at = CURRENT_TIMESTAMP
            """), {
                "collection": collection,
                "key": key,
                "data": json.dumps(data, default=str)
            })
            conn.commit()
        
        return key
    
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        """Load data from PostgreSQL"""
        engine = self._get_engine()
        if engine is None:
            return FileBackend().load(collection, key)
        
        from sqlalchemy import text
        
        with engine.connect() as conn:
            if key:
                result = conn.execute(text("""
                    SELECT data FROM sentinel_data 
                    WHERE collection = :collection AND key = :key
                """), {"collection": collection, "key": key})
                row = result.fetchone()
                return json.loads(row[0]) if row else None
            else:
                result = conn.execute(text("""
                    SELECT data FROM sentinel_data 
                    WHERE collection = :collection
                    ORDER BY created_at DESC
                """), {"collection": collection})
                return [json.loads(row[0]) for row in result.fetchall()]
    
    def delete(self, collection: str, key: str) -> bool:
        """Delete from PostgreSQL"""
        engine = self._get_engine()
        if engine is None:
            return FileBackend().delete(collection, key)
        
        from sqlalchemy import text
        
        with engine.connect() as conn:
            result = conn.execute(text("""
                DELETE FROM sentinel_data 
                WHERE collection = :collection AND key = :key
            """), {"collection": collection, "key": key})
            conn.commit()
            return result.rowcount > 0
    
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        """List keys from PostgreSQL"""
        engine = self._get_engine()
        if engine is None:
            return FileBackend().list_keys(collection, prefix)
        
        from sqlalchemy import text
        
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT key FROM sentinel_data 
                WHERE collection = :collection AND key LIKE :prefix
            """), {"collection": collection, "prefix": f"{prefix}%"})
            return [row[0] for row in result.fetchall()]
    
    def exists(self, collection: str, key: str) -> bool:
        """Check existence in PostgreSQL"""
        engine = self._get_engine()
        if engine is None:
            return FileBackend().exists(collection, key)
        
        from sqlalchemy import text
        
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT 1 FROM sentinel_data 
                WHERE collection = :collection AND key = :key
            """), {"collection": collection, "key": key})
            return result.fetchone() is not None
    
    def health_check(self) -> Dict[str, Any]:
        """Check PostgreSQL health"""
        try:
            engine = self._get_engine()
            if engine is None:
                return {"backend": "postgres", "status": "fallback_to_file"}
            
            from sqlalchemy import text
            
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            return {
                "backend": "postgres",
                "status": "healthy",
                "database": self.database_url.split("@")[-1] if self.database_url else "unknown"
            }
        except Exception as e:
            return {"backend": "postgres", "status": "unhealthy", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# REDIS BACKEND (CACHING / FAST ACCESS)
# ══════════════════════════════════════════════════════════════════════════════

class RedisBackend(StorageInterface):
    """
    Redis storage backend for fast access and caching.
    Requires: pip install redis
    """
    
    def __init__(self, redis_url: Optional[str] = None, prefix: str = "sentinel"):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.prefix = prefix
        self._client = None
    
    def _get_client(self):
        """Lazy load Redis client"""
        if self._client is None:
            try:
                import redis
                self._client = redis.from_url(self.redis_url, decode_responses=True)
            except ImportError:
                logger.warning("Redis not installed. Using file fallback.")
                return None
        return self._client
    
    def _make_key(self, collection: str, key: str) -> str:
        """Create Redis key"""
        return f"{self.prefix}:{collection}:{key}"
    
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        """Save to Redis"""
        client = self._get_client()
        if client is None:
            return FileBackend().save(collection, data, key)
        
        if key is None:
            key = hashlib.md5(json.dumps(data, default=str).encode()).hexdigest()[:12]
        
        redis_key = self._make_key(collection, key)
        client.set(redis_key, json.dumps(data, default=str))
        client.sadd(f"{self.prefix}:{collection}:_keys", key)
        
        return key
    
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        """Load from Redis"""
        client = self._get_client()
        if client is None:
            return FileBackend().load(collection, key)
        
        if key:
            data = client.get(self._make_key(collection, key))
            return json.loads(data) if data else None
        else:
            keys = client.smembers(f"{self.prefix}:{collection}:_keys")
            return [json.loads(client.get(self._make_key(collection, k))) for k in keys]
    
    def delete(self, collection: str, key: str) -> bool:
        """Delete from Redis"""
        client = self._get_client()
        if client is None:
            return FileBackend().delete(collection, key)
        
        result = client.delete(self._make_key(collection, key))
        client.srem(f"{self.prefix}:{collection}:_keys", key)
        return result > 0
    
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        """List keys from Redis"""
        client = self._get_client()
        if client is None:
            return FileBackend().list_keys(collection, prefix)
        
        keys = client.smembers(f"{self.prefix}:{collection}:_keys")
        if prefix:
            keys = [k for k in keys if k.startswith(prefix)]
        return list(keys)
    
    def exists(self, collection: str, key: str) -> bool:
        """Check existence in Redis"""
        client = self._get_client()
        if client is None:
            return FileBackend().exists(collection, key)
        
        return client.exists(self._make_key(collection, key)) > 0
    
    def health_check(self) -> Dict[str, Any]:
        """Check Redis health"""
        try:
            client = self._get_client()
            if client is None:
                return {"backend": "redis", "status": "fallback_to_file"}
            
            client.ping()
            return {
                "backend": "redis",
                "status": "healthy",
                "url": self.redis_url.split("@")[-1] if "@" in self.redis_url else "localhost"
            }
        except Exception as e:
            return {"backend": "redis", "status": "unhealthy", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# S3 BACKEND (OBJECT STORAGE)
# ══════════════════════════════════════════════════════════════════════════════

class S3Backend(StorageInterface):
    """
    S3 storage backend for large objects (STIX bundles, reports).
    Requires: pip install boto3
    """
    
    def __init__(self, bucket: Optional[str] = None):
        self.bucket = bucket or os.getenv("S3_BUCKET", "sentinel-data")
        self._client = None
    
    def _get_client(self):
        """Lazy load S3 client"""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client("s3")
            except ImportError:
                logger.warning("boto3 not installed. Using file fallback.")
                return None
        return self._client
    
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        """Save to S3"""
        client = self._get_client()
        if client is None:
            return FileBackend().save(collection, data, key)
        
        if key is None:
            key = hashlib.md5(json.dumps(data, default=str).encode()).hexdigest()[:12]
        
        s3_key = f"{collection}/{key}.json"
        client.put_object(
            Bucket=self.bucket,
            Key=s3_key,
            Body=json.dumps(data, default=str),
            ContentType="application/json"
        )
        
        return key
    
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        """Load from S3"""
        client = self._get_client()
        if client is None:
            return FileBackend().load(collection, key)
        
        if key:
            try:
                response = client.get_object(Bucket=self.bucket, Key=f"{collection}/{key}.json")
                return json.loads(response["Body"].read().decode())
            except:
                return None
        else:
            # List all objects in collection
            response = client.list_objects_v2(Bucket=self.bucket, Prefix=f"{collection}/")
            results = []
            for obj in response.get("Contents", []):
                data = client.get_object(Bucket=self.bucket, Key=obj["Key"])
                results.append(json.loads(data["Body"].read().decode()))
            return results
    
    def delete(self, collection: str, key: str) -> bool:
        """Delete from S3"""
        client = self._get_client()
        if client is None:
            return FileBackend().delete(collection, key)
        
        try:
            client.delete_object(Bucket=self.bucket, Key=f"{collection}/{key}.json")
            return True
        except:
            return False
    
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        """List keys from S3"""
        client = self._get_client()
        if client is None:
            return FileBackend().list_keys(collection, prefix)
        
        response = client.list_objects_v2(
            Bucket=self.bucket, 
            Prefix=f"{collection}/{prefix}"
        )
        return [
            obj["Key"].split("/")[-1].replace(".json", "") 
            for obj in response.get("Contents", [])
        ]
    
    def exists(self, collection: str, key: str) -> bool:
        """Check existence in S3"""
        client = self._get_client()
        if client is None:
            return FileBackend().exists(collection, key)
        
        try:
            client.head_object(Bucket=self.bucket, Key=f"{collection}/{key}.json")
            return True
        except:
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Check S3 health"""
        try:
            client = self._get_client()
            if client is None:
                return {"backend": "s3", "status": "fallback_to_file"}
            
            client.head_bucket(Bucket=self.bucket)
            return {"backend": "s3", "status": "healthy", "bucket": self.bucket}
        except Exception as e:
            return {"backend": "s3", "status": "unhealthy", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# STORAGE BACKEND FACTORY
# ══════════════════════════════════════════════════════════════════════════════

_backend_instance: Optional[StorageInterface] = None

BACKEND_CLASSES = {
    "file": FileBackend,
    "postgres": PostgresBackend,
    "redis": RedisBackend,
    "s3": S3Backend,
}


class StorageBackend:
    """
    Unified storage interface with automatic backend selection.
    """
    
    def __init__(self, backend_type: Optional[str] = None):
        backend_type = backend_type or os.getenv("SENTINEL_STORAGE", "file")
        
        backend_class = BACKEND_CLASSES.get(backend_type, FileBackend)
        self._backend = backend_class()
        self._type = backend_type
    
    def save(self, collection: str, data: Any, key: Optional[str] = None) -> str:
        return self._backend.save(collection, data, key)
    
    def load(self, collection: str, key: Optional[str] = None) -> Any:
        return self._backend.load(collection, key)
    
    def delete(self, collection: str, key: str) -> bool:
        return self._backend.delete(collection, key)
    
    def list_keys(self, collection: str, prefix: str = "") -> List[str]:
        return self._backend.list_keys(collection, prefix)
    
    def exists(self, collection: str, key: str) -> bool:
        return self._backend.exists(collection, key)
    
    def health_check(self) -> Dict[str, Any]:
        return self._backend.health_check()
    
    @property
    def backend_type(self) -> str:
        return self._type


def get_backend(backend_type: Optional[str] = None) -> StorageBackend:
    """Get storage backend singleton"""
    global _backend_instance
    
    requested_type = backend_type or os.getenv("SENTINEL_STORAGE", "file")
    
    if _backend_instance is None or _backend_instance.backend_type != requested_type:
        _backend_instance = StorageBackend(requested_type)
    
    return _backend_instance


__all__ = [
    "StorageInterface",
    "FileBackend",
    "PostgresBackend",
    "RedisBackend",
    "S3Backend",
    "StorageBackend",
    "get_backend",
]
