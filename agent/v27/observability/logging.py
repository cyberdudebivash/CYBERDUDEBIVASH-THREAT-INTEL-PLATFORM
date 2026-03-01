"""
SENTINEL APEX v27.0 — Structured Logging
=========================================
JSON structured logging with correlation IDs.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from contextvars import ContextVar
from functools import wraps

# Context variable for correlation ID
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


class StructuredFormatter(logging.Formatter):
    """JSON structured log formatter"""
    
    def __init__(self, service_name: str = "sentinel-apex"):
        super().__init__()
        self.service_name = service_name
    
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }
        
        # Add correlation ID if present
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_entry["correlation_id"] = correlation_id
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        
        # Standard fields
        log_entry["module"] = record.module
        log_entry["function"] = record.funcName
        log_entry["line"] = record.lineno
        
        return json.dumps(log_entry)


class StructuredLogger:
    """
    Structured logger with context support.
    """
    
    def __init__(self, name: str, level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
    
    def _log(
        self,
        level: int,
        message: str,
        extra: Optional[Dict[str, Any]] = None
    ):
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            "(unknown)",
            0,
            message,
            (),
            None
        )
        if extra:
            record.extra_fields = extra
        self.logger.handle(record)
    
    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, kwargs)
    
    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, kwargs)
    
    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, kwargs)
    
    def with_context(self, **context) -> "LoggerContext":
        """Create logger with additional context"""
        return LoggerContext(self, context)


class LoggerContext:
    """Context manager for scoped logging context"""
    
    def __init__(self, logger: StructuredLogger, context: Dict[str, Any]):
        self.logger = logger
        self.context = context
    
    def debug(self, message: str, **kwargs):
        self.logger.debug(message, **{**self.context, **kwargs})
    
    def info(self, message: str, **kwargs):
        self.logger.info(message, **{**self.context, **kwargs})
    
    def warning(self, message: str, **kwargs):
        self.logger.warning(message, **{**self.context, **kwargs})
    
    def error(self, message: str, **kwargs):
        self.logger.error(message, **{**self.context, **kwargs})


def setup_logging(
    level: str = "INFO",
    format_type: str = "json",
    service_name: str = "sentinel-apex"
):
    """
    Configure structured logging for the application.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: "json" or "text"
        service_name: Service name for logs
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))
    
    if format_type == "json":
        handler.setFormatter(StructuredFormatter(service_name))
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
    
    root_logger.addHandler(handler)


def with_correlation_id(func):
    """Decorator to add correlation ID to request context"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Get or generate correlation ID
        correlation_id = kwargs.pop("correlation_id", None) or str(uuid.uuid4())
        
        # Set in context
        token = correlation_id_var.set(correlation_id)
        
        try:
            return await func(*args, **kwargs)
        finally:
            correlation_id_var.reset(token)
    
    return wrapper


def get_correlation_id() -> str:
    """Get current correlation ID"""
    return correlation_id_var.get() or str(uuid.uuid4())


def set_correlation_id(correlation_id: str):
    """Set correlation ID for current context"""
    correlation_id_var.set(correlation_id)


__all__ = [
    "StructuredLogger",
    "StructuredFormatter",
    "LoggerContext",
    "setup_logging",
    "with_correlation_id",
    "get_correlation_id",
    "set_correlation_id",
]
