"""ID generation helpers for the RE engine."""

from __future__ import annotations

import hashlib
import uuid


def finding_id(prefix: str = "find") -> str:
    """Generate a unique finding identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def analysis_id(prefix: str = "re") -> str:
    """Generate a unique analysis-run identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def short_hash(data: bytes, length: int = 16) -> str:
    """Return a short, stable hash of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()[:length]