"""Shared small pieces of the restoration API: id validation, error shape, principal.

Errors use the same shape as the rest of the API: HTTPException(detail={"error": {...}}).

Author: Lorenzo Albanese (alblor)
"""

import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Request

JOB_ID_RE = re.compile(r"[0-9a-f]{32}")
TERMINAL_STATUSES = frozenset({"done", "failed", "cancelled"})
KNOWN_ENGINES = frozenset({"recavsr", "sparkvsr", "classical", "none"})
ANONYMOUS = "anonymous"


def api_error(
    status_code: int, message: str, error_type: str, **extra
) -> HTTPException:
    """Build an HTTPException with the error shape the existing endpoints use."""
    error = {"message": message, "type": error_type}
    error.update(extra)
    return HTTPException(status_code=status_code, detail={"error": error})


def not_found() -> HTTPException:
    """The one answer for a job that is missing or belongs to somebody else (never 403)."""
    return api_error(404, "Job not found", "not_found_error")


def now_iso() -> str:
    """ISO 8601 UTC with second precision, the format the worker writes too."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO timestamp written by now_iso(); None when absent or malformed."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_job_id(value: str) -> bool:
    """True only for a 32 character lowercase hex id: the path traversal guard for /restore-work/{id}."""
    return bool(JOB_ID_RE.fullmatch(value))


def get_principal(request: Request) -> str:
    """Return who is calling.

    /v1/jobs has no authentication today (see GET /v1/docs/auth), so there is nothing to verify
    against. If the caller sends X-API-Key, the principal is a hash of it, which scopes jobs per
    key without ever storing the key. Without the header every caller is "anonymous". When real
    authentication lands, this is the single place to change.
    """
    api_key = request.headers.get("x-api-key")
    if not api_key:
        return ANONYMOUS
    return "key-" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:32]


def same_principal(a: str, b: str) -> bool:
    """Timing-safe owner comparison."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
