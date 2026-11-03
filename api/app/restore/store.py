"""Redis side of the restoration job protocol.

Exactly the keys of rules/restore-job-protocol.md: restore:queue:{engine} (one list per engine), restore:job:{id},
restore:cancel:{id} and restore:worker:{name}. One extra key, restore:pw:{id}, holds the
manual-mode password wrapped by EncryptionManager (never in the clear, never visible to the
worker, which has no master key).

The client passed in must be created with decode_responses=True.

Author: Lorenzo Albanese (alblor)
"""

import logging
from typing import Dict, Iterator, List, Optional

from .models import is_job_id

logger = logging.getLogger(__name__)

QUEUE_PREFIX = "restore:queue:"
# One queue per engine, so a worker that does not offer an engine can never pop its jobs.
QUEUE_ENGINES = ("recavsr", "classical", "none")
JOB_PREFIX = "restore:job:"
WORKER_PREFIX = "restore:worker:"


def job_key(job_id: str) -> str:
    return JOB_PREFIX + _checked(job_id)


def cancel_key(job_id: str) -> str:
    return f"restore:cancel:{_checked(job_id)}"


def password_key(job_id: str) -> str:
    return f"restore:pw:{_checked(job_id)}"


def _checked(job_id: str) -> str:
    if not is_job_id(job_id):
        raise ValueError("invalid job id")
    return job_id


class RestoreStore:
    """Thin, explicit wrapper over the protocol keys."""

    def __init__(self, client) -> None:
        self.client = client

    # --- job hash ---------------------------------------------------------------------------

    def create_job(self, job_id: str, fields: Dict[str, str], ttl_seconds: int) -> None:
        """Write the hash with a safety expiry (the worker shortens it when the job ends)."""
        key = job_key(job_id)
        self.client.hset(key, mapping=fields)
        self.client.expire(key, ttl_seconds)

    def push(self, job_id: str, engine: str) -> None:
        """Queue the id on the list of its engine."""
        if engine not in QUEUE_ENGINES:
            raise ValueError("no queue for this engine")
        self.client.lpush(QUEUE_PREFIX + engine, _checked(job_id))

    def get(self, job_id: str) -> Optional[Dict[str, str]]:
        record = self.client.hgetall(job_key(job_id))
        return dict(record) if record else None

    def update(self, job_id: str, fields: Dict[str, str]) -> None:
        self.client.hset(job_key(job_id), mapping=fields)

    def set_expiry(self, job_id: str, ttl_seconds: int) -> None:
        self.client.expire(job_key(job_id), ttl_seconds)

    def ttl(self, job_id: str) -> int:
        return int(self.client.ttl(job_key(job_id)))

    def scan_job_ids(self) -> Iterator[str]:
        """Ids of every job hash, with SCAN so a big keyspace never blocks Redis."""
        for key in self.client.scan_iter(match=JOB_PREFIX + "*", count=200):
            candidate = key[len(JOB_PREFIX) :]
            if is_job_id(candidate):
                yield candidate

    # --- cancel flag, queue ------------------------------------------------------------------

    def request_cancel(self, job_id: str, ttl_seconds: int) -> None:
        self.client.set(cancel_key(job_id), "1", ex=ttl_seconds)

    def cancel_requested(self, job_id: str) -> bool:
        return bool(self.client.get(cancel_key(job_id)))

    def remove_from_queue(self, job_id: str) -> None:
        for engine in QUEUE_ENGINES:
            self.client.lrem(QUEUE_PREFIX + engine, 0, _checked(job_id))

    def queue_lengths(self) -> Dict[str, int]:
        return {e: int(self.client.llen(QUEUE_PREFIX + e)) for e in QUEUE_ENGINES}

    def queue_length(self) -> int:
        return sum(self.queue_lengths().values())

    # --- wrapped password (manual mode) -------------------------------------------------------

    def put_password_record(
        self, job_id: str, record_json: str, ttl_seconds: int
    ) -> None:
        self.client.set(password_key(job_id), record_json, ex=ttl_seconds)

    def get_password_record(self, job_id: str) -> Optional[str]:
        value = self.client.get(password_key(job_id))
        return value if value else None

    # --- removal -------------------------------------------------------------------------------

    def forget_job(self, job_id: str, cancel_flag_ttl: int = 3600) -> None:
        """Delete the hash and the password record, take the id off the queue.

        The cancel flag is kept for a short while on purpose: a worker that popped the id a
        moment before we got here will still see it and stop instead of starting.
        """
        self.client.set(cancel_key(job_id), "1", ex=cancel_flag_ttl)
        self.remove_from_queue(job_id)
        self.client.delete(job_key(job_id), password_key(job_id))

    def discard(self, job_id: str) -> None:
        """Delete the hash and the password record of a job that never reached the queue."""
        self.client.delete(job_key(job_id), password_key(job_id))

    # --- workers -----------------------------------------------------------------------------

    def live_workers(self) -> List[Dict[str, str]]:
        """Workers whose registration key (60 s TTL, written by the worker) is still there."""
        workers: List[Dict[str, str]] = []
        for key in self.client.scan_iter(match=WORKER_PREFIX + "*", count=100):
            record = self.client.hgetall(key)
            if not record:
                continue
            name = key[len(WORKER_PREFIX) :]
            workers.append({"name": name, **{k: str(v) for k, v in record.items()}})
        return sorted(workers, key=lambda w: w["name"])
