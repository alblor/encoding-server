"""RestoreService: the behaviour behind the /v1/restore endpoints.

It owns the lifecycle of a job on the API side (rules/restore-job-protocol.md): validate the
recipe, take the upload into the shared RAM volume, decrypt it per the job's mode, validate the
content, create the Redis hash and queue the id; later report status, serve the result, cancel,
delete, and clean up what nobody asked for any more.

Author: Lorenzo Albanese (alblor)
"""

import asyncio
import base64
import json
import logging
import os
import secrets
import shutil
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from fastapi import HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from restore_core import budget
from restore_core.recipe import PRESETS, EffectiveRecipe, resolve

from .config import RestoreConfig
from .files import (
    JobDirError,
    INPUT_NAME,
    OUTPUT_NAME,
    UPLOAD_NAME,
    UploadTooLarge,
    create_job_dir,
    decrypt_password_file,
    job_dir,
    open_private_output,
    read_chunks,
    wipe_dir,
    wipe_file,
)
from .models import (
    KNOWN_ENGINES,
    TERMINAL_STATUSES,
    api_error,
    is_job_id,
    not_found,
    now_iso,
    parse_iso,
    same_principal,
)
from .probe import ProbeRejected, ProbeResult, ProbeUnavailable, validate_segment
from .store import QUEUE_ENGINES, RestoreStore

logger = logging.getLogger(__name__)

MAX_RECIPE_BYTES = 64 * 1024
MAX_PASSWORD_CHARS = 1024
_MIB = 1024 * 1024


@dataclass
class DownloadHandle:
    """What the router needs to answer a download."""

    stream: Iterator[bytes]
    size: int
    filename: str
    media_type: str


class RestoreService:
    """Coordinates the store, the shared volume and the encryption manager."""

    def __init__(
        self, store: RestoreStore, config: RestoreConfig, encryption_manager
    ) -> None:
        self.store = store
        self.config = config
        self.encryption_manager = encryption_manager
        self._inflight: set = set()
        self._lock = threading.Lock()
        # Slots and bytes promised to uploads that passed the Content-Length check. Slots are
        # dropped when the job directory exists (it is counted from then on), bytes when the
        # request ends.
        self._pending_slots: set = set()
        self._reserved_bytes: Dict[str, int] = {}
        self._clock = lambda: datetime.now(timezone.utc)

    # --- recipe --------------------------------------------------------------------------------

    @staticmethod
    def resolve_recipe(payload: Any) -> EffectiveRecipe:
        """Run restore_core.recipe.resolve and turn any error into a 422 that carries the reason."""
        try:
            effective = resolve(payload)
            if effective.basic.engine not in QUEUE_ENGINES:
                raise api_error(
                    422,
                    f"Invalid recipe: engine {effective.basic.engine!r} not available "
                    f"(available: {', '.join(QUEUE_ENGINES)})",
                    "validation_error",
                )
            return effective
        except ValidationError as exc:
            problems = [
                {
                    "field": ".".join(str(part) for part in err["loc"]),
                    "message": str(err["msg"]),
                }
                for err in exc.errors(include_url=False)
            ]
            raise api_error(
                422,
                "Invalid recipe: "
                + "; ".join(f"{p['field']}: {p['message']}" for p in problems),
                "validation_error",
                problems=problems,
            ) from None
        except ValueError as exc:
            raise api_error(422, f"Invalid recipe: {exc}", "validation_error") from None
        except RecursionError:
            raise api_error(
                422, "Invalid recipe: the JSON is nested too deeply", "validation_error"
            ) from None

    def parse_recipe(self, text: str) -> EffectiveRecipe:
        """Parse the `recipe` form field (a JSON RecipeRequest) and resolve it."""
        if len(text.encode("utf-8")) > MAX_RECIPE_BYTES:
            raise api_error(
                422, "Invalid recipe: the field is too large", "validation_error"
            )
        try:
            payload = json.loads(text)
        except (ValueError, RecursionError):
            raise api_error(
                422, "Invalid recipe: the field is not valid JSON", "validation_error"
            ) from None
        return self.resolve_recipe(payload)

    @staticmethod
    def presets() -> Dict[str, Any]:
        """Every preset with its description and the recipe it resolves to."""
        return {
            name: {
                "description": spec["description"],
                "recipe": json.loads(resolve({"preset": name}).model_dump_json()),
            }
            for name, spec in PRESETS.items()
        }

    # --- limits ----------------------------------------------------------------------------------

    def storage_ready(self) -> bool:
        return self.config.work_dir.is_dir()

    def _job_dir_count(self) -> int:
        try:
            return sum(
                1
                for e in os.scandir(self.config.work_dir)
                if is_job_id(e.name) and e.is_dir(follow_symlinks=False)
            )
        except FileNotFoundError:
            return 0

    def reserve_upload(self, content_length: int) -> str:
        """Check the limits and reserve a slot and space for one upload, atomically.

        Refuses before the body is consumed: too big, too many jobs, or not enough RAM volume
        left. Slots already promised to other uploads count, so concurrent submits cannot
        all pass the same check. The caller must call release_upload with the token when the
        request ends.
        """
        cfg = self.config
        if content_length > cfg.max_segment_bytes + cfg.form_overhead_bytes:
            raise api_error(
                413,
                f"Upload is larger than the {cfg.max_segment_bytes // _MIB} MiB limit per segment",
                "payload_too_large",
            )
        if not self.storage_ready():
            raise api_error(
                503, "Restoration storage is not available", "unavailable_error"
            )
        with self._lock:
            if self._job_dir_count() + len(self._pending_slots) >= cfg.max_jobs:
                raise api_error(
                    429,
                    "Too many restoration jobs are stored, delete finished ones first",
                    "rate_limit_error",
                )
            needed = (
                2 * content_length
                + sum(self._reserved_bytes.values())
                + cfg.free_space_margin_bytes
            )
            if shutil.disk_usage(cfg.work_dir).free < needed:
                raise api_error(
                    507,
                    "Not enough free space on the restoration volume",
                    "insufficient_storage_error",
                )
            token = secrets.token_hex(8)
            self._pending_slots.add(token)
            self._reserved_bytes[token] = 2 * content_length
        return token

    def release_upload(self, token: Optional[str]) -> None:
        """Give back what reserve_upload promised. Safe to call more than once."""
        if token is None:
            return
        with self._lock:
            self._pending_slots.discard(token)
            self._reserved_bytes.pop(token, None)

    # --- submit ----------------------------------------------------------------------------------

    async def submit_job(
        self,
        principal: str,
        upload: UploadFile,
        recipe_text: str,
        first_frame: int,
        segment_index: int,
        password: Optional[str],
        reservation: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate, store and queue one segment. On any failure nothing is left behind."""
        effective = self.parse_recipe(recipe_text)
        mode = effective.basic.encryption
        if mode == "manual":
            if not password:
                raise api_error(
                    400,
                    "Manual mode requires decryption_password parameter",
                    "validation_error",
                )
            if len(password) > MAX_PASSWORD_CHARS:
                raise api_error(
                    400, "decryption_password is too long", "validation_error"
                )
        else:
            password = None
        if not self.storage_ready():
            raise api_error(
                503, "Restoration storage is not available", "unavailable_error"
            )

        job_id = secrets.token_hex(16)
        with self._lock:
            self._inflight.add(job_id)
        directory: Optional[Path] = None
        queued = False
        try:
            with self._lock:
                # From here the directory itself counts against the job limit.
                directory = create_job_dir(
                    self.config.work_dir, job_id, self.config.worker_gid
                )
                self._pending_slots.discard(reservation)
            await self._receive(
                upload, directory / (UPLOAD_NAME if mode == "manual" else INPUT_NAME)
            )
            if mode == "manual":
                await run_in_threadpool(self._decrypt_upload, directory, password)
            probe = await run_in_threadpool(
                validate_segment, directory / INPUT_NAME, self.config
            )
            input_bytes = (directory / INPUT_NAME).stat().st_size
            too_big = budget.refusal(
                effective, probe.width, probe.height, probe.frames,
                self.config.gpu_worker_memory_bytes
                if effective.basic.engine == "recavsr"
                else self.config.cpu_worker_memory_bytes,
            )
            if too_big:
                raise api_error(422, f"Segment rejected: {too_big}", "validation_error")
            await run_in_threadpool(
                self._enqueue,
                job_id,
                principal,
                effective,
                probe,
                input_bytes,
                first_frame,
                segment_index,
                password,
            )
            queued = True
        except UploadTooLarge:
            await self._abandon(job_id, directory, queued)
            raise api_error(
                413,
                f"Upload is larger than the {self.config.max_segment_bytes // _MIB} MiB limit per segment",
                "payload_too_large",
            ) from None
        except ProbeRejected as exc:
            await self._abandon(job_id, directory, queued)
            raise api_error(
                422, f"Segment rejected: {exc}", "validation_error"
            ) from None
        except JobDirError:
            await self._abandon(job_id, directory, queued)
            raise api_error(
                500,
                "The restoration volume is not set up correctly: the API cannot create "
                "job directories in the worker group",
                "processing_error",
            ) from None
        except ProbeUnavailable:
            await self._abandon(job_id, directory, queued)
            raise api_error(
                503, "Content validation is not available", "unavailable_error"
            ) from None
        except HTTPException:
            await self._abandon(job_id, directory, queued)
            raise
        except Exception as exc:
            await self._abandon(job_id, directory, queued)
            logger.error("restore submit failed (%s)", type(exc).__name__)
            raise api_error(500, "Job submission failed", "processing_error") from None
        finally:
            with self._lock:
                self._inflight.discard(job_id)

        warning = self._engine_warning(effective.basic.engine)
        response = {
            "job_id": job_id,
            "status": "queued",
            "encryption": mode,
            "recipe": json.loads(effective.model_dump_json()),
            "input": {
                "bytes": input_bytes,
                "width": probe.width,
                "height": probe.height,
                "frames": probe.frames,
            },
            "submitted_at": now_iso(),
        }
        if warning:
            response["warning"] = warning
        return response

    async def _receive(self, upload: UploadFile, target: Path) -> None:
        """Copy the upload to target in chunks, never holding more than one chunk, stopping at the cap."""
        cfg = self.config
        limit = (
            cfg.max_segment_bytes + 64
        )  # a manual-mode file carries 64 bytes of header and tag
        total = 0
        out = open_private_output(target, cfg.worker_gid)
        try:
            while True:
                chunk = await upload.read(cfg.upload_chunk_bytes)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise UploadTooLarge()
                await run_in_threadpool(out.write, chunk)
        finally:
            out.close()
        if total == 0:
            raise ProbeRejected("the upload is empty")

    def _decrypt_upload(self, directory: Path, password: str) -> None:
        source = directory / UPLOAD_NAME
        try:
            decrypt_password_file(
                source,
                directory / INPUT_NAME,
                password,
                self.config.worker_gid,
                self.config.upload_chunk_bytes,
                self.config.max_segment_bytes,
            )
        except ValueError:
            raise ProbeRejected(
                "the upload could not be decrypted with the given password"
            ) from None
        finally:
            wipe_file(source, self.config.wipe_passes)

    def _enqueue(
        self,
        job_id: str,
        principal: str,
        effective: EffectiveRecipe,
        probe: ProbeResult,
        input_bytes: int,
        first_frame: int,
        segment_index: int,
        password: Optional[str],
    ) -> None:
        cfg = self.config
        if password is not None:
            self._store_wrapped_password(job_id, password)
        stamp = now_iso()
        self.store.create_job(
            job_id,
            {
                "status": "queued",
                "stage": "",
                "progress": "0.0",
                "error": "",
                "recipe": effective.model_dump_json(),
                "first_frame": str(first_frame),
                "segment_index": str(segment_index),
                "created_at": stamp,
                "updated_at": stamp,
                "owner": principal,
                "encryption": effective.basic.encryption,
                "input_bytes": str(input_bytes),
                "input_width": str(probe.width),
                "input_height": str(probe.height),
                "input_frames": str(probe.frames),
            },
            cfg.job_ttl_seconds,
        )
        self.store.push(job_id, effective.basic.engine)

    async def _abandon(
        self, job_id: str, directory: Optional[Path], queued: bool
    ) -> None:
        """Remove everything a failed submission left behind."""

        def clean() -> None:
            if directory is not None:
                wipe_dir(directory, self.config.wipe_passes)
            self._drop_wrapped_key(job_id)
            self.store.discard(job_id)

        await run_in_threadpool(clean)

    def _engine_warning(self, engine: str) -> Optional[str]:
        workers = self.store.live_workers()
        if not workers:
            return "No restoration worker is running right now; the job waits in the queue until one starts."
        offered = {e for w in workers for e in w.get("engines", "").split(",")}
        if engine not in offered:
            return f"No running worker offers the engine {engine!r} right now; the job waits in the queue."
        return None

    # --- manual-mode password ------------------------------------------------------------------------

    def _store_wrapped_password(self, job_id: str, password: str) -> None:
        """Keep the password the way /v1/jobs does (EncryptionManager.automated_encrypt), but for the job's lifetime.

        automated_encrypt stores its key in Redis for one hour, shorter than a restoration job,
        so the key's expiry is extended to the lifetime of the job.
        """
        ttl = self.config.job_ttl_seconds + 3600
        blob, key_id = self.encryption_manager.automated_encrypt(
            password.encode("utf-8")
        )
        self.encryption_manager.redis_client.expire(f"key:{key_id}", ttl)
        record = json.dumps(
            {"key_id": key_id, "blob": base64.b64encode(blob).decode("ascii")}
        )
        self.store.put_password_record(job_id, record, ttl)

    def _unwrap_password(self, job_id: str) -> Optional[str]:
        raw = self.store.get_password_record(job_id)
        if not raw:
            return None
        try:
            record = json.loads(raw)
            plain = self.encryption_manager.automated_decrypt(
                base64.b64decode(record["blob"]), record["key_id"]
            )
            return plain.decode("utf-8")
        except (ValueError, KeyError, TypeError):
            logger.error("stored password of job %s could not be unwrapped", job_id)
            return None

    def _drop_wrapped_key(self, job_id: str) -> None:
        raw = self.store.get_password_record(job_id)
        if not raw:
            return
        try:
            key_id = json.loads(raw)["key_id"]
        except (ValueError, KeyError, TypeError):
            return
        self.encryption_manager.redis_client.delete(f"key:{key_id}")

    # --- reading a job ---------------------------------------------------------------------------------

    def _load_owned(self, principal: str, job_id: str) -> Dict[str, str]:
        """The job record if the caller owns it. Missing, malformed id and foreign job all look the same: 404."""
        if not is_job_id(job_id):
            raise not_found()
        record = self.store.get(job_id)
        if (
            not record
            or "owner" not in record
            or not same_principal(record["owner"], principal)
        ):
            raise not_found()
        # A job whose worker died would stay `running` for ever: settle it before answering.
        settled = self._reap(job_id, record, self._clock())
        if settled is None:
            raise not_found()
        return settled

    def _reap(
        self, job_id: str, record: Dict[str, str], now: datetime
    ) -> Optional[Dict[str, str]]:
        """Fail a `running` job whose worker stopped reporting, or a `queued` one that waited too long.

        Returns the (possibly updated) record, or None when the job had a pending delete and has
        been wiped. The cancel flag is set too, so a worker that comes back late stops at once.
        """
        cfg = self.config
        status = record.get("status")
        if status == "running":
            seen = parse_iso(record.get("updated_at")) or parse_iso(
                record.get("created_at")
            )
            if seen is None or (now - seen).total_seconds() <= cfg.stale_seconds:
                return record
            reason = "the worker stopped responding"
        elif status == "queued":
            created = parse_iso(record.get("created_at"))
            if (
                created is None
                or (now - created).total_seconds() <= cfg.queue_max_seconds
            ):
                return record
            reason = "expired in the queue"
            self.store.remove_from_queue(job_id)
        else:
            return record
        self.store.request_cancel(job_id, cfg.terminal_ttl_seconds)
        self.store.update(
            job_id,
            {
                "status": "failed",
                "stage": "",
                "error": reason,
                "updated_at": now.isoformat(timespec="seconds"),
            },
        )
        self.store.set_expiry(job_id, cfg.terminal_ttl_seconds)
        logger.warning("restore job %s failed: %s", job_id, reason)
        if record.get("delete_requested") == "1":
            if self._destroy(job_id):
                return None
        return self.store.get(job_id)

    def _view(self, job_id: str, record: Dict[str, str]) -> Dict[str, Any]:
        def number(name: str, cast):
            try:
                return cast(record[name])
            except (KeyError, ValueError):
                return None

        status = record.get("status", "queued")
        view: Dict[str, Any] = {
            "job_id": job_id,
            "status": status,
            "stage": record.get("stage", ""),
            "progress": number("progress", float) or 0.0,
            "error": record.get("error", ""),
            "encryption": record.get("encryption", "automated"),
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "first_frame": number("first_frame", int),
            "segment_index": number("segment_index", int),
            "input": {
                k: number(f"input_{k}", int)
                for k in ("bytes", "width", "height", "frames")
            },
        }
        try:
            view["recipe"] = json.loads(record["recipe"])
        except (KeyError, ValueError):
            view["recipe"] = None
        if status == "running" and self.store.cancel_requested(job_id):
            view["cancelling"] = True
        if status == "done":
            view["result"] = {
                "frames": number("frames", int),
                "width": number("width", int),
                "height": number("height", int),
                "seconds": number("seconds", float),
            }
            try:
                view["result"]["bytes"] = (
                    (job_dir(self.config.work_dir, job_id) / OUTPUT_NAME).stat().st_size
                )
            except OSError:
                view["result"]["bytes"] = None
        return view

    def get_status(self, principal: str, job_id: str) -> Dict[str, Any]:
        return self._view(job_id, self._load_owned(principal, job_id))

    # --- cancel, delete -----------------------------------------------------------------------------------

    def cancel(self, principal: str, job_id: str) -> Dict[str, Any]:
        """Stop a queued or running job. Terminal jobs are returned as they are (idempotent)."""
        record = self._load_owned(principal, job_id)
        status = record.get("status")
        if status in TERMINAL_STATUSES:
            return self._view(job_id, record)
        cfg = self.config
        # The flag goes first: a worker that just popped the id sees it before it starts.
        self.store.request_cancel(job_id, cfg.job_ttl_seconds)
        if status == "queued":
            self.store.remove_from_queue(job_id)
            self.store.update(
                job_id,
                {
                    "status": "cancelled",
                    "stage": "",
                    "error": "",
                    "updated_at": now_iso(),
                },
            )
            self.store.set_expiry(job_id, cfg.terminal_ttl_seconds)
            wipe_dir(job_dir(cfg.work_dir, job_id), cfg.wipe_passes)
        # A running job keeps its files: the worker stops at the next poll, sets `cancelled`,
        # and cleanup_once wipes the directory then.
        return self._view(job_id, self.store.get(job_id) or record)

    def delete(self, principal: str, job_id: str) -> Dict[str, Any]:
        """Wipe the files and the keys of a job. A running job is cancelled first and removed once it stops."""
        record = self._load_owned(principal, job_id)
        if record.get("status") == "running":
            self.store.request_cancel(job_id, self.config.job_ttl_seconds)
            self.store.update(
                job_id, {"delete_requested": "1", "updated_at": now_iso()}
            )
            return {
                "job_id": job_id,
                "deleted": False,
                "status": "running",
                "message": "The job is running: it has been told to stop and will be wiped as soon as it does.",
            }
        if not self._destroy(job_id):
            self.store.update(
                job_id, {"delete_requested": "1", "updated_at": now_iso()}
            )
            raise api_error(
                500,
                "Some files could not be removed yet, deletion will be retried",
                "processing_error",
            )
        return {"job_id": job_id, "deleted": True}

    def _destroy(self, job_id: str) -> bool:
        """Overwrite and unlink the directory, then drop the keys. Keys stay if the files could not go."""
        if not wipe_dir(job_dir(self.config.work_dir, job_id), self.config.wipe_passes):
            return False
        self._drop_wrapped_key(job_id)
        self.store.forget_job(job_id)
        return True

    # --- download --------------------------------------------------------------------------------------

    def open_result(self, principal: str, job_id: str) -> DownloadHandle:
        """Open the result for streaming, encrypted as the job's mode says (as /v1/jobs does)."""
        record = self._load_owned(principal, job_id)
        status = record.get("status")
        if status != "done":
            raise api_error(
                409,
                f"Job is not done (status: {status})",
                "conflict_error",
                job_id=job_id,
            )
        cfg = self.config
        directory = job_dir(cfg.work_dir, job_id)
        result = directory / OUTPUT_NAME
        if not result.is_file():
            raise api_error(404, "Result is no longer available", "not_found_error")
        if record.get("encryption") != "manual":
            return DownloadHandle(
                read_chunks(result, cfg.upload_chunk_bytes),
                result.stat().st_size,
                "restored.mkv",
                "video/x-matroska",
            )
        password = self._unwrap_password(job_id)
        if not password:
            raise api_error(
                500, "The result cannot be encrypted for this job", "processing_error"
            )
        wrapped = directory / f"dl-{secrets.token_hex(8)}.enc"
        try:
            open_private_output(wrapped, cfg.worker_gid).close()
            self.encryption_manager.encrypt_password_based_file(
                str(result), str(wrapped), password
            )
            size = wrapped.stat().st_size
            stream = read_chunks(
                wrapped,
                cfg.upload_chunk_bytes,
                lambda: wipe_file(wrapped, cfg.wipe_passes),
            )
        except Exception as exc:
            wipe_file(wrapped, cfg.wipe_passes)
            logger.error(
                "encrypting the result of job %s failed (%s)",
                job_id,
                type(exc).__name__,
            )
            raise api_error(
                500, "Failed to prepare the result", "processing_error"
            ) from None
        return DownloadHandle(
            stream, size, "restored.mkv.enc", "application/octet-stream"
        )

    # --- capabilities ---------------------------------------------------------------------------------------

    def capabilities(self) -> Dict[str, Any]:
        workers = self.store.live_workers()
        listed = []
        engines = set()
        for worker in workers:
            offered = sorted(
                e for e in worker.get("engines", "").split(",") if e in KNOWN_ENGINES
            )
            engines.update(offered)
            listed.append(
                {
                    "name": worker["name"],
                    "engines": offered,
                    "device": worker.get("device", ""),
                    "last_seen": worker.get("updated_at"),
                }
            )
        return {
            "available": bool(listed),
            "message": (
                f"{len(listed)} worker(s) running."
                if listed
                else "No restoration worker is running. Jobs are accepted and wait in the queue until one starts."
            ),
            "engines": sorted(engines),
            "queue_length": self.store.queue_length(),
            "queues": self.store.queue_lengths(),
            "workers": listed,
            "limits": {
                "max_segment_mb": self.config.max_segment_bytes // _MIB,
                "max_frames": self.config.max_frames,
                "max_pixels": self.config.max_pixels,
            },
        }

    # --- cleanup ---------------------------------------------------------------------------------------------

    def cleanup_once(self, now: Optional[datetime] = None) -> Dict[str, int]:
        """One pass of housekeeping. Safe to run at any time and from any thread.

        First settles jobs that cannot finish any more: `running` with no sign of life for
        stale_seconds becomes `failed`, `queued` for longer than queue_max_seconds becomes `failed`.
        Then wipes the directory of a job when: its hash is gone (expired or deleted), the hash is a
        leftover without an owner, the job ended as `cancelled`, a delete was requested and the job
        stopped, or the job reached a terminal status more than 24 h ago. Directories of uploads
        still being received are skipped.
        """
        now = now or self._clock()
        cfg = self.config
        counts = {"wiped": 0, "failed": 0, "reaped": 0}
        for job_id in list(self.store.scan_job_ids()):
            with self._lock:
                if job_id in self._inflight:
                    continue
            record = self.store.get(job_id)
            if record is None or "owner" not in record:
                continue
            before = record.get("status")
            after = self._reap(job_id, record, now)
            if after is None or after.get("status") != before:
                counts["reaped"] += 1
        try:
            entries = [
                e
                for e in os.scandir(cfg.work_dir)
                if is_job_id(e.name) and e.is_dir(follow_symlinks=False)
            ]
        except FileNotFoundError:
            entries = []
        for entry in entries:
            job_id = entry.name
            with self._lock:
                if job_id in self._inflight:
                    continue
            record = self.store.get(job_id)
            drop_keys = False
            if record is None or "owner" not in record:
                wipe, drop_keys = True, True
            else:
                status = record.get("status")
                changed = parse_iso(record.get("updated_at")) or now
                aged = (now - changed).total_seconds() > cfg.terminal_ttl_seconds
                terminal = status in TERMINAL_STATUSES
                requested = record.get("delete_requested") == "1"
                wipe = terminal and (status == "cancelled" or requested or aged)
                drop_keys = terminal and (requested or aged)
            if not wipe:
                continue
            if drop_keys:
                done = self._destroy(job_id)
            else:
                done = wipe_dir(Path(entry.path), cfg.wipe_passes)
            counts["wiped" if done else "failed"] += 1
        self._expire_orphan_hashes()
        return counts

    def _expire_orphan_hashes(self) -> None:
        """A worker that updates a job after it was deleted re-creates a bare hash; give those an expiry."""
        for job_id in self.store.scan_job_ids():
            record = self.store.get(job_id)
            if (
                record is not None
                and "owner" not in record
                and self.store.ttl(job_id) < 0
            ):
                self.store.set_expiry(job_id, 3600)


async def run_cleanup_loop(service: RestoreService) -> None:
    """Background task: run cleanup_once every cleanup_interval_seconds until cancelled."""
    while True:
        try:
            counts = await run_in_threadpool(service.cleanup_once)
            if any(counts.values()):
                logger.info(
                    "restore cleanup: %d wiped, %d failed, %d settled",
                    counts["wiped"],
                    counts["failed"],
                    counts["reaped"],
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("restore cleanup pass failed (%s)", type(exc).__name__)
        await asyncio.sleep(service.config.cleanup_interval_seconds)
