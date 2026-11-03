"""Restore worker: pops jobs from Redis, runs them through the pipeline, reports back. One process per GPU.

Implements the worker side of rules/restore-job-protocol.md. The worker never sees an encryption key: the
API hands it a plaintext segment in the shared RAM volume and takes the result from there.

Configuration, all by environment (secrets by file, never by value):
  REDIS_HOST, REDIS_PORT          where Redis is (default redis-secure:6379)
  REDIS_PASSWORD_FILE             Docker secret holding the worker's Redis password (default /run/secrets/restore_worker_redis_password)
  REDIS_USERNAME                  the restricted Redis user (restore-worker in the compose file)
  WORKER_NAME                     name in the registry and in job records (default: hostname)
  WORKER_DEVICE                   cuda:0 for a GPU worker, cpu for a CPU-only worker (default cuda:0)
  WORKER_ENGINES                  engines this worker offers, comma separated (default: recavsr,classical,none for GPU,
                                  classical,none for CPU). It pops only the queues of those engines.
  MODEL_DIR                       ReCaVSR weights, mounted read-only (default /m)
  RESTORE_WORK_DIR                the shared RAM volume (default /restore-work)
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import redis

from restore_core.recipe import EffectiveRecipe
from restore_worker.pipeline import Cancelled, PipelineError, SegmentJob, run_segment

log = logging.getLogger("restore_worker")

QUEUE_PREFIX = "restore:queue:"          # one queue per engine: a worker only ever pops what it can run
HEARTBEAT_TTL = 60
HEARTBEAT_EVERY = 20
JOB_KEEPALIVE_EVERY = 15                 # seconds: the API fails a running job whose updated_at goes stale
TERMINAL_TTL = 24 * 3600


def queue_keys(engines: list[str]) -> list[str]:
    """Queues for the engines this worker offers, most capable first (BRPOP serves them in this order)."""
    order = ["recavsr", "classical", "none"]
    return [QUEUE_PREFIX + e for e in order if e in engines]
# Overall progress is split across the stages: decode is quick, restore is most of the time, encode follows.
STAGE_SPAN = {"decode": (0.0, 0.05), "restore": (0.05, 0.85), "encode": (0.85, 1.0)}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_secret(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


class Worker:
    def __init__(self, client: "redis.Redis", name: str, device: str, engines: list[str], work_dir: Path, engine=None) -> None:
        self.r, self.name, self.device, self.engines = client, name, device, engines
        self.work_dir, self.engine = work_dir, engine
        self._stop = threading.Event()
        self._last_progress = 0.0
        self.keepalive_every = JOB_KEEPALIVE_EVERY

    # --- registry -----------------------------------------------------------------------------

    def heartbeat(self) -> None:
        key = f"restore:worker:{self.name}"
        precision = getattr(self.engine, "precision", None)
        self.r.hset(key, mapping={"engines": ",".join(self.engines), "device": self.device, "updated_at": now(),
                                  **({"precision": precision} if precision else {})})
        self.r.expire(key, HEARTBEAT_TTL)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(HEARTBEAT_EVERY):
            try:
                self.heartbeat()
            except redis.RedisError:
                log.warning("heartbeat failed, will retry")

    # --- one job ------------------------------------------------------------------------------

    def _set(self, job_id: str, **fields) -> None:
        self.r.hset(f"restore:job:{job_id}", mapping={**{k: str(v) for k, v in fields.items()}, "updated_at": now()})

    def _finish(self, job_id: str, status: str, **fields) -> None:
        self._set(job_id, status=status, **fields)
        self.r.expire(f"restore:job:{job_id}", TERMINAL_TTL)

    def _keepalive(self, job_id: str, done: threading.Event) -> None:
        """Touch updated_at while a job runs, even in a long stage with no progress to report."""
        while not done.wait(self.keepalive_every):
            try:
                self.r.hset(f"restore:job:{job_id}", mapping={"updated_at": now()})
            except redis.RedisError:
                log.warning("keepalive for %s failed, will retry", job_id)

    def _cancelled(self, job_id: str) -> bool:
        return bool(self.r.get(f"restore:cancel:{job_id}"))

    def _progress(self, job_id: str):
        def report(stage: str, fraction: float) -> None:
            lo, hi = STAGE_SPAN.get(stage, (0.0, 1.0))
            overall = lo + (hi - lo) * max(0.0, min(1.0, fraction))
            t = time.monotonic()
            if t - self._last_progress >= 0.5 or fraction >= 1.0:      # keep Redis traffic low
                self._last_progress = t
                self._set(job_id, stage=stage, progress=f"{overall:.3f}")
        return report

    def handle(self, job_id: str) -> None:
        key = f"restore:job:{job_id}"
        record = self.r.hgetall(key)
        if not record or record.get("status") != "queued":
            log.info("job %s is gone or not queued (%s), skipping", job_id, record.get("status") if record else "missing")
            return
        job_dir = self.work_dir / job_id
        out = job_dir / "out.mkv"
        self._set(job_id, status="running", worker=self.name, stage="decode", progress="0.0")
        finished = threading.Event()
        threading.Thread(target=self._keepalive, args=(job_id, finished), daemon=True).start()
        try:
            if self._cancelled(job_id):
                raise Cancelled()
            recipe = EffectiveRecipe.model_validate_json(record["recipe"])
            if recipe.basic.engine not in self.engines:
                raise PipelineError(f"this worker does not offer engine {recipe.basic.engine!r} (offers: {', '.join(self.engines)})")
            job = SegmentJob(job_dir / "in.mkv", out, recipe, first_frame_index=int(record.get("first_frame", 0)))
            result = run_segment(job, self.engine, device=self.device if self.engine is not None else "cpu",
                                 progress=self._progress(job_id), cancelled=lambda: self._cancelled(job_id))
            self._finish(job_id, "done", stage="", progress="1.0", error="", frames=result.frames,
                         width=result.width, height=result.height, seconds=f"{result.seconds:.1f}")
            log.info("job %s done: %d frames in %.1fs", job_id, result.frames, result.seconds)
        except Cancelled:
            out.unlink(missing_ok=True)
            self._finish(job_id, "cancelled", stage="", error="")
            log.info("job %s cancelled", job_id)
        except Exception as exc:                                       # a failed job must never kill the worker
            out.unlink(missing_ok=True)
            message = f"{type(exc).__name__}: {exc}"[:400]
            self._finish(job_id, "failed", stage="", error=message)
            log.error("job %s failed: %s", job_id, message)
            if "CUDA" in message and "out of memory" not in message.lower():
                # A sticky CUDA error poisons the process, so leave. The container stays down (its secret is shredded
                # from the host after start-up) until `make gpu-down && make gpu-up`; the API then shows no worker.
                log.error("fatal CUDA error, exiting")
                self._stop.set()
                raise SystemExit(1)
        finally:
            finished.set()

    # --- main loop ----------------------------------------------------------------------------

    def run(self) -> None:
        os.umask(0o007)                      # job files are group-writable for the API, never world-readable
        self.heartbeat()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        keys = queue_keys(self.engines)
        log.info("worker %s ready on %s, engines: %s, queues: %s", self.name, self.device, ",".join(self.engines), ",".join(keys))
        while not self._stop.is_set():
            try:
                item = self.r.brpop(keys, timeout=5)
            except redis.RedisError as exc:
                log.warning("redis error while waiting: %s", exc)
                time.sleep(2)
                continue
            if item:
                self.handle(item[1])

    def stop(self, *_):
        self._stop.set()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    device = os.environ.get("WORKER_DEVICE", "cuda:0")
    default_engines = "recavsr,classical,none" if device.startswith("cuda") else "classical,none"
    engines = [e.strip() for e in os.environ.get("WORKER_ENGINES", default_engines).split(",") if e.strip()]
    password = read_secret(os.environ.get("REDIS_PASSWORD_FILE", "/run/secrets/restore_worker_redis_password"))
    client = redis.Redis(host=os.environ.get("REDIS_HOST", "redis-secure"), port=int(os.environ.get("REDIS_PORT", "6379")),
                         username=os.environ.get("REDIS_USERNAME") or None, password=password, decode_responses=True, socket_timeout=30, socket_connect_timeout=10,
                         health_check_interval=30)
    engine = None
    if "recavsr" in engines:
        from restore_worker.recavsr_tiled import RecavsrTiledEngine
        engine = RecavsrTiledEngine(os.environ.get("MODEL_DIR", "/m"), device, precision=os.environ.get("RESTORE_PRECISION", "bf16"))
    worker = Worker(client, os.environ.get("WORKER_NAME", socket.gethostname()), device, engines,
                    Path(os.environ.get("RESTORE_WORK_DIR", "/restore-work")), engine)
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    worker.run()


if __name__ == "__main__":
    main()
