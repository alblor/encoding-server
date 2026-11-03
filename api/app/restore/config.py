"""Plain configuration object for the restoration API.

It is a frozen dataclass on purpose: the service gets it injected, so tests can point it at a
temporary directory without touching environment variables or the secrets-backed Settings.

Author: Lorenzo Albanese (alblor)
"""

from dataclasses import dataclass
from pathlib import Path

MIB = 1024 * 1024


@dataclass(frozen=True)
class RestoreConfig:
    """Limits and paths of the restoration API. Defaults match rules/restore-job-protocol.md."""

    work_dir: Path = Path("/restore-work")
    worker_gid: int = 10001
    max_segment_bytes: int = 2048 * MIB
    max_frames: int = 400
    max_pixels: int = 3840 * 2304
    max_jobs: int = 64
    gpu_worker_memory_bytes: int = 22 * 1024 * MIB    # mem_limit of restore-worker-gpu* in the compose file
    cpu_worker_memory_bytes: int = 12 * 1024 * MIB    # mem_limit of restore-worker-cpu
    job_ttl_seconds: int = 48 * 3600
    terminal_ttl_seconds: int = 24 * 3600
    stale_seconds: int = 900
    queue_max_seconds: int = 86400
    cleanup_interval_seconds: int = 60
    wipe_passes: int = 3
    ffprobe_path: str = "ffprobe"
    ffprobe_timeout_seconds: int = 60
    upload_chunk_bytes: int = 1 * MIB
    form_overhead_bytes: int = 1 * MIB
    free_space_margin_bytes: int = 256 * MIB
    upload_idle_seconds: float = 30.0                  # no body bytes for this long: the upload is dropped and its slot freed
    upload_min_bytes_per_second: int = 64 * 1024       # slowest accepted average rate (0.5 Mbit/s), counted after the grace period
    upload_grace_seconds: float = 30.0

    @classmethod
    def from_settings(cls, settings) -> "RestoreConfig":
        """Build the configuration from the application Settings (environment backed)."""
        return cls(
            work_dir=Path(settings.RESTORE_WORK_DIR),
            worker_gid=settings.RESTORE_WORKER_GID,
            max_segment_bytes=settings.RESTORE_MAX_SEGMENT_MB * MIB,
            max_frames=settings.RESTORE_MAX_SEGMENT_FRAMES,
            max_pixels=settings.RESTORE_MAX_PIXELS,
            max_jobs=settings.RESTORE_MAX_JOBS,
            gpu_worker_memory_bytes=settings.RESTORE_GPU_WORKER_MEMORY_MB * MIB,
            cpu_worker_memory_bytes=settings.RESTORE_CPU_WORKER_MEMORY_MB * MIB,
            stale_seconds=settings.RESTORE_STALE_SECONDS,
            queue_max_seconds=settings.RESTORE_QUEUE_MAX_SECONDS,
            cleanup_interval_seconds=settings.RESTORE_CLEANUP_INTERVAL_SECONDS,
            wipe_passes=settings.RESTORE_WIPE_PASSES,
            ffprobe_path=settings.RESTORE_FFPROBE_PATH,
        )
