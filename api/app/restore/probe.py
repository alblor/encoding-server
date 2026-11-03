"""Content validation of an uploaded segment with ffprobe.

Rules: the file must parse as Matroska or MP4, hold exactly one video stream, and stay inside
the frame and pixel limits. The demuxer is forced with -f, so a playlist or any other text that
names other files (HLS, concat) is never followed. The probed path is always the server's own
<work_dir>/<id>/in.mkv, nothing from the client reaches the command line.

Author: Lorenzo Albanese (alblor)
"""

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import RestoreConfig

logger = logging.getLogger(__name__)

# Demuxer to force, and the format_name token that must come back for the file to count.
_DEMUXERS = (("matroska", "matroska"), ("mov", "mp4"))
_MAX_STREAMS = 64
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024


MIN_SIDE = 64      # the finisher and the encoder fail on frames of 16 px or less, and nothing sensible is that small


class ProbeRejected(Exception):
    """The segment is not acceptable. The message is safe to show the client."""


class ProbeUnavailable(Exception):
    """ffprobe itself could not run: a server problem, not a client one."""


@dataclass(frozen=True)
class ProbeResult:
    container: str
    width: int
    height: int
    frames: int


def _run_ffprobe(path: Path, demuxer: str, config: RestoreConfig):
    args = [
        config.ffprobe_path,
        "-v",
        "error",
        "-protocol_whitelist",
        "file",
        "-f",
        demuxer,
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        "-count_packets",
        "-i",
        str(path),
    ]
    env = {"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"}
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=config.ffprobe_timeout_seconds,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise ProbeRejected("the file took too long to inspect") from None
    except FileNotFoundError:
        logger.error("ffprobe not found at %s", config.ffprobe_path)
        raise ProbeUnavailable() from None
    except OSError as exc:
        logger.error("ffprobe could not start: %s", exc.strerror)
        raise ProbeUnavailable() from None
    return completed


def validate_segment(path: Path, config: RestoreConfig) -> ProbeResult:
    """Inspect path and return its facts, or raise ProbeRejected with a client-safe reason."""
    parsed = None
    container = ""
    for demuxer, token in _DEMUXERS:
        completed = _run_ffprobe(path, demuxer, config)
        if completed.returncode != 0 or len(completed.stdout) > _MAX_OUTPUT_BYTES:
            continue
        try:
            candidate = json.loads(completed.stdout)
        except ValueError:
            continue
        names = str(candidate.get("format", {}).get("format_name", "")).split(",")
        if token in names:
            parsed, container = candidate, token
            break
    if parsed is None:
        raise ProbeRejected("the file is not a readable Matroska or MP4 video")

    streams = parsed.get("streams", [])
    if len(streams) > _MAX_STREAMS:
        raise ProbeRejected("the file has too many streams")
    videos = [s for s in streams if s.get("codec_type") == "video"]
    if len(videos) != 1:
        raise ProbeRejected(f"expected exactly one video stream, found {len(videos)}")
    video = videos[0]

    try:
        width, height = int(video.get("width", 0)), int(video.get("height", 0))
        frames = int(video.get("nb_read_packets", 0))
    except (TypeError, ValueError):
        raise ProbeRejected(
            "the video stream has unreadable dimensions or length"
        ) from None
    if width <= 0 or height <= 0:
        raise ProbeRejected("the video stream has no valid dimensions")
    if min(width, height) < MIN_SIDE:
        raise ProbeRejected(f"frame size {width}x{height} is below the {MIN_SIDE} pixel minimum on a side")
    if width * height > config.max_pixels:
        raise ProbeRejected(
            f"frame size {width}x{height} is above the limit of {config.max_pixels} pixels"
        )
    if frames <= 0:
        raise ProbeRejected("the video stream has no frames")
    if frames > config.max_frames:
        raise ProbeRejected(
            f"{frames} frames is above the limit of {config.max_frames} per segment"
        )
    return ProbeResult(container=container, width=width, height=height, frames=frames)
