#!/usr/bin/env python3
"""Restore a whole film through the encoding server, segment by segment, and rebuild it with its audio.

    probe -> plan cuts on keyframes -> for each segment: cut, (encrypt), send, wait, download, verify, delete
          -> concatenate the restored segments and mux the original audio, subtitles and chapters back in

Why keyframes: a keyframe cut with a stream copy is frame-exact and needs no re-encode, and encoders put keyframes at
scene changes, so the cuts land between shots almost always. A segment holds a few seconds of picture, which bounds the
RAM a worker needs. Every segment is an independent job; a manifest in the work folder makes the run resumable: kill
this script or the server at any point and run the same command again, finished segments are not redone.

The film never lands on the server's disk: segments travel to its RAM, come back, and are deleted from it. Segments are
cut one at a time and removed after upload, so this machine only ever holds a few seconds of the film besides the results.

usage: restore_film.py MOVIE (--preset NAME | --recipe FILE.json) [--api-url https://host:8443] [--out restored.mkv]
                       [--workdir DIR] [--parallel 3] [--no-ssl-verify] [--limit-segments N]
Environment: MEDIA_ENCRYPTION_PASSWORD (manual encryption mode), RESTORE_API_KEY (optional, scopes jobs to you).
The recipe file is a RecipeRequest: {"preset": "...", "basic": {...}, "advanced": {...}}.
"""
from __future__ import annotations

import argparse
import bisect
import functools
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from fractions import Fraction
from pathlib import Path

import requests

POLL_SECONDS = 2.0
# ffmpeg and ffprobe only look at the first 5 s of a file to learn its streams. A video that starts later than that (a long
# lead-in of audio only) gets bogus timestamps in a copy cut: frames repeat and others are lost, silently. A larger window fixes it.
PROBE = ["-analyzeduration", "60000000", "-probesize", "100000000"]
TERMINAL = {"done", "failed", "cancelled"}


# --- planning ----------------------------------------------------------------------------------------------------

@dataclass
class Segment:
    index: int
    start: float          # seconds, a keyframe
    end: float            # seconds, the next keyframe (or the end of the film)
    frames: int           # planned, from the frame rate
    first_frame: int      # absolute index of the first frame, seeds the grain
    last_pts: float | None = None   # presentation time of the last frame, when the packet list is known (checks the cut's end)
    forced: bool = False            # starts inside a GOP, not on a keyframe: only a transcode cut can make it


def probe_source(path: Path) -> dict:
    out = subprocess.run(["ffprobe", "-v", "error", *PROBE, "-print_format", "json", "-count_frames", "-show_streams", "-show_format", str(path)],
                         capture_output=True, text=True, check=True).stdout
    info = json.loads(out)
    video = next(s for s in info["streams"] if s["codec_type"] == "video")
    num, den = (int(v) for v in video["r_frame_rate"].split("/"))
    return {
        "fps": Fraction(num, den),
        "frames": int(video["nb_read_frames"]),
        "duration": float(info["format"]["duration"]),
        "width": int(video["width"]),
        "height": int(video["height"]),
        "audio": sum(1 for s in info["streams"] if s["codec_type"] == "audio"),
        "subtitles": sum(1 for s in info["streams"] if s["codec_type"] == "subtitle"),
    }


def packet_times(path: Path) -> tuple[list[float], list[float]]:
    """(all video presentation times, the keyframes among them), from the packet headers: no decoding, fast on a 4K film."""
    out = subprocess.run(["ffprobe", "-v", "error", *PROBE, "-select_streams", "v:0", "-show_entries", "packet=pts_time,flags", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout
    every, keys = [], []
    for line in out.splitlines():
        pts, _, flags = line.partition(",")
        if not pts or pts == "N/A":
            continue
        every.append(float(pts))
        if "K" in flags:
            keys.append(float(pts))
    return sorted(every), sorted(set(keys))


def keyframe_times(path: Path) -> list[float]:
    return packet_times(path)[1]


def plan_segments(keys: list[float], duration: float, fps: Fraction, *, target_seconds: float, max_frames: int,
                  pts: list[float] | None = None, force_cuts: bool = False) -> list[Segment]:
    """Cut at keyframes: each segment runs to the first keyframe at or past the target length, never past max_frames.

    The end of the film counts as a final keyframe, so the tail is handled like every other cut. A tail of a couple
    of frames is folded into the segment before it when that stays within the limit.

    With `force_cuts`, a stretch longer than max_frames without a keyframe is cut inside the GOP instead of refused. Those
    segments start on an ordinary frame, so they can only be made by decoding (`transcode_segment`), and are marked `forced`.
    """
    f = float(fps)
    marks = [0.0] + [k for k in sorted(set(keys)) if 0.0 < k < duration - 1e-6] + [duration]
    bounds: list[tuple[float, float]] = []
    start = marks[0]
    for i in range(1, len(marks)):
        key = marks[i]
        while (key - start) * f > max_frames + 0.5:         # taking this keyframe would make the segment too long
            previous = marks[i - 1]
            if previous > start:
                bounds.append((start, previous))
                start = previous
                continue
            if not force_cuts:
                raise ValueError(f"the source has {key - start:.1f} s without a keyframe at {start:.1f} s, longer than the "
                                 f"{max_frames}-frame segment limit: re-encode it with a shorter keyframe interval first")
            # Cut inside the GOP into equal pieces (not one full piece and a sliver): each is at most max_frames long.
            first = bisect.bisect_left(pts, start - 1e-4) if pts is not None else None
            total = (bisect.bisect_left(pts, key - 1e-4) - first) if pts is not None else round((key - start) * f)
            size = -(-total // -(-total // max_frames))
            if size >= total:
                break                                                                   # nothing left that needs cutting
            cut = pts[min(first + size, len(pts) - 1)] if pts is not None else start + size / f
            bounds.append((start, cut))
            start = cut
        if key - start >= target_seconds and key < duration:
            bounds.append((start, key))
            start = key
    if duration - start > 1e-6:
        if bounds and (duration - start) * f < 3 and (duration - bounds[-1][0]) * f <= max_frames:
            bounds[-1] = (bounds[-1][0], duration)         # fold a sliver into its neighbour
        else:
            bounds.append((start, duration))
    segments, first = [], 0
    for index, (a, b) in enumerate(bounds):
        if pts is not None:                                  # exact: the frames whose presentation time falls in [a, b)
            frames = bisect.bisect_left(pts, b - 1e-4) - bisect.bisect_left(pts, a - 1e-4)
        else:
            frames = round((b - a) * f)
        last_pts = pts[bisect.bisect_left(pts, a - 1e-4) + frames - 1] if pts and frames else None
        on_key = a < 1e-6 or any(abs(k - a) < 1e-4 for k in keys[max(0, bisect.bisect_left(keys, a - 1e-3) - 1):bisect.bisect_left(keys, a + 1e-3) + 1])
        segments.append(Segment(index, a, b, frames, first, last_pts, forced=not on_key))
        first += frames
    return segments


def plan_film(movie: Path, info: dict, max_seconds: float, force_cuts: bool) -> list[Segment]:
    """The segments of a film, on the film's own timeline. Raises ValueError when they cannot cover it exactly.

    A source whose first frame is not at time zero (a TS stream, or a Matroska with an offset) is planned from its first
    frame to the end of its last one, and the offset is put back into the cut times afterwards. `info["span"]` then holds
    that length, which is what the assembled film must last (format.duration is not reliable for these sources)."""
    every, keys = packet_times(movie)
    offset = every[0] if every else 0.0
    info["video_start"] = offset if every else None
    # From the frames themselves, never from format.duration: that one includes an audio tail longer than the picture, which
    # makes the plan one cut too many on a stretch that is exactly max_frames long.
    duration = every[-1] + 1 / float(info["fps"]) - offset if every else info["duration"]
    info["span"] = duration if abs(offset) >= 1e-3 else None
    segments = plan_segments([k - offset for k in keys], duration, info["fps"], target_seconds=max_seconds * 0.6,
                             max_frames=int(max_seconds * float(info["fps"])), pts=[t - offset for t in every], force_cuts=force_cuts)
    for seg in segments:
        seg.start, seg.end = seg.start + offset, seg.end + offset
        seg.last_pts = None if seg.last_pts is None else seg.last_pts + offset
    if sum(s.frames for s in segments) != info["frames"]:
        raise ValueError(f"the plan covers {sum(s.frames for s in segments)} of the source's {info['frames']} frames "
                         f"(first frame at {offset:.3f} s)")
    return segments


# --- manifest ----------------------------------------------------------------------------------------------------

class Manifest:
    """Per-segment state, written to disk after every change so a run can be resumed."""

    def __init__(self, path: Path, header: dict):
        self.path, self.lock = path, threading.Lock()
        self.data = json.loads(path.read_text()) if path.exists() else {"header": header, "segments": {}}
        if self.data["header"].get("source_size") != header.get("source_size") or self.data["header"].get("recipe") != header.get("recipe"):
            raise SystemExit("the work folder belongs to another film or another recipe: use a new --workdir, or delete this one")
        if not path.exists():
            self._save()                              # record which film and recipe this folder is for, straight away

    def get(self, index: int) -> dict:
        return self.data["segments"].get(str(index), {"state": "pending"})

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1))
        tmp.replace(self.path)

    def update(self, index: int, **fields) -> None:
        with self.lock:
            self.data["segments"].setdefault(str(index), {"state": "pending"}).update(fields)
            self._save()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- one segment against the server --------------------------------------------------------------------------------

class Client:
    def __init__(self, base: str, verify, api_key: str | None):
        self.base, self.session = base.rstrip("/"), requests.Session()
        self.session.verify = verify
        if api_key:
            self.session.headers["X-API-Key"] = api_key

    def call(self, method: str, path: str, **kw):
        kw.setdefault("timeout", 120)
        return self.session.request(method, f"{self.base}/v1/restore{path}", **kw)


def first_frame_md5(path: Path, at: float | None = None) -> str:
    """MD5 of the first decoded video frame of a file, from `at` seconds when given (an accurate, decoding seek)."""
    cmd = ["ffmpeg", "-v", "error", "-nostdin"] + (["-ss", f"{at:.6f}"] if at else []) + \
          [*PROBE, "-i", str(path), "-map", "0:v:0", "-an", "-sn", "-frames:v", "1", "-f", "md5", "-"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def last_frame_md5(path: Path, count: int) -> str:
    """MD5 of the frame number `count - 1` in decoding order of presentation (the last one), found by decoding the file."""
    cmd = ["ffmpeg", "-v", "error", "-nostdin", *PROBE, "-i", str(path), "-map", "0:v:0", "-an", "-sn",
           "-vf", f"select=eq(n\\,{count - 1})", "-fps_mode", "passthrough", "-frames:v", "1", "-f", "md5", "-"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def cut_segment(src: Path, seg: Segment, out: Path) -> int:
    """Cut one segment with a stream copy and PROVE the cut is right; returns the real frame count.

    Seeking exactly onto a keyframe time is unreliable with B-frames in Matroska (the cue points and the presentation
    times disagree, and ffmpeg may land one GOP early), so the seek goes a little past the keyframe: the copy then
    starts at the keyframe at or before that point, which is the one we want. The result is checked two ways, because
    a count alone cannot see a cut that is the right length but two seconds early: the frame count must equal the plan
    (which comes from the packet list, so it is exact) and the first decoded frame must be the very frame the source has at `start`.
    The LAST frame is checked too: with an open GOP the copy counts packets in decoding order, so the next GOP's keyframe can
    displace the last leading B-frame, which keeps the count right and the first frame right and still drops one frame.
    """
    span = seg.end - seg.start
    seek = seg.start + min(0.25, 0.25 * span)
    # -frames:v, not -t: in copy mode -t counts from a timestamp that B-frame delay shifts and overshoots by several frames.
    subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-y", "-ss", f"{seek:.6f}", *PROBE, "-i", str(src), "-frames:v", str(seg.frames),
                    "-map", "0:v:0", "-c", "copy", "-avoid_negative_ts", "make_zero", "-f", "matroska", str(out)], check=True)
    frames = count_frames(out)
    if frames != seg.frames:
        raise RuntimeError(f"segment {seg.index}: the cut has {frames} frames, the plan said {seg.frames}: the cut is not frame-exact")
    if first_frame_md5(out) != first_frame_md5(src, seg.start):
        raise RuntimeError(f"segment {seg.index}: the cut starts at the wrong frame (not the source's frame at {seg.start:.3f} s)")
    if seg.last_pts is not None and last_frame_md5(out, frames) != first_frame_md5(src, max(seg.last_pts - 0.001, 0.0)):
        raise RuntimeError(f"segment {seg.index}: the cut ends at the wrong frame, which happens with open-GOP sources: "
                           f"re-encode the film to closed GOPs first (for example x265 with open-gop=0)")
    return frames


TRANSCODE_MIN_PSNR = 42.0     # dB between a transcoded piece and the source frame it replaces, on its first and last frame


def _psnr(a: tuple[list[str], str | None], b: tuple[list[str], str | None]) -> float:
    """PSNR (dB) of one frame from each of two inputs, each given as (input args, optional -vf to pick the frame)."""
    (args_a, vf_a), (args_b, vf_b) = a, b
    chain = []
    for label, vf in (("0", vf_a), ("1", vf_b)):
        # One frame each: the psnr filter averages over every pair it sees, and the shorter stream's last frame is repeated.
        # Timestamps are reset to zero so that the two frames are paired.
        chain.append(f"[{label}:v]{vf + ',' if vf else ''}trim=end_frame=1,setpts=PTS-STARTPTS,format=gbrp10le[v{label}]")
    out = subprocess.run(["ffmpeg", "-hide_banner", "-nostdin", *args_a, *args_b, "-filter_complex",
                          ";".join(chain) + ";[v0][v1]psnr", "-frames:v", "1", "-f", "null", "-"],
                         capture_output=True, text=True)
    for token in out.stderr.split():
        if token.startswith("average:"):
            value = token.split(":")[1]
            return float("inf") if value == "inf" else float(value)
    raise RuntimeError(f"could not measure the transcoded piece: {out.stderr.strip()[-200:]}")


@functools.lru_cache(maxsize=None)
def stream_start(src: Path) -> float:
    """Start time of the first video stream: input `-ss` is relative to it, while timestamps with -copyts are absolute."""
    out = subprocess.run(["ffprobe", "-v", "error", *PROBE, "-select_streams", "v:0", "-show_entries", "stream=start_time", "-of", "csv=p=0", str(src)],
                         capture_output=True, text=True).stdout.strip()
    try:
        return float(out)
    except ValueError:
        return 0.0


def frame_at(src: Path, t: float) -> tuple[list[str], str]:
    """Input args and filter that give the source frame at presentation time `t`, even in an open-GOP source.

    A plain `-ss t` seek can land on a keyframe whose leading pictures cannot be decoded and silently start one frame
    late. Seeking a few seconds earlier and selecting by timestamp decodes everything in between, so it cannot.
    """
    return ["-ss", f"{max(t - 3.0 - stream_start(src), 0.0):.6f}", "-copyts", *PROBE, "-i", str(src)], f"select=gte(t\\,{t - 0.001:.6f})"


def transcode_segment(src: Path, seg: Segment, out: Path) -> int:
    """Cut one segment by DECODING and writing a near-lossless closed-GOP piece, for sources the copy cut cannot do.

    Open-GOP sources (the x265 default) cannot be cut by stream copy without dropping a frame at the boundary. Decoding
    is exact, so this path is: seek accurately, take exactly seg.frames frames, encode at a quality far above anything
    the restoration can see (it is an input to the model, not a delivery file). One extra generation of compression,
    then, but at CRF 8 in 10 bits; the piece's first and last frames are compared with the source's to prove it.
    """
    encoders = subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout
    if "libsvtav1" in encoders:
        codec = ["-c:v", "libsvtav1", "-preset", "6", "-crf", "8", "-svtav1-params", "irefresh-type=2:keyint=120"]
    elif "libx265" in encoders:
        codec = ["-c:v", "libx265", "-preset", "medium", "-crf", "8", "-x265-params", "open-gop=0:keyint=120:log-level=error"]
    else:
        raise RuntimeError("cutting this source needs ffmpeg with libsvtav1 or libx265 to write the pieces")
    args, picker = frame_at(src, seg.start)
    subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-y", *args, "-map", "0:v:0", "-an", "-sn",
                    "-vf", f"{picker},setpts=PTS-STARTPTS", "-fps_mode", "passthrough", "-frames:v", str(seg.frames),
                    "-pix_fmt", "yuv420p10le", *codec, "-f", "matroska", str(out)], check=True)
    frames = count_frames(out)
    if frames != seg.frames:
        raise RuntimeError(f"segment {seg.index}: the transcoded piece has {frames} frames, the plan said {seg.frames}")
    first = _psnr((["-i", str(out)], None), frame_at(src, seg.start))
    if first < TRANSCODE_MIN_PSNR:
        raise RuntimeError(f"segment {seg.index}: the transcoded piece starts at the wrong frame (first-frame PSNR {first:.1f} dB)")
    if seg.last_pts is not None:
        last = _psnr((["-i", str(out)], f"select=eq(n\\,{frames - 1})"), frame_at(src, seg.last_pts))
        if last < TRANSCODE_MIN_PSNR:
            raise RuntimeError(f"segment {seg.index}: the transcoded piece ends at the wrong frame (last-frame PSNR {last:.1f} dB)")
    return frames


def cut(src: Path, seg: Segment, out: Path, mode: str = "copy") -> int:
    return transcode_segment(src, seg, out) if mode == "transcode" else cut_segment(src, seg, out)


def preflight(src: Path, segments: list[Segment], work: Path, requested: str = "auto") -> str:
    """Cut and verify the first, a middle and the last segment before any GPU time is spent.

    Sources the copy cut cannot reproduce frame for frame (open GOPs, a start time that is not zero, keyframes only
    forward) fail on EVERY segment but the first, and only after the others have been paid for, so the failure is
    found here, once, with the reason.
    """
    sample = sorted({0, len(segments) // 2, len(segments) - 1})
    probe_dir = work / "preflight"
    probe_dir.mkdir(parents=True, exist_ok=True)

    def check(mode: str) -> None:
        for i in sample:
            cut(src, segments[i], probe_dir / f"check_{i:05d}.mkv", mode)

    try:
        if requested == "transcode":
            check("transcode")
            return "transcode"
        try:
            check("copy")
            return "copy"
        except (RuntimeError, subprocess.CalledProcessError):
            if requested == "copy":
                raise
        check("transcode")                      # the copy cut is not exact on this source: decode instead, and say so
        return "transcode"
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


def count_frames(path: Path) -> int:
    out = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries", "stream=nb_read_frames", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout.strip()
    return int(out)


def process_segment(client: Client, src: Path, seg: Segment, recipe_json: str, work: Path, manifest: Manifest, mode: str,
                    password: str | None, stop: threading.Event, log, stale_seconds: float = 900,
                    cut_mode: str = "copy") -> bool:
    """Returns True when this call did the work, False when the segment was already done (resume)."""
    result = work / "results" / f"seg_{seg.index:05d}.mkv"
    state = manifest.get(seg.index)
    if state.get("state") == "done" and result.exists() and sha256_file(result) == state.get("sha256"):
        seg.frames = state.get("frames", seg.frames)
        return False
    if stop.is_set():
        raise KeyboardInterrupt                                     # interrupted: do not cut or upload anything more
    job_id = state.get("job_id") if state.get("state") == "submitted" else None
    if job_id:                                                      # resume: is the old job still known to the server?
        r = client.call("GET", f"/jobs/{job_id}")
        if r.status_code == 404:
            job_id = None
    if not job_id:
        piece = work / "pieces" / f"seg_{seg.index:05d}.mkv"
        piece.parent.mkdir(parents=True, exist_ok=True)
        seg.frames = cut(src, seg, piece, cut_mode)                 # the real count, verified, not the plan's estimate
        upload = piece
        if mode == "manual":
            from encrypt_media import MediaEncryptor
            upload = piece.with_suffix(".enc")
            MediaEncryptor().encrypt_file(str(piece), str(upload), password)
        try:
            with upload.open("rb") as f:
                data = {"recipe": recipe_json, "first_frame": str(seg.first_frame), "segment_index": str(seg.index)}
                if mode == "manual":
                    data["decryption_password"] = password
                r = client.call("POST", "/jobs", files={"file": (upload.name, f, "application/octet-stream")}, data=data, timeout=1800)
        finally:
            for p in {piece, upload}:
                p.unlink(missing_ok=True)                           # never keep more of the film here than the segments in flight
        if r.status_code >= 400:
            raise RuntimeError(f"segment {seg.index}: server refused it ({r.status_code}): {r.text[:300]}")
        body = r.json()
        job_id = body["job_id"]
        if body.get("warning"):
            log(f"  ! {body['warning']}")
        if body["input"]["frames"] != seg.frames:
            # Never adopt the server's number: a difference means the upload was damaged or cut wrongly.
            client.call("DELETE", f"/jobs/{job_id}")
            raise RuntimeError(f"segment {seg.index}: the server counts {body['input']['frames']} frames in what was sent, {seg.frames} were cut")
        manifest.update(seg.index, state="submitted", job_id=job_id, frames=seg.frames)

    last_seen, last_change = None, time.time()
    while not stop.is_set():
        status = client.call("GET", f"/jobs/{job_id}").json()
        if status["status"] in TERMINAL:
            break
        if status.get("updated_at") != last_seen:                   # the worker touches updated_at every 15 s while alive
            last_seen, last_change = status.get("updated_at"), time.time()
        elif status["status"] == "running" and time.time() - last_change > stale_seconds:   # a queued job has no worker to hear from yet
            client.call("POST", f"/jobs/{job_id}/cancel")
            client.call("DELETE", f"/jobs/{job_id}")
            manifest.update(seg.index, state="pending", job_id=None)
            raise RuntimeError(f"segment {seg.index}: no sign of life from the worker for {stale_seconds:.0f} s, job dropped; run again to retry")
        time.sleep(POLL_SECONDS)
    if stop.is_set():
        client.call("POST", f"/jobs/{job_id}/cancel")
        client.call("DELETE", f"/jobs/{job_id}")
        manifest.update(seg.index, state="pending", job_id=None)    # cancelled on the server: resubmit on the next run
        raise KeyboardInterrupt
    if status["status"] != "done":
        manifest.update(seg.index, state="failed", error=status.get("error", ""))
        raise RuntimeError(f"segment {seg.index} {status['status']}: {status.get('error', '')}")

    result.parent.mkdir(parents=True, exist_ok=True)
    download = result.with_suffix(".part")
    with client.call("GET", f"/jobs/{job_id}/download", stream=True, timeout=1800) as r:
        r.raise_for_status()
        with download.open("wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
    if mode == "manual":
        from decrypt_media import MediaDecryptor
        plain = result.with_suffix(".plain")
        MediaDecryptor().decrypt_file(str(download), str(plain), password)
        download.unlink()
        download = plain
    download.replace(result)
    got = count_frames(result)
    if got != seg.frames:
        manifest.update(seg.index, state="failed", error=f"frame count {got}, expected {seg.frames}")
        raise RuntimeError(f"segment {seg.index}: result has {got} frames, expected {seg.frames}")
    client.call("DELETE", f"/jobs/{job_id}")
    manifest.update(seg.index, state="done", sha256=sha256_file(result), frames=got, job_id=None)
    return True


# --- final assembly ---------------------------------------------------------------------------------------------------

def format_duration(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", *PROBE, "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True).stdout.strip()
    return float(out) if out and out != "N/A" else 0.0


def video_start_delay(src: Path, video_start: float | None = None) -> float:
    """How much later the first video stream starts than the earliest stream of the file, in seconds (0 when it is the first).

    `video_start` is the presentation time of the first video frame when the caller knows it from the packet list. It is
    preferred over ffprobe's stream start_time, which is only 0 for a video that starts after the end of ffprobe's default
    probe window (a lead-in of several seconds)."""
    out = subprocess.run(["ffprobe", "-v", "error", "-analyzeduration", "60000000", "-probesize", "100000000", "-show_entries",
                          "stream=codec_type,start_time", "-of", "csv=p=0", str(src)], capture_output=True, text=True).stdout
    starts: dict[str, list[float]] = {}
    for line in out.splitlines():
        kind, _, value = line.partition(",")
        try:
            starts.setdefault(kind, []).append(float(value))
        except ValueError:
            continue
    if video_start is not None:
        starts["video"] = [video_start]
    if "video" not in starts:
        return 0.0
    return max(0.0, min(starts["video"]) - min(t for v in starts.values() for t in v))


def assemble(src: Path, work: Path, segments: list[Segment], out: Path, info: dict) -> None:
    src, work, out = src.resolve(), work.resolve(), out.resolve()      # the concat demuxer resolves relative names against its own list file
    expected = sum(s.frames for s in segments)
    if expected != info["frames"]:
        raise SystemExit(f"assembly check failed: the segments hold {expected} frames, the source {info['frames']}: nothing was assembled")
    listing = work / "concat.txt"
    def quoted(path: Path) -> str:
        return path.as_posix().replace("'", "'\\''")                  # the concat list quotes with ', so a ' in a film title must be escaped

    listing.write_text("".join(f"file '{quoted(work / 'results' / f'seg_{s.index:05d}.mkv')}'\n" for s in segments))
    # ffmpeg shifts the source input so that its EARLIEST stream starts at zero, while the restored video starts at zero by
    # itself. When the source's video starts later than its audio (or subtitles), the restored video has to be delayed by the
    # same amount or it would play early against them.
    delay = video_start_delay(src, info.get("video_start"))
    base = ["ffmpeg", "-v", "error", "-nostdin", "-y", "-f", "concat", "-safe", "0", *(["-itsoffset", f"{delay:.6f}"] if delay > 0.001 else []),
            "-i", str(listing), *PROBE, "-i", str(src), "-map", "0:v:0", "-map", "1:a?", "-map", "1:t?", "-map_chapters", "1"]
    # Subtitles are copied when the container takes them as they are; mp4 text subtitles (mov_text) need converting to srt.
    attempts = [base + ["-map", "1:s?", "-c", "copy", str(out)],
                base + ["-map", "1:s?", "-c", "copy", "-c:s", "srt", str(out)],
                base + ["-c", "copy", str(out)]]
    for number, cmd in enumerate(attempts):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            if number == 2 and info["subtitles"]:
                print("warning: the subtitles could not be carried over (unsupported format); video and audio are complete")
            break
    else:
        raise SystemExit(f"could not write the final file: {result.stderr.strip()[-400:]}")
    frames = count_frames(out)
    one_frame = 1 / float(info["fps"])
    problems = []
    if frames != expected:
        problems.append(f"{frames} frames in the result, {expected} restored")
    # Matroska has no per-stream duration, so compare the container durations: audio and video must end together.
    wanted = info.get("span") or format_duration(src)            # the span of the frames when the source does not start at zero
    lasts, tolerance = format_duration(out), max(0.5, 3 * one_frame)
    # The video was delayed by `delay` to keep its place against the audio, so the file may last that much longer than
    # the container duration the source reports (some muxers leave the lead-in out of it).
    if min(abs(lasts - wanted), abs(lasts - wanted - delay)) > tolerance:
        problems.append(f"the result lasts {lasts:.3f} s, the source {wanted:.3f} s")
    if problems:
        out.unlink(missing_ok=True)                  # a file that failed its own check must not sit next to the film looking finished
        raise SystemExit("assembly check failed, the file was removed (the restored segments are kept in the work folder): " + "; ".join(problems))
    print(f"assembled {out}: {frames} frames, {format_duration(out):.1f} s, audio/subtitles/chapters copied from the source")


# --- main ---------------------------------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("movie", type=Path)
    ap.add_argument("--preset")
    ap.add_argument("--recipe", type=Path)
    ap.add_argument("--api-url", default=os.environ.get("API_BASE_URL", "https://localhost:8443"))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--workdir", type=Path)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--no-ssl-verify", action="store_true")
    ap.add_argument("--ca-cert", help="CA bundle or the server's own certificate to trust")
    ap.add_argument("--limit-segments", type=int, help="process only the first N segments (for a quick trial)")
    ap.add_argument("--cut", choices=["auto", "copy", "transcode"], default="auto",
                    help="how segments are cut: copy (no re-encode, needs a closed-GOP source), transcode (decode and re-encode "
                         "near-losslessly, works on any source) or auto (copy when it is exact, else transcode)")
    ap.add_argument("--stale-seconds", type=float, default=900, help="give up on a job whose worker shows no sign of life for this long")
    args = ap.parse_args()

    if bool(args.preset) == bool(args.recipe):
        ap.error("give exactly one of --preset and --recipe")
    request = json.loads(args.recipe.read_text()) if args.recipe else {"preset": args.preset}
    if not args.movie.is_file():
        print(f"no such file: {args.movie}", file=sys.stderr)
        return 2
    args.movie = args.movie.resolve()                       # every path is absolute from here: ffmpeg's concat list needs it
    work = (args.workdir or args.movie.parent / (args.movie.stem + ".restore-work")).resolve()
    out = (args.out or args.movie.with_name(args.movie.stem + ".restored.mkv")).resolve()
    verify = False if args.no_ssl_verify else (args.ca_cert or True)
    client = Client(args.api_url, verify, os.environ.get("RESTORE_API_KEY"))

    r = client.call("POST", "/recipe/resolve", json=request)
    if r.status_code >= 400:
        print(f"the recipe is not valid: {r.text[:600]}", file=sys.stderr)
        return 2
    effective = r.json()["effective_recipe"]
    mode = effective["basic"]["encryption"]
    password = os.environ.get("MEDIA_ENCRYPTION_PASSWORD") if mode == "manual" else None
    if mode == "manual" and not password:
        import getpass
        password = getpass.getpass("Encryption password: ")

    info = probe_source(args.movie)
    max_seconds = effective["advanced"]["restore"]["segment_max_seconds"]
    try:
        segments = plan_film(args.movie, info, max_seconds, args.cut != "copy")
    except ValueError as exc:
        print(f"cannot plan the cuts: {exc}", file=sys.stderr)
        return 2
    if args.limit_segments:
        segments = segments[:args.limit_segments]
    total = sum(s.frames for s in segments)
    print(f"{args.movie.name}: {info['width']}x{info['height']}, {info['frames']} frames, {len(segments)} segments of up to {max_seconds:g} s, "
          f"recipe preset={effective['preset']} engine={effective['basic']['engine']} encryption={mode}")

    work.mkdir(parents=True, exist_ok=True)
    try:
        forced = sum(1 for s in segments if s.forced)
        cut_mode = preflight(args.movie, segments, work, "transcode" if forced else args.cut)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"this source cannot be cut frame-exactly, so nothing was started: {exc}", file=sys.stderr)
        return 2
    if cut_mode == "transcode":
        why = (f"its keyframes are further apart than {max_seconds:g} s, so {forced} segments start inside a GOP" if forced
               else "it cannot be cut by stream copy without dropping a frame at the boundaries (open GOP or a start time that is not zero)")
        print(f"note: this source needs decoded cuts ({why}): each segment is decoded and re-encoded near-losslessly "
              f"(CRF 8, 10-bit, closed GOP) before it is sent")
    manifest = Manifest(work / "manifest.json", {"source_size": args.movie.stat().st_size, "recipe": effective})
    recipe_json = json.dumps(request)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    started, done_frames, lock = time.time(), 0, threading.Lock()
    already = sum(manifest.get(s.index).get("frames", 0) for s in segments if manifest.get(s.index).get("state") == "done")
    failures = []

    def log(msg):
        print(msg, flush=True)

    def run(seg: Segment):
        nonlocal done_frames
        worked = process_segment(client, args.movie, seg, recipe_json, work, manifest, mode, password, stop, log, args.stale_seconds, cut_mode)
        if not worked:
            return                                          # resumed: finished in an earlier run, no timing to report
        with lock:
            done_frames += seg.frames
            rate = done_frames / max(time.time() - started, 1e-6)       # only the work done in THIS run
            left = max(total - already - done_frames, 0) / rate if rate else 0
            log(f"  segment {seg.index + 1}/{len(segments)} done: {already + done_frames}/{total} frames, {rate:.2f} frames/s, about {left / 3600:.1f} h left")

    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        futures = {pool.submit(run, s): s for s in segments}
        for f in as_completed(futures):
            try:
                f.result()
            except KeyboardInterrupt:
                pass
            except Exception as exc:
                failures.append(f"segment {futures[f].index}: {exc}")
                log(f"  ! {failures[-1]}")
    if stop.is_set():
        print("interrupted: run the same command again to resume", file=sys.stderr)
        return 130
    if failures:
        print(f"{len(failures)} segments failed; run the same command again to retry them", file=sys.stderr)
        return 1
    if args.limit_segments:
        print(f"trial of {len(segments)} segments done; results are in {work / 'results'}")
        return 0
    assemble(args.movie, work, segments, out, info)
    shutil.rmtree(work / "pieces", ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
