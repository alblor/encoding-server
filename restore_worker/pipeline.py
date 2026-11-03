"""One segment through the restoration pipeline, in RAM from decode to encode.

    probe -> decode (classical pre-filter at source size) -> restore (engine) -> finish -> encode -> verify

The segment is a few seconds of picture (the recipe bounds it), cut by the client on a scene change,
so a whole segment fits in memory twice: once at source size and once restored. Pictures move
between stages as NumPy arrays and pipes. Nothing is written to disk but the final stream, and the
caller gives that a RAM-backed path.

Engines share one interface (`Engine.restore`). `classical` and `none` need no GPU and are handled
here, so the whole application works and can be tested before any GPU is involved.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

import numpy as np

from restore_core import budget
from restore_core.ffmpeg_cmds import SourceInfo, decode_cmd, encode_cmd, guess_matrix, probe_cmd
from restore_core.recipe import EffectiveRecipe, effective_scale
from restore_worker.finish import Finisher


FACE_ZOOM_MAX_SHARE = 0.12        # faces taller than this share of the picture height are not redrawn (see finish.FACE_NONE_FROM)


class Cancelled(Exception):
    """Raised between chunks when the job was cancelled."""


class PipelineError(Exception):
    """A stage failed in a way the caller should report, with the stage named."""


class Engine(Protocol):
    def restore(self, frames: np.ndarray, *, scale: float, tile_height: int, tile_width: int,
                min_overlap: int, progress=None) -> tuple[np.ndarray, dict]: ...


@dataclass
class SegmentJob:
    src: Path
    out: Path
    recipe: EffectiveRecipe
    first_frame_index: int = 0     # absolute index of this segment's first frame in the film (grain seeding)


@dataclass
class SegmentResult:
    frames: int
    width: int
    height: int
    seconds: float
    stages: dict = field(default_factory=dict)


Progress = Callable[[str, float], None]


def probe(src: Path) -> SourceInfo:
    out = subprocess.run(probe_cmd(src), capture_output=True, text=True)
    if out.returncode:
        raise PipelineError(f"probe failed: {out.stderr.strip()[:300]}")
    stream = json.loads(out.stdout)["streams"][0]
    num, den = (int(v) for v in stream["r_frame_rate"].split("/"))
    height = int(stream["height"])
    return SourceInfo(
        width=int(stream["width"]), height=height, fps_num=num, fps_den=den or 1,
        frames=int(stream["nb_read_frames"]) if stream.get("nb_read_frames", "N/A").isdigit() else None,
        color_matrix=guess_matrix(stream.get("color_space"), height),
        color_range="pc" if stream.get("color_range") == "pc" else "tv",
        color_transfer=stream.get("color_transfer") or "bt709",
        color_primaries=stream.get("color_primaries") or "bt709",
    )


def _encoder_tail(stderr: str) -> str:
    """The last words of the encoder, without the SVT start-up banner that fills the beginning of stderr."""
    lines = [line for line in stderr.strip().splitlines() if not line.startswith("Svt[info]")]
    return "\n".join(lines)[-400:] or "no message from the encoder"


def _even(value: float) -> int:
    return max(2, int(round(value / 2)) * 2)


def _read_frames(cmd: list[str], width: int, height: int, count: int) -> np.ndarray:
    """Read exactly `count` rgb24 frames from a decoder into one preallocated array (no double copy)."""
    frames = np.empty((count, height, width, 3), dtype=np.uint8)
    flat = memoryview(frames.reshape(-1))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    filled = 0
    while filled < len(flat):
        got = proc.stdout.readinto(flat[filled:])
        if not got:
            break
        filled += got
    proc.stdout.close()
    err = proc.stderr.read().decode(errors="replace")
    proc.wait()
    if proc.returncode or filled != len(flat):
        raise PipelineError(f"decode produced {filled // (width * height * 3)} of {count} frames: {err.strip()[:300]}")
    return frames


def recipe_needs_source(recipe) -> bool:
    """Whether a stage compares the restored frames with the original, so the original has to be kept next to them. Every
    source-consuming field belongs here: a stage missing from this list is skipped without a word (BUG-091, then glow)."""
    adv = recipe.advanced
    return bool((recipe.basic.grain == "auto" and adv.grain.mode in ("source", "auto")) or adv.fidelity.soften in ("match", "adaptive")
                or adv.fidelity.anchor == "source" or adv.fidelity.face_guard != "off" or adv.fidelity.glow > 0)


def run_segment(job: SegmentJob, engine: Engine | None = None, *, device: str = "cpu",
                progress: Progress | None = None, cancelled: Callable[[], bool] = lambda: False) -> SegmentResult:
    recipe, adv = job.recipe, job.recipe.advanced
    hdr10 = recipe.basic.hdr == "synthesize"
    report = progress or (lambda stage, fraction: None)
    started = time.perf_counter()
    stages: dict[str, float] = {}

    # --- probe and decode ---
    t = time.perf_counter()
    info = probe(job.src)
    if not info.frames:
        raise PipelineError("could not count the frames of the input")
    # Without a readable cgroup limit only the encoder's size limit is checked.
    reason = budget.refusal(recipe, info.width, info.height, info.frames, budget.cgroup_limit_bytes() or 1 << 62)
    if reason:
        raise PipelineError(reason)
    cmd = decode_cmd(job.src, info, recipe, frames=info.frames)
    frames = _read_frames(cmd, info.width, info.height, info.frames)
    stages["decode"] = time.perf_counter() - t
    report("decode", 1.0)
    if cancelled():
        raise Cancelled()

    # --- restore ---
    t = time.perf_counter()
    source_frames = frames if recipe_needs_source(recipe) else None        # grain transfer and softness matching compare with the source
    engine_name = recipe.basic.engine
    if engine_name == "recavsr":
        if engine is None:
            raise PipelineError("engine 'recavsr' needs a GPU worker, and none is attached")
        scale = effective_scale(recipe, info.height)
        r = adv.restore
        running = getattr(engine, "precision", None)
        if r.precision and running and r.precision != running:
            raise PipelineError(f"the recipe asks for precision {r.precision} and this worker runs {running}: "
                                f"leave advanced.restore.precision unset or send the job to a worker with that precision")
        frames, engine_stats = engine.restore(
            frames, scale=scale, tile_height=r.tile_height, tile_width=r.tile_width, min_overlap=r.min_overlap,
            progress=lambda tile, tiles, done: report("restore", (tile + done / len(frames)) / tiles),
        )
        stages["engine"] = engine_stats
    elif engine_name == "classical":
        frames = _classical_resize(frames, recipe.basic.target_height)
    elif engine_name == "none":
        pass
    else:
        raise PipelineError(f"engine {engine_name!r} is not available in this worker")
    if not (isinstance(frames, np.ndarray) and frames.dtype == np.uint8 and frames.ndim == 4 and frames.shape[3] == 3 and len(frames) == info.frames):
        got = (frames.dtype, frames.shape) if isinstance(frames, np.ndarray) else type(frames).__name__
        raise PipelineError(f"the engine returned {got}, expected uint8 frames of shape ({info.frames}, H, W, 3)")
    stages["restore"] = time.perf_counter() - t
    report("restore", 1.0)
    if cancelled():
        raise Cancelled()

    faces, patches = None, None
    if adv.fidelity.face_guard != "off" and source_frames is not None and source_frames.shape == frames.shape:
        from restore_worker.face_zoom import ZoomError, zoom_track
        from restore_worker.faces import FaceModelMissing, FaceStageCancelled, find_face_tracks, tracks_to_boxes
        t = time.perf_counter()
        try:
            tracks = find_face_tracks(source_frames, os.environ.get("FACE_MODEL", "/m/yunet.onnx"), cancelled)
        except FaceModelMissing as exc:
            raise PipelineError(str(exc)) from None
        except FaceStageCancelled:
            raise Cancelled() from None
        stages["faces"] = {"seconds": time.perf_counter() - t, "tracks": len(tracks),
                           "frames_with_faces": len({int(f) for tr in tracks for f in tr["frames"]})}
        zoomed = []
        if adv.fidelity.face_guard == "zoom" and engine is not None and engine_name == "recavsr":
            t = time.perf_counter()
            patches = {}
            zoom_tracks = list(tracks)
            head_model = os.environ.get("HEAD_MODEL", "/m/yolox.onnx")
            if os.path.isfile(head_model):
                # Heads the face detector cannot see (from behind, in profile): found as small persons, redrawn the same way.
                from restore_worker.heads import HeadModelMissing, find_head_tracks, without_faces
                try:
                    extra = without_faces(find_head_tracks(source_frames, head_model, cancelled), tracks)
                except HeadModelMissing as exc:
                    raise PipelineError(str(exc)) from None
                except FaceStageCancelled:
                    raise Cancelled() from None
                zoom_tracks += extra
                stages["heads"] = {"tracks": len(extra)}
            for track in zoom_tracks:
                if cancelled():
                    raise Cancelled()
                if not any(box[3] / frames.shape[1] < FACE_ZOOM_MAX_SHARE for box in track["boxes"]):
                    continue                                    # a face that is never small has the model's detail already
                try:
                    redrawn = zoom_track(engine, source_frames, track)
                except ZoomError as exc:
                    raise PipelineError(str(exc)) from None
                zoomed.append(track)
                for f, x, y, patch in redrawn:
                    k = int(np.where(track["frames"] == f)[0][0])
                    patches.setdefault(f, []).append((x, y, patch, np.append(track["boxes"][k], track["weights"][k]).astype(np.float32)))
            stages["face_zoom"] = {"seconds": time.perf_counter() - t, "tracks": len(zoomed), "frames": len(patches)}
        # The original is blended back into every face that was not redrawn (all of them with `on`, the larger ones with `zoom`).
        faces = tracks_to_boxes([tr for tr in tracks if not any(tr is z for z in zoomed)], len(frames))      # head tracks are never blended

    # --- finish and encode ---
    t = time.perf_counter()
    height, width = frames.shape[1:3]
    # Static mapping puts SDR white at the reference white and nothing above it, so that bounds both light levels.
    nits = adv.hdr.reference_white_nits
    enc = subprocess.Popen(encode_cmd(job.out, width, height, info.fps, recipe, hdr10=hdr10, max_cll=nits, max_fall=nits),
                           stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        written = 0
        for chunk in Finisher(recipe, device).process(frames, job.first_frame_index, reference=source_frames, faces=faces, patches=patches):
            enc.stdin.write(chunk.tobytes())
            written += len(chunk)
            report("encode", written / len(frames))
            if cancelled():
                raise Cancelled()
        enc.stdin.close()
    except BrokenPipeError:
        # The encoder exited early: its own message says why, which a bare broken pipe never does.
        enc.wait()
        killed = " (the encoder was killed, most likely out of memory)" if enc.returncode in (-9, 137) else ""
        raise PipelineError(f"encoder stopped early{killed}: {_encoder_tail(enc.stderr.read().decode(errors='replace'))}")
    except BaseException:
        enc.kill()
        enc.wait()
        raise
    err = enc.stderr.read().decode(errors="replace")
    enc.wait()
    if enc.returncode:
        killed = " (the encoder was killed, most likely out of memory)" if enc.returncode in (-9, 137) else ""
        raise PipelineError(f"encode failed{killed}: {_encoder_tail(err)}")
    stages["finish_encode"] = time.perf_counter() - t

    # --- verify: the frame count is where audio drift hides ---
    out_frames = probe(job.out).frames
    if out_frames != info.frames:
        raise PipelineError(f"frame count changed: {info.frames} in, {out_frames} out")
    return SegmentResult(frames=out_frames, width=width, height=height, seconds=time.perf_counter() - started, stages=stages)


def _classical_resize(frames: np.ndarray, target_height: int) -> np.ndarray:
    """CPU Lanczos resize to the target height, keeping the aspect ratio. Never shrinks."""
    import cv2

    h, w = frames.shape[1:3]
    if target_height <= h:
        return frames
    new_h, new_w = _even(target_height), _even(target_height * w / h)
    # Fill a preallocated array: np.stack of a list would hold every resized frame twice at the same moment.
    out = np.empty((len(frames), new_h, new_w, 3), dtype=np.uint8)
    for i, frame in enumerate(frames):
        out[i] = cv2.resize(frame, (new_w, new_h), interpolation=cv2.INTER_LANCZOS4)
    return out
