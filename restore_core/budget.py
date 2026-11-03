"""Memory a segment needs in a worker, worked out before anything is allocated.

A worker holds the whole segment in RAM, decoded, restored and being encoded at the same time. Allocating blindly lets
one big request get the worker OOM-killed, and a killed worker stays down (restart is off on purpose), so the same
arithmetic runs twice: the API refuses at submit, and the worker refuses again before it decodes, from its own cgroup
limit.

The model is an envelope over measurements, not a derivation: where the real use was found to be above what the parts add
up to, the model follows the measurement (cgroup anonymous memory, 2026-10-31):

  recavsr, 2160p to 2160p, GPU worker   161 frames 16.5 GiB, 241 frames 24.3 GiB: 0.0975 GiB per frame, 0.8 GiB fixed.
                                        The frame arrays explain half of that, the rest is the encoder, which grows with the
                                        frames here. The model charges 4.5 frames of the output size per frame.
  classical, 640x360 to 2160p, CPU      25 frames 5.7 GiB, 50 frames 7.4, 100 frames 10.2 (ffmpeg 4.4 to 5.8 of it) on the
                                        server, 3.9, 5.5 and over 6 on a laptop VM: about 0.06 GiB per frame.
  none, 2160p, heavy chain, CPU         16 frames 3.8 GiB, 40 frames 5.7: about 0.08 GiB per frame.
  encoder alone, 2160p, engine off      7.0 to 8.0 GiB between 60 and 241 frames (GPU worker).

Output frames the encoder cannot produce at all (AV1 stops at 16384 pixels on a side) are refused outright.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

from pathlib import Path

from restore_core.recipe import EffectiveRecipe, effective_scale

GIB = 1024 ** 3
MAX_SIDE = 16384                       # AV1 level limit, SVT-AV1 refuses larger frames

BASE_BYTES = 1 * GIB                   # the worker process, finishing chunks and ffmpeg itself
ENGINE_BYTES = GIB // 2                # CUDA engine host-side state, only when the engine is recavsr
ENCODER_BYTES_PER_MPX = 0.55 * GIB     # SVT-AV1 10-bit, fixed part: 4.4 GiB at 8.3 Mpx (CPU engines; on the GPU runs it grew with the frames)
# Per frame, in units of one RGB frame at the output size (the source frame counts as its own size).
OUT_FRAMES_PER_FRAME = {"recavsr": 4.5, "classical": 3.5, "none": 5.0}     # none: 0.12 GiB per 2160p frame measured on the heavy chain


def output_size(recipe: EffectiveRecipe, width: int, height: int) -> tuple[int, int]:
    """Frame size the engine will produce. Mirrors the pipeline: even numbers, never smaller than the source."""
    engine = recipe.basic.engine
    if engine == "recavsr":
        scale = effective_scale(recipe, height)
        return _even(width * scale), _even(height * scale)
    if engine == "classical" and recipe.basic.target_height > height:
        return _even(recipe.basic.target_height * width / height), _even(recipe.basic.target_height)
    return width, height


def _per_frame_bytes(recipe: EffectiveRecipe, width: int, height: int, out_w: int, out_h: int) -> float:
    out_frame = 3 * out_w * out_h
    units = OUT_FRAMES_PER_FRAME.get(recipe.basic.engine, 3.5)
    # A source smaller than the output (an upscale) is a small extra array of its own; at equal size it is inside the units.
    extra = 3 * width * height if (out_w, out_h) != (width, height) else 0
    return units * out_frame + extra


def overhead_bytes(recipe: EffectiveRecipe, out_w: int, out_h: int) -> int:
    if recipe.basic.engine == "recavsr":
        return BASE_BYTES + ENGINE_BYTES           # the GPU runs' fixed part was 0.8 GiB: the encoder is inside the per-frame term
    return int(BASE_BYTES + ENCODER_BYTES_PER_MPX * out_w * out_h / 1e6)


def estimate_bytes(recipe: EffectiveRecipe, width: int, height: int, frames: int) -> int:
    out_w, out_h = output_size(recipe, width, height)
    return int(frames * _per_frame_bytes(recipe, width, height, out_w, out_h)) + overhead_bytes(recipe, out_w, out_h)


def refusal(recipe: EffectiveRecipe, width: int, height: int, frames: int, limit_bytes: int) -> str | None:
    """A sentence for the client when the segment cannot be produced or cannot fit, or None when it can."""
    out_w, out_h = output_size(recipe, width, height)
    if max(out_w, out_h) > MAX_SIDE:
        return (f"{width}x{height} would be restored to {out_w}x{out_h}, and AV1 cannot encode a side above {MAX_SIDE} pixels: "
                f"lower basic.target_height (or advanced.restore.scale if it is set)")
    need = estimate_bytes(recipe, width, height, frames)
    if need <= limit_bytes:
        return None
    per_frame = _per_frame_bytes(recipe, width, height, out_w, out_h)
    fits = max(0, int((limit_bytes - overhead_bytes(recipe, out_w, out_h)) // per_frame))
    return (f"{frames} frames of {width}x{height} restored to {out_w}x{out_h} need about {need / GIB:.1f} GiB of worker memory, "
            f"above the {limit_bytes / GIB:.1f} GiB limit: cut shorter segments (at most {fits} frames fit)")


def cgroup_limit_bytes(path: str = "/sys/fs/cgroup/memory.max") -> int | None:
    """The container's own memory limit (cgroup v2), or None when there is none or it cannot be read."""
    try:
        text = Path(path).read_text().strip()
    except OSError:
        return None
    return int(text) if text.isdigit() else None


def _even(value: float) -> int:
    return max(2, int(round(value / 2)) * 2)
