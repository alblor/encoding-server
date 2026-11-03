#!/usr/bin/env python3
"""Probe a film and propose the restoration recipe for it, with an honest time estimate.

Reads the file with ffprobe, decodes a handful of frames spread across it, measures them, and prints a JSON
report holding the classification, the reasons, the recipe to send (a RecipeRequest, ready for restore_film.py)
and the estimated GPU time. Nothing is uploaded: this runs on your machine, on your own copy of the film.

What it measures, on luma, on frames sampled evenly from 5% to 95% of the film:
  detail      share of spectral energy above half of the Nyquist frequency: low means soft or upscaled
  blockiness  mean step across 8-pixel boundaries over the mean step elsewhere: about 1.0 is clean, above 1.15 is visible blocking
  noise       Immerkaer's fast noise estimate, in grey levels of 8 bits

Classes and the preset each one gets
  low-res        shorter than 1080 lines: upscale and restore            film-restoration
  hd             1080 to 2159 lines: upscale and restore                 film-restoration
  uhd-damaged    2160p with compression damage or noise: same-size       cleanup-4k
  uhd-clean      2160p and already clean: restoration would not help      clean-4k
HDR sources are reported, not processed: hdr 'preserve' is not implemented yet.

usage: python probe_media.py MOVIE [--samples 8] [--gpus 2] [--target-height 2160] [--out report.json]
Needs ffmpeg and ffprobe on PATH and numpy.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from dataclasses import asdict, dataclass

import numpy as np

# Measured on the RTX 5080 (2160p output, six tiles of 1344x1152, warm): the engine takes 0.58 s per frame, and the
# first live run took 0.83 s per frame end to end because decode and encode ran one after the other. Cost scales
# with output pixels. These are estimates for planning, not promises: the first real segments refine them.
ENGINE_SECONDS_PER_FRAME_2160P = 0.58
END_TO_END_SECONDS_PER_FRAME_2160P = 0.83
PIXELS_2160P = 3840 * 2160

BLOCKINESS_DAMAGED = 1.15
NOISE_DAMAGED = 3.0             # grey levels (8-bit): visible noise or grain
DETAIL_SOFT = 0.020             # below this share of high-frequency energy the picture is soft or upscaled


@dataclass
class Metrics:
    detail: float
    blockiness: float
    noise: float


def ffprobe(path: str) -> dict:
    out = subprocess.run(["ffprobe", "-v", "error", "-analyzeduration", "60000000", "-probesize", "100000000", "-print_format", "json", "-count_frames", "-show_streams", "-show_format", path],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def sample_frame(path: str, seconds: float, width: int, height: int) -> np.ndarray:
    """One luma frame at full resolution, as float32 [H, W]."""
    raw = subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-ss", f"{seconds:.3f}", "-i", path, "-frames:v", "1",
                          "-vf", "format=gray", "-f", "rawvideo", "-"], capture_output=True, check=True).stdout
    if len(raw) != width * height:
        raise RuntimeError(f"could not decode a frame at {seconds:.1f}s")
    return np.frombuffer(raw, np.uint8).reshape(height, width).astype(np.float32)


def measure(luma: np.ndarray) -> Metrics:
    h, w = luma.shape
    # detail: spectral energy in the outer half of the frequency plane, on a centred crop (cheap and size independent)
    side = min(h, w, 1024)
    y0, x0 = (h - side) // 2, (w - side) // 2
    crop = luma[y0:y0 + side, x0:x0 + side]
    crop = (crop - crop.mean()) * np.hanning(side)[:, None] * np.hanning(side)[None, :]
    power = np.abs(np.fft.fftshift(np.fft.fft2(crop))) ** 2
    fy, fx = np.indices(power.shape)
    radius = np.hypot(fy - side / 2, fx - side / 2) / (side / 2)
    detail = float(power[radius > 0.5].sum() / max(power.sum(), 1e-9))
    # blockiness: horizontal steps that fall on 8-pixel boundaries against all the others
    step = np.abs(np.diff(luma, axis=1))
    on = step[:, 7::8].mean()
    mask = np.ones(step.shape[1], bool)
    mask[7::8] = False
    blockiness = float(on / max(step[:, mask].mean(), 1e-6))
    # noise: Immerkaer's estimate from the response of a Laplacian-difference kernel
    k = (luma[:-2, :-2] - 2 * luma[:-2, 1:-1] + luma[:-2, 2:] - 2 * luma[1:-1, :-2] + 4 * luma[1:-1, 1:-1]
         - 2 * luma[1:-1, 2:] + luma[2:, :-2] - 2 * luma[2:, 1:-1] + luma[2:, 2:])
    noise = float(np.sqrt(np.pi / 2) / 6 * np.abs(k).mean())
    return Metrics(detail, blockiness, noise)


def median_metrics(samples: list[Metrics]) -> Metrics:
    return Metrics(*(float(np.median([getattr(s, f) for s in samples])) for f in ("detail", "blockiness", "noise")))


def classify(height: int, m: Metrics) -> tuple[str, str, list[str]]:
    """Returns (class, preset, reasons)."""
    if height < 1080:
        return "low-res", "film-restoration", [f"{height} lines: upscaled to the target and restored"]
    if height < 2160:
        return "hd", "film-restoration", [f"{height} lines: upscaled to the target and restored"]
    reasons = []
    if m.blockiness > BLOCKINESS_DAMAGED:
        reasons.append(f"blocking visible (blockiness {m.blockiness:.2f}, clean is about 1.0)")
    if m.noise > NOISE_DAMAGED:
        reasons.append(f"noise or grain level {m.noise:.1f} grey levels")
    if m.detail < DETAIL_SOFT:
        reasons.append(f"soft picture (high-frequency share {m.detail:.3f}): likely upscaled from a lower resolution")
    if reasons:
        return "uhd-damaged", "cleanup-4k", reasons
    return "uhd-clean", "clean-4k", ["2160p with no measurable damage: restoration would change little, so only the encode is proposed"]


def estimate_hours(frames: int, out_height: int, out_width: int, gpus: int, engine: str) -> dict:
    if engine == "none":
        return {"note": "no GPU restoration: only the CPU encode, which this estimate does not cover"}
    scale = (out_height * out_width) / PIXELS_2160P
    return {
        "gpu_hours_engine_only": round(frames * ENGINE_SECONDS_PER_FRAME_2160P * scale / gpus / 3600, 1),
        "gpu_hours_end_to_end_today": round(frames * END_TO_END_SECONDS_PER_FRAME_2160P * scale / gpus / 3600, 1),
        "basis": f"{gpus} GPU(s); engine 0.58 s/frame and 0.83 s/frame end to end at 2160p, scaled by output pixels; estimates",
    }


def build_report(path: str, samples: int, gpus: int, target_height: int) -> dict:
    info = ffprobe(path)
    video = next(s for s in info["streams"] if s["codec_type"] == "video")
    width, height = int(video["width"]), int(video["height"])
    num, den = (int(v) for v in video["r_frame_rate"].split("/"))
    duration = float(info["format"].get("duration") or video.get("duration") or 0)
    frames = int(video.get("nb_read_frames") or round(duration * num / den))
    hdr = video.get("color_transfer") in ("smpte2084", "arib-std-b67") or video.get("color_primaries") == "bt2020"
    times = [duration * (0.05 + 0.9 * i / max(samples - 1, 1)) for i in range(samples)]
    metrics = median_metrics([measure(sample_frame(path, t, width, height)) for t in times])
    klass, preset, reasons = classify(height, metrics)

    recipe: dict | None = {"recipe_version": 1, "preset": preset, "basic": {"target_height": max(target_height, height)}}
    warnings = []
    if hdr:
        recipe = None                                       # saying "no recipe" while proposing one would be contradictory
        warnings.append("HDR source: restoration of PQ or HLG pictures is not supported yet, so no recipe is proposed")
    if video.get("field_order") not in (None, "progressive", "unknown"):
        warnings.append(f"interlaced source ({video['field_order']}): deinterlace before restoration; not handled by this recipe")
    if float(info["format"].get("bit_rate") or 0) > 0:
        bpp = float(info["format"]["bit_rate"]) / (width * height * num / den)
        reasons.append(f"average bitrate {float(info['format']['bit_rate']) / 1e6:.1f} Mb/s, {bpp:.3f} bits per pixel per frame")
    out_h = max(target_height, height)
    out_w = round(width * out_h / height / 2) * 2
    return {
        "file": path,
        "video": {"width": width, "height": height, "fps": f"{num}/{den}", "frames": frames, "duration_s": round(duration, 1),
                  "codec": video.get("codec_name"), "pix_fmt": video.get("pix_fmt"),
                  "color": {k: video.get(k) for k in ("color_space", "color_transfer", "color_primaries", "color_range")}},
        "metrics": {k: round(v, 3) for k, v in asdict(metrics).items()},
        "class": klass,
        "reasons": reasons,
        "warnings": warnings,
        "recipe": recipe,
        "estimate": estimate_hours(frames, out_h, out_w, gpus, "none" if preset == "clean-4k" else "recavsr"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("movie")
    ap.add_argument("--samples", type=int, default=8)
    ap.add_argument("--gpus", type=int, default=2)
    ap.add_argument("--target-height", type=int, default=2160)
    ap.add_argument("--out", help="write the report here as well as printing it")
    args = ap.parse_args()
    path = Path(args.movie)
    if not path.is_file():
        print(f"no such file: {args.movie}", file=sys.stderr)
        return 2
    if path.stat().st_size == 0:
        print(f"{args.movie} is empty", file=sys.stderr)
        return 2
    try:
        report = build_report(args.movie, args.samples, args.gpus, args.target_height)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        print(f"{args.movie} could not be read as a video: {detail.strip()[-300:] or 'ffprobe failed'}", file=sys.stderr)
        return 2
    except StopIteration:
        print(f"{args.movie} has no video stream", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
