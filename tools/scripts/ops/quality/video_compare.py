"""Objective side of a restoration comparison: temporal stability, sharpness and faithfulness.

For one low-quality INPUT and several restored videos of the same frames, reports per video:
  flicker      mean |(Y_t - Y_t-1)_out - (Y_t - Y_t-1)_ref|, where ref is the input upscaled with Lanczos.
               It isolates instability the model ADDED on top of the source's own motion. Lower is better.
  sharpness    mean variance of the Laplacian of the luma. Higher means more fine detail, but noise and
               invented texture raise it too, so read it next to lr_psnr and the eyes, never alone.
  lr_psnr      PSNR between the output downscaled back to the input size and the input. High means the
               output stays faithful to what the source showed; low means content was invented.
Frame counts must match; frame timestamps are ignored (a 16 fps writer and a 24 fps one compare fine).
No reference-free perceptual metric here: those need a model and are run separately on the server.

usage: uv run --with numpy python video_compare.py INPUT.mp4 NAME=VIDEO.mp4 [NAME=VIDEO.mp4 ...]
"""
import subprocess
import sys

import numpy as np


def ffprobe_size(path: str) -> tuple[int, int]:
    out = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                          "stream=width,height", "-of", "csv=p=0", path],
                         capture_output=True, text=True, check=True).stdout.strip()
    w, h = out.split(",")
    return int(w), int(h)


def luma_frames(path: str, width: int, height: int, flags: str) -> np.ndarray:
    """Decode every frame as 8-bit luma at width x height, ignoring timestamps."""
    raw = subprocess.run(
        ["ffmpeg", "-v", "error", "-i", path, "-fps_mode", "passthrough",
         "-vf", f"scale={width}:{height}:flags={flags},format=gray", "-f", "rawvideo", "-"],
        capture_output=True, check=True).stdout
    return np.frombuffer(raw, np.uint8).reshape(-1, height, width).astype(np.float32)


def laplacian_variance(frames: np.ndarray) -> float:
    f = frames
    lap = (-4 * f[:, 1:-1, 1:-1] + f[:, :-2, 1:-1] + f[:, 2:, 1:-1] + f[:, 1:-1, :-2] + f[:, 1:-1, 2:])
    return float(lap.var(axis=(1, 2)).mean())


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    mse = float(((a - b) ** 2).mean())
    return float("inf") if mse == 0 else 10 * np.log10(255.0**2 / mse)


def main() -> None:
    source = sys.argv[1]
    named = [arg.split("=", 1) for arg in sys.argv[2:]]
    in_w, in_h = ffprobe_size(source)
    out_w, out_h = ffprobe_size(named[0][1])
    # Evaluate at the output size, so the Lanczos reference and the restored videos line up pixel for pixel.
    ref = luma_frames(source, out_w, out_h, "lanczos")
    src_small = luma_frames(source, in_w, in_h, "bicubic")
    ref_dt = np.diff(ref, axis=0)
    print(f"{len(ref)} frames, input {in_w}x{in_h}, outputs {out_w}x{out_h}")
    print(f"{'video':14s} {'flicker':>9s} {'sharpness':>10s} {'lr_psnr':>8s}")
    print(f"{'lanczos ref':14s} {0.0:9.3f} {laplacian_variance(ref):10.1f} {psnr(luma_frames(source, in_w, in_h, 'area'), src_small):8.2f}")
    for name, path in named:
        out = luma_frames(path, out_w, out_h, "bicubic")
        assert len(out) == len(ref), f"{name}: {len(out)} frames, expected {len(ref)}"
        flicker = float(np.abs(np.diff(out, axis=0) - ref_dt).mean())
        small = luma_frames(path, in_w, in_h, "area")
        print(f"{name:14s} {flicker:9.3f} {laplacian_variance(out):10.1f} {psnr(small, src_small):8.2f}")


if __name__ == "__main__":
    main()
