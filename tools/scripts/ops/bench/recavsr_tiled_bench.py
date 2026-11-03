"""Run the tiled ReCaVSR engine on a clip and report speed, memory and run-to-run determinism.

Runs on the GPU host inside the ReCaVSR image (its own uv environment), with the repo's
restore_core/ and restore_worker/ on PYTHONPATH. Reads one clip through ffmpeg, restores it, and
writes the result with ffmpeg (H.264, CRF 10, for looking at it, not for delivery).

usage: python recavsr_tiled_bench.py INPUT OUTPUT [--scale 1] [--frames 49] [--tile-h 1152] [--tile-w 1344]
                                     [--overlap 96] [--repeat 1] [--model-dir /m] [--precision bf16|fp8|fp8_fast]
                                     [--save-raw FRAMES.npy] [--keep-edge-blocks N]
--repeat 2 runs the same segment twice on the same engine: the second run is warm (no compile) and
must give the same pixels as the first, which proves the per-tile session reset leaks no state.
--save-raw keeps the exact uint8 RGB output (no encode), so two precisions can be compared without codec noise
(tools/scripts/ops/bench/fp8_output_compare.py).
"""
import argparse
import json
import subprocess
import time

import numpy as np

from restore_worker.quantize import MODES
from restore_worker.recavsr_tiled import RecavsrTiledEngine


def read_frames(path: str, limit: int | None) -> tuple[np.ndarray, str]:
    probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                            "stream=width,height,r_frame_rate", "-of", "csv=p=0", path],
                           capture_output=True, text=True, check=True).stdout.strip().split(",")
    width, height, rate = int(probe[0]), int(probe[1]), probe[2]
    cmd = ["ffmpeg", "-v", "error", "-i", path, "-an", "-pix_fmt", "rgb24"]
    if limit:
        cmd += ["-frames:v", str(limit)]
    raw = subprocess.run(cmd + ["-f", "rawvideo", "-"], capture_output=True, check=True).stdout
    return np.frombuffer(raw, np.uint8).reshape(-1, height, width, 3), rate


def write_frames(path: str, frames: np.ndarray, rate: str) -> None:
    height, width = frames.shape[1:3]
    proc = subprocess.Popen(
        ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{width}x{height}",
         "-r", rate, "-i", "-", "-c:v", "libx264", "-crf", "10", "-preset", "fast", "-pix_fmt", "yuv420p", path],
        stdin=subprocess.PIPE)
    proc.communicate(frames.tobytes())
    if proc.returncode:
        raise RuntimeError("ffmpeg failed to write the result")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--frames", type=int)
    ap.add_argument("--tile-h", type=int, default=1152)
    ap.add_argument("--tile-w", type=int, default=1344)
    ap.add_argument("--overlap", type=int, default=96)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--model-dir", default="/m")
    ap.add_argument("--precision", default="bf16", choices=MODES)
    ap.add_argument("--save-raw", help="also save the last run's uint8 RGB frames as .npy")
    ap.add_argument("--keep-edge-blocks", type=int,
                    help="experiment only: bf16 blocks kept at each end when quantizing (engine default 2)")
    ap.add_argument("--no-compile", action="store_true", help="skip torch.compile (fast start, slower steady state)")
    args = ap.parse_args()

    frames, rate = read_frames(args.input, args.frames)
    print(f"input {frames.shape[2]}x{frames.shape[1]}, {len(frames)} frames, {rate} fps", flush=True)
    if args.keep_edge_blocks is not None:
        # the engine always uses the default; this swaps in a partial for this benchmark process only
        import functools

        import restore_worker.recavsr_tiled as tiled
        from restore_worker.quantize import quantize_transformer
        tiled.quantize_transformer = functools.partial(quantize_transformer, keep_edge_blocks=args.keep_edge_blocks)
    t0 = time.perf_counter()
    engine = RecavsrTiledEngine(args.model_dir, precision=args.precision,
                                compile_blocks=not args.no_compile, compile_decoder=not args.no_compile)
    print(f"quantization: {json.dumps(engine.quantization)}", flush=True)
    print(f"model loaded in {time.perf_counter() - t0:.1f}s", flush=True)

    results = []
    for run in range(args.repeat):
        out, stats = engine.restore(frames, scale=args.scale, tile_height=args.tile_h, tile_width=args.tile_w,
                                    min_overlap=args.overlap,
                                    progress=lambda i, n, f: print(f"  run {run + 1}: tile {i + 1}/{n} frame {f}", flush=True)
                                    if f == len(frames) else None)
        results.append(out)
        print(f"run {run + 1}: {json.dumps(stats)}", flush=True)
    if len(results) > 1:
        diff = np.abs(results[0].astype(np.int16) - results[1].astype(np.int16))
        print(f"run-to-run max abs diff {int(diff.max())}, mean {float(diff.mean()):.5f}", flush=True)
    if args.save_raw:
        np.save(args.save_raw, results[-1])
    write_frames(args.output, results[-1], rate)
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
