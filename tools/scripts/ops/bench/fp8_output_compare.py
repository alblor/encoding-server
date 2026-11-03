"""Compare two restored outputs of the same clip pixel for pixel: PSNR overall and per frame, plus crops to look at.

Reads the uint8 RGB arrays written by recavsr_tiled_bench.py --save-raw (no codec in between, so the numbers
are the model's difference and nothing else). For each crop it writes one PNG with three panels side by side:
REFERENCE | CANDIDATE | absolute difference amplified --amplify times (grey 0 = identical).

Author: Lorenzo Albanese (alblor)
usage: python fp8_output_compare.py REFERENCE.npy CANDIDATE.npy [--crops OUT_PREFIX] [--amplify 8]
"""
import argparse

import numpy as np


def psnr(a: np.ndarray, b: np.ndarray) -> float:
    mse = np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2)
    return float("inf") if mse == 0 else 10 * np.log10(255.0 ** 2 / mse)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("reference")
    ap.add_argument("candidate")
    ap.add_argument("--crops", help="prefix for PNG crops, e.g. /out/crop")
    ap.add_argument("--amplify", type=float, default=8.0)
    ap.add_argument("--size", type=int, default=384)
    args = ap.parse_args()
    ref, cand = np.load(args.reference, mmap_mode="r"), np.load(args.candidate, mmap_mode="r")
    if ref.shape != cand.shape:
        raise SystemExit(f"shape mismatch {ref.shape} vs {cand.shape}")
    # one frame at a time: whole-clip float copies of 161 4K frames would need tens of GB of RAM
    per_frame, sq_sum, max_diff, abs_sum, off = [], 0.0, 0, 0.0, 0
    for i in range(len(ref)):
        d = ref[i].astype(np.int16) - cand[i].astype(np.int16)
        sq = float(np.square(d, dtype=np.int64).sum())
        sq_sum += sq
        per_frame.append(float("inf") if sq == 0 else 10 * np.log10(255.0 ** 2 * d.size / sq))
        ad = np.abs(d)
        max_diff = max(max_diff, int(ad.max()))
        abs_sum += float(ad.sum())
        off += int((ad.max(-1) > 4).sum())
    total = ref.size
    overall = float("inf") if sq_sum == 0 else 10 * np.log10(255.0 ** 2 * total / sq_sum)
    print(f"frames {len(ref)} {ref.shape[2]}x{ref.shape[1]}: PSNR {overall:.2f} dB overall, per frame "
          f"min {min(per_frame):.2f} median {np.median(per_frame):.2f} max {max(per_frame):.2f}; "
          f"max abs diff {max_diff}, mean {abs_sum / total:.4f}, pixels off by >4: "
          f"{off / (total / 3) * 100:.4f}%")
    # drift along the stream: the engine carries recycled latents and the KV cache from block to block, so an
    # error that accumulates shows up as a falling PSNR from the first frames to the last
    n = min(10, len(per_frame) // 2)
    finite = np.array([p if np.isfinite(p) else 99.0 for p in per_frame])
    slope = np.polyfit(np.arange(len(finite)), finite, 1)[0] * 100 if len(finite) > 1 else 0.0
    print(f"drift: first {n} frames {finite[:n].mean():.2f} dB, last {n} frames {finite[-n:].mean():.2f} dB, "
          f"linear trend {slope:+.2f} dB per 100 frames")
    win = 20     # mean PSNR per window of frames: shows whether the drift flattens or keeps falling
    print("per 20 frames: " + " ".join(f"{i}-{min(i + win, len(finite)) - 1}:{finite[i:i + win].mean():.2f}"
                                       for i in range(0, len(finite), win)))
    if args.crops:
        import cv2
        t, h, w, _ = ref.shape
        s = args.size
        # centre, a tile seam region (x around 1344 for 2160p tiles), the worst frame's worst spot, and a corner
        worst_t = int(np.argmin(per_frame))
        err = np.abs(ref[worst_t].astype(np.int16) - cand[worst_t].astype(np.int16)).sum(-1).astype(np.float32)
        k = s // 4
        pooled = err[: h // k * k, : w // k * k].reshape(h // k, k, w // k, k).sum((1, 3))
        wy, wx = np.unravel_index(int(np.argmax(pooled)), pooled.shape)
        spots = {"centre": (t // 2, h // 2 - s // 2, w // 2 - s // 2),
                 "seam": (t // 2, h // 2 - s // 2, min(w - s, 1344 - s // 2)),
                 "worst": (worst_t, min(h - s, max(0, wy * k - s // 2)), min(w - s, max(0, wx * k - s // 2))),
                 "corner": (t - 1, 0, 0)}
        for name, (f, y, x) in spots.items():
            a, b = ref[f, y:y + s, x:x + s], cand[f, y:y + s, x:x + s]
            d = np.clip(np.abs(a.astype(np.int16) - b.astype(np.int16)) * args.amplify, 0, 255).astype(np.uint8)
            panel = np.concatenate([a, b, d], axis=1)
            path = f"{args.crops}_{name}_f{f}_y{y}_x{x}.png"
            cv2.imwrite(path, cv2.cvtColor(np.ascontiguousarray(panel), cv2.COLOR_RGB2BGR))
            print(f"crop {name}: frame {f} at ({x},{y}) PSNR {psnr(a, b):.2f} dB -> {path}")


if __name__ == "__main__":
    main()
