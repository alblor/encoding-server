"""Does re-running the restoration model on a zoomed crop of a small face give a better face than the guarded output?

Takes decoded source frames of one or more segments, follows one face with a smoothed square crop (about 4 face heights wide),
runs the real engine on the crop at scale 4 (the model's own default: the face is then about 200 px, in the range it was trained
for), shrinks the result back with an area filter, and pastes it over the face with a feathered ellipse. The brightness and
colour of the crop are tied to the source's so the patch does not stand out. Writes PNG strips for judging frame by frame.

Runs on the GPU host inside the worker image (code mounted on /app):
  python face_zoom_experiment.py OUT_DIR SEGMENT [SEGMENT ...] --face 2465,1355 --from 862 --to 936 --first-frame 805
Outputs OUT_DIR/zoom_f<N>.png (crop of the zoomed result) and OUT_DIR/src_f<N>.png (the same crop of the source).

Author: Lorenzo Albanese (alblor)
"""
import argparse
import subprocess
import time
from pathlib import Path

import cv2
import numpy as np

from restore_core.ffmpeg_cmds import decode_cmd
from restore_core.recipe import resolve
from restore_worker.faces import find_faces
from restore_worker.pipeline import _read_frames, probe
from restore_worker.recavsr_tiled import RecavsrTiledEngine


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("segments", nargs="+")
    ap.add_argument("--face", required=True, help="x,y of a point on the face in the first frame, to choose the track")
    ap.add_argument("--first-frame", type=int, required=True, help="absolute index of the first frame of the first segment")
    ap.add_argument("--from", dest="start", type=int, required=True)
    ap.add_argument("--to", dest="stop", type=int, required=True)
    ap.add_argument("--zoom-side", type=int, default=0, help="crop side in source pixels (0 = 4 face heights, multiple of 16)")
    ap.add_argument("--box", default="", help="x,y,w,h of a fixed head box: skips the face detector (a head seen from behind has no face to find)")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    recipe = resolve({"preset": "cleanup-4k"})
    chunks = []
    for seg in args.segments:
        info = probe(Path(seg))
        chunks.append(_read_frames(decode_cmd(Path(seg), info, recipe, frames=info.frames), info.width, info.height, info.frames))
    src = np.concatenate(chunks)
    lo, hi = args.start - args.first_frame, args.stop - args.first_frame
    src = src[lo:hi + 1]
    t, h, w = src.shape[:3]
    px, py = (float(v) for v in args.face.split(","))
    if args.box:
        fixed = np.array([float(v) for v in args.box.split(",")], dtype=np.float32)
        track = [fixed] * t
    else:
        boxes = find_faces(src, "/m/yunet.onnx")
        track = []
        for f in range(t):
            near = [b for b in boxes[f] if abs(b[0] + b[2] / 2 - px) < 160 and abs(b[1] + b[3] / 2 - py) < 160]
            track.append(min(near, key=lambda b: abs(b[0] + b[2] / 2 - px) + abs(b[1] + b[3] / 2 - py)) if near else None)
    known = [i for i, b in enumerate(track) if b is not None]
    assert known, "no face found near that point"
    for i in range(t):                       # frames without a box take the nearest known one: a head moves slowly
        if track[i] is None:
            track[i] = track[min(known, key=lambda k: abs(k - i))]
    centers = np.array([[b[0] + b[2] / 2, b[1] + b[3] / 2] for b in track], dtype=np.float32)
    heights = np.array([b[3] for b in track], dtype=np.float32)
    kernel = np.ones(9) / 9
    centers = np.stack([np.convolve(np.pad(centers[:, k], 4, mode="edge"), kernel, mode="valid") for k in range(2)], axis=1)
    side = args.zoom_side or int(round(float(np.median(heights)) * 4 / 16) * 16)
    side = max(side, 160)
    print(f"{t} frames, crop {side}x{side}, median face height {np.median(heights):.0f}px", flush=True)
    xs = np.clip(centers[:, 0] - side / 2, 0, w - side).astype(int)
    ys = np.clip(centers[:, 1] - side / 2, 0, h - side).astype(int)
    crops = np.stack([src[i, ys[i]:ys[i] + side, xs[i]:xs[i] + side] for i in range(t)])
    engine = RecavsrTiledEngine("/m", "cuda:0", precision="bf16")
    started = time.perf_counter()
    big, stats = engine.restore(crops, scale=4.0, tile_height=1152, tile_width=1344, min_overlap=96)
    print(f"restored {t} crops of {side}px at 4x in {time.perf_counter() - started:.1f}s ({stats['tiles']} tiles)", flush=True)
    for i in range(t):
        zoom = cv2.resize(big[i], (side, side), interpolation=cv2.INTER_AREA).astype(np.float32)
        ref = crops[i].astype(np.float32)
        # tie the colour and brightness of the zoomed face to the source's, coarse scale only
        fix = cv2.GaussianBlur(ref, (0, 0), 6) - cv2.GaussianBlur(zoom, (0, 0), 6)
        zoom = np.clip(zoom + fix, 0, 255).astype(np.uint8)
        absolute = args.start + i
        cv2.imwrite(str(out / f"zoom_f{absolute}.png"), cv2.cvtColor(zoom, cv2.COLOR_RGB2BGR))
        cv2.imwrite(str(out / f"src_f{absolute}.png"), cv2.cvtColor(crops[i], cv2.COLOR_RGB2BGR))
        np.save(out / f"pos_f{absolute}.npy", np.array([xs[i], ys[i], side]))


if __name__ == "__main__":
    main()
