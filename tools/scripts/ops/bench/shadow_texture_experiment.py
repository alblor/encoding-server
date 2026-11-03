"""Where do the textures of the dark areas go: the model, the finishing stage or the AV1 encode?

Restores one stretch of a segment with the real engine, runs the real finishing stage for several settings, encodes each result
with several SVT-AV1 settings and scores the DARK areas of the picture (where the SOURCE is darker than a threshold) on the
frames before and after the encode: share of pixels in flat plateaus (a pixel equal to its four neighbours), number of distinct
luma codes, and the RMS of three luma bands. The encode is the suspect: it removes anything faint in dark flat areas.

Runs on the GPU host inside the worker image (code mounted on /app):
  python shadow_texture_experiment.py SEGMENT OUT_DIR --keep 40:64
Prints one JSON line per variant and writes OUT_DIR/<variant>_dark.png (a shadow-lifted crop) for looking.

Author: Lorenzo Albanese (alblor)
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

import cv2
import numpy as np

from restore_core.ffmpeg_cmds import FFMPEG, decode_cmd
from restore_core.recipe import resolve
from restore_worker.finish import Finisher
from restore_worker.pipeline import _read_frames, probe
from restore_worker.recavsr_tiled import RecavsrTiledEngine

BASE = "tune=0:enable-variance-boost=1:irefresh-type=2:color-primaries=1:transfer-characteristics=1:matrix-coefficients=1"
# name -> (advanced overrides of the finishing stage, crf, extra SVT-AV1 params)
VARIANTS = {
    "B0_current": ({}, 24, ""),
    "H1_nodeband_sh0.35_E1": ({"bitdepth": {"deband": "off"}, "grain": {"shadow_weight": 0.35}}, 24, "ac-bias=1.0:enable-qm=1"),
    "H2_nodeband_sh0.5_E1": ({"bitdepth": {"deband": "off"}, "grain": {"shadow_weight": 0.5}}, 24, "ac-bias=1.0:enable-qm=1"),
    "H3_nodeband_sh0.35_ac2": ({"bitdepth": {"deband": "off"}, "grain": {"shadow_weight": 0.35}}, 24, "ac-bias=2.0:enable-qm=1"),
    "H4_nodeband_sh0.35_E1_crf22": ({"bitdepth": {"deband": "off"}, "grain": {"shadow_weight": 0.35}}, 22, "ac-bias=1.0:enable-qm=1"),
    "H5_nodeband_E1": ({"bitdepth": {"deband": "off"}}, 24, "ac-bias=1.0:enable-qm=1"),
}


def luma_full(rgb: np.ndarray) -> np.ndarray:
    a = rgb.astype(np.float32)
    return 0.2126 * a[..., 0] + 0.7152 * a[..., 1] + 0.0722 * a[..., 2]


def scores(y: np.ndarray, mask: np.ndarray) -> dict:
    """y: (T,H,W) luma in 10-bit codes (0..1023). Scores on the pixels of mask (T,H,W)."""
    flat_share, codes, bands = [], [], [[], [], []]
    for t in range(len(y)):
        a = y[t]
        m = mask[t]
        flat = (a[1:-1, 1:-1] == a[:-2, 1:-1]) & (a[1:-1, 1:-1] == a[2:, 1:-1]) & (a[1:-1, 1:-1] == a[1:-1, :-2]) & (a[1:-1, 1:-1] == a[1:-1, 2:])
        flat_share.append(float((flat & m[1:-1, 1:-1]).sum() / max(m[1:-1, 1:-1].sum(), 1)))
        codes.append(len(np.unique(a[m])))
        af = a.astype(np.float32) / 4.0                     # 8-bit scale
        prev = af
        for k, s in enumerate((1.5, 3.0, 6.0)):
            blur = cv2.GaussianBlur(af, (0, 0), s)
            band = prev - blur
            bands[k].append(float(np.sqrt((band[m] ** 2).mean())))
            prev = blur
    return {"flat_plateau_%": round(100 * float(np.mean(flat_share)), 1), "distinct_codes": int(np.mean(codes)),
            "band_rms_1.5/3/6px": [round(float(np.mean(b)), 3) for b in bands]}


def encode(frames16: np.ndarray, out: Path, fps: str, crf: int, extra: str, preset: int) -> float:
    h, w = frames16.shape[1:3]
    params = BASE + (":" + extra if extra else "")
    vf = ("scale=out_color_matrix=bt709:out_range=tv:flags=bicubic+accurate_rnd+full_chroma_int,"
          "setparams=colorspace=bt709:color_primaries=bt709:color_trc=bt709:range=tv,format=yuv420p10le")
    cmd = [FFMPEG, "-v", "error", "-nostdin", "-y", "-f", "rawvideo", "-pix_fmt", "rgb48le", "-s", f"{w}x{h}", "-r", fps, "-i", "-", "-vf", vf,
           "-c:v", "libsvtav1", "-preset", str(preset), "-crf", str(crf), "-pix_fmt", "yuv420p10le", "-svtav1-params", params, "-f", "matroska", str(out)]
    t = time.perf_counter()
    proc = subprocess.run(cmd, input=frames16.tobytes(), capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode()[-300:])
    return time.perf_counter() - t


def decode_y(path: Path, w: int, h: int) -> np.ndarray:
    raw = subprocess.run([FFMPEG, "-v", "error", "-i", str(path), "-vf", "extractplanes=y", "-f", "rawvideo", "-pix_fmt", "gray10le", "-"],
                         capture_output=True, check=True).stdout
    return np.frombuffer(raw, np.uint16).reshape(-1, h, w)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("segment", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--keep", default="40:64")
    ap.add_argument("--preset", type=int, default=4)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    lo, hi = (int(v) for v in args.keep.split(":"))
    recipe = resolve({"preset": "cleanup-4k"})
    info = probe(args.segment)
    frames = _read_frames(decode_cmd(args.segment, info, recipe, frames=info.frames), info.width, info.height, info.frames)
    engine = RecavsrTiledEngine("/m", "cuda:0")
    restored, stats = engine.restore(frames[:hi], scale=1.0)
    print(json.dumps({"restored": len(restored), "seconds": round(stats["seconds"], 1)}), flush=True)
    del engine
    h, w = info.height, info.width
    src_y = luma_full(frames[lo:hi])
    mask = cv2.GaussianBlur(src_y[0], (0, 0), 20) < 25.0
    masks = np.stack([cv2.GaussianBlur(f, (0, 0), 20) < 25.0 for f in src_y])
    print(json.dumps({"dark_area_%": round(100 * float(masks.mean()), 1), "source": scores(np.round(src_y * 4.0).astype(np.uint16), masks)}), flush=True)
    only = set(args.only.split(",")) if args.only else None
    for name, (override, crf, extra) in VARIANTS.items():
        if only and name not in only:
            continue
        vrecipe = resolve({"preset": "cleanup-4k", "advanced": {"fidelity": {"face_guard": "off"}, **override}})
        finished = np.ascontiguousarray(np.concatenate(list(Finisher(vrecipe, "cuda:0").process(restored[:hi], 0, reference=frames[:hi])))[lo:hi])
        pre_y = np.round(luma_full(finished) / 65535.0 * 1023.0).astype(np.uint16)
        out = args.out / f"{name}.mkv"
        seconds = encode(finished, out, f"{info.fps_num}/{info.fps_den}", crf, extra, args.preset)
        dec = decode_y(out, w, h)
        full = np.clip((dec.astype(np.float32) - 64.0) / 876.0 * 1023.0, 0, 1023).round().astype(np.uint16)       # limited to full range
        row = {"variant": name, "crf": crf, "extra": extra, "mb": round(out.stat().st_size / 1e6, 2), "enc_s": round(seconds, 1),
               "before_encode": scores(pre_y, masks), "after_encode": scores(full, masks)}
        print(json.dumps(row), flush=True)
        lift = np.clip((full[len(full) // 2, 300:900, 1000:1800].astype(np.float32) / 1023.0 * 4.0) ** 0.6, 0, 1)
        cv2.imwrite(str(args.out / f"{name}_dark.png"), (lift * 255).astype(np.uint8))


if __name__ == "__main__":
    main()
