"""Where does blocking in dark smooth areas come from: the restoration, the finishing stage or the AV1 encode?

Restores the start of one segment with the real engine, runs the real finishing stage, keeps the finished 16-bit
frames (the truth before any encoding), then encodes the same frames with several SVT-AV1 settings aimed at dark
flat areas. For each encode it reports size and the error against the truth in a crop, so the encoder's own
contribution can be told apart from the model's.

Runs on the GPU host inside the worker image (code mounted on /app):
  python dark_encode_experiment.py SEGMENT OUT_DIR [--restore-frames 81] [--keep 40:61] [--crop 2300,1100,900,500]
Writes OUT_DIR/pre_encode_f<N>.png (16-bit, the truth), OUT_DIR/<variant>.mkv and prints a table.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

import cv2
import numpy as np

from restore_core.ffmpeg_cmds import FFMPEG, SourceInfo, decode_cmd
from restore_core.recipe import resolve
from restore_worker.finish import Finisher
from restore_worker.pipeline import _read_frames, probe
from restore_worker.recavsr_tiled import RecavsrTiledEngine

# name -> (advanced overrides for the finishing stage, crf, extra svtav1 params). Parameter names are SVT-AV1 4.x.
# The finishing stage runs once per distinct override set; the restoration runs once for all of them.
BAKED = lambda strength: {"grain": {"mode": "baked", "strength": strength}}
FGS = lambda level, strength: {"grain": {"mode": "av1_fgs", "fgs_level": level, "strength": strength, "fgs_denoise": True}}
NONE = {"grain": {"mode": "none"}}
LOWLUMA = "variance-boost-strength=3:variance-boost-curve=1:luminance-qp-bias=40"
SOFT = lambda amount, mask: {"grain": {"mode": "none"}, "fidelity": {"soften": "match", "soften_amount": amount, "soften_mask": mask}}
VARIANTS = {
    "N_nograin": (NONE, 24, ""),
    "S_match0.6_mask": (SOFT(0.6, True), 24, ""),
    "S_match0.8_mask": (SOFT(0.8, True), 24, ""),
    "S_match1.0_mask": (SOFT(1.0, True), 24, ""),
}


def encode(frames16: np.ndarray, out: Path, fps: str, crf: int, extra: str, preset: int, fgs: tuple[int, int] | None = None) -> float:
    h, w = frames16.shape[1:3]
    params = "tune=0:enable-variance-boost=1:irefresh-type=2:color-primaries=1:transfer-characteristics=1:matrix-coefficients=1"
    if extra:
        params += ":" + extra
    if fgs:
        params += f":film-grain={fgs[0]}:film-grain-denoise={fgs[1]}"
    vf = ("scale=out_color_matrix=bt709:out_range=tv:flags=bicubic+accurate_rnd+full_chroma_int,"
          "setparams=colorspace=bt709:color_primaries=bt709:color_trc=bt709:range=tv,format=yuv420p10le")
    cmd = [FFMPEG, "-v", "error", "-nostdin", "-y", "-f", "rawvideo", "-pix_fmt", "rgb48le", "-s", f"{w}x{h}", "-r", fps, "-i", "-",
           "-vf", vf, "-c:v", "libsvtav1", "-preset", str(preset), "-crf", str(crf), "-pix_fmt", "yuv420p10le",
           "-svtav1-params", params, "-f", "matroska", str(out)]
    t = time.perf_counter()
    proc = subprocess.run(cmd, input=frames16.tobytes(), capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode()[-300:])
    return time.perf_counter() - t


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("segment", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--restore-frames", type=int, default=81)
    ap.add_argument("--keep", default="40:61")
    ap.add_argument("--crop", default="2300,1100,900,500", help="x,y,w,h of the region to score")
    ap.add_argument("--preset", type=int, default=4)
    ap.add_argument("--model-dir", default="/m")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    lo, hi = (int(v) for v in args.keep.split(":"))
    x, y, cw, ch = (int(v) for v in args.crop.split(","))

    recipe = resolve({"preset": "cleanup-4k"})
    info = probe(args.segment)
    frames = _read_frames(decode_cmd(args.segment, info, recipe, frames=args.restore_frames), info.width, info.height, args.restore_frames)
    engine = RecavsrTiledEngine(args.model_dir, "cuda:0")
    restored, stats = engine.restore(frames, scale=1.0)
    print(json.dumps({"restore": {"frames": len(restored), "seconds": round(stats["seconds"], 1)}}), flush=True)

    rows = []
    for name, (override, crf, extra) in VARIANTS.items():
        variant_recipe = resolve({"preset": "cleanup-4k", "advanced": override})
        # the original frames go in as the reference: softness matching and grain transfer compare with them
        finished = np.ascontiguousarray(np.concatenate(list(Finisher(variant_recipe, "cuda:0").process(restored[:hi], 0, reference=frames[:hi])))[lo:hi])
        mid = (hi - lo) // 2
        if not rows:
            truth_name = args.out / f"pre_encode_crop_f{lo + mid}.png"
            cv2.imwrite(str(truth_name), cv2.cvtColor(finished[mid, y:y + ch, x:x + cw], cv2.COLOR_RGB2BGR))
        fgs = None
        if override.get("grain", {}).get("mode") == "av1_fgs":
            fgs = (override["grain"]["fgs_level"], 1 if override["grain"].get("fgs_denoise") else 0)
        out = args.out / f"{name}.mkv"
        seconds = encode(finished, out, f"{info.fps_num}/{info.fps_den}", crf, extra, args.preset, fgs)
        rows.append({"variant": name, "crf": crf, "extra": extra, "fgs": fgs, "mb": round(out.stat().st_size / 1e6, 2), "enc_s": round(seconds, 1)})
        print(json.dumps(rows[-1]), flush=True)
        del finished
    del engine


if __name__ == "__main__":
    main()
