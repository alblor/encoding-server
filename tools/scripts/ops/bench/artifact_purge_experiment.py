"""Does an artifact-purging stage remove compression damage without removing real detail? Measurements, sheets.

Runs on the GPU host inside the worker image, GPU 1 only, no network, with the work directory mounted on /work and this
folder on /code (see the docker line at the bottom). Media never leaves /work (RAM disk). Subcommands:

  degrade                       controlled material: clean frames in /work/in/v8_*.png are put through low-quality encodes
                                (x264 and x265 at high CRF, a plain 8-bit requantisation that bands the shadows, and the
                                two together) -> /work/deg/<variant>/<frame>.png
  run [--frames 900,1000,...]   every candidate on every degraded frame, on the clean frame itself and on the real frames
                                (--only a,b limits the candidates, --tag names the results file) -> /work/results_<tag>.json
  report                        the table of every results file together
  sheets                        side-by-side crops (stretched so that the shadows show) -> /work/sheets/*.png

Measured against the clean frame G, for the degraded frame D and a candidate output O (luma, in 8-bit codes):
  masks (from G only)  tex   detail: strong gradient (dilated) or local band energy above the grain floor
                       art   not tex and a low-frequency error |blur(D-G)| over 1 code: banding, blocking, contour patches
                       ring  a band around strong edges, off the edge itself: where mosquito noise lives
  artifacts removed    art_lf   mean |blur3(O-G)| on art, against the same for D  (lower is better)
                       ring     mean |O-G| on ring, against the same for D
                       grid     blockiness ratio (step on the detected grid over the step off it): 1.0 is clean
  detail kept          tex_mad  mean |O-D| on tex (target 0: the stage must not touch detail)
                       tex_hf   energy of O minus its blur(1.5) over the same for D on tex (target 1.0)
                       tex_dmae mean |O-G| minus mean |D-G| on tex (target <= 0: detail is not further from the truth)
  clean content        clean    mean |O(G)-G| and the share of pixels moved by 1 code or more when the INPUT is the clean frame

usage (inside the worker image):  python artifact_purge_experiment.py run
Needs cv2, numpy, torch and ffmpeg.  Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import cv2
import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import artifact_purge_candidates as C

WORK = Path("/work")
FRAMES = [400, 900, 1000, 1272, 1500, 1750]
REAL_FRAMES = [900, 1000, 1500]
DEV = torch.device("cuda" if torch.cuda.is_available() else "cpu")

DEGRADE = {
    # name: (requantise step in codes or 0, encoder args or None)
    "x264_crf38": (0, ["-c:v", "libx264", "-preset", "veryfast", "-crf", "38"]),
    "x265_crf36": (0, ["-c:v", "libx265", "-preset", "veryfast", "-crf", "36", "-x265-params", "log-level=error"]),
    "bands": (2, None),
    "bands_x264_crf30": (2, ["-c:v", "libx264", "-preset", "veryfast", "-crf", "30"]),
}


def ffmpeg(*args) -> None:
    subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-y", *args], check=True)


def read(path: Path) -> torch.Tensor:
    img = cv2.imread(str(path), cv2.IMREAD_COLOR)[..., ::-1]
    return torch.from_numpy(np.ascontiguousarray(img)).to(DEV).permute(2, 0, 1)[None].float() / 255.0


def write(path: Path, x: torch.Tensor) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    arr = (x.clamp(0, 1) * 65535 + 0.5).to(torch.int32)[0].permute(1, 2, 0).cpu().numpy().astype(np.uint16)
    cv2.imwrite(str(path), np.ascontiguousarray(arr[..., ::-1]), [cv2.IMWRITE_PNG_COMPRESSION, 1])


def write8(path: Path, x: torch.Tensor) -> None:
    arr = (x.clamp(0, 1) * 255 + 0.5).to(torch.uint8)[0].permute(1, 2, 0).cpu().numpy()
    cv2.imwrite(str(path), np.ascontiguousarray(arr[..., ::-1]), [cv2.IMWRITE_PNG_COMPRESSION, 1])


def strip_grain_and_requantise(g: torch.Tensor, step: int) -> torch.Tensor:
    """What a low-bitrate encode does to dark flat areas: the grain is thrown away (a wide blur, only where the area is dark and
    quiet), then the 8-bit codes are floored to a multiple of `step` with no dither, so the gradients become staircases."""
    y = C._luma(g) * 255.0
    s = g.shape[-2] / 2160.0
    energy = C.blur((y - C.blur(y, 3.0 * s)) ** 2, 4.0 * s).sqrt()
    gate = C.blur(((C.blur(y, 2.0 * s) < 60.0) & (energy < 6.0)).float(), 6.0 * s)
    mixed = g + gate * (C.blur(g, 4.0 * s) - g)
    return torch.floor(mixed * 255.0 / step) * step / 255.0


def degrade() -> None:
    for name, (step, enc) in DEGRADE.items():
        for f in FRAMES:
            src = WORK / "in" / f"v8_{f}.png"
            out = WORK / "deg" / name / f"{f}.png"
            out.parent.mkdir(parents=True, exist_ok=True)
            (WORK / "tmp").mkdir(parents=True, exist_ok=True)
            current = src
            if step:
                requant = WORK / "tmp" / f"{name}_{f}.png"
                write8(requant, strip_grain_and_requantise(read(src), step))
                current = requant
            if enc:
                tmp = WORK / "tmp" / f"{name}_{f}.mkv"
                ffmpeg("-i", str(current), "-frames:v", "1", "-vf", "format=yuv420p", *enc, str(tmp))
                ffmpeg("-i", str(tmp), "-frames:v", "1", "-vf", "format=rgb24", str(out))
                tmp.unlink()
            else:
                ffmpeg("-i", str(current), "-pix_fmt", "rgb24", str(out))
            print("degraded", name, f, flush=True)


# ---- masks and scores -----------------------------------------------------------------------------------------------------

def luma_codes(x: torch.Tensor) -> torch.Tensor:
    return C._luma(x) * 255.0


def masks_from_clean(g: torch.Tensor, d: torch.Tensor) -> dict:
    yg, yd = luma_codes(g), luma_codes(d)
    s = g.shape[-2] / 2160.0
    smooth = C.blur(yg, 2.0 * s)
    gx = (C._shift(smooth, -1, 0) - C._shift(smooth, 1, 0)) * 0.5
    gy = (C._shift(smooth, 0, -1) - C._shift(smooth, 0, 1)) * 0.5
    grad = torch.hypot(gx, gy)
    edges = C._max_sep((grad > 2.0).float(), 11)
    band = C.blur((yg - C.blur(yg, 3.0 * s)) ** 2, 4.0 * s).sqrt()
    tex = (edges > 0) | (band > 4.0)
    err_lf = C.blur(yd - yg, 3.0 * s).abs()
    art = (~tex) & (err_lf > 1.0)
    strong = (grad > 8.0).float()
    ring = (C._max_sep(strong, 17) > 0) & (C._max_sep(strong, 5) == 0)
    return dict(tex=tex, art=art, ring=ring)


def hf(y: torch.Tensor) -> torch.Tensor:
    return y - C.blur(y, 1.5)


def mean_on(v: torch.Tensor, m: torch.Tensor) -> float:
    return float((v * m).sum() / m.sum().clamp_min(1)) if m.sum() > 0 else float("nan")


def score(o: torch.Tensor, d: torch.Tensor, g: torch.Tensor, m: dict) -> dict:
    yo, yd, yg = luma_codes(o), luma_codes(d), luma_codes(g)
    s = g.shape[-2] / 2160.0
    art, tex, ring = m["art"].float(), m["tex"].float(), m["ring"].float()
    out = {}
    out["art_lf_D"] = mean_on(C.blur(yd - yg, 3 * s).abs(), art)
    out["art_lf_O"] = mean_on(C.blur(yo - yg, 3 * s).abs(), art)
    stair = lambda y: C.blur(y, 2.5 * s) - C.blur(y, 12.0 * s)       # grain is mostly gone at 2.5 px, a staircase of 20+ px plateaus is still there
    out["stair_G"] = mean_on(stair(yg) ** 2, art) ** 0.5
    out["stair_D"] = mean_on(stair(yd) ** 2, art) ** 0.5
    out["stair_O"] = mean_on(stair(yo) ** 2, art) ** 0.5
    zone = ((C.plateau_masks(d)["density"].amax(dim=1, keepdim=True) > 0.5) & (~m["tex"])).float()          # where D has plateaus and G has no detail
    # contour visibility: a staircase has the same total variation as a ramp but a strong Laplacian at every step
    lap = lambda y: (4 * y - C._shift(y, 1, 0) - C._shift(y, -1, 0) - C._shift(y, 0, 1) - C._shift(y, 0, -1)).abs()
    curv = lambda y: C.blur(lap(C.blur(y, 1.5 * s)), 1.0 * s + 0.5)
    out["band_T"] = mean_on(curv(C.blur(yg, 4.0 * s)), zone)
    out["band_D"] = mean_on(curv(yd), zone)
    out["band_O"] = mean_on(curv(yo), zone)
    out["band_zone"] = float(zone.mean())
    out["ring_D"] = mean_on((yd - yg).abs(), ring)
    out["ring_O"] = mean_on((yo - yg).abs(), ring)
    out["tex_mad"] = mean_on((yo - yd).abs(), tex)
    out["tex_hf"] = mean_on(hf(yo) ** 2, tex) / max(mean_on(hf(yd) ** 2, tex), 1e-9)
    out["tex_dmae"] = mean_on((yo - yg).abs(), tex) - mean_on((yd - yg).abs(), tex)
    gd, go = C.detect_grid(d), C.detect_grid(o)
    out["grid_D"] = max(gd["x"][2], gd["y"][2])
    out["grid_O"] = max(go["x"][2], go["y"][2])
    out["art_share"] = float(art.mean())
    out["tex_share"] = float(tex.mean())
    return out


# ---- the candidates -----------------------------------------------------------------------------------------------------------

FF = {
    "ff_deblock_weak": "deblock=filter=weak:block=8",
    "ff_deblock_strong": "deblock=filter=strong:block=16",
    "ff_spp": "spp=quality=4:qp=12",
    "ff_uspp": "uspp=quality=4:qp=12",
    "ff_fspp": "fspp=quality=4:qp=12:strength=0",
    "ff_gradfun": "gradfun=strength=1.2:radius=16",
    "ff_deband_5": "deband=1thr=0.02:2thr=0.02:3thr=0.02:range=16:blur=1",
    "ff_deband_2": "deband=1thr=0.008:2thr=0.008:3thr=0.008:range=16:blur=1",
}


def ffmpeg_candidate(name: str, x: torch.Tensor, tag: str) -> torch.Tensor:
    """The picture goes through ffmpeg as raw rgb24 over pipes (4:4:4 inside, so the colour conversion costs next to nothing)."""
    h, w = x.shape[-2:]
    raw = (x.clamp(0, 1) * 255 + 0.5).to(torch.uint8)[0].permute(1, 2, 0).contiguous().cpu().numpy().tobytes()
    chain = "format=yuv444p,format=rgb24" if name == "ff_null444" else f"format=yuv444p,{FF[name]},format=rgb24"
    done = subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{w}x{h}", "-i", "-",
                           "-vf", chain, "-f", "rawvideo", "-pix_fmt", "rgb24", "-"], input=raw, capture_output=True, check=True)
    out = np.frombuffer(done.stdout, np.uint8).reshape(h, w, 3)
    return torch.from_numpy(out.copy()).to(DEV).permute(2, 0, 1)[None].float() / 255.0


def torch_candidates() -> dict:
    def existing(level):
        def run(x, ref, g):
            return C.deband_reference(x, level, g)
        return run
    learned = {}
    if (WORK / "models" / "fbcnn_color.pth").exists():
        import artifact_purge_learned as L
        learned = {
            "fbcnn_blind": lambda x, ref, g: L.fbcnn(x),
            "fbcnn_qf20": lambda x, ref, g: L.fbcnn(x, 20),
            "fbcnn_blind_gated": lambda x, ref, g: L.gate_delta(x, L.fbcnn(x)),
            "fbcnn_qf20_gated": lambda x, ref, g: L.gate_delta(x, L.fbcnn(x, 20)),
        }
    return {
        **learned,
        "deband_light_existing": existing("light"),
        "deband_medium_existing": existing("medium"),
        "plateau_purge": lambda x, ref, g: C.plateau_purge(x),
        "plateau_purge+ref": lambda x, ref, g: C.plateau_purge(x, ref),
        "deblock_gated": lambda x, ref, g: C.deblock_gated(x),
        "ring_suppress": lambda x, ref, g: C.ring_suppress(x),
        "plateau+deblock": lambda x, ref, g: C.deblock_gated(C.plateau_purge(x)),
        "plateau+deblock+ring": lambda x, ref, g: C.ring_suppress(C.deblock_gated(C.plateau_purge(x))),
    }


def all_candidates(only: list[str] | None) -> list[str]:
    names = ["ff_null444", *FF, *torch_candidates()]
    return [n for n in names if not only or n in only]


def apply(name: str, x: torch.Tensor, ref: torch.Tensor | None, tag: str) -> torch.Tensor:
    if name in FF or name == "ff_null444":
        return ffmpeg_candidate(name, x, tag)
    g = torch.Generator(device=DEV)
    g.manual_seed(1234)
    return torch_candidates()[name](x, ref, g)


def clean_change(o: torch.Tensor, g: torch.Tensor) -> dict:
    d = (o - g).abs() * 255.0
    return dict(mean=float(d.mean()), moved_1=float((d.amax(dim=1) >= 0.25).float().mean()), p999=float(torch.quantile(d.flatten()[::97], 0.999)))


def run(frames: list[int], only: list[str] | None, save_for: list[int], tag: str, variants: list[str] | None = None, skip_real: bool = False) -> None:
    results: dict = {}
    for cand in all_candidates(only):
        res = results.setdefault(cand, {"variants": {}, "clean": [], "real": {}})
        for name in (variants or DEGRADE):
            rows = []
            for f in frames:
                g = read(WORK / "in" / f"v8_{f}.png")
                d = read(WORK / "deg" / name / f"{f}.png")
                o = apply(cand, d, d, f"{cand}_{name}_{f}")          # the reference of the controlled test is the degraded frame itself
                rows.append(score(o, d, g, masks_from_clean(g, d)))
                if f in save_for:
                    write(WORK / "out" / cand / name / f"{f}.png", o)
            res["variants"][name] = {k: float(np.nanmean([r[k] for r in rows])) for k in rows[0]}
        for f in frames:
            g = read(WORK / "in" / f"v8_{f}.png")
            res["clean"].append(clean_change(apply(cand, g, g, f"{cand}_clean_{f}"), g))
        for f in ([] if skip_real else REAL_FRAMES):
            for kind in ("src", "v8"):
                x = read(WORK / "in" / f"{kind}_{f}.png")
                ref = read(WORK / "in" / f"src_{f}.png")
                o = apply(cand, x, ref, f"{cand}_real_{kind}_{f}")
                res["real"][f"{kind}_{f}"] = clean_change(o, x)
                if f in save_for:
                    write(WORK / "out" / cand / f"real_{kind}" / f"{f}.png", o)
        print("done", cand, flush=True)
        (WORK / f"results_{tag}.json").write_text(json.dumps(results, indent=1))
    report(results)


def merge_results() -> dict:
    """All results_*.json files, later files (sorted by name) winning per candidate and variant."""
    merged: dict = {}
    for f in sorted(WORK.glob("results_*.json")):
        for cand, r in json.loads(f.read_text()).items():
            into = merged.setdefault(cand, {"variants": {}, "clean": [], "real": {}})
            into["variants"].update(r["variants"])
            into["clean"] = r["clean"] or into["clean"]
            into["real"].update(r["real"])
    return merged


def report(results: dict) -> None:
    for variant in DEGRADE:
        print(f"\n== {variant}: art_lf (D -> O), contour curvature (smooth truth, D -> O), ring (D -> O), grid (D -> O), tex_mad, tex_hf, tex_dmae")
        for cand, r in results.items():
            v = r["variants"].get(variant)
            if v and "band_T" in v:
                print(f"{cand:26s} art_lf {v['art_lf_D']:.2f}->{v['art_lf_O']:.2f}  curv {v['band_T']:.3f},{v['band_D']:.3f}->{v['band_O']:.3f}  ring {v['ring_D']:.2f}->{v['ring_O']:.2f}  "
                      f"grid {v['grid_D']:.3f}->{v['grid_O']:.3f}  tex_mad {v['tex_mad']:.3f}  tex_hf {v['tex_hf']:.3f}  tex_dmae {v['tex_dmae']:+.3f}")
    print("\n== change on clean content (input = the clean frame): mean codes, share moved >= 0.25 code, p99.9 (mean of frames)")
    for cand, r in results.items():
        cl = r["clean"]
        print(f"{cand:26s} mean {np.mean([c['mean'] for c in cl]):.4f}  moved_1 {np.mean([c['moved_1'] for c in cl]) * 100:.3f}%  p99.9 {np.mean([c['p999'] for c in cl]):.2f}")
    print("\n== real frames (no ground truth): share of pixels moved >= 0.25 code")
    for cand, r in results.items():
        print(f"{cand:26s} " + "  ".join(f"{k} {v['moved_1'] * 100:.2f}%" for k, v in r["real"].items()))


# ---- sheets ---------------------------------------------------------------------------------------------------------------------

# name: (frame, kind, crop x y w h at 2160p, candidates). kind is a degraded variant, or real_src / real_v8 (the real draft).
SHEETS = {
    "contours_f900_src": (900, "real_src", (1100, 420, 420, 340), ["plateau_purge", "deband_light_existing", "ff_gradfun", "ff_deband_2"]),
    "contours_f900_v8": (900, "real_v8", (1100, 420, 420, 340), ["plateau_purge", "deband_light_existing", "ff_gradfun", "ff_deband_2"]),
    "banding_f900_bands": (900, "bands", (1100, 420, 420, 340), ["plateau_purge", "deband_light_existing", "ff_gradfun", "ff_deband_2"]),
    "blocky_f1000_x264": (1000, "x264_crf38", (1200, 500, 700, 450), ["deblock_gated", "ff_deblock_strong", "ff_spp", "plateau+deblock+ring"]),
    "ringing_f400_x265": (400, "x265_crf36", (1500, 600, 700, 450), ["ring_suppress", "ff_spp", "ff_fspp", "plateau+deblock+ring"]),
}


def stretch(img: np.ndarray, lo: float, hi: float) -> np.ndarray:
    return (np.clip((img.astype(np.float32) - lo) / max(hi - lo, 1), 0, 1) ** 0.8 * 255).astype(np.uint8)


def label(img: np.ndarray, text: str) -> np.ndarray:
    cv2.rectangle(img, (0, 0), (img.shape[1], 30), (0, 0, 0), -1)
    cv2.putText(img, text, (8, 22), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (255, 255, 255), 1, cv2.LINE_AA)
    return img


def load_crop(path: Path, crop) -> np.ndarray:
    x0, y0, w, h = crop
    img = cv2.imread(str(path), cv2.IMREAD_UNCHANGED)[y0:y0 + h, x0:x0 + w]
    return (img / 257.0).astype(np.float32) if img.dtype == np.uint16 else img.astype(np.float32)


def sheets(only: list[str] | None) -> None:
    for name, (frame, kind, crop, cands) in SHEETS.items():
        if only and name not in only:
            continue
        controlled = kind in DEGRADE
        src_path = WORK / "deg" / kind / f"{frame}.png" if controlled else WORK / "in" / f"{kind[5:]}_{frame}.png"
        panels = [("input" if not controlled else f"degraded {kind}", load_crop(src_path, crop))]
        if controlled:
            panels.insert(0, ("clean (ground truth)", load_crop(WORK / "in" / f"v8_{frame}.png", crop)))
        base = panels[-1][1]
        for cand in cands:
            path = WORK / "out" / cand / (kind if controlled else kind) / f"{frame}.png"
            if path.exists():
                panels.append((cand, load_crop(path, crop)))
        luma = base.mean(axis=2)
        lo, hi = np.percentile(luma, 1), np.percentile(luma, 97)
        zoom = 2 if crop[2] <= 450 else 1
        z = lambda img: cv2.resize(img, None, fx=zoom, fy=zoom, interpolation=cv2.INTER_NEAREST) if zoom > 1 else img
        panels = [(t, z(p)) for t, p in panels]
        base = panels[1][1] if controlled else panels[0][1]
        top = np.hstack([label(stretch(p, lo, hi), t) for t, p in panels])
        diff = np.hstack([label(np.clip(np.abs(p - base).mean(axis=2, keepdims=True).repeat(3, 2) * 24, 0, 255).astype(np.uint8), f"|{t} - input| x24") for t, p in panels])
        out = WORK / "sheets" / f"{name}.png"
        out.parent.mkdir(parents=True, exist_ok=True)
        cv2.imwrite(str(out), np.vstack([top, diff]))
        print("sheet", out, flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["degrade", "run", "report", "sheets"])
    ap.add_argument("--frames", default=",".join(map(str, FRAMES)))
    ap.add_argument("--only", default="")
    ap.add_argument("--save-for", default="900,1000")
    ap.add_argument("--variants", default="")
    ap.add_argument("--skip-real", action="store_true")
    ap.add_argument("--tag", default="main", help="results land in /work/results_<tag>.json")
    a = ap.parse_args()
    if a.command == "degrade":
        degrade()
    elif a.command == "run":
        run([int(v) for v in a.frames.split(",")], [v for v in a.only.split(",") if v] or None, [int(v) for v in a.save_for.split(",") if v], a.tag, [v for v in a.variants.split(",") if v] or None, a.skip_real)
    elif a.command == "sheets":
        sheets([v for v in a.only.split(",") if v])
    else:
        report(merge_results())
