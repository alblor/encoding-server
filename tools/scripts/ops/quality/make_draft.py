"""Build a labelled side-by-side draft video (and a few still frames) from several versions of one clip.

Every panel is the same frames: timestamps are rebuilt from the frame index at --fps, so a writer
that stamped 16 fps (SparkVSR's script) lines up with 24 fps ones. The lead panel is the input
upscaled with Lanczos, the baseline any restoration has to beat. Needs ffmpeg and Pillow on the Mac;
local ffmpeg has no drawtext, so labels are drawn with Pillow and overlaid.

usage: uv run --with pillow python make_draft.py OUT_DIR INPUT.mp4 NAME=VIDEO.mp4 [NAME=VIDEO.mp4 ...]
       [--fps 24] [--panel-width 640] [--stills 24,120,240]
Writes OUT_DIR/draft.mp4 (H.264, CRF 14) and OUT_DIR/still_fNNN.png for each requested frame.
"""
import argparse
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def probe(path: str) -> tuple[int, int]:
    out = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                          "stream=width,height", "-of", "csv=p=0", path],
                         capture_output=True, text=True, check=True).stdout.strip()
    w, h = out.split(",")
    return int(w), int(h)


def label_bar(names: list[str], panel_w: int, height: int = 44) -> Image.Image:
    bar = Image.new("RGBA", (panel_w * len(names), height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(bar)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 26)
    except OSError:
        font = ImageFont.load_default()
    for i, name in enumerate(names):
        draw.rectangle([i * panel_w, 0, (i + 1) * panel_w, height], fill=(0, 0, 0, 170))
        draw.text((i * panel_w + 14, 8), name, fill=(255, 255, 255, 255), font=font)
    return bar


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("source")
    ap.add_argument("versions", nargs="+", help="NAME=VIDEO")
    ap.add_argument("--fps", type=int, default=24)
    ap.add_argument("--panel-width", type=int, default=640)
    ap.add_argument("--stills", default="")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    named = [("Lanczos baseline", args.source)] + [tuple(v.split("=", 1)) for v in args.versions]
    ow, oh = probe(named[1][1])
    pw = args.panel_width
    ph = round(oh * pw / ow / 2) * 2
    bar_path = out / "labels.png"
    label_bar([n for n, _ in named], pw).save(bar_path)

    inputs: list[str] = []
    chains: list[str] = []
    for i, (_, path) in enumerate(named):
        inputs += ["-i", path]
        # Frame index drives time, so differing writer fps never desynchronise the panels.
        chains.append(f"[{i}:v]setpts=N/({args.fps}*TB),scale={ow}:{oh}:flags=lanczos,"
                      f"scale={pw}:{ph}:flags=lanczos,format=yuv420p[p{i}]")
    stack = "".join(f"[p{i}]" for i in range(len(named))) + f"hstack={len(named)}[row]"
    graph = ";".join(chains + [stack, f"[row][{len(named)}:v]overlay=0:0:shortest=1[v]"])

    subprocess.run(["ffmpeg", "-v", "error", "-y", *inputs, "-loop", "1", "-i", str(bar_path), "-filter_complex", graph,
                    "-map", "[v]", "-r", str(args.fps), "-c:v", "libx264", "-preset", "slow", "-crf", "14", "-pix_fmt", "yuv420p",
                    "-movflags", "+faststart", str(out / "draft.mp4")], check=True)
    print(f"wrote {out / 'draft.mp4'}")

    for n in [s for s in args.stills.split(",") if s]:
        subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(out / "draft.mp4"),
                        "-vf", f"select=eq(n\\,{n})", "-frames:v", "1", str(out / f"still_f{int(n):03d}.png")],
                       check=True)
        print(f"wrote still_f{int(n):03d}.png")


if __name__ == "__main__":
    main()
