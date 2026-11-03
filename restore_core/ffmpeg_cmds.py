"""Typed ffmpeg command builders for the restoration pipeline.

Every argument comes from a validated recipe field (numbers and enums) or from a path the worker
itself created inside its RAM-backed work directory. No client-supplied string ever reaches a
command line, so there is nothing to inject into and no whitelist to keep in step with ffmpeg.

Three commands: probe, decode (to raw RGB frames), encode (raw 16-bit RGB in, 10-bit AV1 out).
The worker holds the pictures in memory and pipes them; nothing is written to disk in between.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from restore_core.recipe import EffectiveRecipe

FFMPEG = "ffmpeg"
FFPROBE = "ffprobe"

PREFILTER_CHAINS = {
    # hqdn3d luma_spatial:chroma_spatial:luma_temporal:chroma_temporal. Deterministic, cannot hallucinate.
    "none": [],
    "light": ["hqdn3d=1.5:1.2:3:2.5"],
    "medium": ["hqdn3d=3:2.5:5:4"],
    "strong": ["hqdn3d=5:4:8:6"],
}


@dataclass(frozen=True)
class SourceInfo:
    width: int
    height: int
    fps_num: int
    fps_den: int
    frames: int | None = None
    color_matrix: str = "bt709"       # bt601 | bt709 | bt2020nc
    color_range: str = "tv"           # tv | pc
    color_transfer: str = "bt709"
    color_primaries: str = "bt709"

    @property
    def fps(self) -> str:
        return f"{self.fps_num}/{self.fps_den}"


def probe_cmd(path: Path) -> list[str]:
    return [FFPROBE, "-v", "error", "-select_streams", "v:0", "-count_frames",
            "-show_entries", "stream=width,height,r_frame_rate,nb_read_frames,color_space,color_range,color_transfer,color_primaries",
            "-of", "json", str(path)]


def guess_matrix(info_matrix: str | None, height: int) -> str:
    """Use the stream's matrix when it is one we handle, else the usual convention: SD is BT.601."""
    if info_matrix in ("bt709", "bt601", "smpte170m", "bt470bg", "bt2020nc"):
        return {"smpte170m": "bt601", "bt470bg": "bt601"}.get(info_matrix, info_matrix)
    return "bt601" if height <= 576 else "bt709"


def decode_cmd(src: Path, info: SourceInfo, recipe: EffectiveRecipe, *, frames: int | None = None) -> list[str]:
    """Decode to raw rgb24 on stdout, with the recipe's classical pre-filter applied at source size."""
    chain = list(PREFILTER_CHAINS[recipe.advanced.prefilter.mode])
    if recipe.advanced.prefilter.deblock:
        chain.append("deblock=filter=strong:block=8")
    # The matrix and range are stated explicitly: swscale's guess is wrong for 10-bit HD sources often enough to matter.
    chain.append(f"scale=in_color_matrix={info.color_matrix}:in_range={'tv' if info.color_range == 'tv' else 'pc'}:out_range=pc:flags=bicubic+accurate_rnd+full_chroma_int")
    chain.append("format=rgb24")
    # passthrough: exactly the frames the container holds, never duplicated or dropped to fit a guessed constant frame rate
    cmd = [FFMPEG, "-v", "error", "-nostdin", "-i", str(src), "-an", "-sn", "-dn", "-vf", ",".join(chain), "-fps_mode", "passthrough"]
    if frames is not None:
        cmd += ["-frames:v", str(frames)]
    return cmd + ["-f", "rawvideo", "-"]


# HDR10 signalling for SVT-AV1 (BT.2020 primaries, PQ transfer, BT.2020 non-constant-luminance matrix).
HDR10_PARAMS = ["color-primaries=9", "transfer-characteristics=16", "matrix-coefficients=9"]
BT709_PARAMS = ["color-primaries=1", "transfer-characteristics=1", "matrix-coefficients=1"]
# Mastering display of the common P3-D65 grade: G R B white point, then max/min luminance (SVT-AV1 syntax).
MASTERING_P3D65 = "mastering-display=G(0.265,0.690)B(0.150,0.060)R(0.680,0.320)WP(0.3127,0.3290)L({max_nits},0.0001)"


def encode_cmd(out: Path, width: int, height: int, fps: str, recipe: EffectiveRecipe, *, hdr10: bool,
               max_cll: int = 1000, max_fall: int = 400) -> list[str]:
    """Raw rgb48le on stdin to a 10-bit AV1 stream in Matroska, closed GOP so segments concatenate cleanly."""
    adv = recipe.advanced
    params = [f"tune={adv.encode.tune}", f"enable-variance-boost={1 if adv.encode.variance_boost else 0}",
              "irefresh-type=2"]                                   # IDR at the start: independent segments
    if adv.encode.ac_bias > 0:
        params.append(f"ac-bias={adv.encode.ac_bias:g}")
    if adv.encode.quant_matrices:
        params.append("enable-qm=1")
    if adv.grain.mode == "av1_fgs" and recipe.basic.grain == "auto":
        params += [f"film-grain={adv.grain.fgs_level}", f"film-grain-denoise={1 if adv.grain.fgs_denoise else 0}"]
    if hdr10:
        params += HDR10_PARAMS
        params += [MASTERING_P3D65.format(max_nits=adv.hdr.peak_nits), f"content-light={max_cll},{max_fall}"]
        matrix, primaries, trc = "bt2020nc", "bt2020", "smpte2084"
    else:
        params += BT709_PARAMS
        matrix, primaries, trc = "bt709", "bt709", "bt709"
    # setparams tags the frames themselves: in current ffmpeg the encoder takes its colour description from the
    # frames it receives, and the command-line flags below alone leave primaries and transfer unset in the container.
    vf = (f"scale=out_color_matrix={matrix}:out_range=tv:flags=bicubic+accurate_rnd+full_chroma_int,"
          f"setparams=colorspace={matrix}:color_primaries={primaries}:color_trc={trc}:range=tv,format=yuv420p10le")
    return [
        FFMPEG, "-v", "error", "-nostdin", "-y",
        "-f", "rawvideo", "-pix_fmt", "rgb48le", "-s", f"{width}x{height}", "-r", fps, "-i", "-",
        "-vf", vf,
        "-c:v", "libsvtav1", "-preset", str(recipe.encoder_preset), "-crf", str(recipe.encoder_crf),
        "-pix_fmt", "yuv420p10le", "-svtav1-params", ":".join(params),
        # The same colour description at container level: players and ffprobe read the Matroska tags first.
        "-colorspace", matrix, "-color_primaries", primaries, "-color_trc", trc, "-color_range", "tv",
        "-f", "matroska", str(out),
    ]
