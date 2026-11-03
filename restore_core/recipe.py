"""The restoration recipe: the one contract between the client, the API and the GPU worker.

Three layers, each documented in /v1/docs:
  preset    a named starting point that fills the whole recipe (what most people pick)
  basic     a deliberately short set of choices (engine, target size, quality, HDR, grain, encryption)
  advanced  the troubleshooting and optimisation tier: every field has a safe default, is validated
            and bounded, and is never passed through to a shell as a string

A request carries a preset and/or overrides. `resolve()` turns it into an EffectiveRecipe with every
field filled in, which the API returns with the job so a run can be reproduced exactly.
Unknown keys are rejected at every level, so a typo can never silently fall back to a default.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

RECIPE_VERSION = 1


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --- basic ---------------------------------------------------------------------------------------

Engine = Literal["recavsr", "sparkvsr", "classical", "none"]
Quality = Literal["draft", "standard", "high", "maximum"]
# "preserve" (keep an HDR source as it is) is deliberately absent: PQ sources need their own handling and tests, and the
# schema offers only what works, so an unsupported request is refused at submit time instead of failing in a worker.
HdrMode = Literal["off", "synthesize"]
GrainBasic = Literal["off", "auto"]
Encryption = Literal["automated", "manual", "off"]
AudioSubs = Literal["copy", "drop"]


class Basic(_Strict):
    engine: Engine = Field("recavsr", description="Restoration engine. 'none' only re-encodes; 'classical' is the CPU path.")
    target_height: int = Field(2160, ge=240, le=4320, description="Output height in pixels. The width follows the source aspect ratio.")
    quality: Quality = Field("high", description="Encoder quality level: the single knob most people should touch.")
    hdr: HdrMode = Field("off", description="off keeps SDR; synthesize maps SDR to HDR10 (static BT.2408 mapping: SDR white at 203 nits, BT.2020, PQ). HDR sources are not supported yet.")
    grain: GrainBasic = Field("auto", description="auto re-adds film grain after restoration; off leaves the picture clean.")
    encryption: Encryption = Field("automated", description="Transport encryption of the media. 'off' still keeps media in RAM only.")
    audio_subs: AudioSubs = Field("copy", description="Keep the original audio and subtitles untouched, or drop them.")


# --- advanced ------------------------------------------------------------------------------------

class Restore(_Strict):
    scale: Optional[float] = Field(None, gt=0, le=8, description="Override the scale factor. Default: target height over source height (1 for native 2160p).")
    precision: Optional[Literal["bf16", "fp8", "fp8_fast"]] = Field(None, description="Transformer precision the job requires. Unset means whatever the worker runs (set per worker with RESTORE_PRECISION, default bf16: the reference quality). A worker that runs another precision fails the job instead of changing the picture quietly. fp8: about 1.4x faster transformer and 3.5 GiB less VRAM, needs torch.compile, 46.8 dB against bf16 on detailed 49-frame clips and the error grows along a segment (it resets at each cut). fp8_fast: older per-tensor variant, slower than fp8, kept for comparison.")
    tile_height: int = Field(1152, ge=256, le=2048, multiple_of=32, description="Tile height in pixels at target size.")
    tile_width: int = Field(1344, ge=256, le=2048, multiple_of=32, description="Tile width in pixels at target size.")
    min_overlap: int = Field(96, ge=32, le=512, multiple_of=32, description="Overlap between neighbouring tiles; a larger overlap hides seams and costs time.")
    color_fix: Literal["none", "wavelet", "adain"] = Field("none", description="Pull the restored colours back towards the source.")
    decoder: Literal["flashdecoder", "wan"] = Field("flashdecoder", description="ReCaVSR decoder. 'wan' is slower and needs more memory.")
    seed: int = Field(42, ge=0, le=2**31 - 1, description="Noise seed. The same seed gives the same pixels.")
    segment_max_seconds: float = Field(8.0, ge=2, le=30, description="Longest piece handled in one go: bounds the RAM a worker needs.")

    @model_validator(mode="after")
    def _tile_larger_than_overlap(self):
        if self.min_overlap >= min(self.tile_height, self.tile_width):
            raise ValueError("min_overlap must be smaller than the tile")
        return self


class Prefilter(_Strict):
    mode: Literal["none", "light", "medium", "strong"] = Field("none", description="Gentle classical clean-up before the engine (hqdn3d, optional deblock). Never learned, never hallucinates.")
    deblock: bool = Field(False, description="Also run a deblocking filter (block size 8): for heavily compressed sources.")


class Bitdepth(_Strict):
    deband: Literal["off", "light", "medium", "strong"] = Field("light", description="Smooth banding in flat gradients before the 10-bit conversion.")
    plateau_purge: float = Field(0.0, ge=0, le=1, description="Smooth banding and posterised contour patches (the staircases a low-quality encode leaves in dark walls, skies and fog) and nothing else. A pixel is touched only inside a wide staircase that spans a few grey levels and holds no line: grain, texture, edges and flat areas are exactly as they were, which `deband` cannot promise (it averages anything within a threshold and flattens dark texture). 1 is full strength, 0 is off. Blocking and ringing are not handled: measured, they cannot be removed without losing detail.")
    dither: bool = Field(True, description="Dither when converting to 10-bit so gradients do not step.")
    anchor_source: Literal["off", "lowfreq"] = Field("off", description="For 10-bit sources: pull smooth tones back to the source's own 10-bit values.")


class Grain(_Strict):
    mode: Literal["none", "auto", "baked", "source", "av1_fgs"] = Field("auto", description="auto: keep the original's own grain when the source has some (source, or matched to its measured level after an upscale), otherwise synthesise film-like grain (baked, at `strength`); baked: film-like grain synthesised into the pixels (irregular, works on every player, costs bitrate); source: carry the source's own grain over onto the restored picture (as close to the original as it gets; same-size sources only, after an upscale the grain residual is upscaled with the picture, bicubically, and nothing else is changed); av1_fgs: give the encoder a grained picture so it signals the grain for the decoder to re-create (cheap, but AV1's synthesis repeats a small template, so it looks regular at higher strengths, and it needs a decoder that applies it); none: leave the picture clean.")
    strength: float = Field(0.4, ge=0, le=1, description="Grain strength, 0 to 1, for SYNTHETIC grain: baked: the grain amplitude; av1_fgs: the grain given to the encoder to estimate (the original's grain is set by source_strength). Measured on real footage: with av1_fgs at level 8, strength 1.0 made the file 5 times larger.")
    source_strength: float = Field(1.0, ge=0, le=1.5, description="How much of the ORIGINAL's grain to bring back when the source has some (modes auto and source): 1 is the original's own level, 0.5 half of it. Same-size sources get their own grain back pixel for pixel; after an upscale that residual is upscaled with the picture, bicubically.")
    size: float = Field(1.0, ge=0.5, le=3.0, description="Grain size for baked and av1_fgs: larger is coarser.")
    shadow_weight: float = Field(0.12, ge=0, le=1, description="Synthetic grain (baked): how much of its full amplitude it keeps at pure black, between 0 and 1. Film grain is as visible in the shadows as anywhere, but the AV1 encode throws away anything faint in dark flat areas, which then turn into flat patches: raising this puts back more there. The default 0.12 fades the grain almost out at black.")
    fgs_level: int = Field(20, ge=0, le=50, description="SVT-AV1 film-grain level when mode is av1_fgs: how hard the encoder denoises before it signals the grain. Higher levels gave smaller files and smoother gradients on the test footage (level 20 to 40); the SVT-AV1 documentation suggests about 8 for plain live action.")
    fgs_denoise: bool = Field(True, description="av1_fgs only: encode the denoised picture and rely on the signalled grain. Turning it off codes the noise too.")


class Fidelity(_Strict):
    soften: Literal["off", "match", "adaptive"] = Field("off", description="adaptive: limit the model's excess detail band by band and place by place, but only where the original gives no support for it: where the source has structure at that scale the model's detail is kept (tolerated up to `adaptive_tolerance` times the source's energy, more where supported), where the source is flat or the model went far beyond it, it is pulled back. Luma only (colour is untouched), needs a same-size source, and follows the source frame by frame, so it cannot make seams. match: soften the restored picture to the original's level where the model added more mid-frequency detail than the source ever had. Needs a source of the same size (same-size cleanup); otherwise it is skipped.")
    soften_amount: float = Field(0.8, ge=0, le=1, description="How far to go towards the original's softness: 0 changes nothing, 1 matches the original's spectrum band by band. A light value keeps recovered detail.")
    anchor: Literal["off", "source"] = Field("off", description="source: pull the picture's brightness and colour at coarse scale (cells of about 16 px) back to the original's. The model drifts in brightness along a segment and starts over at every cut, which shows as a flicker (up to 3.5 grey levels at the cuts of a real draft); the original's coarse level has no such drift. Detail finer than a cell is not touched. Works on any source size.")
    anchor_amount: float = Field(0.9, ge=0, le=1, description="How much of the coarse BRIGHTNESS difference to remove: 1 makes the coarse brightness equal to the original's, 0 changes nothing.")
    anchor_chroma_amount: float = Field(0.35, ge=0, le=1, description="The same for the coarse COLOUR (what is left once brightness is taken out). Lower than the brightness amount on purpose: the model's colour extension and saturation are usually welcome, its brightness drift is not.")
    glow: float = Field(0.0, ge=0, le=1, description="Bring back the original's bloom around bright lights (halation, diffusion filter, soft highlights) that the model draws tighter. Measured on the original in linear light at one width (`glow_sigma`) and added back only near highlights, so everything finer than that width, and every area away from a light, stays exactly as the model made it. Needs a same-size source. 1 matches the original's glow, 0 is off.")
    glow_sigma: float = Field(4.0, ge=1.0, le=16.0, description="glow: width in pixels, at 2160 lines (scaled with the picture), of the bloom that is matched. Detail narrower than this is never touched.")
    adaptive_tolerance: float = Field(1.2, ge=1.0, le=3.0, description="adaptive softening: how many times the source's local energy in a band the model may have before it is pulled back (1.2 is about 1.6 dB).")
    adaptive_keep: float = Field(0.7, ge=0, le=1, description="adaptive softening: how much more is tolerated where the source has real structure at that scale (0 pulls back the same everywhere, 1 tolerates up to double).")
    adaptive_min_gain: float = Field(0.5, ge=0.1, le=1, description="adaptive softening: the most a band may be turned down, so that a flat area is never blanked.")
    face_guard: Literal["off", "on", "zoom"] = Field("off", description="zoom: the small faces are REDRAWN by the restoration model itself on a zoomed crop of the tracked face (the face is enlarged 4x, so it is at the size the model was trained for), then pasted back with the same soft mask: natural, consistent faces, but at 40 to 60 px the original holds almost no information about the person, so the face is plausible and not necessarily the real features. GPU engine recavsr only (otherwise it behaves as on). on: inside SMALL faces (the model has no detail to recover there and invents wrong eyes and mouths, the uncanny valley) the output is blended back towards the original. The strength falls smoothly with the face size: full for a face under 4 percent of the picture height, nothing from 15 percent up, so close-ups keep all of the model's detail. Needs the face detector model next to the weights (scripts/stage_restore_weights.sh) and a same-size source.")
    face_guard_amount: float = Field(0.7, ge=0, le=1, description="face_guard: how much of the original is blended in on the smallest faces: 1 is the original's own pixels.")
    face_zoom_mix: float = Field(0.8, ge=0, le=1, description="face_guard zoom: share of the redrawn face in the paste, the rest is the original's own pixels (0.8 means 80 percent redrawn and 20 percent original, which keeps the subject more natural than the redrawn face alone).")
    soften_mask: bool = Field(True, description="Apply the softening only where the restored picture has clearly more mid-band detail than the source (a light, local merge), so real recovered detail is left alone.")


class Hdr(_Strict):
    peak_nits: int = Field(1000, ge=203, le=4000, description="Target peak luminance when synthesizing HDR.")
    reference_white_nits: int = Field(203, ge=80, le=400, description="Where SDR white lands in the HDR range.")

    @model_validator(mode="after")
    def _white_below_peak(self):
        if self.reference_white_nits > self.peak_nits:
            raise ValueError(f"reference_white_nits ({self.reference_white_nits}) cannot be above peak_nits ({self.peak_nits})")
        return self


class Encode(_Strict):
    preset: Optional[int] = Field(None, ge=0, le=10, description="SVT-AV1 preset (lower is slower and smaller). Default follows the quality level.")
    crf: Optional[int] = Field(None, ge=10, le=50, description="Constant rate factor. Default follows the quality level.")
    tune: Literal[0, 1, 2, 4] = Field(0, description="SVT-AV1 4.x tune: 0 visual quality (default), 1 PSNR, 2 SSIM, 4 MS-SSIM. Tune 3 (IQ) is for still images and the encoder refuses it on video.")
    variance_boost: bool = Field(True, description="SVT-AV1 variance boost: better detail in flat areas.")
    ac_bias: float = Field(0.0, ge=0, le=8, description="SVT-AV1 ac-bias: how much the encoder protects texture (the AC energy of a block) against its rate-distortion trade-off. 0 is the encoder's default. Measured on a very dark 2160p shot: at 1.0 together with quant_matrices, flat patches in the shadows fell from 34 to 19 percent of the dark pixels for 16 percent more bits.")
    quant_matrices: bool = Field(False, description="SVT-AV1 enable-qm: quantisation matrices, which quantise the fine detail less coarsely than the coarse detail. A normative AV1 tool that hardware decoders support.")


class Tone(_Strict):
    contrast: float = Field(0.0, ge=0, le=1, description="Global contrast curve (an S around `pivot` that leaves pure black and pure white where they are, and that is limited so that contrast x pivot and contrast x (1 - pivot) stay under 0.15, which keeps the slopes at black and at white above 0.4): darks get deeper and lights brighter, smoothly, so the range really widens instead of the blacks just sinking. 0.2 to 0.3 is clearly visible. It runs after the anchor, so scene brightness stays tied to the original and nothing drifts.")
    pivot: Optional[float] = Field(None, ge=0.02, le=0.9, description="Brightness (0 to 1, display-referred) the contrast curve turns around: darker values get darker, lighter values lighter. Unset means the scene's own median brightness, measured on the source once per segment, so a dark scene is not pushed darker as a whole and a bright one not brighter: only its range widens. A fixed value darkens every scene whose average lies below it.")
    local_contrast: float = Field(0.0, ge=0, le=1, description="Large-scale local contrast (clarity): each area is pushed away from the average of its surroundings (about 3 percent of the picture height wide), damped near black and white. Adds depth to flat-looking scenes; too much shows halos.")
    saturation: float = Field(1.0, ge=0.5, le=1.5, description="Colour saturation after the curve, 1 leaves it alone.")


class Advanced(_Strict):
    restore: Restore = Restore()
    prefilter: Prefilter = Prefilter()
    bitdepth: Bitdepth = Bitdepth()
    grain: Grain = Grain()
    fidelity: Fidelity = Fidelity()
    tone: Tone = Tone()
    hdr: Hdr = Hdr()
    encode: Encode = Encode()


# --- presets -------------------------------------------------------------------------------------

# What keeps the textures of dark areas through the AV1 encode (measured on a very dark 2160p shot of the owner's draft, 24 frames:
# flat patches among the dark pixels after the encode, 34 percent with the old settings, 8.9 percent with these, at about 50 percent
# more bits in that shot): no debanding (it smoothed the faint texture away), grain that keeps 35 percent of its amplitude at black
# instead of 12, and an encoder that protects texture (ac-bias) and quantises fine detail less coarsely (quantisation matrices).
SHADOW_TEXTURE = {
    "bitdepth": {"deband": "off"},
    "grain": {"shadow_weight": 0.35},
    "encode": {"ac_bias": 1.0, "quant_matrices": True},
}

# Each preset is a partial request: only what differs from the defaults above.
PRESETS: dict[str, dict] = {
    "film-restoration": {
        "description": "Old or compressed film: restore at the target size, re-add grain, 10-bit.",
        "basic": {"engine": "recavsr", "target_height": 2160, "quality": "high", "grain": "auto"},
        "advanced": {"fidelity": {"anchor": "source"}, **SHADOW_TEXTURE},
    },
    "cleanup-4k": {
        "description": "Native 2160p source with compression artifacts or noise: same-size cleanup.",
        "basic": {"engine": "recavsr", "target_height": 2160, "quality": "high", "grain": "auto"},
        # 6 s, not 8: a native 2160p segment keeps the source and the restored frames in RAM beside the AV1 encoder, and 241 frames
        # peaked at 24.3 GiB on the real worker (161 frames: 16.5 GiB). At 6 s a 30 fps film stays under the 22 GiB worker limit.
        "advanced": {
            "restore": {"scale": 1.0, "segment_max_seconds": 6.0}, "prefilter": {"mode": "light"},
            # Chosen on the owner's draft: the model's detail kept where the original supports it (adaptive), brightness tied to the
            # original, a modest contrast curve and a little saturation, and the original blended back into small faces.
            "fidelity": {"soften": "adaptive", "soften_amount": 1.0, "anchor": "source", "face_guard": "zoom", "face_guard_amount": 1.0, "face_zoom_mix": 0.8,
                         # Bloom around lights, measured on the original and added back (additive only, near highlights only).
                         "glow": 1.0},
            "tone": {"contrast": 0.2, "saturation": 1.06},
            **SHADOW_TEXTURE,
        },
    },
    "clean-4k": {
        "description": "Native 2160p source that is already clean: no restoration, just encode.",
        "basic": {"engine": "none", "target_height": 2160, "quality": "high", "grain": "off"},
        "advanced": {"bitdepth": {"deband": "off"}},
    },
    "budget": {
        "description": "No GPU or a quick pass: classical upscale and a lighter encode.",
        "basic": {"engine": "classical", "target_height": 2160, "quality": "standard", "grain": "off"},
        # Half-length segments: the CPU path holds a whole segment at target size in RAM, about 5 GB for 8 s of 2160p.
        "advanced": {"restore": {"segment_max_seconds": 4.0}},
    },
    "draft": {
        "description": "Short clips to judge a setting: smaller target and a fast encode.",
        "basic": {"engine": "recavsr", "target_height": 1080, "quality": "draft", "grain": "off"},
    },
}

QUALITY_TABLE = {            # quality -> (SVT-AV1 preset, CRF); provisional until the CRF ladder on real clips
    "draft": (8, 34),
    "standard": (6, 28),
    "high": (4, 24),
    "maximum": (2, 20),
}


# --- request and resolution ----------------------------------------------------------------------

class BasicOverrides(_Strict):
    engine: Optional[Engine] = None
    target_height: Optional[int] = Field(None, ge=240, le=4320)
    quality: Optional[Quality] = None
    hdr: Optional[HdrMode] = None
    grain: Optional[GrainBasic] = None
    encryption: Optional[Encryption] = None
    audio_subs: Optional[AudioSubs] = None


class RecipeRequest(_Strict):
    """What a client sends: a preset and/or overrides. Advanced is a free-form tree validated on resolve()."""

    recipe_version: Literal[1] = 1
    preset: Optional[str] = None
    basic: BasicOverrides = BasicOverrides()
    advanced: dict = Field(default_factory=dict)


class EffectiveRecipe(_Strict):
    """Every field filled in. This is what runs, and what the API echoes back."""

    recipe_version: Literal[1] = 1
    preset: Optional[str] = None
    basic: Basic
    advanced: Advanced

    @property
    def encoder_preset(self) -> int:
        return self.advanced.encode.preset if self.advanced.encode.preset is not None else QUALITY_TABLE[self.basic.quality][0]

    @property
    def encoder_crf(self) -> int:
        return self.advanced.encode.crf if self.advanced.encode.crf is not None else QUALITY_TABLE[self.basic.quality][1]

    @model_validator(mode="after")
    def _consistent(self):
        if self.basic.engine == "none" and self.advanced.restore.scale not in (None, 1.0):
            raise ValueError("engine 'none' does not resize with the restoration engine; use 'classical' to scale")
        if self.basic.hdr == "synthesize" and self.basic.engine == "none" and self.basic.target_height > 2160:
            raise ValueError("target_height above 2160 is not supported with HDR synthesis")
        if self.advanced.grain.mode == "av1_fgs" and self.advanced.grain.fgs_level == 0 and self.basic.grain == "auto":
            raise ValueError("grain 'auto' with av1_fgs needs fgs_level above 0")
        return self


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for key, value in over.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


def resolve(request: RecipeRequest | dict) -> EffectiveRecipe:
    """Preset, then basic overrides, then advanced overrides; validate the result as a whole."""
    req = request if isinstance(request, RecipeRequest) else RecipeRequest.model_validate(request)
    base: dict = {}
    if req.preset is not None:
        if req.preset not in PRESETS:
            raise ValueError(f"unknown preset {req.preset!r}; available: {', '.join(sorted(PRESETS))}")
        base = {k: v for k, v in PRESETS[req.preset].items() if k != "description"}
    basic = _merge(base.get("basic", {}), req.basic.model_dump(exclude_none=True))
    advanced = _merge(base.get("advanced", {}), req.advanced)
    return EffectiveRecipe(recipe_version=RECIPE_VERSION, preset=req.preset, basic=basic, advanced=advanced)


def effective_scale(recipe: EffectiveRecipe, source_height: int) -> float:
    """Scale the engine applies: the override if set, else target height over source height, never below 1."""
    if recipe.advanced.restore.scale is not None:
        return recipe.advanced.restore.scale
    return max(1.0, recipe.basic.target_height / source_height)
