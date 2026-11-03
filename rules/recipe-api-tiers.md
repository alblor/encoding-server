# Recipe tiers: presets, basic block, advanced block (FEATURE-036)

Owner decision of 2026-10-30, implemented the same day in `restore_core/recipe.py` (22 unit tests) and exposed through `/v1/restore` (`api/app/restore/`). QC is pending, so FEATURE-036 is in `review`.

The recipe is the public contract of the job endpoint. The owner wanted a small surface and a deep underneath, so it has three layers, documented in `/v1/docs` the way the existing endpoints are (every field with type, default, allowed values, effect and cost). The documentation text is GENERATED from the pydantic schema in `api/app/documentation.py`, so the docs cannot drift from the code: change a field, and the docs change with it.

## The rules the code enforces

- A request with only a preset, or only the basic block, is valid; unknown keys are rejected at every level (`extra="forbid"`), so a typo never falls back to a default silently.
- Resolution order: preset, then basic overrides, then advanced overrides, then the whole result is validated again. `POST /v1/restore/recipe/resolve` returns the EffectiveRecipe without queueing anything, and every job returns its effective recipe, so a run can be reproduced.
- Advanced fields are bounded numbers and enums, never passed through as strings (same principle as `restore_core/ffmpeg_cmds.py`).
- Cross-field checks: `engine none` cannot rescale; HDR synthesis above 2160p is refused; `grain auto` with `av1_fgs` needs `fgs_level` above 0; the tile must be larger than the overlap.

## Presets

`film-restoration` (old or compressed film, restore at target size, grain, 10-bit), `cleanup-4k` (native 2160p with artifacts: scale 1 and a light prefilter), `clean-4k` (no restoration, only encode), `budget` (classical upscale, lighter encode, no GPU), `draft` (1080p target, fast encode, to judge a setting).

## Basic block (short on purpose)

`engine` (recavsr, sparkvsr, classical, none), `target_height` (240 to 4320), `quality` (draft, standard, high, maximum, mapped to an SVT-AV1 preset and CRF: provisional until the CRF ladder on real clips), `hdr` (off, synthesize; `preserve` left the schema on 2026-10-31 because no job with it could succeed, so an unsupported value is a 422 at submit), `grain` (off, auto), `encryption` (automated, manual, off), `audio_subs` (copy, drop).

## Advanced block (troubleshooting and optimisation)

Sections `restore` (scale, precision: Optional, unset means whatever the worker runs (env `RESTORE_PRECISION`, default bf16), values `bf16 | fp8 | fp8_fast`, a worker with another precision fails the job, tile size and minimum overlap, color_fix, decoder, seed, `segment_max_seconds`), `prefilter` (hqdn3d level, deblock), `bitdepth` (deband, dither, `anchor_source` planned and NOT implemented, MIN-051), `grain` (mode none, baked, source or av1_fgs, and in the current tree `auto`; strength, size, `fgs_level`, `fgs_denoise`), `fidelity` (`soften` off or match, `soften_amount` default 0.8, `soften_mask`: the softness match of MIN-056; `anchor` off or source and `anchor_amount` 0.9: the brightness anchor of ISSUE-069; `soften=match` and `anchor=source` in `cleanup-4k`, the anchor also in `film-restoration`), `hdr` (peak nits, reference white nits), `encode` (preset, crf, tune 0/1/2/4, variance boost). Added 2026-10-31 (night): `fidelity.soften` also takes `adaptive` (`adaptive_tolerance` 1.2, `adaptive_keep` 0.7, `adaptive_min_gain` 0.5), `anchor_chroma_amount` 0.35, `face_guard off|on|zoom` with `face_guard_amount` (0.7, 1.0 in `cleanup-4k`), grain `source_strength` up to 1.5 and a new `tone` section (`contrast`, `pivot`, `local_contrast`, `saturation`). `cleanup-4k` is now soften adaptive 1.0, anchor source, `face_guard` zoom 1.0 with `face_zoom_mix` 0.8, tone contrast 0.2 and saturation 1.06, `segment_max_seconds` 6. Late night additions: `fidelity.face_zoom_mix` (0.8 in the preset), `grain.shadow_weight` (default 0.12, 0.35 in `cleanup-4k` and `film-restoration`), `encode.ac_bias` (default 0) and `encode.quant_matrices` (default false, true in both presets) and `bitdepth.deband` off in both presets (`SHADOW_TEXTURE` in `restore_core/recipe.py`, `restore-shadow-texture.md`). Added 2026-11-01 (both default 0 = off, in no preset): `fidelity.glow` 0..1 with `glow_sigma` (default 4.0 px at 2160 lines; needs a same-size source) and `bitdepth.plateau_purge` 0..1; heads from behind need no field (they follow `face_guard: zoom` when `yolox.onnx` is staged). Why and how: `restore-finishing-features.md`, `restore-face-guard.md`. Defaults and the measured reasons behind them: `restore-measurements.md`, `restore-finish-grain-hdr.md`.

## When you change it

Changing a field means updating the recipe, `api/app/documentation.py` (generated, so usually nothing to write), the README section, `tests/integration/test_documentation_api.py` and the unit tests together. The endpoints and the job protocol are in `restore-job-protocol.md`.
