# Finishing features added on 2026-10-31 night: adaptive softening, tone, chroma anchor, grain from the source

After the owner watched v4 he kept asking for the same thing in different words: keep the model's detail where the original supports it, keep the original's softness and brightness everywhere else, and do not make it look "processed". Each answer became a stage in `restore_worker/finish.py` with its fields in `restore_core/recipe.py` (the code and the generated `/v1/docs` text are the authority for defaults and bounds). All of it is `review`: built and tested (`make test-restore` 211, `make test-restore-worker` 130), QC run 6 found no critical or high, and the last fixes wait for the ISSUE-059 re-check. IDs: FEATURE-078 to 081, MIN-080, MIN-089, FEATURE-095, MIN-097, and since 2026-11-01 MIN-102 (glow) and MIN-103 (plateau purge), both below. Faces have their own file: `restore-face-guard.md`.

## Adaptive softening (FEATURE-078)

`fidelity.soften = adaptive` is a source-supported four-band luma limiter. Why it exists: `match` (MIN-056) takes one gain per band for a whole segment, so it softens a sharp shot as much as a blurry one. `adaptive` looks at the source place by place and band by band, and pulls the model back only where the original gives no support for the energy it added. It never adds energy, it touches luma only, and it needs a source of the SAME size (after an upscale it is skipped, see the QC note below). Fields: `adaptive_tolerance` 1.2 (about 1.6 dB over the source's local energy before a band is pulled back), `adaptive_keep` 0.7 (more is tolerated where the source has real structure at that scale), `adaptive_min_gain` 0.5 (a band is never turned down by more than half, so a flat area is not blanked), plus `soften_amount`.

## Tone (FEATURE-079)

A new `tone` block, opt-in: `contrast`, `pivot` (optional), `local_contrast`, `saturation`. With the pivot unset it is the scene median, measured ONCE per segment. The contrast is clamped on both sides, `contrast * pivot` and `contrast * (1 - pivot)` at or below 0.15 (QC run 4 found that above 0.25 the curve flattens the shadows and clamped at 0.24; run 6 asked for the white side too). Known seam (ISSUE-077): because each segment measures its own median, a slow brightness change inside one shot can step slightly at a segment cut. It is documented in `/v1/docs`, and a film-level pivot is the fix if the owner ever turns tone on with a moving scene.

## Colour anchor and grain from the source (MIN-080, FEATURE-081)

- `anchor_chroma_amount` 0.35: the model's colour wanders too, though less than its brightness, so the coarse colour is tied to the source at a lower amount on purpose. The brightness anchor stays at 0.9 (`polishing-log.md` item 6).
- Grain: for ANY source size the finishing stage uses the source's own grain residual (bicubically upscaled after an upscale) instead of inventing noise, `source_strength` default 1.0, up to 1.5. Measured on real grainy clips through the GPU worker, 2026-10-31: the finished picture keeps about 60% of the source grain amplitude, and the default AV1 encode removes about a third of that. It does not answer INQUIRY-058: the owner's draft still has no grain to transfer.

## What the preset does now (MIN-089, MIN-097, FEATURE-095)

The owner decided from comparison clips ("p9 with face guard", for softness plus details), then answered the face question and the texture complaint. `cleanup-4k` is now: soften adaptive (amount 1.0), anchor source, `face_guard: zoom` at amount 1.0 with `face_zoom_mix` 0.8 (INQUIRY-086, answered: a 20/80 mix of the original and the redrawn face), tone contrast 0.2 and saturation 1.06, `segment_max_seconds` 6, plus the shadow-texture set from `restore_core/recipe.py` (`SHADOW_TEXTURE`: deband off, `grain.shadow_weight` 0.35, `encode.ac_bias` 1.0, `encode.quant_matrices` true; `film-restoration` carries it too). The set costs +72% file size on the dark draft: `restore-shadow-texture.md`. Zoom costs about 0.7 s per frame, so the old 19.7 h film ETA is stale (INQUIRY-017).

## Glow (MIN-102, opt-in, 2026-11-01)

`finish.glow_match`, recipe `fidelity.glow` 0..1 and `glow_sigma` (default 4.0 pixels at 2160 lines, scaled with the picture), default 0 = off. Why it exists: a model that sharpens a light also draws its halo tighter, and the owner wanted the original's soft look back. In linear light the difference of the two pictures blurred to `glow_sigma` is the bloom the model took away, so adding it back cannot touch anything narrower than that width. It is ADDITIVE only and gated to the neighbourhood of source highlights; a step is capped. It runs after the anchor and before the face patches and tone, and needs a same-size source.
- Measured on frame 900 (session): v8's halo falloff around bright lights is already about 93% of the original's, glow adds about 1%. Result at the time: a tool kept for other films, enabled in no preset. Since 2026-11-03 `cleanup-4k` sets `glow` 1.0 (MIN-119, the owner's answer to INQUIRY-106): on this film it changes almost nothing, and it is a floor for films where the model tightens the bloom.
- A first version that also subtracted light (where the model drew a light brighter or smaller than the source) turned one lamp core red and dark. Hence additive only; the docstring says so.
- 6 tests in `tests/unit/test_restore_finish.py`. The diagnostic that shows where the restored picture loses light against the source, by blur width, is `tools/scripts/ops/bench/glow_diagnose.py`.
- The owner's "blur overlay" question (INQUIRY-106) was answered on 2026-11-03: bloom only, no defocus logic, so glow is the answer.

## Plateau purge (MIN-103, opt-in, 2026-11-01)

`finish.plateau_purge`, recipe `bitdepth.plateau_purge` 0..1, default 0, applied after the anchor and before tone and grain, in float. Why it exists: banding and posterised contour patches in dark walls, skies and fog, without the damage the existing `deband` does. A pixel is touched only inside a wide staircase (long plateaus, a range of a few grey levels, no thin line); there it takes a wide Gaussian average at one of three scales (sigma 3, 6 and 12 px at 2160 lines), which turns the steps into a ramp that dither and grain then quantise without bands. Everywhere else no pixel moves.
- Evidence came from a background agent (prototype `artifact_purge_candidates.py`, experiment `artifact_purge_experiment.py`, a learned variant `artifact_purge_learned.py`, all in `tools/scripts/ops/bench/`, sheets in the gitignored `tools/sandbox/artifacts`). Measured on synthetic degradations of clean v8 frames: banding curvature 0.051 to 0.027, textured-area change 0.006 to 0.016 codes, high-frequency energy ratio 0.999 to 1.000, mean change on a clean frame 0.012 codes. On real v8 frames 0.2 to 1.4% of the pixels moved.
- Rejected on the same material: the existing `deband` (changes 81 to 87% of a clean frame), ffmpeg `gradfun`, `deband`, `spp`, `fspp`, `uspp` and `deblock`, FBCNN (Apache-2.0, damages clean content: high-frequency ratio 0.81 to 0.95), ring suppression (does nothing), gated deblocking (safe but modest, not shipped). Blocking and ringing of low-quality encodes are NOT solvable conservatively.
- On the real draft, after restoration plus grain, it is a near no-op (dark flat-pixel share 0.338 against 0.344), so it stays opt-in for damaged sources (IDEA-105). Peak VRAM unchanged (9.67 GiB allocated), no measurable time cost (session).
- Caveat: the evidence is synthetic degradations plus eyeballed sheets, not a real damaged film. 5 tests in `tests/unit/test_restore_finish.py`.

## Measured on the draft stretch 33.5 to 43.6 s (8-bit grey levels, 2026-10-31)

| Version | mean Y | p99 | contrast rms | fine detail |
|---|---|---|---|---|
| source | 19.9 | 123 | 22.6 | 0.57 |
| v2 | 18.7 | 134 | 25.1 | 1.29 |
| v3 | 15.2 | 111 | 20.9 | 0.75 |
| v4 | 19.6 | 123 | 22.6 | 0.78 |
| p9 | 21.1 | 150 | 26.8 | 1.21 |
| p10 | 21.4 | 164 | 28.7 | 1.36 |

Reading it: the "deeper blacks" of v3 were a brightness drift with a narrowed range (mean 15.2 and p99 111 against 19.9 and 123), not real contrast, and the anchor brought v4 back to the source's mean, p99 and contrast (19.6, 123, 22.6) with the fine detail at 0.78 against 0.57. The two later variants p9 and p10 (stretches in `variants/` next to the drafts, `polishing-log.md` item 7) go beyond the source on purpose: contrast rms 26.8 and 28.7 against 22.6, fine detail 1.21 and 1.36. The owner picked p9 ("with face guard").

## QC run 4 notes that belong here

- A tiny or very narrow frame crashed adaptive softening and local contrast: fixed.
- On an UPSCALED source (the source has a different size from the output) `adaptive`, `match` and `face_guard` are skipped, and `/v1/docs` says so; there is no warning in the job output (MIN-076, to confirm with the owner whether he wants one).
- Texture can be read as grain by the automatic grain detection (MIN-076, state to confirm).
