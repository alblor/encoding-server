# Polishing log: the owner's feedback on the restored draft, step by step

Written 2026-10-31 and updated the same evening, so a fresh agent can continue without the chat; items 8 to 10 added the same night. The restoration works, the owner watched the restored draft of his 2160p film and sent notes, and each note became a measurement and then a decision. Items are chronological (2026-10-30 to 2026-10-31); status is done (built and tested), review (built, waiting for the ISSUE-059 re-check) or open (waiting for a fact). Numbers are measured on the owner's draft unless marked "arithmetic". The code is the authority for current defaults: `restore_core/recipe.py`. Next steps: `resume-checklist.md`.

## 1. Deeper blacks (done, explained by item 6)

The owner: "deeper black can be fine if slight and with a real contrast enhancement that does not impact the original movie". The first restored segment looked faithful at normal brightness with slightly deeper blacks, and I left `color_fix` at `none`, because I had no evidence yet that it hurt. Item 6 found the real cause: a brightness drift along each segment. `color_fix` stays `none`, the answer is the anchor stage.

## 2. Banding, 8-bit pictures in a 10-bit or HDR film (done for the classical part)

The owner, relaying the concern: "we need a diffusion-like model for 8 to 10 bit, and for 10-bit sources re-apply that information". The finishing stage keeps float, debands, dithers, adds grain and rounds once to 16 bits (`restore-finish-grain-hdr.md`). Research found NO open learned 8-to-10-bit model for video, only image models (`restore-research.md`), so the recommendation is float + classical deband + grain. Not implemented: `bitdepth.anchor_source` (MIN-051), a method nobody has published.

The Sony paper "Generating HDR Video from SDR Video" (arXiv 2605.14703) does have released code, which I first missed by reading the paper page alone (the lesson is in the agent memory). Evaluated: not feasible at film scale (about 147 h per 2 h film at 1280x704, arithmetic) and not a bit-depth method, so the static BT.2408 mapping stays (INQUIRY-062, `restore-research.md`).

## 3. Grain: "the grain looks too distant from the original and very regular" (done)

Two causes. AV1 film-grain synthesis regenerates grain from a small repeating template (32x32 blocks, regular at higher strengths) and estimates its parameters from my noise, which was a single-scale Gaussian. Measured before: the encoder removes low-amplitude baked grain in dark flat areas, and synthesis fed a clean picture estimates nothing.

Fix in `restore_worker/finish.py`: a film-like model with two scales of filtered noise (sigma 0.6 and 1.5 px, 70/30), mild skew, channel correlation 0.6, a brightness weight peaking in shadows and mid-tones, and new noise every frame. Since the last session it is seeded by (recipe seed, ABSOLUTE frame index), so the same frame gets the same grain whatever the cut. The finishing chunk is sized by pixels (12 Mpx). Tests cover mean, variance, skew, no echo at lags 16 to 73, channel correlation and the brightness curve. Mode `source` (`transfer_source_grain`) moves the source's own grain onto same-size restored frames; `av1_fgs` stays as the cheap, honestly regular option.

Bitrate on a bright real segment (21 frames, CRF 24), against no grain at 9.5 Mb/s: AV1 synthesis x1.42, baked 0.35 x1.67, baked 0.5 x2.92, baked 0.8 x6.17. At 1:1 no grain gives posterised petals, 0.35 and 0.5 look film-like, 0.8 is heavy. Default: baked, strength 0.4.

## 4. Fidelity and softness (done, built as the soften stage)

The owner: "let's keep it a little softer like the original: I hope there is a way to set the right blur looking at the original, maybe with a light mask merge". The first spectral measurement (restored over source per band, geometric mean over 12 detailed crops, luma) showed the model is not uniformly sharper: it adds energy in the lower mid band and has slightly LESS than the source at the highest frequencies, so a global blur is the wrong tool. Per band (fraction of Nyquist, restored over source, model alone, no grain): 0-0.125 x1.11, 0.125-0.25 x4.69, 0.25-0.375 x1.96, 0.375-0.5 x1.08, 0.5-0.625 x0.91, 0.625-0.75 x0.87, 0.75-0.875 x0.89, 0.875-1.0 x0.88.

Built in the finishing stage for same-size sources: per-band gain from the radial power spectra, applied as an isotropic FFT filter, plus a local mask merge that only softens where the restored mid-band energy exceeds the source's. Recipe: `advanced.fidelity.soften` (`off | match`, `match` in `cleanup-4k`), `soften_amount`, `soften_mask`. Measured again on the real draft: the model adds +3.7 dB at 12-25% of Nyquist. Mask thresholds 1.0 and 2.0. Amount 0.6 with the mask was a no-op, 0.8 with the mask gives +2.2 dB and 1.0 gives +1.5 dB, so the default `soften_amount` is 0.8.

## 5. The draft carries no grain (fact, open question to the owner)

`output_av1.mkv` (project root, gitignored) has NO film grain: no AV1 film-grain parameters, noise 0.118 grey levels (detail 0.001, blockiness 1.171, 0.006 bits per pixel). The grain the owner remembers belongs to the original film or to what his player adds, so it cannot be transferred from this file. With grain `auto` the draft gets baked 0.4. Open (INQUIRY-058): a short grainy reference clip or a description of the look. Planned (MIN-057): a grain profile measured from it.

## 6. Brightness drifts along a segment and restarts at every cut (found and fixed, review)

New finding. Mean luminance of the restored picture against the source averaged -4.6 grey levels, worst 12.6, and this is what the owner saw as "deeper blacks". The global-mean step at the 22 cuts reached +-3.5 (source +-0.7), so the film breathes at every segment seam. The model drifts along a segment and starts over at the next one.

Fix: the finishing stage `fidelity.anchor=source` pulls the low frequencies back to the source (`anchor_amount` 0.9, cells of about 16 px, any source size; on in `film-restoration` and `cleanup-4k`). Measured: average -0.4, worst 1.6, cut-step rms 1.64 -> 0.70 (source 0.32). The owner can lower `anchor_amount` to keep some of the model's tone shift, or set the anchor off. His call after watching v4.

## 7. Draft outputs on the Mac

In `~/Downloads/restoration-comparison/draft_movie/`: `restored_draft_v2.mkv` (run D, 8 s segments, old defaults), `restored_draft_v3.mkv` (soften 0.8, fp8, no anchor), `restored_draft_v4.mkv` (v3 plus anchor), `restored_draft_v5.mkv` (the `cleanup-4k` preset, face guard on), `restored_draft_v6.mkv` (the same with `zoom`) and `restored_draft_v7.mkv` (the final recipe: shadow texture plus zoom mix 0.8, whole draft). In `variants/`: stretches `p1` to `p13`, `face_sheet.png`, `zoom_sheet*.png`, `v5_v6_faces.png`, `detail_sheet_f900.png`; in `abrupt/`: the sheets of the cut and fast-zoom simulations (item 10).

## 8. After v4: details kept where the source supports them, and the faces (done, review)

The owner looked at v4 and the comparison stretches and chose "p9 with face guard", for softness plus details; the measured table is in `restore-finishing-features.md`. Why a new stage and not a bigger blur: the model's excess is not uniform, so `soften: adaptive` limits it band by band and place by place, never adds energy and only where the original gives no support (FEATURE-078). Alongside it: the tone block (FEATURE-079), a chroma anchor of 0.35 (MIN-080), grain from the source (FEATURE-081), the preset (MIN-089). Then the one thing no spectrum had shown: a woman at about 36 s, face 45 px tall, with hollow dark eyes in the plain model output. `face_guard` (FEATURE-082, 083) fixes it, `on` looks natural but blurry and `zoom` natural and consistent, with the honest caveat that at 40 to 60 px it is plausible and not necessarily the real face (`restore-face-guard.md`). The preset question (on or zoom, INQUIRY-086) is answered in item 10.

## 9. "Textures are flattened, lack dynamic range" (done, review)

The owner: "textures from the original are flattened, lack dynamic range; keep the warm cinematic blur, not flat". Measured on the 0:52 to 0:54 shot: before the AV1 encode only 0.9% of the dark pixels sat in flat plateaus, after the default encode 34.1% (source 62.1%). So the encoder flattened the shadows, not the model or the finishing stage. Chosen for `cleanup-4k` and `film-restoration`: deband off, `shadow_weight` 0.35, `ac_bias` 1.0, `quant_matrices` true (FEATURE-095). Whole draft v7 against v6: plateaus 83.6% to 33.2% (source 76.9%), fine-band RMS 0.89 to 0.96, but the file grows 99.6 MB to 171 MB (+72%, about 17 Mb/s on a very dark film). He can trade texture for bits with `shadow_weight` or `ac_bias`. Table of twelve variants and the SVT-AV1 parameter check: `restore-shadow-texture.md`. A known limit stays: the model path is 8-bit (IDEA-096).

## 10. Faces: the owner chose zoom with a 20/80 mix, and the abrupt cases (done, review)

Answer to INQUIRY-086: `face_guard` zoom with a mix of 20% original and 80% redrawn face (`fidelity.face_zoom_mix` 0.8, preset `cleanup-4k` `face_guard: zoom`, MIN-097). The tracker learned two things (FEATURE-098, `restore-face-guard.md`): it stops at hard cuts inside a segment, and it follows fast faces. Simulated through the real worker on the draft (sheets in `abrupt/`): a hard cut into a shot where the 45 px face is already visible now gets the redrawn face from the first frame of the new shot (without face handling the uncanny face shows immediately); a fast digital zoom-in (4x in 24 frames, face 45 to 180 px) lost the face in the first tracker, since it moved more than a face width per frame and IoU linking failed, and the first frames stayed uncanny, which the wide link gate fixed. Face research is closed (KEEP rejected, VACE dropped): `restore-research.md`. He then approved v8: continued in `polishing-log-2.md`.
