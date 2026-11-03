# ReCaVSR evaluation: facts, measurements, the first comparison and the decision (2026-10-30)

Why this file exists: SparkVSR failed the speed gate (`m3-benchmark.md`, VAE spike), and the owner's condition for switching to ReCaVSR was that it is also SOTA in quality. He decided on 2026-10-30 (last section). Below is what is known. Measured items were observed on 2026-10-30; the authors' claims are labelled as theirs; estimates say so. The server is only ever "the LXC" here.

## What it is (authors' description, not independent)

Paper arXiv 2609.37831 (USTC, submitted 2026-09-29), code at github.com/kopperx/ReCaVSR, weights `kopper/ReCaVSR` on Hugging Face. One-step streaming diffusion on Wan2.2-TI2V-5B with recycled latents and learned cache routing, and a 57M FlashDecoder in place of the VAE, which is exactly the part that sank SparkVSR.

Authors' claims: best DOVER on UDM10, YouHQ40, VideoLQ and REDS30, best LPIPS on two sets, 21.2 FPS at 1080p on an A100 against 0.56 FPS for SparkVSR, peak 27.5 GB at 4K and 18.3 GB at 1440p. SparkVSR appears only in their speed table and NOT in any quality table, so "better than SparkVSR in quality" is not claimed anywhere by the paper. The repo was about 7 weeks old with 19 stars when checked.

## Licence and packaging

- Code is Apache-2.0. The WEIGHTS LICENCE IS NOT STATED: no tag on Hugging Face, and the README says weights remain subject to their licences. The base Wan2.2-TI2V-5B is Apache-2.0. Closed by the owner for home use (INQUIRY-011).
- Needs its own environment: torch 2.10 with CUDA 13.0 wheels through `uv.lock`, Python 3.13 in the venv. It ran fine on the RTX 5080 with the 580 driver in its own container. The image needs gcc, because Triton compiles a launcher.
- Its reader and writer buffer the whole clip in CPU memory, and it does not copy audio. Both have to be handled by our own streamer and muxer (planned, FEATURE-006), not by the upstream script.

## Measured on one RTX 5080

Demo clip 488x830 at 24 fps, output scale 2 (976x1660, 1.62 Mpx), 31, 49, 121 and 336 frames.

- Peak allocated 13.3 GiB, peak VRAM 15.4 GiB. 1.62 Mpx output is about the limit: scale 3 (3.6 Mpx) and scale 4 (6.5 Mpx) both OOM on 16 GB, in `lq_proj` streaming.
- One-time compile cost about 100 s per process (dit about 27 to 44 s, plus decode about 77 to 81 s on first use). A real worker has to persist the compile cache or stay resident.
- Steady state about 0.08 to 0.09 s/frame at 1.62 Mpx (about 11 FPS), taken from 31 versus 121 frames and the 336-frame model loop.
- Host RAM peak about 5.5 GB for 336 frames.

ESTIMATE, not measured: scaling by area to 2160p (5.1x) gives about 0.4 to 0.6 s/frame, so about 12 to 14 h per 2 h film on two GPUs, roughly 10 to 15x faster than SparkVSR. 2160p needs spatial tiling (tiles of about 1.6 Mpx) or a smaller weight footprint. Here the transformer, not a VAE, dominates, so FP8 would free about 5 GB of the 10.6 GB transformer and quantization finally matters for speed and memory (INQUIRY-038). UPDATE 2026-10-30 (evening): measured at 2160p with the tiled engine, 0.573 s/frame warm on one GPU (inside the estimate), 0.82 s/frame end to end on real footage; FP8 turned out transparent but not faster (INQUIRY-038 closed): `restore-measurements.md`.

## First quality comparison (one clip, so a first impression and not a verdict)

Deliverables sit on the owner's Mac in a `restoration-comparison/` folder under Downloads: `short/` (49 frames), `long/` (213 frames), `draft_213f/draft.mp4` (labelled 3-panel 1920x1088, plus stills), `crop_face_f193.png`, `cut/` (scene-cut test).

Setup: ReCaVSR's own demo clip (modern, AI-looking footage, home ground for ReCaVSR and NOT old film), 2x upscale, SparkVSR with `ref_mode=no_ref` (the authors say it is not their best mode; the PiSA-SR reference is still untested, INQUIRY-033) and 49-frame chunks. Objective numbers come from `tools/scripts/ops/quality/video_compare.py`.

| Metric (213 frames) | Lanczos | SparkVSR | ReCaVSR |
|---|---|---|---|
| Added flicker (lower is better) | - | 5.98 | 5.07 |
| Sharpness (Laplacian variance) | 32 | 327 | 198 |
| LR-consistency PSNR (output downscaled vs input) | - | 25.0 dB | 27.8 dB |

On the first 49 frames only: flicker 3.89 vs 4.17, sharpness 504 vs 240, LR-PSNR 31.6 vs 27.9 dB (SparkVSR vs ReCaVSR). The short and the long clip disagree on faithfulness, so the 213-frame one is the more reliable. Per-frame flicker: SparkVSR median 4.46 (lower than ReCaVSR at 5.00) but bursts to 16 to 17, 3 to 4x its median, at the final chunk seam (frames 167 and 168: 14.2 and 10.1) and at frames 192 to 196; ReCaVSR peaks at 7.9 with no seam signature. Global mean luma matches (63.0, 63.0, 63.8).

Visual reading of 1:1 crops (my reading, to be confirmed by the owner on the TV): SparkVSR is crisper but painterly and posterised (foliage gaps turn into hard blobs, invented grit on asphalt, face geometry and expression drift on at least one frame); ReCaVSR is more natural and faithful, a bit softer.

Scene-cut test (ReCaVSR, 48 frames of the demo, then a hard cut to unrelated letterboxed footage): no content bleed. Only the first post-cut frame showed faint residue in the black bar (mean Y 16.1 against black 16, max 44), clean from frame 49, and detail re-forms visibly over the first few frames after the cut. That is why the streamer handles shot boundaries itself.

## Decision (owner, 2026-10-30) and what it changes

After seeing the draft videos, stills and metrics: "Commit and push everything, we don't need to do further tests on that, since quality looks very similar among the two." So ReCaVSR is the PRIMARY restoration engine and SparkVSR stays an optional engine in the recipe. INQUIRY-035 is closed and this record is kept. On the licence: "ReCaVSR weights licence doesn't matter, as everything is for home use". The licence stays unstated, so look again if the use ever changes (MIN-043).

Residual risk, said plainly: all comparisons used ReCaVSR's own modern, AI-looking demo clip, not film, and "very similar" is a visual call on that one clip. The first live rung of the M6 ladder (a short clip per title, FEATURE-009) gives the first real-film look before any full run.

Native 2160p sources (owner): some clips are already 2160p, and there the model's job is to remove compression, noise and other low-quality artifacts at the SAME size, plus the SDR to HDR expansion. It is not upscaling. Consequences:

- Recipe: `restore.scale` 1 for native 2160p, 2 or 1.5 otherwise. The README lists 2 and 1.5; scale 1 is UNTESTED here. Its training degradations are RealBasicVSR-style (blur, noise, compression), so it may suit cleanup, but same-size restoration could be outside the training distribution. Needs a compressed native-2160p clip (INQUIRY-042).
- Cost follows OUTPUT pixels, so a 2160p cleanup costs about what an upscale to 2160p costs: ESTIMATE 0.4 to 0.6 s/frame, 12 to 14 h per 2 h film on two GPUs, unmeasured at 2160p (INQUIRY-017).
- The probe and recipe generator (FEATURE-005) classify each film: low-res source (upscale + restore), native 2160p with visible compression or noise (restore at scale 1), clean native 2160p (may skip restoration, HDR + encode only).
- HDR is expected for the 2160p clips, so the HDR milestone is P1 (FEATURE-007, HDRTVNet++, PQ checks in INQUIRY-015). The choice stays per film and the owner's, informed by the probe.

## Caveats

One clip, the authors' own demo footage, objective metrics are proxies, no real film material and no TV A/B (skipped by the owner). Nothing here shows ReCaVSR is SOTA on old film, or that scale 1 works.
