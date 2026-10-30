# Restoration pipeline: planned design (nothing here is built yet)

Source of truth: the plan approved on 2026-10-29 plus the roadmap in `CLAUDE.md`. If code and this file disagree, the code wins and this file gets fixed. Everything is planned unless the roadmap says otherwise.

## Why it exists

The goal is a configurable video restoration pipeline (upscale to 2160p, or cleanup at 2160p) with AV1 output, visually lossless on a 60" 4K TV, for .mkv/.mp4 movies. It extends this project because the hard parts (RAM-only processing, encryption, queueing, hardened containers, AV1 whitelisted) already exist here. NVIDIA GPUs (2x RTX 5080 on the owner's Proxmox server) become an optional compute device: with no GPU the stack behaves exactly as today.

## Decisions taken (2026-10-29)

- The restoration engine runs on the 2xRTX 5080 Proxmox server, never on the Mac (SparkVSR and ReCaVSR are CUDA-only).
- The whole film goes through the restoration engine (update 2026-10-30: the probe may skip it for a clean native 2160p film, see below). HDR is decided per film.
- Media stays in RAM/VRAM while processing. Encryption defaults to ON, with an opt-out.
- The app is driven by a JSON recipe that is generated per film.
- Docker-in-LXC is the only path (unprivileged LXC, host NVIDIA driver working): the server runs Proxmox 8.4.14, which has no native OCI app containers, so IDEA-019 closed as moot (`m0-server-spikes.md`).
- Security is the standing priority (owner: "security is key"): speed and convenience never override it.
- Server access during testing: SSH with a throwaway key, then full teardown (MIN-018).

## Decisions taken (2026-10-30, owner)

1. About 7 days per film (SparkVSR) is too long. The VAE could not be sped up (`m3-benchmark.md`), so the engine switches to ReCaVSR. Later that day, after seeing the drafts: quality looks very similar, no further tests, ReCaVSR is PRIMARY and its weights licence does not matter for home use. SparkVSR stays an optional engine. The real-film A/B was skipped, residual risk in `recavsr-evaluation.md` (INQUIRY-035 closed).
2. The final job endpoint exposes a LIMITED set of basic parameters plus an ADVANCED tier for troubleshooting and optimisation, very well organised and documented in the `/v1/docs` style (FEATURE-036, below).
3. GPU 1 runs hot because the neighbouring card blocks its airflow (owner's diagnosis). An undervolt or power-cap phase is planned at the END of the project (MIN-037).
4. Native 2160p sources: the engine cleans at the SAME size (compression, noise, other artifacts) plus SDR to HDR, no upscaling. So `restore.scale` is 1 for native 2160p (2 or 1.5 otherwise; scale 1 is untested, INQUIRY-042), cost follows output pixels, the probe classifies each film as low-res, native 2160p with artifacts, or clean native 2160p (may skip restoration), and HDR is expected for these clips (FEATURE-007 is P1, HDR still per film). Details: `recavsr-evaluation.md`.

## Recipe (the product)

One versioned, pydantic-validated JSON per job: `recipe_version`, `encryption` (`automated|manual|off`), `target`, `restore` (`engine: recavsr|sparkvsr|classical|none`, `scale: 1|1.5|2`, `precision: bf16|mixed_nvfp4`, with `fp8` a proposed value pending INQUIRY-038 (see below), bf16 is the baseline and FP16 is excluded, `ref_mode: pisasr` for SparkVSR only, window/overlap/tile sizes), `hdr` (`mode: off|preserve|synthesize`), `encode` (libsvtav1 preset/crf/tune/pix_fmt/film grain/variance boost), `audio_subs`. The new job type builds FFmpeg commands from typed fields, never from free-form strings, so the legacy whitelist in `ffmpeg_validation_config.py` stays untouched for `/v1/jobs`. FP16 is excluded (black segments upstream), and the `api` reference mode too (it sends frames to a third party).

## Job endpoint tiers

The recipe is also the public contract of the job endpoint: presets, a LIMITED basic block and an ADVANCED troubleshooting tier, all documented in `/v1/docs` style. Full design: `recipe-api-tiers.md` (FEATURE-036).

## Data plane: one job is one segment

RAM-only processing means a server restart loses everything in flight, and a film takes days. So a job is one scene-aligned segment (about 30-60 s), and the Mac client `client-tools/restore_film.py` (planned) does the orchestration: ffprobe, scene-aware split with `-c copy`, per-segment encrypt, submit, poll, download, sha256 verify, a JSON manifest for resume, final mux with the original audio/subs. Forced cuts inside long takes carry 8 frames of pre/post-roll that the worker discards. Every segment starts on a closed-GOP keyframe with identical encoder params so they concatenate cleanly.

## Services

`docker-compose.secure.yml` gets an opt-in `gpu` profile. The default stack is unchanged. New `restore-worker` image (glibc, because CUDA does not run on Alpine/musl): PyTorch cu128+, FFmpeg with a pinned SVT-AV1, SparkVSR, PiSA-SR, HDRTVNet++; one instance per GPU, internal network only, no egress, plaintext handed over through a shared tmpfs volume with 0700 per-job dirs wiped after each job, weights on a read-only volume. CPU-only recipes (`classical`) run in the same image without a GPU, so the app is testable before any GPU exists. The security-model change this implies is tracked as ISSUE-012.

## Stage order inside the worker

decode (10-bit) -> optional light classical clean-up -> Lanczos resize to 2160p when needed -> restoration engine (ReCaVSR primary, SparkVSR optional; skipped for clean native 2160p) -> SDR-to-HDR if enabled -> SVT-AV1 10-bit -> MKV segment. Restoration models are trained on SDR BT.709 RGB, so restore first and convert to HDR after. Film grain is re-synthesized by AV1 (`--film-grain`) instead of baking diffusion output plus noise into bitrate. PQ/BT.2020 math is done in torch/numpy because the local FFmpeg 8.1.2 has no zscale/libplacebo.

## Known numbers (facts from the research, not measurements of this project)

- SparkVSR (CogVideoX1.5-5B based): the paper reports no inference timing, VRAM or FPS (one-step pass at t=399, trained on 320x640x33-frame clips). The only speed figure was a community report (issue #28): 588 s for 48 frames at 3456x1920, RTX 3090, BF16, 28 tiles of 512x512 (about 12 s/frame), so the roughly 15 days per film was an upper bound from different hardware. The measured figure on this project's hardware is below and in `m3-benchmark.md`.
- RTX 5080 is Blackwell sm_120: needs PyTorch >= 2.7 with CUDA 12.8; SparkVSR pins torch 2.5/cu124 (INQUIRY-002). Measured 2026-10-30: `pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime` ships sm_120 and runs bf16 matmul at about 120 TFLOPS per card.
- 5080 has 16 GB VRAM; a 3090 tiled run peaked at 14.9 GiB allocated.
- Measured here 2026-10-30 (one 5080, bf16, `no_ref`, 49 frames to 2160p): about 6.9 s/frame swap-free, 9.1 with a naive swap, the VAE being about 87% of the time; about 7 days per 2 h film on two GPUs is an ESTIMATE. The stock script does not fit in 16 GiB and needs about 34 GB of host RAM per process, so stage-major scheduling and a windowed streamer are required (`m3-benchmark.md`).
- Dolby Vision is not carried: HDR10 base layer fallback, flagged by the probe.

## Precision ladder (M3, planned, nothing built)

Recipe field `restore.precision = bf16 | mixed_nvfp4` (plus a possible `fp8`, INQUIRY-038). BF16 is the baseline. Since 2026-10-30 the first target is the ReCaVSR transformer (10.6 GB, the part that dominates its runtime; SparkVSR's was only about 13%). The next rung is mixed NVFP4/BF16: only the large FFN and attention-projection linears of the middle transformer blocks are NVFP4, while patch embed, first and last blocks, norms, adaLN/timestep modulation, conditioning pathways, output projection and the decoder stay BF16. Tooling candidates: NVIDIA TensorRT Model Optimizer NVFP4 PTQ, torchao, or a custom `torch._scaled_mm`. UNVERIFIED: NVFP4 support for these models and sm_120 FP4 kernels in PyTorch; a community full-NVFP4 test on an I2V model (LTX-2.3) lost reference fidelity. Acceptance gate: PSNR/LPIPS/DOVER/MUSIQ deltas vs BF16, the flicker metric, and a visual A/B on the TV. Kernel spike: INQUIRY-029 (closed, `m3-benchmark.md`); real-weight work: INQUIRY-038.

## Measured ETA gate (INQUIRY-017)

Hard gate at the end of M3, measured per engine: record the measured s/frame, the peak VRAM per 5080 and the film ETA in the roadmap. If the figure is unacceptable, scope gets revisited, and a selective or budget mode is a recipe change, not a rewrite. First figure recorded 2026-10-30 (about 6.9 s/frame, `m3-benchmark.md`), but it comes from a patched upstream script and quality is not assessed, so the gate stays open until the streamer is measured. ReCaVSR has only an estimate (about 12 to 14 h per film on two GPUs, `recavsr-evaluation.md`), to be measured at 2160p as upscale and as cleanup; SparkVSR failed the proposed 3.0 s/frame/GPU gate (about 5.2 s/frame from the VAE alone).

## Where each risk is tracked

Blackwell INQUIRY-002 (complete: torch and SparkVSR run on both cards; LXC storage ISSUE-030 resolved; encrypted TrueNAS storage idea INQUIRY-031); LXC idmap INQUIRY-003 (complete, not needed); upscale=1 and PiSA-SR keyframe INQUIRY-010; weights licences INQUIRY-011 (SparkVSR parts only); glibc worker security ISSUE-012; weights staging MIN-013; frame/A-V drift MIN-014; PQ output INQUIRY-015, HDR stage FEATURE-007; SVT-AV1 pin MIN-016; measured ETA INQUIRY-017; VAE speed INQUIRY-032 (complete: not fixable); ReCaVSR evaluation INQUIRY-035 (complete, A/B skipped), scale 1 on native 2160p INQUIRY-042, ReCaVSR pin MIN-043; endpoint tiers FEATURE-036; thermals MIN-037; FP8 on ReCaVSR INQUIRY-038; VAE `torch.compile` IDEA-039; eval image in the repo MIN-040 (complete); PiSA-SR quality run INQUIRY-033; 1080p budget recipe IDEA-034; SSH teardown MIN-018; NVFP4 kernels INQUIRY-029 (complete); API bind address ISSUE-028. No server-side upload size limit exists in code today (MIN-023), and segments are meant to fit under one.
