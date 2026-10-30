# Restoration pipeline: planned design (nothing here is built yet)

Source of truth: the approved plan (`~/.claude/plans/hello-claude-in-this-sequential-origami.md`, approved 2026-10-29) plus the roadmap in `CLAUDE.md`. If code and this file disagree, the code wins and this file gets fixed. Status of every item: planned unless the roadmap says otherwise.

## Why it exists

The goal is a configurable video restoration and upscale-to-2160p pipeline with AV1 output, visually lossless on a 60" 4K TV, for .mkv/.mp4 movies. It extends this project instead of starting a new one because the hard parts (RAM-only processing, encryption, queueing, hardened containers, AV1 already whitelisted) already exist here. NVIDIA GPUs (2x RTX 5080 on the owner's Proxmox server) become an optional compute device: with no GPU the stack behaves exactly as today.

## Decisions taken (2026-10-29)

- SparkVSR runs on the 2xRTX 5080 Proxmox server, never on the Mac (it is CUDA-only).
- The whole film goes through SparkVSR. HDR is decided per film later.
- Media stays in RAM/VRAM while processing. Encryption defaults to ON, with an opt-out.
- The app is driven by a JSON recipe that is generated per film.
- Docker-in-LXC is the primary target (unprivileged LXC, host NVIDIA driver already working). Proxmox 9.1 native OCI containers are a technology preview and stay an optional later spike (IDEA-019).
- Security is the standing priority (owner: "security is key"): speed and convenience never override it.
- Server access during testing: SSH with a throwaway key, then full teardown (MIN-018).

## Recipe (the product)

One versioned, pydantic-validated JSON per job: `recipe_version`, `encryption` (`automated|manual|off`), `target`, `restore` (`engine: sparkvsr|classical|none`, `precision: bf16|mixed_nvfp4` (see below), bf16 is the baseline and FP16 is excluded, `ref_mode: pisasr`, window/overlap/tile sizes), `hdr` (`mode: off|preserve|synthesize`), `encode` (libsvtav1 preset/crf/tune/pix_fmt/film grain/variance boost), `audio_subs`. The new job type builds FFmpeg commands from typed fields, never from free-form strings, so the legacy whitelist in `ffmpeg_validation_config.py` stays untouched for `/v1/jobs`. FP16 is excluded on purpose (black segments upstream), and the `api` reference mode is excluded because it sends frames to a third party.

## Data plane: one job is one segment

RAM-only processing means a server restart loses everything in flight, and a film takes days. So a job is one scene-aligned segment (about 30-60 s), and the Mac client `client-tools/restore_film.py` (planned) does the orchestration: ffprobe, scene-aware split with `-c copy`, per-segment encrypt, submit, poll, download, sha256 verify, a JSON manifest for resume, final mux with the original audio/subs. Forced cuts inside long takes carry 8 frames of pre/post-roll that the worker discards. Every segment starts on a closed-GOP keyframe with identical encoder params so they concatenate cleanly.

## Services

`docker-compose.secure.yml` gets an opt-in `gpu` profile. The default stack is unchanged. New `restore-worker` image (glibc, because CUDA does not run on Alpine/musl): PyTorch cu128+, FFmpeg with a pinned SVT-AV1, SparkVSR, PiSA-SR, HDRTVNet++; one instance per GPU, internal network only, no egress, plaintext handed over through a shared tmpfs volume with 0700 per-job dirs wiped after each job, weights on a read-only volume. CPU-only recipes (`classical`) run in the same image without a GPU, so the app is testable before any GPU exists. The security-model change this implies is tracked as ISSUE-012.

## Stage order inside the worker

decode (10-bit) -> optional light classical clean-up -> Lanczos resize to 2160p when needed -> SparkVSR -> SDR-to-HDR if enabled -> SVT-AV1 10-bit -> MKV segment. Restoration models are trained on SDR BT.709 RGB, so restore first and convert to HDR after. Film grain is re-synthesized by AV1 (`--film-grain`) instead of baking diffusion output plus noise into bitrate. PQ/BT.2020 math is done in torch/numpy because the local FFmpeg 8.1.2 has no zscale/libplacebo.

## Known numbers (facts from the research, not measurements of this project)

- SparkVSR (CogVideoX1.5-5B based): the paper (full text) reports no inference timing, VRAM or FPS. It confirms a one-step pass (t=399) and training on 320x640x33-frame clips. The only speed figure is a community report (issue #28): 588 s for 48 frames at 3456x1920 output, RTX 3090, Windows, BF16, 28 tiles of 512x512 (about 12 s/frame). The roughly 15 days for a 2 h film on 2 GPUs is therefore an upper bound extrapolated from different hardware. The real figure must come from M3 (INQUIRY-017).
- RTX 5080 is Blackwell sm_120: needs PyTorch >= 2.7 with CUDA 12.8; SparkVSR pins torch 2.5/cu124 (INQUIRY-002).
- 5080 has 16 GB VRAM; a 3090 tiled run peaked at 14.9 GiB allocated.
- Dolby Vision is not carried; it falls back to the HDR10 base layer and the probe report flags it.

## Precision ladder (M3, planned, nothing built)

Recipe field `restore.precision = bf16 | mixed_nvfp4`. BF16 is the baseline. The next rung is mixed NVFP4/BF16 where only the large FFN and attention-projection linears of the middle transformer blocks are NVFP4, while patch embed, first and last blocks, norms, adaLN/timestep modulation, conditioning/keyframe pathways, output projection and the VAE stay BF16. Tooling candidates: NVIDIA TensorRT Model Optimizer NVFP4 PTQ, torchao, or a custom `torch._scaled_mm`. UNVERIFIED: CogVideoX NVFP4 support and sm_120 FP4 kernels in PyTorch. Known risk: a community full-NVFP4 test on an I2V model (LTX-2.3) lost reference fidelity, and SparkVSR is I2V-derived. Acceptance gate: PSNR/LPIPS/DOVER/MUSIQ deltas vs BF16, the flicker metric, and a visual A/B on the TV. Tracked as INQUIRY-029.

## Where each risk is tracked

Blackwell INQUIRY-002; LXC idmap INQUIRY-003; upscale=1 and PiSA-SR keyframe INQUIRY-010; weights licences INQUIRY-011; glibc worker security ISSUE-012; weights staging MIN-013; frame/A-V drift MIN-014; PQ output INQUIRY-015; SVT-AV1 pin MIN-016; measured ETA INQUIRY-017; SSH teardown MIN-018; NVFP4 INQUIRY-029; API bind address ISSUE-028. No server-side upload size limit exists in code today (MIN-023), and segments are meant to fit under one.
