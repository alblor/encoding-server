# Restoration pipeline: design and status

Source of truth: the plan approved on 2026-10-29, the owner's decisions below and the roadmap in `CLAUDE.md`. If code and this file disagree, the code wins and this file gets fixed. Status on 2026-10-30 (evening): the recipe engine, probe, tiled ReCaVSR worker, finishing stage, static HDR mapping, the `/v1/restore` API, the client tools and the hardened worker image are BUILT in the working tree (uncommitted) and measured on real footage (`restore-measurements.md`); QC and the deploy are pending (FEATURE-004 to FEATURE-009).

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
3. GPU 1 runs hot because the neighbouring card blocks its airflow (owner's diagnosis). The undervolt and fan policy phase is done (MIN-037, 2026-11-03, `gpu-undervolt.md`).
4. Native 2160p sources: the engine cleans at the SAME size (compression, noise, other artifacts) plus SDR to HDR, no upscaling. So `restore.scale` is 1 for native 2160p (2 or 1.5 otherwise; scale 1 is untested, INQUIRY-042), cost follows output pixels, the probe classifies each film as low-res, native 2160p with artifacts, or clean native 2160p (may skip restoration), and HDR is expected for these clips (FEATURE-007 is P1, HDR still per film). Details: `recavsr-evaluation.md`.

5. Evening of 2026-10-30, the owner approved the plan and said to proceed unattended, interrupting only if results look bad or something is infeasible. When everything is ready and nothing is broken (the quality-control engineer verifies), merge to main and deploy live with the version bumped: release v1.1.0, internal API string 2.1.0-secure (not bumped yet). FP8 or MXFP8 is optional and NVFP4 is overkill. Deeper blacks are fine if slight and with real contrast enhancement that does not impact the original. Restored frames are 8-bit: banding must not show in 10-bit or HDR, and a 10-bit source's own precision could be re-applied to the final film (`restore-finish-grain-hdr.md`).

## Recipe (the product)

One versioned, pydantic-validated JSON per job (`restore_core/recipe.py`, `recipe_version` 1): a preset plus a short `basic` block (`engine recavsr|sparkvsr|classical|none`, `target_height`, `quality`, `hdr off|synthesize`, `grain off|auto`, `encryption automated|manual|off`, `audio_subs`) and an `advanced` tree (restore, prefilter, bitdepth, grain, hdr, encode). Fields and bounds: `recipe-api-tiers.md`. The FFmpeg commands are built from typed fields (`restore_core/ffmpeg_cmds.py`), never from free-form strings, so the legacy whitelist in `ffmpeg_validation_config.py` stays untouched for `/v1/jobs`. FP16 is excluded (black segments upstream), and the SparkVSR `api` reference mode too (it sends frames to a third party).

## Job endpoint tiers

The recipe is also the public contract of the job endpoint: presets, a LIMITED basic block and an ADVANCED troubleshooting tier, all documented in `/v1/docs` style. Full design: `recipe-api-tiers.md` (FEATURE-036).

## Data plane: one job is one segment

RAM-only processing means a server restart loses everything in flight, and a film takes days. So a job is one scene-aligned segment (about 30-60 s), and the Mac client `client-tools/restore_film.py` does the orchestration: ffprobe, keyframe split with `-c copy`, per-segment encrypt, submit, poll, download, sha256 verify, a JSON manifest for resume, final mux with the original audio/subs. Forced cuts inside long takes were meant to carry 8 frames of pre/post-roll; they do not yet (ISSUE-048). Every segment starts on a closed-GOP keyframe with identical encoder params so they concatenate cleanly.

## Services

`docker-compose.secure.yml` has an opt-in `gpu` profile; the default stack is unchanged (verified by rendering). `restore-worker/Dockerfile.gpu` (glibc, because CUDA does not run on Alpine/musl): pinned static ffmpeg n8.1.3 with SVT-AV1 4.2.0 (SHA-256 verified), ReCaVSR at a pinned commit with its `uv.lock` (torch 2.10, CUDA 13), non-root user. One worker per GPU (`restore-worker-gpu0`, `restore-worker-gpu1`) on the internal-only `restore-net` (Redis is all they can reach), plaintext handed over through the `restore-work` tmpfs volume, weights on a read-only mount. The security-model change is ISSUE-012, described in `stack.md`. CPU-only recipes (`classical`) run in the same image without a GPU, so the app is testable before any GPU exists. The security-model change this implies is tracked as ISSUE-012.

## Stage order inside the worker

decode with the classical prefilter at source size -> restoration engine (ReCaVSR; skipped for `engine none`) -> finishing stage (SDR-to-HDR if enabled, deband, grain, dither, 16-bit) -> SVT-AV1 10-bit -> MKV segment -> frame-count check. Restoration models are trained on SDR BT.709 RGB, so restore first and convert to HDR after. Grain defaults to the encoder's film-grain synthesis fed a grained picture (measured, `restore-finish-grain-hdr.md`). PQ/BT.2020 math is done in torch because FFmpeg has no zscale/libplacebo here.

## Numbers, precision and the ETA gate

Measured figures of the tiled engine and the real-footage run (0.82 s/frame end to end per GPU, about 19.7 h projected for a 2 h film on two GPUs, about 14 h if decode and encode overlap) are in `restore-measurements.md`, with the FP8 outcome (bf16 stays the default). Facts from earlier research stay in `m3-benchmark.md` (SparkVSR: about 6.9 s/frame, the VAE about 87% of it, about 7 days per film, failed the gate). RTX 5080 is Blackwell sm_120 (torch 2.8 cu128 runs it; the worker uses torch 2.10, CUDA 13), 16 GB VRAM. Dolby Vision is not carried: HDR10 base layer fallback, flagged by the probe. The ETA gate (INQUIRY-017) is measured per engine and the owner judges the number.

## Where each risk is tracked

Blackwell INQUIRY-002 (complete: torch and SparkVSR run on both cards; LXC storage ISSUE-030 resolved; encrypted TrueNAS storage idea INQUIRY-031); LXC idmap INQUIRY-003 (complete, not needed); upscale=1 and PiSA-SR keyframe INQUIRY-010; weights licences INQUIRY-011 (SparkVSR parts only); glibc worker security ISSUE-012; weights staging MIN-013; frame/A-V drift MIN-014; PQ output INQUIRY-015, HDR stage FEATURE-007; SVT-AV1 pin MIN-016; measured ETA INQUIRY-017; VAE speed INQUIRY-032 (complete: not fixable); ReCaVSR evaluation INQUIRY-035 (complete, A/B skipped), scale 1 on native 2160p INQUIRY-042, ReCaVSR pin MIN-043; endpoint tiers FEATURE-036; thermals MIN-037; FP8 on ReCaVSR INQUIRY-038; VAE `torch.compile` IDEA-039; eval image in the repo MIN-040 (complete); PiSA-SR quality run INQUIRY-033; 1080p budget recipe IDEA-034; SSH teardown MIN-018; NVFP4 kernels INQUIRY-029 (complete); API bind address ISSUE-028. The restore endpoints cap the upload (default 6144 MiB, 400 frames, 3840x2304 pixels, `api/app/restore/config.py`); the legacy `/v1/jobs` still has no server-side upload limit (MIN-023). New on 2026-10-30: overlap of decode/restore/encode FEATURE-044; DART evaluation INQUIRY-045; BM3D upgrade IDEA-046; tile work on the GPU IDEA-047; mid-shot cuts ISSUE-048; open-GOP cuts MIN-049; bit-depth research INQUIRY-050 and source anchoring MIN-051; TV film-grain check INQUIRY-052; HDR10 TV check INQUIRY-053; API without authentication ISSUE-054; su-exec group check MIN-055.
