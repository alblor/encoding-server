# HISTORY

**Read this file before applying any version control command or commit.** It is the diary of the project: what happened, when, and why. It is the main reference for past work, and the roadmap in `CLAUDE.md` records what is tracked while this file records what actually happened. Keep them in step: whenever a roadmap item moves or completes, add an entry here in the same session. Newest entries first. Author of all work: Lorenzo Albanese (alblor).

---

## 2026-10-30 - M3 benchmark gate: SparkVSR runs, the VAE is the bottleneck

Roadmap: ISSUE-030 (complete), INQUIRY-002 (complete), FEATURE-001 (M0.4 done), FEATURE-006 (progress), INQUIRY-017 (progress, first figure), INQUIRY-029 (priority lowered to P3), INQUIRY-032, INQUIRY-033, IDEA-034 (new). Nothing committed; the full numbers are in `rules/m3-benchmark.md`, and the five scripts under `tools/scripts/ops/bench/` are new and uncommitted (index in the new `tools/CLAUDE.md`).

The storage blocker is gone (ISSUE-030): the LXC rootfs was resized by +70G, so 92 GB in total with 85 GB free, and the SparkVSR weights were downloaded to a host directory in the LXC. That is 28 files, 42.2 GB (39.3 GiB), and the SHA-256 of all 14 LFS files was checked against the Hugging Face listing with 0 mismatches. With that, the SparkVSR smoke test ran on both GPUs, so INQUIRY-002 is complete and M0.4 has no open box left. FEATURE-001 stays in progress on purpose, since closing the milestone is the owner's call.

The measurements (one RTX 5080 per run, torch 2.8.0+cu128, bf16, S2 weights, `no_ref`, upstream script patched only to skip T5 and add timers): a warm 49-frame clip at 2160p (28 tiles of 512x512, overlap 32) takes 457 s on GPU 0 and 436 s on GPU 1, which is about 9.1 s/frame with a naive per-tile transformer swap. Per clip the transformer needs 44 s (one denoise step per tile), the VAE decode 203 s, the swap 114 s, and the remaining 96 s is mostly VAE encode and I/O. Without the swap that is about 340 s per clip, about 6.9 s/frame, and the VAE is about 87% of it while the transformer is only about 13%. Estimate, not measurement: about 13.8 days per 2 h film on one GPU and about 7 days on two, roughly half of the 15 days upper bound from the 3090 community report, though still days and not hours. Cost follows target pixels, so a restore at a 1080p target with a Lanczos resize to 2160p would be about 4x cheaper, a quality trade-off nobody tested yet (IDEA-034). Quality was NOT assessed: there is no PiSA-SR reference, and the authors do not recommend `no_ref`.

INQUIRY-017 stays in progress, because its definition is a gate at the end of M3 and this figure comes from a patched upstream script. It closes on the number of the stage-major streamer.

The benchmark also showed why the stock script cannot be the production path. The model does not fit in 16 GiB (transformer about 11 GB plus T5 about 9.5 GB OOM at load); a cached empty-prompt embedding lets the pipeline load with `text_encoder=None`. Even then the resident transformer leaves no room for the VAE, so the design answer is stage-major scheduling (the owner suggested serial load/offload loops): transformer on all tiles, one offload (pinned memory should bring an 11 GB move to about a second, the 4-5 s measured was pageable memory), then the VAE. One upstream process held about 34 GB of host RAM against the 50 GB cap of the LXC, so the windowed frame streamer with bounded uint8 windows is required and not optional. Upstream imports `fal_client` (a cloud API client) unconditionally, so the production worker gets a stub that raises on use and runs with no egress; it also imports `pyiqa` without listing it. A suspected tile coverage gap (28 x 512^2 is 7.3 Mpx against 8.3 Mpx per frame) was checked by PSNR against a bilinear upscale and found no pass-through region, so it is not a bug, but the harness keeps a per-region check.

Quantization spike (INQUIRY-029, synthetic 3072 to 12288 linear, no real weights, torchao 0.13.0 because newer releases need torch >= 2.11): bf16 10.54 ms, FP8 weight-only 11.75 ms (no speedup), FP8 dynamic W8A8 7.16 ms (1.47x, 3.7% error), NVFP4 12.41 ms (0.85x, 22.8% error on random data, not compiled). All of them run on sm_120, though the memory saving was not measured. Since the transformer is only about 13% of the runtime, quantization buys at most a few percent end to end, and stage-major scheduling already solves the memory side with no quality risk. INQUIRY-029 stays open at P3 and gets revisited after the VAE is optimised.

New roadmap items: INQUIRY-032 (VAE speed spike: larger tiles, tiling off in stage-major, channels_last_3d, torch.compile), INQUIRY-033 (PiSA-SR reference quality run, weights still not located) and IDEA-034 (budget recipe, postponed). The streamer, the embedding cache, the `fal_client` stub and the coverage check are sub-tasks of FEATURE-006.

---

## 2026-10-30 - M0.4 server spikes: GPUs reach containers, storage becomes the blocker

Roadmap: FEATURE-001 (M0.4 partly done), INQUIRY-002 (progress), INQUIRY-003 (complete), IDEA-019 (complete, moot), INQUIRY-011 (partly answered), ISSUE-030 (new), INQUIRY-031 (new), MIN-018 (updated), ISSUE-028 (still open). Nothing committed in this session; the full measurements are in `rules/m0-server-spikes.md`.

First session on the real server, run over SSH with a throwaway key. The Proxmox host is 8.4.14 (kernel 6.8.12-15-pve), not 9.x, so native OCI app containers are not there to be had: IDEA-019 is closed as moot and Docker-in-LXC is the only path, which is what the plan already treated as the primary target anyway.

The host runs NVIDIA driver 580.76.05 with two RTX 5080 (16,303 MiB each). The LXC (CT 901, Ubuntu 22.04.5, unprivileged, nesting + keyctl, 32 cores, 50,000 MB RAM cap, 22 GB ZFS rootfs) received the five device nodes through `dev0` to `dev4` lines. Since the nodes are `crw-rw-rw-` on the host, no idmap work was needed, which answers INQUIRY-003 (the "likeliest M0 snag" was not one, for these nodes at least). Inside the LXC went the NVIDIA userspace 580.76.05 from the official `.run` with `--no-kernel-modules`, `nvidia-container-toolkit` 1.20.1 with `no-cgroups=true`, and the `nvidia` Docker runtime (Docker 28.4.0). NVIDIA publishes no checksum file for this release (the URL returned 404), so only the installer's embedded md5/crc and TLS to `download.nvidia.com` were available as integrity checks, and `nvidia-smi` matching the host module is the functional proof. `nvidia-smi` in a plain container lists both GPUs.

The Blackwell spike (INQUIRY-002) passed on the torch side: `pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime` ships sm_120, both cards report capability 12.0, and a bf16 matmul runs at about 119-120 TFLOPS per card (script: `tools/scripts/ops/gpu_smoke_test.py`, new and uncommitted). torch exposes `float8_e4m3fn`, `float8_e5m2`, `float4_e2m1fn_x2` and `torch._scaled_mm`, so the NVFP4 idea (INQUIRY-029) stays open, though FP4 kernels on sm_120 and CogVideoX quality under NVFP4 are still unproven. The SparkVSR smoke test itself has not run yet, and INQUIRY-002 stays in progress for that reason.

Licences (INQUIRY-011, partly answered): `JiongzeYu/SparkVSR` is a full diffusers-format pipeline (transformer, text_encoder, vae; 39.3 GiB in 28 files), tagged apache-2.0 and not gated. `zai-org/CogVideoX1.5-5B-I2V` (28.9 GiB) is tagged `license:other`, so the card needs reading for personal-use terms before M3. The SD 2.1 base and the PiSA-SR weights for `ref_mode=pisasr` were not located (the API call for `stabilityai/stable-diffusion-2-1-base` failed), so that part stays open.

New blocker (ISSUE-030, P1): the LXC rootfs is 22 GB, the torch image alone took it to 13 GB used (9.8 GB free), and the SparkVSR weights are 39.3 GiB. The M3 benchmark cannot run until storage is added, either a rootfs resize of at least about 70 GB or a host-side mount point. RAM is not an option, since the cap is 50 GB and weights in tmpfs would eat 39 GB of it. The weights are public artifacts and not user media, so they may live on normal disk: the RAM-only rule covers media only. Related idea (INQUIRY-031, P3): the owner wants the LXC storage on a TrueNAS dataset (a Proxmox VM with the storage controller passed through), isolated and encrypted. Constraints recorded: Docker `overlay2` does not work on NFS so the Docker data root stays on block storage (local ZFS or an iSCSI zvol), ZFS native encryption protects data at rest only and the key must be available at boot, and the TrueNAS VM has to boot before the LXC. The suggested use for now is read-only weights on an encrypted dataset mounted into the LXC from the host.

Teardown lessons for MIN-018: sshd in the LXC is socket-activated, so both `ssh.socket` and `ssh.service` must be disabled. The Mac reaches the LXC over a different interface than the Wi-Fi one, so the key was locked with the correct source IP after a first failed login, where the `from=` lock rejected the wrong IP exactly as designed.

Housekeeping: the two docs commits (676f443, 9ac067f) are pushed to `origin/feature/restoration-pipeline`, `main` is untouched, and ISSUE-028 (bind address) is still open as the first code change planned.

---

## 2026-10-29 - Baseline run, security finding, plan corrections

Roadmap: FEATURE-001 (M0.3 done), ISSUE-028, INQUIRY-029, INQUIRY-017, MIN-024, MIN-025, MIN-026, MIN-027. Nothing committed.

The M0.3 baseline was run on pristine v1.0.0 in a Colima VM on the Mac (4 CPU, 8 GiB). The AppArmor `security_opt` line was removed from a disposable copy, because the VM has no `ffmpeg-isolated` profile loaded. Results: unit 17/17, encryption_stubs 8/8, manual 9/9, automated 12/12, documentation 100%, progress 6/6, cancellation 6/6, api_endpoints 8/11. `test-apparmor` was not run, it needs real AppArmor and can only be verified on Proxmox. The 3 api_endpoints failures exist upstream (MIN-024): the test submits manual mode without `decryption_password`, and two error-handling checks expect a top-level `error` field while FastAPI nests it under `detail`.

Running the suite away from the target turned up more friction, logged as small items: the generated test clips are random bytes named `.mp4`, so every encode test fails with "moov atom not found" until valid clips exist (MIN-025); the integration scripts need `requests` and `cryptography` in the interpreter on PATH, with `uv run --with requests --with cryptography python tests/integration/<test>.py` as the working invocation, and macOS has no `timeout` (MIN-026); the secret lifecycle script hard-codes a container name from the compose project name `encoding-server`, and Colima only shares `$HOME` with the VM (MIN-027).

Security finding (ISSUE-028, P1): `docker-compose.secure.yml` publishes 8443 on 0.0.0.0 and the bridge sets `host_binding_ipv4: 0.0.0.0`. That is fine inside an LXC behind the Proxmox firewall, but on any other host it exposes the API to the LAN, and `ALLOWED_HOSTS` hard-codes a private LXC IP in a public repo. The owner said "security is key", recorded as a standing priority at the top of the quick reminders in `CLAUDE.md`.

Plan corrections. The SparkVSR paper (full text) reports no inference timing, VRAM or FPS; it confirms the one-step pass (t=399) and training on 320x640x33-frame clips. The 588 s per 48 frames figure comes only from community issue #28 (RTX 3090, Windows, BF16, 28 tiles, 3456x1920), so the roughly 15 days per film is an upper bound from different hardware, to be replaced by the M3 measurement (INQUIRY-017). M3 also gets a recipe field `restore.precision = bf16 | mixed_nvfp4` with a precision ladder (BF16 baseline, then mixed NVFP4/BF16 on the large middle-block linears only), gated by metric deltas, the flicker metric and an A/B on the TV (INQUIRY-029). CogVideoX NVFP4 support and sm_120 FP4 kernels in PyTorch are unverified, and a community full-NVFP4 test on an I2V model (LTX-2.3) lost reference fidelity. Planned, not built.

The session was relaunched from the new path, so work continues from `~/Downloads/encoding-server`.

## 2026-10-29 - M0.1 documentation pass for the restoration feature

Roadmap: FEATURE-001 (progress). Nothing is committed yet, the changes are in the working tree for review.

Before any feature code, the project got its memory. A root `CLAUDE.md` now holds the purpose, the quick reminders and the roadmap (FEATURE-001 to FEATURE-009 for the milestones M0 to M6, plus the risk and housekeeping items: INQUIRY-002, INQUIRY-003 and everything from INQUIRY-010 to MIN-023), with the longer material split into `rules/stack.md`, `rules/commands.md`, `rules/conventions.md` and `rules/restoration-design.md`. Folder-level `CLAUDE.md` guides were added to `api/`, `api/app/`, `client-tools/`, `scripts/`, `security/`, `redis/` and `tests/`.

The README got one clearly labelled section describing the restoration pipeline as a feature under development (status: planned) and NVIDIA GPUs as an optional compute device. The `/v1/docs/overview` response got a separate `planned_features` key, leaving `key_features`, the five quick-start steps and every endpoint id untouched because `tests/integration/test_documentation_api.py` asserts on them.

Things noticed while reading the repo and logged instead of fixed: `.gitignore` hides `CLAUDE.md` and `.claude/` (so the roadmap is private) and does not cover `.secrets/` (MIN-020); the compose file sets `pid: "host"` on the API (INQUIRY-022); no server-side upload size limit exists in code although the README mentions `MAX_FILE_SIZE` (MIN-023); the README endpoint count differs from the routes in `api/main.py` (MIN-021). `.env.example` was not created, since no environment variable carries a secret: the four secrets are Docker secret files.

## 2026-10-29 - Repository imported and folder renamed to encoding-server

Roadmap: FEATURE-001 (M0.2).

The working folder `Movies conversion` was renamed to `encoding-server` and the existing project `github.com/alblor/encoding-server` (release v1.0.0, AGPL-3.0) was cloned into it with its history preserved. Work happens on the branch `feature/restoration-pipeline`; `main` is untouched and nothing is pushed until the owner asks. The rename was done before any coding on purpose, so the session working directory would not move underneath running work; the Mac session was then relaunched from `~/Downloads/encoding-server`.

## 2026-10-29 - Plan approved and the owner's decisions

Roadmap: FEATURE-001 to FEATURE-009, INQUIRY-002/003/010/011/017, ISSUE-012, MIN-013/014/016/018.

The plan "Restoration + AV1 pipeline" was approved, building on the existing encoding server instead of starting a new project, because RAM-only processing, encryption, the queue and hardened containers are already here and `libsvtav1` is already whitelisted. Decisions taken by the owner:

- SparkVSR runs on the 2xRTX 5080 Proxmox server, as an optional NVIDIA compute device of this project. It never runs on the Mac.
- The whole film goes through SparkVSR. Whether a film gets HDR is decided per film, later.
- Media stays in RAM/VRAM during processing. Encryption defaults to ON with an opt-out (`automated | manual | off`).
- The application is driven by a JSON recipe, generated per film, and a film is processed as many scene-aligned segment jobs so a server restart loses little.
- Docker-in-LXC stays the primary deployment target: unprivileged LXC, host NVIDIA driver already working with both cards. Proxmox 9.1 native OCI containers are a technology preview and remain an optional later spike (IDEA-019).
- Server access during testing is SSH with a dedicated throwaway key, followed by a verified teardown: key removed from `authorized_keys`, private key shredded, host removed from `known_hosts`, SSH disabled with Proxmox web UI access confirmed first (MIN-018).
- Milestones: M0 foundation, M1 recipe engine and CPU path, M2 probe and recipe generator, M3 SparkVSR stage, M4 HDR stage, M5 verification, M6 Proxmox deploy guide and live-movie tests. Each is built and validated before the next. No multi-agent workflow was used: the phases are sequential and gated by GPU benchmarks.

## 2026-10-29 - Research findings behind the plan

Roadmap: INQUIRY-002, INQUIRY-010, INQUIRY-011, INQUIRY-015, INQUIRY-017, MIN-016.

SparkVSR is built on CogVideoX1.5-5B and does one transformer pass per window (`sr_noise_step=399`). It is CUDA-only (`pipe.to("cuda")`), so no Mac. The only speed figure found is 588 s for 48 frames at 3456x1920 output on an RTX 3090, with 28 tiles of 512x512, about 12 s per frame (corrected later the same day: it is a community report, issue #28, and the paper itself gives no timing). Extrapolated to a 2 h film at 2160p that is roughly 15 days on two GPUs, an upper bound from different hardware and not a measurement, which is why the measured ETA from M3 became an exit criterion (INQUIRY-017). VRAM figures: 29 GB for 32 frames 270p to 1080p on an A100 untiled, 14.9 GiB allocated peak for the tiled 3090 run, and the RTX 5080 has 16 GB.

The upstream inference script could not be used as it stands: it bilinear-resizes to the target resolution, loads the whole clip into fp32 through `decord`, does not blend overlapping chunks, and writes libx264 CRF 0 at 16 fps by default. So M3 plans its own windowed frame streamer with a crossfade blend. FP16 produced black segments upstream, so bf16 only; the `api` reference mode sends frames to a third-party service, so only the local `pisasr` reference mode is allowed.

The RTX 5080 is Blackwell (sm_120) and needs PyTorch 2.7 or newer with CUDA 12.8, while SparkVSR pins torch 2.5 with cu124, which would fail with "no kernel image". This became the first spike (INQUIRY-002).

For SDR to HDR, HDRTVNet++ (MIT licence, four `.pth` files, a small per-frame CNN) was chosen. LumaFlux was rejected because it needs 27 GB and 5.3 s per 1080p frame and its weights are non-commercial; the method of arXiv 2605.14703 was rejected because no code has been released. The local FFmpeg 8.1.2 has no `zscale` or `libplacebo`, so PQ/BT.2020 math will be done in torch/numpy. Local SVT-AV1 is 4.2.0 while the server image is Alpine 3.19 with an older one, hence the version pin in the worker image (MIN-016).
