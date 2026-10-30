# HISTORY

**Read this file before applying any version control command or commit.** It is the diary of the project: what happened, when, and why. It is the main reference for past work, and the roadmap in `CLAUDE.md` records what is tracked while this file records what actually happened. Keep them in step: whenever a roadmap item moves or completes, add an entry here in the same session. Newest entries first. Author of all work: Lorenzo Albanese (alblor).

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
