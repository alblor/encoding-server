# Roadmap task details: FEATURE items (keyed by ID)

The roadmap table lives in `CLAUDE.md`. This file holds the FEATURE entries; the INQUIRY, ISSUE, MIN and IDEA entries are in `roadmap-open-items.md`, and what completed IDs turned out to be is in `roadmap-outcomes.md`. IDs are global and never reused. A `[x]` means done and verified at the level the line names (unit tests, a measurement, a run on real footage); a row stays `review` until the quality-control engineer has run the whole thing, and `complete` only after that. Last updated 2026-10-30 (evening).

### FEATURE-001 — M0 Foundation: docs, repo, baseline, spikes
No feature code before this closed (`m0-server-spikes.md`); the owner decided to proceed to M1 to M6 on 2026-10-30 and still decides when M0 closes.
- [x] M0.1 docs baseline (commits 676f443, 9ac067f pushed); M0.3 baseline green except api_endpoints 8/11 (MIN-024, `commands.md`)
- [x] M0.4 server spikes (2026-10-30): GPU passthrough, torch cu128 on sm_120, SparkVSR 49-frame smoke test on both GPUs
- [ ] Owner decides to close M0 (MIN-018 teardown is tracked on its own)

### FEATURE-004 — M1 Recipe engine + CPU path (review)
The recipe carries `restore.engine: recavsr | sparkvsr | classical | none` so engines plug in without a schema change. Built 2026-10-30, uncommitted; design in `recipe-api-tiers.md`.
- [x] `restore_core/recipe.py` (RecipeRequest, 5 presets, Basic and Advanced tiers, EffectiveRecipe, `resolve()`, `effective_scale`): 22 tests
- [x] `restore_core/tiling.py` (18 tests) and `restore_core/ffmpeg_cmds.py` (typed probe, decode, encode builders, SVT-AV1 params, HDR10 signalling)
- [x] `api/app/restore/`: 8 endpoints, Redis job store, streaming manual-mode crypto, ffprobe validation, two-phase cancel and delete; 78 tests (`restore-job-protocol.md`)
- [x] Compose stack: `restore-work` tmpfs, internal `restore-net`, `restore-worker-gpu0/gpu1` in profile `gpu` (default stack renders unchanged)
- [ ] QC engineer run on the whole path; then version bump (release v1.1.0, API string 2.1.0-secure), merge to main and live deploy (owner's instruction)
- [ ] Observed at the end of the session and not covered by the brief: `restore-worker/Dockerfile.cpu` and a `restore-worker-cpu` service (no GPU, same code); QC to check it

### FEATURE-005 — M2 Probe + recipe generator (review)
`client-tools/probe_media.py` (11 tests): samples frames, classifies the film as `low-res`, `hd`, `uhd-damaged` or `uhd-clean` from detail, blockiness and noise, proposes a preset plus only the overrides that differ, and prints an ETA. On the owner's draft: `uhd-damaged`, preset `cleanup-4k` (`restore-measurements.md`).
- [x] Low-res, native 2160p with artifacts (scale 1), clean native 2160p (skip restoration) are classes of the probe
- [ ] The probe report flags Dolby Vision and informs the HDR choice, which stays per film and the owner's (check in QC)

### FEATURE-006 — M3 Restore stage (engine-agnostic) (review)
Widened on 2026-10-30 (SparkVSR failed the speed gate, so the engine became a recipe field; the earlier title was "M3 SparkVSR stage"); the same day ReCaVSR became the PRIMARY engine. Cost follows OUTPUT pixels.
- [x] Resident tiled ReCaVSR engine (`restore_worker/recavsr_tiled.py`): six 1344x1152 tiles at 2160p, one compiled session, bit-identical runs; 0.573 s/frame, 13.2 GiB (`restore-measurements.md`)
- [x] Measured real 2160p s/frame and VRAM, upscale path and same-size cleanup (feeds INQUIRY-017)
- [x] Pipeline (`pipeline.py`, 10 tests): classical prefilter, restore, finish, encode, frame-count verification; worker (`worker.py`, 8 tests) implements the job protocol; `run_local.py` batch driver
- [x] Optional FP8 (`quantize.py`): experimental `precision: fp8_fast`, bf16 stays default
- [x] Worker image `restore-worker/Dockerfile.gpu` with pinned ffmpeg, SVT-AV1 and ReCaVSR
- [ ] Optional SparkVSR adapter (stage-major windowed streamer, one pinned-memory offload, cached empty-prompt embedding, no `fal_client`, frame counts 49+41k): not built, only needed if SparkVSR comes back
- [ ] Overlap decode/restore/encode with the GPU (FEATURE-044), tile work on the GPU (IDEA-047)

### FEATURE-007 — M4 HDR stage (progress)
Raised to P1 on 2026-10-30; HDR stays a per-film choice, restoration stays before HDR. Static part built (`restore_worker/hdr.py`, 12 tests): BT.1886, BT.709 to BT.2020, ST 2084 PQ, 203-nit reference white, HDR10 signalling (`restore-finish-grain-hdr.md`).
- [x] `hdr.mode` in the recipe, PQ/BT.2020 math in torch, tests against ST 2084 anchor values
- [ ] INQUIRY-015 answered: is the HDRTVNet++ output PQ-encoded, then the learned highlight expansion
- [ ] `hdr: preserve` for PQ sources (removed from the schema on 2026-10-31; a PQ source gets no recipe from `probe_media`; revisit if the owner ever has one)
- [ ] Real-TV check of the HDR10 output (INQUIRY-053)

### FEATURE-008 — M5 Verification + docs (progress)
- [x] Objective comparison and draft scripts exist: `tools/scripts/ops/quality/` (flicker, sharpness, LR-consistency, labelled drafts); tiled bench and dark-scene encode experiment in `tools/scripts/ops/bench/`
- [ ] QC engineer pass on the whole feature; README and `/v1/docs` checked against the schema

### FEATURE-009 — M6 Deploy guide + live-movie testing (progress)
The first live rung is the owner's 79 s draft, already run on the server (`restore-measurements.md`); the TV checks of grain and HDR are pending with the owner (INQUIRY-052, INQUIRY-053).
- [x] Makefile `gpu-*` targets and `scripts/stage_restore_weights.sh` exist in the working tree (observed, not run by the documenter)
- [x] `docs/DEPLOY_PROXMOX.md` written 2026-10-31 by the owner's session; the documenter checked its facts against Makefile, compose and `.env.example` (open points: it quotes the fp8 figures as measured on 49-frame clips, which is not in my notes, and MIN-072)
- [ ] Deploy the new images after QC (FEATURE-060)
- [ ] Check ISSUE-028 from a second host, MIN-055 in the real container, then MIN-018 teardown

### FEATURE-036 — Recipe endpoint: basic + advanced tiers (review)
Owner decision 2026-10-30; design and rules in `recipe-api-tiers.md`. Implemented and documented from the pydantic schema.
- [x] Presets, a LIMITED basic block and an ADVANCED block in the recipe model; unknown keys rejected, advanced fields bounded
- [x] `/v1/docs` entries generated from the schema in `api/app/documentation.py`; README section added; docs test extended
- [x] Effective recipe returned by `/v1/restore/recipe/resolve` and with every job
- [ ] QC: run `make test-docs` against the live API

### FEATURE-044 — Overlap decode, restore and encode (planned)
Today the three stages run one after the other per segment: warm, per GPU 0.53 s engine + 0.05 decode + 0.22 finish/encode = 0.82 s/frame. Overlapping them could take about 30% off (ESTIMATE): about 14 h against 19.7 h for a 172,800-frame film on two GPUs. Memory-bounded by segment length (a 322-frame segment needs about 16 GB RAM), so the queue between stages must be bounded.
- [ ] Bounded producer/consumer between decode, restore and encode inside the worker
- [ ] Measure again on the draft (1,896 frames) and record the new s/frame in INQUIRY-017
