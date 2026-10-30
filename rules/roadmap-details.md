# Roadmap task details (keyed by ID)

The roadmap table lives in `CLAUDE.md`; this file holds the descriptions and sub-tasks that would not fit there under the 10,000-byte limit. Same conventions as the `claude-roadmap` skill: IDs are global and never reused, `[x]` is done and verified, nothing is `complete` until verified. Last updated 2026-10-30.

### FEATURE-001 — M0 Foundation: docs, repo, baseline, spikes
No feature code before this closes (`m0-server-spikes.md`).
- [x] M0.1 docs baseline (commits 676f443, 9ac067f pushed); M0.3 baseline green except api_endpoints 8/11 (MIN-024, `commands.md`)
- [x] M0.4 server spikes (2026-10-30): GPU passthrough, torch cu128 on sm_120, SparkVSR 49-frame smoke test on both GPUs
- [ ] Owner decides to close M0 (MIN-018 teardown is tracked on its own)

### FEATURE-004 — M1 Recipe engine + CPU path
The recipe schema carries `restore.engine: recavsr | sparkvsr | classical | none` from the start, so engines plug in without a schema change. The recipe is built as presets + basic block + advanced block (FEATURE-036 owns the public contract and its docs).

### FEATURE-005 — M2 Probe + recipe generator
Proposed: the generator emits a preset name plus only the overrides that differ from it, so a generated recipe stays readable (FEATURE-036).
Owner decision 2026-10-30: some clips are already 2160p, so the probe classifies each film and picks the recipe (`restoration-design.md`):
- [ ] Low-res source: upscale + restore (`restore.scale` 2 or 1.5, Lanczos to 2160p as needed)
- [ ] Native 2160p with visible compression or noise: restore at `restore.scale` 1 (cleanup at the same size, depends on INQUIRY-042)
- [ ] Clean native 2160p: restoration may be skipped, only HDR + encode (a cheaper recipe)
- [ ] The probe report flags Dolby Vision and informs the HDR choice, which stays per film and the owner's

### FEATURE-006 — M3 Restore stage (engine-agnostic)
Scope widened on 2026-10-30, same milestone and same component (the restore stage): SparkVSR failed the speed gate (`m3-benchmark.md`), so the engine became a recipe field. Later the same day the owner made ReCaVSR the PRIMARY engine and skipped further quality tests (`recavsr-evaluation.md`); the tiled streamer is the next build. The earlier title was "M3 SparkVSR stage".
Cost follows OUTPUT pixels: a same-size cleanup at 2160p costs about the same per frame as an upscale to 2160p (ESTIMATE 0.4 to 0.6 s/frame, 12 to 14 h per 2 h film on two GPUs, unmeasured at 2160p).
- [ ] Engine adapter boundary: one interface behind `restore.engine`
- [ ] ReCaVSR tiled stage-major streamer: spatial tiles of about 1.6 Mpx with blending, own shot-boundary and chunk handling, bounded RAM, no network, compile cache persisted or a resident worker to avoid the roughly 100 s start-up; audio is muxed by us, since ReCaVSR does not copy it
- [ ] `restore.scale` in the recipe: 1 for native 2160p sources, 2 or 1.5 otherwise (the README lists 2 and 1.5; 1 is untested, INQUIRY-042)
- [ ] Measure real 2160p s/frame and VRAM on that streamer, both as upscale and as same-size cleanup (feeds INQUIRY-017)
- [ ] Optional SparkVSR adapter: stage-major windowed streamer with ONE pinned-memory offload, cached empty-prompt embedding (`text_encoder=None`), `fal_client` stub that raises, `pyiqa` pinned, no egress, per-region tile coverage check, frame counts of the form 49+41k (upstream chunk-merge crash, `m3-benchmark.md`)

### FEATURE-007 — M4 HDR stage
Raised from P2 to P1 on 2026-10-30: the 2160p clips are expected to get the SDR to HDR10 expansion, so it is on the main path now. HDRTVNet++ is the planned engine; HDR stays a per-film choice, PQ checks still apply (INQUIRY-015), and restoration stays before HDR (models are trained on SDR BT.709).
- [ ] INQUIRY-015 answered first: is the HDRTVNet++ output PQ-encoded
- [ ] Stage after restoration, off by default, `hdr.mode` in the recipe
- [ ] PQ/BT.2020 math in torch/numpy (local FFmpeg has no zscale/libplacebo)

### FEATURE-009 — M6 Deploy guide + live-movie testing
The ladder starts with a short clip per title: that first live rung is where ReCaVSR meets real film for the first time (the real-film A/B was skipped on 2026-10-30), so look at it on the TV before any full run.

### FEATURE-036 — Recipe endpoint: basic + advanced tiers
Owner decision 2026-10-30. Design and rules: `recipe-api-tiers.md`.
- [ ] Presets, a LIMITED basic block and an ADVANCED troubleshooting and optimisation block in the recipe model
- [ ] Documented in the `/v1/docs` style: every field with type, default, allowed values, effect and cost
- [ ] Update `api/app/documentation.py`, the README and `tests/integration/test_documentation_api.py` together
- [ ] Effective recipe (preset + overrides) returned, advanced fields validated and bounded

### INQUIRY-042 — Test ReCaVSR at scale 1 on native 2160p
Owner decision 2026-10-30: for native 2160p sources the engine's job is cleanup at the SAME size (compression artifacts, noise, other low-quality artifacts) plus HDR expansion, not upscaling. ReCaVSR's README lists `--scale` 2 and 1.5; scale 1 is UNTESTED here. Its training degradations are RealBasicVSR-style (blur, noise, compression), so it may suit cleanup, but same-size restoration could be outside its training distribution.
Blocked until the owner provides a compressed native-2160p clip, or a rung of the M6 ladder reaches one.
- [ ] Run `--scale 1` on a compressed native-2160p clip (needs the tiled streamer, or a crop that fits 16 GB)
- [ ] Compare against the untouched input with `video_compare.py` and a labelled draft, 1:1 crops, then the TV
- [ ] Decide: scale 1 is fine, or same-size cleanup needs another path (owner's call with the results)
- [ ] Record the outcome in FEATURE-005 (classification) and FEATURE-006 (`restore.scale`)

### MIN-043 — Pin ReCaVSR commit and weights SHA-256
Proposed (as ISSUE-030 did for SparkVSR): `Dockerfile.recavsr-bench` clones the repo head (it records the commit in a `COMMIT` file) and the weights revision is not pinned. Moved here from INQUIRY-035.
- [ ] Pin the ReCaVSR commit and the Hugging Face weights revision
- [ ] Verify the weights SHA-256 against the Hugging Face listing, record it in `recavsr-evaluation.md`
- [ ] Revisit the unstated weights licence if the use ever leaves the home (INQUIRY-011)

### INQUIRY-017 — Measured ETA per film (M3 exit criterion)
Gate measured per engine. SparkVSR: about 6.9 s/frame swap-free, 9.1 with the naive swap, about 7 days per film on two GPUs (estimate), 15.5 GiB reserved; VAE alone about 5.2 s/frame, gate of 3.0 s/frame/GPU not reachable. ReCaVSR: about 0.08-0.09 s/frame at 1.62 Mpx measured, about 0.4-0.6 s/frame at 2160p and 12-14 h per film ESTIMATED. The gate stays per engine and closes on the number of the streamer that ships; for ReCaVSR it must be measured at 2160p both as upscale and as same-size cleanup.

### INQUIRY-038 — FP8 spike on the ReCaVSR transformer
Successor of INQUIRY-029 (closed): the transformer, not a VAE, dominates ReCaVSR, and FP8 would free about 5 GB of its 10.6 GB, so it helps speed and memory (2160p tiles, where VRAM is the limit). Kernel numbers: FP8 W8A8 1.47x, NVFP4 0.85x (synthetic layer).
- [ ] FP8 on the real transformer: s/frame, VRAM, quality delta against bf16
- [ ] NVFP4 only if FP8 is not enough (unverified on this model; the quality gate in `restoration-design.md` applies)

### IDEA-039 — torch.compile on the SparkVSR VAE
Not tested in INQUIRY-032: the runtime image has no C compiler and the VAE is conv-bound, so little gain is expected. Only worth it if SparkVSR comes back.

### INQUIRY-033, INQUIRY-010, IDEA-034 — SparkVSR-only questions
They matter for the optional engine and for a fair SparkVSR comparison (INQUIRY-035, closed without the real-film A/B). `no_ref` is not the authors' recommended mode; SD 2.1 base and `pisa_sr.pkl` are not located. INQUIRY-010 dropped from P1 to P2 on 2026-10-30 for that reason. IDEA-034 (restore at 1080p, Lanczos to 2160p) is about 4x cheaper by estimate and untested.
- [ ] Locate weights, run `pisasr`, compare against `no_ref`

### INQUIRY-011 — Verify weights licences before M3
ReCaVSR part CLOSED by the owner on 2026-10-30: "ReCaVSR weights licence doesn't matter, as everything is for home use". Its code is Apache-2.0 and the weights licence is still unstated (no tag on Hugging Face, the README defers to the licences of the parts; Wan2.2-TI2V-5B is Apache-2.0). It is no blocker, and the note stays in case the use ever changes (MIN-043). Priority P2 from now on, since only the optional SparkVSR engine is left: it is apache-2.0 but CogVideoX1.5-5B-I2V is `license:other`.
- [ ] Read the CogVideoX card (personal use); locate SD 2.1 base and PiSA-SR weights

### ISSUE-028 — Bind API port to configurable address
Status review: implemented in the working tree on 2026-10-30, uncommitted, awaiting the owner's go because it changes how the Mac reaches the server (`stack.md`).
- [x] Bind address as a variable (default 127.0.0.1), IP out of the tracked file, `.env.example` added; `docker compose config` checked by default and with the override
- [x] Owner's go: "Commit and push everything" (2026-10-30), committed by the git agent
- [ ] Verify from a second host that the port is not reachable (needs a deployment; keep open until then)

### MIN-037 — GPU thermals: power cap / undervolt phase
Planned for the END of the project (owner). GPU 1 reached 87 C (fan 100%) under dual load and 85 C alone, GPU 0 stayed at 69 C; owner's diagnosis: the neighbouring card blocks the airflow. GPU 0 also links at PCIe gen4 x8 against x16 (`m0-server-spikes.md`).
- [ ] Try a power cap of about 300 W on GPU 1 (`nvidia-smi -pl` on the Proxmox host, resets on reboot), re-run `gpu_thermal_check.py`
- [ ] Then undervolt if needed; check whether the PCIe x8 link on GPU 0 is a slot or BIOS setting

Outcomes of completed IDs: `roadmap-outcomes.md`.
