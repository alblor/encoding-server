# Roadmap task details: INQUIRY, ISSUE, MIN and IDEA items (keyed by ID)

Companion of `roadmap-details.md` (FEATURE items); the table is in `CLAUDE.md`, completed IDs are in `roadmap-outcomes.md`. Same conventions. Last updated 2026-11-03 (MIN-037 closed, see `roadmap-outcomes.md`). Newer items (056 onwards): `roadmap-polishing.md`. Rows with no entry here are fully described by their title and dependencies.

### ISSUE-012 — Security-model change for the glibc worker (review)
Implemented and documented in `stack.md`: the worker runs on an internal-only network (Redis is all it reaches), plaintext goes through a RAM volume, a root entrypoint copies the Redis secret to tmpfs and drops every privilege with `setpriv`, and no key ever reaches the worker. Verified so far by rendering the compose file and by the hardened containers of the two-GPU run; the su-exec group check (MIN-055) and the QC pass are open.
- [x] Internal network, read-only root, `cap_drop ALL` + SETUID/SETGID/CHOWN, no-new-privileges, tmpfs secret, privileges dropped before Python
- [ ] QC engineer attacks the boundary (worker egress, shared-volume permissions, secret left on disk)

### MIN-013 — Weights staging ops step (review)
`scripts/stage_restore_weights.sh` (`make gpu-weights`) fetches the ReCaVSR weights once in a throwaway container with network, checks SHA-256 and leaves them for a read-only mount. Observed in the working tree at the end of the session; not run by the documenter.
- [ ] Run it on the server and record the result

### MIN-014 — Frame-count and A/V-drift assertions (review)
Frame counts are verified after each segment in `pipeline.py` and the client checks the assembled film (`restore_film.py`). Whether audio and video durations of the assembled film are compared is for QC to confirm.
- [ ] Confirm or add a duration check of audio against video on the assembled film

### MIN-016 — Pin SVT-AV1 version in worker image (review)
Static ffmpeg n8.1.3 with SVT-AV1 4.2.0, SHA-256 verified in `Dockerfile.gpu` (and `Dockerfile.cpu`). Pins are listed in `commands.md`.

### INQUIRY-015 — HDRTVNet++ output PQ-encoded? check
Gates the learned highlight expansion of FEATURE-007. Not started: the static mapping needs no model.

### INQUIRY-017 — Measured ETA per film (review)
Measured per engine. ReCaVSR on real 2160p footage, two GPUs, hardened containers: 0.82 s/frame end to end per GPU (engine 0.53), about 19.7 h for a 172,800-frame film, about 14 h with overlap (FEATURE-044); the earlier ESTIMATE was 12 to 14 h (`restore-measurements.md`). Not re-measured with the fp8 mode (0.475 against 0.578 s/frame in the engine alone, MIN-070) nor with soften and anchor. SparkVSR: about 6.9 s/frame, about 7 days, failed the gate. Stays in review until the owner judges the number.

### INQUIRY-042 — Test ReCaVSR at scale 1 on native 2160p (review)
The owner's draft is native 2160p and ran with the `cleanup-4k` preset (scale 1) on the whole clip; the first restored segment looked faithful at normal brightness, with slightly deeper blacks. That is the engine's first real-footage run at scale 1, but not the comparison originally asked for.
- [ ] Compare against the untouched input with `tools/scripts/ops/quality/video_compare.py`, 1:1 crops, then the TV
- [ ] Decide with the owner: scale 1 is fine, or same-size cleanup needs another path; record in FEATURE-005 and FEATURE-006

### MIN-043 — Pin ReCaVSR commit and weights SHA-256 (review)
Commit `b98b1f2e` is pinned in `Dockerfile.gpu` with its `uv.lock`; the weights revision and SHA-256 values are in `stage_restore_weights.sh`. The unstated weights licence stays noted in case the use ever leaves the home (INQUIRY-011).

### IDEA-039 — torch.compile on the SparkVSR VAE
Not tested in INQUIRY-032: the runtime image has no C compiler and the VAE is conv-bound. Only worth it if SparkVSR comes back.

### INQUIRY-033, INQUIRY-010, IDEA-034 — SparkVSR-only questions
They matter for the optional engine. `no_ref` is not the authors' recommended mode; SD 2.1 base and `pisa_sr.pkl` are not located. IDEA-034 (restore at 1080p, Lanczos to 2160p) is about 4x cheaper by estimate and untested.
- [ ] Locate weights, run `pisasr`, compare against `no_ref`

### INQUIRY-011 — Verify weights licences before M3
ReCaVSR part CLOSED by the owner on 2026-10-30: "ReCaVSR weights licence doesn't matter, as everything is for home use" (code Apache-2.0, weights licence unstated). Only the optional SparkVSR engine is left: CogVideoX1.5-5B-I2V is `license:other`.
- [ ] Read the CogVideoX card (personal use); locate SD 2.1 base and PiSA-SR weights

### ISSUE-028 — Bind API port to configurable address (review)
Implemented: bind address variable (default 127.0.0.1), `.env.example`, `docker compose config` checked.
- [ ] Verify from a second host that the port is not reachable (needs a deployment)

### INQUIRY-045 — DART soft-step evaluation (planned)
First learned candidate for the soft pre-step (`restore-research.md`): MIT licence, 52 MB, scratches/dust/flicker, trained on 256 px crops, 2160p behaviour unverified.
- [ ] Run it on a clip of the draft, compare to hqdn3d with `video_compare.py` and a labelled draft

### IDEA-046 — BM3D temporal as an upgrade of the classical step (postponed)
Possible upgrade over hqdn3d if the light prefilter is not enough on real film.

### IDEA-047 — Move tile prepare and composite to the GPU (postponed)
CPU prepare and composite are about 23% of the wall time (`restore-measurements.md`). Revisit after FEATURE-044.

### ISSUE-048 — Forced cuts mid-shot have no pre-roll (planned)
The client cuts on keyframes; a forced cut inside a long take starts a new stream without history.
- [ ] Add pre/post-roll that the worker discards, or document the limit in `/v1/docs`

### MIN-049 — Open-GOP keyframe cuts may lose frames (review)
Sources with open GOPs (x265 default) lose leading frames on a stream-copy cut. Built 2026-10-31 with BUG-068: the client falls back automatically to a closed-GOP transcode cut (near-lossless SVT-AV1 CRF 8) checked by frame count and PSNR >= 42 dB; `--cut auto|copy|transcode`.
- [ ] Verify with a real HEVC source in QC run 3 or the deploy trial

### INQUIRY-050 — Bit-depth expansion research (progress)
The owner's concern: restored frames are 8-bit (banding in 10-bit and HDR); he suggested a diffusion-like 8-to-10-bit model and re-applying a 10-bit source's precision. Today deband, dither and 16-bit quantisation handle it (`restore-finish-grain-hdr.md`). The research landed (2026-10-31): no open learned 8-to-10-bit model for video exists, and the Sony SDR-to-HDR method is not feasible at film scale (`restore-research.md`, `polishing-log.md` item 2).
- [x] Research linked; recommendation: classical stage (float, deband, grain, one 16-bit rounding)
- [ ] Owner confirms the classical stage is enough on his TV, or MIN-051 gets built

### MIN-051 — Implement `bitdepth.anchor_source` (planned)
The owner's idea: for 10-bit sources, re-apply their information. The recipe field (`off | lowfreq`) exists; it is NOT implemented. Depends on INQUIRY-050.

### INQUIRY-052 — Does the owner's TV apply AV1 film grain? (planned)
Decides the `av1_fgs` option: it needs a decoder that applies AV1 film grain, and its synthesis repeats a small template (regular at higher strengths). The default moved to `baked` (film-like grain, strength 0.4) on 2026-10-31, so this is no longer a blocker. For the owner to test on his TV with the restored draft produced with the defaults. SVT-AV1 estimates are not monotonic in the level, so the values (level 8, strength 1.0) also need a look on real footage.
- [ ] Owner plays the draft with `av1_fgs` and with `baked`, and reports

### INQUIRY-053 — Real-TV check of the HDR10 output (planned)
No HDR10 file made by `hdr: synthesize` has been played on a TV yet (signalling: BT.2020, PQ, mastering display and content light 203 nits).

### ISSUE-054 — The API has no authentication (planned)
The existing API has none, and that is documented. The restore endpoints scope jobs by the SHA-256 of `X-API-Key`, which keeps callers apart but proves nothing about who they are. Security is the standing priority, so it stays visible.
- [ ] Decide with the owner: authentication on `/v1/restore` (and `/v1/jobs`), or the network boundary is enough
- Candidate answer researched 2026-11-03: a YubiKey touch per token (INQUIRY-111, `yubikey-auth-inquiry.md`); the docs overstate what exists today (MIN-112)

### MIN-055 — su-exec supplementary groups for gid 10001 (review)
QC found that `su-exec 1000:1000` never loads the group, so every submit failed; the entrypoint now uses `su-exec 1000` (BUG-064, `restore-qc.md`). Still to confirm in the real container.
- [ ] Check `id` of the API process inside the container on the server, and a real upload

### MIN-020 — Gitignore `.secrets/` and `tools/sandbox/` (review)
The working-tree `.gitignore` now lists `.secrets/` and `tools/sandbox/`, plus more media containers (`*.m2ts`, `*.mxf`, `*.webm`) and `*.restore-work/`; seen at the end of the 2026-10-30 session, uncommitted, not part of the documenter's brief.
- [ ] Commit it and check with `git check-ignore -v`
