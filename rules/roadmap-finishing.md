# Roadmap task details: QC runs 3 to 6, finishing features, faces, shadow texture (IDs 073 to 099)

Companion of `roadmap-polishing.md` (IDs 056 to 072); the table is in `CLAUDE.md`. Created 2026-10-31 (night), updated 2026-11-01; IDs from 100 are in `roadmap-v8.md`. `review` means built and tested, waiting for the ISSUE-059 re-check (one short QC pass on what changed after run 6, or the owner's acceptance). The story is in `restore-qc.md`, `restore-finishing-features.md`, `restore-face-guard.md` and `restore-shadow-texture.md`.

### BUG-073 — QC run 3 fixes (review, P1)
Run 3 said FAIL with 2 HIGH client findings: A/V desync when the video starts after the audio, and an `IndexError` in `plan_segments`. Both fixed; run 6 exercised lead-ins (12 cases) without a high finding.
- [x] Fixed (client suite counted in the 211); [ ] re-check closes it

### BUG-074 — QC run 4 high: assembly delay (review, P1)
HIGH 1: the `assemble()` duration check aborted a correct file when the video lead-in was more than about 0.5 s. HIGH 2: `video_start_delay()` returned 0 for a lead-in beyond ffprobe's probe window, a silent A/V desync. Fixed: the delay comes from packet times, the plan from frame times.
- [x] Fixed; [ ] re-check closes it

### BUG-075 — QC run 4 medium (review, P2)
`Dockerfile.cpu` did not copy `faces.py`; adaptive softening and local contrast crashed on tiny frames; the tone curve flattened shadows above contrast * pivot 0.25 (clamped, and bounded on the white side since run 6). The fourth medium, the pivot seam, is ISSUE-077.
- [ ] Re-check closes it

### MIN-076 — QC run 4 low findings (review, P3)
Stale docs text (fixed); no warning when adaptive, match or face_guard are skipped on an upscaled source; texture read as grain by the automatic detection.
- [ ] Owner decides whether the skip needs a warning; state of the texture-as-grain finding to be confirmed

### ISSUE-077 — Tone pivot steps at segment cuts (planned, P3)
An unset pivot is the scene median per segment, so a gradual brightness change inside a shot can step at a forced cut. Documented in `/v1/docs`; tone is opt-in. Possible fix: a film-level pivot.
- [ ] Decide only if the owner turns tone on for a film with moving scenes

### FEATURE-078, FEATURE-079, MIN-080 — Adaptive softening, tone, colour anchor (review, P1/P2)
Built in `restore_worker/finish.py` (`restore-finishing-features.md`): `fidelity.soften=adaptive`, the `tone` block, `anchor_chroma_amount` 0.35.
- [x] Built, tested, measured on the draft stretch; [ ] re-check closes them; the owner judges them in the drafts

### FEATURE-081 — Grain from the source for any size (review, P1)
Uses the source's own grain residual, `source_strength` 1.0 up to 1.5. About 60% of the source grain survives the finish, the default AV1 encode removes about a third of that. INQUIRY-058 and MIN-057 stay open: the draft has no grain.
- [ ] Re-check closes it

### FEATURE-082, FEATURE-083 — Face guard on and zoom (review, P1)
YuNet detection and tracking, `on` blends the original back, `zoom` redraws the face with the model on a crop (`restore-face-guard.md`).
- [x] Measured on the draft; [ ] re-check closes them

### INQUIRY-086 — Preset default: face_guard on or zoom (complete, P1)
Answered by the owner on 2026-10-31 (late night): zoom with a 20/80 mix of the original and the redrawn face. Implemented as MIN-097. Outcome line in `roadmap-outcomes.md`.

### MIN-089 — cleanup-4k preset updated (review, P1)
Soften adaptive 1.0, anchor source, tone contrast 0.2 and saturation 1.06, `segment_max_seconds` 6; since the late night also `face_guard: zoom` with mix 0.8 (MIN-097) and the shadow-texture set (FEATURE-095).
- [x] In `restore_core/recipe.py`; [ ] README and `rules/recipe-api-tiers.md` follow (the README does not mention the new fields yet, MIN-021)

### ISSUE-084 — Face tracks cannot cross a segment cut (planned, P2)
Segments are independent jobs, so a head that turns right at a segment seam starts unguarded in the segment before it. The hard cuts INSIDE a segment are handled by FEATURE-098.
### FEATURE-085 — Whole-film face pre-pass with hints (planned, P2)
The client detects and tracks faces on the whole film once and sends per-segment hints with each job. Not built.
- [ ] Hint format in the recipe or job (and `/v1/docs`), client pass, worker uses it

### INQUIRY-087 and INQUIRY-088 (complete)
087: reference-based face restorers and ComfyUI options rejected for now. 088 closed 2026-11-01: KEEP rejected, the VACE retest dropped by the owner (`restore-research.md`, `roadmap-outcomes.md`).

### MIN-090 — Makefile and env template (review, P3)
`make secure-down` passes `--profile cpu --profile gpu`; `make test-restore` (211) and `make test-restore-worker` (130 on 2026-11-01); `.env.example` gained `COMPOSE_PROJECT_NAME`, `RESTORE_MODELS_DIR` and `RESTORE_CACHE_DIR`.
- [ ] Re-check confirms `secure-down` leaves nothing running

### BUG-091 — QC run 5 critical and high (review, P0)
Run 5 said FAIL. CRITICAL: a COPY cut of an mkv whose video starts 6 s or more after its audio silently corrupted frames (ffmpeg's default 5 s probe window misses the late video). HIGH: `needs_source` left out adaptive and match softening and `face_guard` other than off. Fixed: `PROBE` constant (`-analyzeduration 60000000 -probesize 100000000`) before every source `-i` in the client and in `probe_media.py`, `decode_cmd -fps_mode passthrough`, `needs_source` extended. Run 6 exercised 12 lead-in cases (0.4 to 20 s, AAC and PCM) without a finding of that kind.
- [x] Fixed; [ ] re-check covers the client probe constant

### BUG-092 — QC run 5 medium and low (review, P2)
MEDIUM: zoom output unvalidated (now `ZoomError`, and the main engine output too: `PipelineError` "the engine returned ..."); guard weight ramp popped (reaches the first and last detection weight exactly); cancel and report blind during face stages (checked between detections and tracks); raw `cv2.error` for a corrupt face model (`FaceModelMissing`); tone clamp. The LOW findings were not itemised in the brief I received.
- [x] Fixed; [ ] re-check covers main-engine validation and cancellation

### BUG-093 — QC run 6 medium (review, P2)
Run 6 said PASS WITH CONCERNS. Fixed: tone curve bounded on the white side (contrast * pivot and contrast * (1 - pivot) at or below 0.15); a weak detection (score under 0.7) links only within 2 face sizes; non-finite detection rows dropped; duplicate tracks merged (IoU above 0.5 on 70% of common frames); a failed client assembly deletes the rejected output.
- [x] Fixed; [ ] re-check covers these

### MIN-094 — QC run 6 low leftovers (planned, P3)
Open on purpose: crossing faces swap track identity; VFR with real timestamp gaps or mixed frame rates fails closed only at assembly; jittered VFR with duplicate pts is refused at preflight (false positive); video late against a subtitle track with no audio is delayed twice (fail-closed); the cpu compose service has no `/m` mount, so `face_guard` needs `yunet.onnx` there.
- [ ] Decide which to fix before the release and which to document

### FEATURE-095 — Shadow texture: deband off, shadow grain, AV1 ac-bias (review, P1)
The owner: textures flattened, no dynamic range. Measured: the AV1 encoder flattened the dark pixels (0.9% in plateaus before the encode, 34.1% after). Set in `cleanup-4k` and `film-restoration` (`SHADOW_TEXTURE` in `restore_core/recipe.py`): `bitdepth.deband` off, `grain.shadow_weight` 0.35 (new, default 0.12), `encode.ac_bias` 1.0 and `encode.quant_matrices` true (new, defaults 0 and false). Whole draft v7 against v6: plateaus 83.6% to 33.2% (source 76.9%), file +72%.
- [x] Built, measured (`restore-shadow-texture.md`); [ ] the owner judges v7 and the size; [ ] re-check covers the new fields; [ ] README and `/v1/docs` mention them (MIN-021)

### IDEA-096 — 10-bit path through the model (postponed, P3)
The pipeline decodes to rgb24 and the model outputs 8-bit, so a 10-bit source loses its shadow precision at the model stage. Known limit, not changed; related research: INQUIRY-050.

### MIN-097 — face_zoom_mix and zoom as preset default (review, P1)
The owner's answer to INQUIRY-086: `fidelity.face_zoom_mix` 0.8 (20% original, 80% redrawn), `cleanup-4k` `face_guard: zoom`.
- [x] In the recipe and preset; [ ] re-check; [ ] re-measure the film ETA with zoom (INQUIRY-017)

### FEATURE-098 — Face tracker: shot cuts and fast faces (review, P1)
Tracks stop at hard cuts inside a segment (`shot_cuts`: 64x36 thumbnails, mean change above max(24, 5x median)); confident faces link within 8 face sizes (cost = distance + 3*log(size ratio) - 3*score - 4*IoU), weak ones within 2. Simulated on the draft through the real worker (sheets in `abrupt/`): a cut into a shot with a visible 45 px face is redrawn from its first frame; a 4x zoom-in in 24 frames is followed (the first tracker lost it).
- [x] Built, simulated; [ ] re-check covers the tracker

### INQUIRY-099 — MiniMax-H3 and Bernini for face identity (planned, P3)
Only if the owner asks (the VACE retest, INQUIRY-088, ended with the owner dropping VACE; this was never researched). MiniMax-H3 is open-weight but its community licence excludes the EU, UK, Korea and the US, and the open weights have no video-to-video; the owner knows (told once) and asked for research, also on Reddit, only in that case. "Germini from ByteDance" is most plausibly Bernini (Apache-2.0), an unverified inference. Details: `restore-research.md`.
- [ ] Wait for the owner; [ ] if he asks, research both
