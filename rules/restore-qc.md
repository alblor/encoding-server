# Restoration QC: runs 1 to 3 FAIL, 4 PASS WITH CONCERNS, 5 FAIL, 6 PASS WITH CONCERNS, run 7 (numeric gate) PASS 4.80

The quality-control engineer attacks the whole restoration feature on a local stack (Colima, a disposable copy under `~`, loopback only). Verdicts so far: run 1 FAIL (4 critical, 3 high), run 2 FAIL (2 critical, 2 high, 3 medium), run 3 FAIL (2 high), run 4 PASS WITH CONCERNS, **run 5 FAIL (1 critical)**, **run 6 PASS WITH CONCERNS (no critical, no high)**. Runs 1 and 2 are in `restore-qc-early.md`. Everything below is fixed in the working tree except the points marked open. **Run 7 (2026-11-03, three rounds) is the re-check of ISSUE-059 and it passed with 4.80: the merge gate is met.** Nothing here is `complete` until it says so. Tests after run 7 (session, 2026-11-03): `make test-restore` 215 passed, `make test-restore-worker` 138 passed.

## Run 3 and run 4 (BUG-073, BUG-074, BUG-075, MIN-076, ISSUE-077)

Run 3 (FAIL, 2 HIGH, both in the client): the audio and video desynchronised when the video starts after the audio, and `plan_segments` raised an `IndexError`. Fixed (BUG-073).

Run 4 (PASS WITH CONCERNS):
- HIGH, `assemble()` aborted a correct file when the video lead-in was more than about 0.5 s, and `video_start_delay()` returned 0 for a lead-in beyond ffprobe's probe window, a silent desync. Fixed (BUG-074): the delay uses packet times, the plan takes durations from frame times, forced cuts and `--cut auto|copy|transcode` are in the plan (open-GOP and start-offset sources are cut by decoding and re-encoded near-losslessly, CRF 8, closed GOP).
- MEDIUM, `Dockerfile.cpu` did not copy `faces.py`; adaptive softening and local contrast crashed on tiny or very narrow frames; the tone curve flattened shadows when contrast * pivot > 0.25. Fixed (BUG-075). The unset tone pivot stepping at segment cuts is documented and left open on purpose, tone being opt-in (ISSUE-077).
- LOW, stale docs text; no warning when adaptive, match or face_guard are skipped on an upscaled source; texture read as grain by the automatic detection (MIN-076).

## Run 5: FAIL, 1 critical (BUG-091, BUG-092)

The critical one is the kind that does not announce itself. A COPY cut of an mkv whose video starts 6 s or more after its audio silently corrupts frames: ffmpeg's default probe window is 5 s, so a video that begins later is not seen when the file is opened and the cut decodes garbage. A default that is fine for almost every file turned into a silent failure on the few that matter, so the window is now explicit.

- CRITICAL, fixed (BUG-091): a `PROBE` constant (`-analyzeduration 60000000 -probesize 100000000`) before EVERY source `-i`, in the client and in `probe_media.py`; `decode_cmd` also passes `-fps_mode passthrough`.
- HIGH, fixed (BUG-091): `needs_source` left out `soften` adaptive and match and any `face_guard` other than off, so the worker never got the source those stages need; it now includes them.
- MEDIUM, fixed (BUG-092): the zoom engine output is validated (`ZoomError`), and now the main engine output too (a `PipelineError` that starts with "the engine returned"); the guard weight ramp reaches exactly the first and last detection weight (it popped before); cancel and the report are checked between detections and tracks (they were blind during the face stages); an unreadable or corrupt face model raises `FaceModelMissing` (it was a raw `cv2.error`); the tone clamp.
- LOW: the brief I received did not itemise the run 5 LOW findings, so they are not listed here.

## Run 6: PASS WITH CONCERNS (BUG-093, MIN-094)

No critical, no high. QC ran 12 lead-in cases (0.4 to 20 s, AAC and PCM audio), VFR inputs, ffmpeg decoding of libdav1d and libaom encodes made with `ac-bias` and `qm`, and the memory envelope, which held within 3%. Its MEDIUM findings are fixed (BUG-093):
- The tone curve is also bounded on the white side: contrast * pivot and contrast * (1 - pivot) both at 0.15 or below.
- A weak detection (score under 0.7) may only link to a track within 2 face sizes (a lamp could hijack a face track).
- Non-finite detection rows are dropped; duplicate tracks are merged (IoU above 0.5 on at least 70% of their common frames).
- A failed client assembly deletes the rejected output file.

Known LOW leftovers, open on purpose (MIN-094): crossing faces swap track identity; VFR with real timestamp gaps or mixed frame rates fails closed, but only at assembly; jittered VFR with duplicate pts is refused at preflight (a false positive); a video that starts late against a subtitle track with no audio is delayed twice (fail-closed); the cpu compose service has no `/m` mount, so `face_guard` needs `yunet.onnx` there.

## Run 7: the numeric merge gate, PASS 4.80 (ISSUE-059; BUG-113 to BUG-115, INQUIRY-116, INQUIRY-117, MIN-118)

The owner's rule: deploy only if QC >= 4.8/5, otherwise fix first. The quality-control engineer scored with a rubric: 5.0 minus 1.0 per CRITICAL, 0.5 per HIGH, 0.1 per MEDIUM, 0.02 per LOW and 0.1 per UNVERIFIED area.

- Round 1, 3.56 FAIL: F1 HIGH (already in HEAD), the secret lifecycle script aborted after the first secret under `set -euo pipefail`, plus F1b and F1c; F2 MEDIUM, `needs_source` omitted glow; F3 MEDIUM, a wrong-shape ONNX failed cryptically; F4 MEDIUM, the backup passphrase was thrown away; F5 LOW, secret previews; F6 LOW/info, no CHOWN in the API container; 6 UNVERIFIED areas.
- Round 2, 4.66: all of that fixed except F6, which stays informational (behaviour unchanged since before this branch). New G1 MEDIUM (compile-cache directory never created), G2 LOW (deploy doc gaps), G3 LOW (`gpu-status` address); 2 UNVERIFIED left.
- Round 3, 4.80 PASS, no findings. The gate is met with ZERO margin: one more LOW finding (4.78) would have failed it.
- Fixes and tests: `roadmap-outcomes-2.md` (BUG-113 to BUG-115). Counts: 215 host, 138 worker, all passing. The legacy stack in the QC sandbox: unit 17/17, manual 9/9, automated 12/12, progress 6/6, cancellation 6/6, docs 37/37, API 8/11 (the known MIN-024).
- Still UNVERIFIED, left for the deploy trial: the AppArmor profile (INQUIRY-116) and the GPU image on the real host (INQUIRY-117).
- Notes with no points: `tone.pivot` falls back to the restored frames when no source is kept; `bitdepth.anchor_source` is accepted and unused (MIN-051); `Dockerfile.cpu` does not copy `run_local.py` or `quantize.py` (fine for the worker); `budget.py` does not charge the zoom arrays (MIN-118).
- Anything that changes authentication after the deploy needs a re-QC (`yubikey-auth-inquiry.md`).

## What the re-check had to cover (closed by run 7)

What changed after run 6, in two groups. Fixes of run 6 and after: the white-side tone clamp, the tracker (weak-link gate, non-finite rows, dedupe, shot cuts, the wide gate for fast faces: `restore-face-guard.md`), the main-engine output validation, the client probe constant, the deleted rejected output, and the `shadow_weight`, `ac_bias` and `quant_matrices` fields (`restore-shadow-texture.md`). New code since 2026-11-01: `restore_worker/heads.py` (FEATURE-100: tiled YOLOX search, head box, `without_faces`, a missing or unreadable model file) and the face stage in `pipeline.py` that joins head tracks to the zoom tracks, `finish.glow_match` (MIN-102) and `finish.plateau_purge` (MIN-103) with their recipe fields (`fidelity.glow`, `glow_sigma`, `bitdepth.plateau_purge`; both default 0), and the staging of `yolox.onnx` (`scripts/stage_restore_weights.sh`, SHA-256 check). The unit suites at the time of writing: 211 host and 130 CPU-worker, all passing (session). Run 7 passed and closed ISSUE-059. Promoting the other rows is pending (see `resume-checklist.md`); the rule was that a PASS lets BUG-064 to 068, BUG-073 to 075, BUG-091 to 093, ISSUE-069, MIN-055, MIN-070 and the `review` finishing rows (also FEATURE-100, MIN-102, MIN-103) become `complete`. Scope notes: `roadmap-v8.md`.
