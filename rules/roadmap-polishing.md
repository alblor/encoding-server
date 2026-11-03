# Roadmap task details: polishing, QC and release items (ID 056 onwards)

Companion of `roadmap-details.md` (FEATURE items) and `roadmap-open-items.md` (the older INQUIRY, ISSUE, MIN, IDEA items); the table is in `CLAUDE.md`. The story behind each item is in `polishing-log.md` and `restore-qc.md`. Created 2026-10-31, updated late that night. Status `review` means built, waiting for the ISSUE-059 re-check. Later IDs: `roadmap-finishing.md`.

### MIN-056 — Softness match to the original (review, P1)
Built as the soften stage of the finishing stage (`polishing-log.md` item 4): per-band spectral gain plus a local mask; mask thresholds 1.0 and 2.0, default `soften_amount` 0.8, `soften=match` in `cleanup-4k`. Measured on the real draft: the model adds +3.7 dB at 12-25% of Nyquist.
- [x] Spectral gain estimation, FFT filter and mask in `restore_worker/finish.py`; tests; measured on the real draft
- [ ] Check seams between segments for flicker (gains are per segment; a film-level estimate is the fix)
- [ ] The owner judges it on the later drafts (`adaptive` supersedes `match` in the preset, MIN-089)

### MIN-057 — Grain profile measured from a reference clip (planned, P2)
The draft has no grain, so the look the owner remembers cannot be transferred from it. A `probe_media` option measures strength, size and channel correlation of a grainy reference, and the recipe uses them. Depends on INQUIRY-058.
- [ ] Measurement option in `client-tools/probe_media.py` and tests with synthetic grain of known parameters
- [ ] Recipe fields to carry the profile (and the `/v1/docs` text, README and docs test with them)

### INQUIRY-058 — Reference clip for the grain (planned, P1, blocked on the owner)
Question for the owner: a short clip of the original film or another grainy source to measure, or a description of the look. Only MIN-057 is blocked by it.

### ISSUE-059 — QC re-run on the fixed tree (review, P0 gate)
Runs 1 to 3 said FAIL, run 4 PASS WITH CONCERNS, run 5 FAIL (1 critical), run 6 PASS WITH CONCERNS with no critical or high (`restore-qc.md`). The ID started as the run-3 gate and stays the one merge gate across runs. Nothing is running now: the fixes made after run 6 have not been looked at, so the gate needs ONE short QC re-check of them or the owner's explicit acceptance.
- [x] Run 6: unit tests (211 host, 115 CPU worker), 12 lead-in cases, VFR, libdav1d and libaom decode of ac-bias/qm encodes, memory envelope within 3%
- [ ] Short re-check of: tone white clamp, tracker (weak-link gate, non-finite rows, dedupe, shot cuts, wide gate), main-engine output validation, client probe constant, deleted rejected output, `shadow_weight`/`ac_bias`/`quant_matrices`; or the owner's acceptance
- [ ] On PASS or acceptance, move BUG-064 to 068, BUG-073 to 075, BUG-091 to 093, ISSUE-069, MIN-055, MIN-056, MIN-070 and the finishing rows of `roadmap-finishing.md` to `complete`; on FAIL, add the new findings as rows

### FEATURE-060 — Release v1.1.0 and live deploy (planned, P0)
Owner's standing authorization of 2026-10-30, plus one gate: he compares `restored_draft_v7.mkv` and the abrupt sheets and says go (INQUIRY-086 is answered: zoom, mix 0.8). Steps and deploy plan: `resume-checklist.md`, guide: `docs/DEPLOY_PROXMOX.md`.
- [x] Version bump to 2.1.0-secure is in the tree (`api/main.py`, `api/app/documentation.py`)
- [ ] Commits via `git-scm-master`, push the branch, merge to main (no force), tag v1.1.0
- [ ] Deploy to the LXC (non-destructive), verify capabilities (gpu0 and gpu1), a 3-segment trial through the client, ISSUE-028 from a second host, API groups 1000 and 10001, worker uid 10001 with CapEff 0
- [ ] SSH teardown and cleanup of test artefacts

### INQUIRY-061 and MIN-070 — FP8 (complete / review)
INQUIRY-061 is closed as adopted: own `fp8` mode 1.43x on the DiT at 46.83 dB, gate passed (`restore-measurements.md`, `roadmap-outcomes.md`). MIN-070 is the build: `Fp8Linear` in `restore_worker/quantize.py`, `advanced.restore.precision` Optional (`bf16 | fp8 | fp8_fast`, worker env `RESTORE_PRECISION`, a mismatching worker fails the job).
- [x] Measured on the server, tests in `tests/unit/test_restore_quantize.py`
- [ ] Re-measure end to end s/frame and the ETA with fp8, the finishing stages and the face guard (INQUIRY-017)
- [ ] The owner chooses the production precision; bf16 is the default until he does

### INQUIRY-062 and MIN-063 (complete)
Sony "Generating HDR Video from SDR Video" evaluated: not feasible at film scale, not a bit-depth method (`restore-research.md`). The lesson from the wrong "no released code" note is saved in the agent memory.

### BUG-064, BUG-065, BUG-066 — QC run 1 fixes (review)
Critical, high, and medium plus low findings, all fixed, listed in `restore-qc.md`.

### BUG-067 — QC run 2: memory budget, secrets, upload DoS (review, P0)
Two critical, two high and three medium findings (which was which was not recorded per item). Fixed: the memory envelope and worker limit 22g, the fifth secret with a restricted Redis ACL user, upload idle and minimum-rate limits, the other points in `restore-qc.md`.
- [ ] The ISSUE-059 re-check confirms each fix

### BUG-068 — Client cuts: open-GOP, preflight, planning (review, P1)
Open-GOP sources fall back to a closed-GOP transcode cut with a PSNR check; preflight of three segments; forced pieces inside a long GOP; sources that do not start at 0. This also covers MIN-049 (open-GOP cuts may lose frames), which stays `review` with it. Owner decision: re-encode open-GOP films to a closed GOP without considerable quality loss.
- [ ] The ISSUE-059 re-check confirms it; a real HEVC film is the best test

### ISSUE-069 — Brightness drift along a segment (review, P1)
The restored picture drifts about -4.6 grey levels on average (worst 12.6) and the global-mean step at 22 cuts reached +-3.5. Fixed with `fidelity.anchor=source` (`polishing-log.md` item 6).
- [x] Measured on the real draft after the fix: average -0.4, worst 1.6, cut-step rms 0.70
- [ ] The owner judges `anchor_amount` 0.9 on the drafts (v4 onward)

### MIN-071 — MPEG-TS with an offset is not supported (planned, P3)
A source in MPEG-TS that does not start at 0 fails closed in `plan_film()`. Deferred on purpose; remux to mkv first.
- [ ] Support it or document the remux step in `/v1/docs`

### MIN-072 — Worker memory against LXC RAM (planned, P2)
Two GPU workers at `mem_limit` 22g plus the 8g RAM volume are more than the 50,000 MB of the LXC if both peak together. The budget guard refuses a segment that cannot fit one worker, but nothing enforces the sum. Found while checking the deploy guide.
- [ ] Decide: lower the limits, raise the LXC RAM, or document it in `docs/DEPLOY_PROXMOX.md`
