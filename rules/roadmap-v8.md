# Roadmap task details: head tracks, glow, plateau purge, research closures (ID 100 onwards)

Companion of `roadmap-finishing.md` (IDs 073 to 099); the table is in `CLAUDE.md`, the outcomes of closed IDs are in `roadmap-outcomes.md`. Created 2026-11-01. `review` means built and tested, waiting for the ISSUE-059 re-check. Measurements marked "session" were reported by the working session on 2026-11-01 and not re-run by the documenter.

### ISSUE-059 and FEATURE-060 — scope update (superseded 2026-11-03)
ISSUE-059 is complete: the final QC passed with 4.80 (`restore-qc.md` run 7, outcome in `roadmap-outcomes-2.md`). FEATURE-060 is `progress`: the owner's conditional go was satisfied and the merge, tag and deploy started. Details in `roadmap-gate.md`.

### FEATURE-100 — Head tracks for people seen from behind (review, P1)
YuNet only finds faces that look at the camera, so a head from behind got the plain model's plastic, messy hair. `restore_worker/heads.py` finds small persons with YOLOX and derives a head box, the zoom stage redraws it. Active only with `face_guard: zoom`; optional (no file, no stage); a head track that overlaps a face track is dropped. Details and licence: `restore-face-guard.md`. Seen on the draft at 0:33 to 0:36 (segment 10): 1 head track, 79 zoomed frames (session).
- [x] Built, unit tests for the head box and for dropping head tracks that follow a face (`test_restore_finish.py`); [x] seen on the draft; [ ] re-check covers it; [ ] `/v1/docs` text mentions heads (MIN-021)

### INQUIRY-101 — SparkVSR as the face engine (complete, P2)
Question: could SparkVSR redraw small faces better than the ReCaVSR zoom? Answer (session): no. See `roadmap-outcomes.md` and `restore-research.md`.

### MIN-102 — Glow stage, opt-in (review, P2)
`finish.glow_match`, recipe `fidelity.glow` 0..1 and `glow_sigma` (pixels at 2160 lines), default 0, additive only, after the anchor and before the face patches and tone. Measured on frame 900 (session): v8's falloff around bright lights is already about 93% of the original's and glow adds about 1%, so no preset enabled it. Update 2026-11-03: after the owner's answer to INQUIRY-106, `cleanup-4k` now sets `glow` 1.0 (MIN-119). A first version that also subtracted light turned one lamp core red and dark, hence additive only. Needs a same-size source. `restore-finishing-features.md`.
- [x] Built, 6 tests; [ ] re-check covers it; [ ] owner decides whether any preset turns it on

### MIN-103 — Plateau purge, opt-in (review, P2)
`finish.plateau_purge`, recipe `bitdepth.plateau_purge` 0..1, default 0, before tone and grain. Touches only wide staircases (banding, posterised contour patches). Evidence and the list of what was rejected: `restore-finishing-features.md`. Caveat: the evidence is synthetic degradations of clean v8 frames plus eyeballed sheets, no real damaged film. Peak VRAM unchanged (9.67 GiB allocated), no measurable time cost.
- [x] Built, 5 tests; [ ] re-check covers it; [ ] try it on a real damaged source

### INQUIRY-104 — Artifact removal for low-quality encodes (complete, P2)
A background agent compared conservative ways to remove banding, blocking and ringing. Outcome: only plateau purge (MIN-103) is safe; blocking and ringing cannot be removed conservatively. Details in `roadmap-outcomes.md` and `restore-finishing-features.md`.

### IDEA-105 — Plateau purge on for uhd-damaged (postponed, P3)
On the real draft, after restoration plus grain, the purge is a near no-op (dark flat-pixel share 0.338 against 0.344), so no preset turns it on. A candidate default for the `uhd-damaged` probe class (`client-tools/probe_media.py`, preset `cleanup-4k`) once a damaged source is tried.
- [ ] Wait for a real damaged 2160p source; [ ] compare with and without

### INQUIRY-106 — The original's "blur overlay": which meaning? (complete 2026-11-03, P1)
Answered by the owner: bloom only, inferred from the original, no conditional or defocus logic. The focus-aware softening design is dropped. Result: MIN-119 (`cleanup-4k` with `glow` 1.0). Outcome: `roadmap-outcomes-2.md`; the question as asked: `polishing-log-2.md` item 13.

### MIN-107 — Server cleanup after the research (complete, P2)
2026-11-01, with the owner's approval: the SparkVSR weights, code, image and scratch were deleted from the server. Kept: the `encoding-restore-worker` image, `/srv/models/recavsr` (recavsr weights, `yunet.onnx`, `yolox.onnx`), `/srv/src/code`, RAM scratch under `/dev/shm/media`. Effect on older IDs: INQUIRY-010, INQUIRY-033, IDEA-034 and IDEA-039 (SparkVSR scale 1, PiSA-SR runs, SparkVSR VAE compile) now need the weights and code staged again before anybody can work on them; they stay as written. The bench images listed in `resume-checklist.md` teardown were not named in the cleanup report, so that list is unchanged.

### INQUIRY-088 and INQUIRY-099 — closed and still open
088 is complete (KEEP rejected, VACE retest dropped by the owner; no CodeFormer result is recorded, open a new ID if he wants that test). 099 was never researched: MiniMax-H3 and Bernini only if the owner asks.

### MIN-108 — Reboot test of the GPU profile boot order (planned, P2)
`gpu-profile.service` is ordered `Before=pve-guests.service`, but that ordering has never been tested with a real reboot, because a reboot wipes the media the LXC keeps in RAM (`/dev/shm/media`), hence it waits for the next planned one. Details and the check commands: `gpu-undervolt.md`.
- [ ] After the reboot: `systemctl status gpu-profile gpu-fan-policy`, `python3 /opt/gpu-profile/gpu_profile.py verify && echo OK`, `journalctl -u gpu-profile -u gpu-fan-policy -b`, and `nvidia-smi` showing PL 300 W before the LXC starts its jobs
- [ ] While the host is down anyway, check GPU 0's PCIe link (it runs gen4 x8 against x16 on GPU 1, `m0-server-spikes.md`): this was a sub-task of the old MIN-037 text that the campaign never covered; give it its own ID if the owner wants it tracked apart

### MIN-109 — Re-validate the GPU profile after a driver update (planned, P3)
By design the profile stays at stock on any driver other than 580.76.05 (`GPU_PROFILE_DRIVER`), because the curve goes through undocumented NvAPI calls that were validated on that driver only. A driver update is the trigger, so there is no date.
- [ ] Screening round (`run_config.sh screen`), then a 2 h ReCaVSR soak (`recsoak`), then check the host kernel log for Xid
- [ ] Only then change `GPU_PROFILE_DRIVER` in `/etc/default/gpu-profile` and restart both units

### INQUIRY-110 — Promote the GPU campaign tooling to tools/scripts/ops/? (planned, P3)
`run_config.sh`, `campaign.py`, `analyze.py`, `summarize.py` and `deploy/` live only in the gitignored `tools/sandbox/gpu-tuning/`, and MIN-109 needs them. Owner's decision, low priority: if they stay there, a clean checkout cannot repeat the validation.
- [ ] Owner decides; if yes, move them per `conventions.md` and index them in `tools/CLAUDE.md`
