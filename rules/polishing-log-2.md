# Polishing log, part 2: v8 approved, heads from behind, the blur question, v9 (items 11 to 14)

Continues `polishing-log.md` (items 1 to 10). Same rule as there: each owner note as he said it, what was measured, what was decided, its status. Written 2026-11-01. Numbers marked "session" were reported by the working session and not re-run by the documenter.

## 11. Draft v8: "looks great" (done, owner approved the draft)

The owner watched v8 and said it looks great. This is the draft he accepts as the result of the polishing, which is NOT his go for commit, merge, tag and deploy: that go is a separate, still pending gate (`resume-checklist.md`, FEATURE-060).

What v8 is: preset `cleanup-4k` with the own fp8 mode (MIN-070), the shadow-texture set (`bitdepth.deband` off, `grain.shadow_weight` 0.35, `encode.ac_bias` 1.0, `encode.quant_matrices` true, FEATURE-095), `face_guard: zoom` with `face_zoom_mix` 0.8 (MIN-097), and the new head tracks (FEATURE-100). Measured (session): 23 segments of 6 s, 1896 frames, 170 MB, 52 min on one GPU, about a third of that time in the zoom pass. Arithmetic, not measured: 52 min over 1896 frames is about 1.65 s per frame, so a 2 h film at 24 fps (172,800 frames) would be about 79 h on one GPU; the old 19.7 h figure is stale, and INQUIRY-017 stays open until the trial through the real client gives the number that counts.

## 12. Hair of people seen from behind (done, review)

What the drafts before head tracks showed: a person seen from behind in the shot at 0:33 to 0:36 (segment 10) with plastic, messy hair, the same family of problem as the wrong eyes on a small face. The face detector cannot help, there is no face. FEATURE-100 adds a YOLOX person detector (`restore_worker/heads.py`), derives a head box from each person box and sends it through the same zoom stage. Result on v8 (session): 1 head track and 79 zoomed frames in that segment. Details, licence and the model checksum: `restore-face-guard.md`.

## 13. "A dynamic way to understand the blur overlay of the original" (answered in item 14, INQUIRY-106)

The owner asked for a dynamic way to understand the "blur overlay" of the original and re-apply it. I measured the obvious reading first: it is not the bloom. The glow stage (MIN-102) changes about 1% on frame 900, because v8's falloff around bright lights is already about 93% of the original's. What does differ (session): the original's out-of-focus lamps and candles are soft orbs, and the model gives them filament detail; restored over source band energy there is 1.1 to 1.5x, up to 3x at edges. A candidate design exists (focus-aware softening that follows the original frame by frame, a per-region sharpness limit with a better focus measure than the fine over mid energy ratio, which was too noisy because of the source's compression noise), but it solves one meaning of his sentence, and there may be another. I did not answer for him: the question waited for him to say which meaning he wanted (item 14).

## 14. v9 approved: bloom only, no defocus logic (done 2026-11-03, MIN-119)

The owner answered item 13: bloom only, inferred from the original, with NO conditional or defocus logic. In his words, "the model should improve the details anyway" and "it should be adapting to the movie source itself, and in this case it wasn't much to restore". So the focus-aware softening candidate is dropped and the glow stage (MIN-102) becomes the answer: `cleanup-4k` now sets `fidelity.glow` 1.0 in `restore_core/recipe.py`, with fp8 as before.

I rendered v9 on both GPUs (the owner freed GPU 0): 23 segments, 1896 frames, about 26 min wall against 52 min for v8 on one GPU, 170.06 MB against 170.02 MB. Measured against v8 (session): elsewhere identical to 4 digits; on frame 900 the restored light near highlights is already above the source (0.048 mean linear-light surplus); clip-wide luma +0.07 on about 138. In practice v9 looks like v8 on this film, and glow acts as a floor for films where the model tightens the bloom. The owner watched it: "that's what I was looking for". `plateau_purge` stays opt-in (IDEA-105 open). His go for commit, merge and deploy was tied to the QC gate, see `roadmap-gate.md` (FEATURE-060).

## Research closed on the same day

- SparkVSR is not better than the zoom for small faces (INQUIRY-101); its weights, code, image and scratch were deleted from the server with his approval (MIN-107).
- Wan VACE retest and KEEP are closed (INQUIRY-088): the owner dropped VACE. MiniMax-H3 and Bernini were not researched and only will be if he asks (INQUIRY-099).
- Banding, blocking and ringing: only the plateau purge is safe (MIN-103, INQUIRY-104). Outcomes with numbers: `roadmap-outcomes.md`, `restore-research.md`, `restore-finishing-features.md`.
