# Face guard: small faces and the uncanny valley (FEATURE-082, 083, 097, 100, MIN-097)

I want to write down why this exists before how it works, because it is the one stage that came from looking at a face and not from a spectrum. On the owner's draft, a woman at about 36 s has a face 45 px tall. The model draws eyes, nose and mouth on it anyway, and at that size they come out wrong: plain model output has hollow dark eyes, which reads as uncanny. A face that small holds almost no information in the original, so the soft blur would just read as distance. Code: `restore_worker/faces.py` (detect, track, shot cuts), `restore_worker/face_zoom.py` (redraw), blending in `restore_worker/finish.py`; recipe `fidelity.face_guard off|on|zoom`, `face_guard_amount` (default 0.7, 1.0 in `cleanup-4k`) and `face_zoom_mix`. Status `review`, waiting for the ISSUE-059 re-check.

## Detection and tracking

- Detector: YuNet through OpenCV (MIT licence, 232 KB, SHA-256 `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4`). `scripts/stage_restore_weights.sh` stages it next to the ReCaVSR weights and checks the hash; the worker finds it through `FACE_MODEL` (default `/m/yunet.onnx`, a read-only mount, no network). An unreadable or corrupt model raises `FaceModelMissing`, not a raw `cv2.error`.
- It runs on the SOURCE every 4th frame and the detections are linked into tracks. A track counts as a face only with at least 2 confident detections (score 0.7 or more) and a 25% share of its detections: a chandelier lamp scored 0.5 to 0.66 on the draft, and the painted faces of a painting ARE detected (honest consequence: they get guarded, and with `zoom` redrawn too). Non-finite detection rows are dropped and duplicate tracks are merged (IoU above 0.5 on at least 70% of their common frames).
- Linking (2026-10-31, late night): the cost is distance + 3*log(size ratio) - 3*score - 4*IoU. A confident face links within a WIDE gate of 8 face sizes, so a fast-moving or fast-zooming face is followed; a weak detection (score under 0.7) links only within 2 face sizes, so a lamp cannot hijack a face track. Weak detections inside a confirmed track are kept (a head turning scores low long before it scores high).
- Tracks stop at hard cuts inside a segment (`shot_cuts`: 64x36 thumbnails, mean change above max(24, 5x the median)), so a face never gets blended across two shots. Cancellation is checked between detections and between tracks.
- The weight follows the score with a floor of 0.5, eases in exponentially over 36 frames before the first detection and out after the last, and now reaches EXACTLY the first and last detection weight (it popped before, QC run 5). Strength falls with face size: full under 4% of the picture height, none from 15%.

## The two modes

- `on`: blends the original back over the face with the track's soft mask. Natural, but blurry (measured on the draft).
- `zoom` (GPU `recavsr` only): re-runs the ReCaVSR model on a crop of about 4 face heights, enlarged 4x so the face lands near the size the model was trained for, shrinks it back with an area filter, ties the coarse colour to the source and pastes it with the same mask. The crop side is bucketed (160, 192, 256, 320, 384) so only a few model sessions compile, and faces taller than 12% of the picture are not zoomed. The crop of one tracked face is a video of its own, so the face stays consistent frame to frame. The output is validated (`ZoomError`). Caveat I do not want to lose: at 40 to 60 px the original holds almost no information, so the face is plausible, not necessarily the real features.
- `face_zoom_mix` (new, MIN-097): how much of the redrawn face goes into the paste. The owner chose 0.8, a 20/80 mix of the original and the redrawn face, and `cleanup-4k` uses `face_guard: zoom` with it.

## Abrupt cases, simulated on the draft through the real worker

Sheets in `~/Downloads/restoration-comparison/draft_movie/abrupt/`. (i) A hard cut into a shot where the 45 px face is already visible: with the preset the face is redrawn from the first frame of the new shot, the version without face handling shows the uncanny face immediately. (ii) A fast digital zoom-in, 4x in 24 frames (face 45 to 180 px): the first tracker lost the face, since it moved more than a face width per frame and IoU linking failed, so the first frames stayed uncanny; the wide gate fixed it and the whole zoom is natural.

## Cost (measured 2026-10-31, GPU worker)

Detection about 0.08 s per frame; zoom about 0.7 s per frame once compiled; the first compile about 190 s per worker process and per crop size, cached on disk. The comment in `face_zoom.py` still says about 100 s: the measured number is the one here. The film ETA (INQUIRY-017) has not been re-measured with zoom.

## Limits and decisions

- Tracks cannot cross a SEGMENT cut, and segments are independent jobs, so a head that turns right at a segment seam starts unguarded in the segment before it (ISSUE-084). The design is a client-side whole-film face pre-pass that sends per-segment hints (FEATURE-085, planned, not built).
- Crossing faces can swap track identity (MIN-094, open on purpose).
- Preset default: `zoom` with mix 0.8, the owner's answer to INQUIRY-086 (complete). He approved draft v8, which adds head tracks (below). Files: `polishing-log.md` items 7 and 10, `polishing-log-2.md` item 11.
- The CPU worker image must COPY `faces.py`, `face_zoom.py` and `heads.py` (it does); the cpu compose service has no `/m` mount, so `face_guard` there needs `yunet.onnx` placed by hand (MIN-094).
- Alternatives weighed, verdicts and the VACE retest: `restore-research.md` (INQUIRY-087, 088, 099).

## Heads seen from behind (FEATURE-100, 2026-11-01)

YuNet only finds faces that turn toward the camera. A person seen from behind has hair and no face, and at this size the model draws that hair plastic and messy, the same family of problem as the wrong eyes. `restore_worker/heads.py` finds small persons and redraws their heads with the same zoom stage. Seen on the draft at 0:33 to 0:36 (segment 10): 1 head track, 79 zoomed frames (session).
- Detector: YOLOX through `cv2.dnn` (OpenCV model zoo, Apache-2.0, 36 MB, SHA-256 `c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063`), staged by `scripts/stage_restore_weights.sh` as `yolox.onnx` next to the other weights; the worker reads it from `HEAD_MODEL` (default `/m/yolox.onnx`).
- Search: the frame is shrunk to half size and scanned in overlapping 640 px tiles (step 512), because a person 100 px tall at 2160p is 50 px there, which YOLOX still sees, while the whole frame at 640 px would make it 17 px. Persons under 40 px (full resolution) are ignored. Detection runs every 4th frame like the faces.
- Head box: a square of about 17% of the person's height (at most half the width), centred on the top of the person box. Person scores are lower than face scores, so the tracker gets lower thresholds (0.5 and 0.25 against 0.7).
- A head track that overlaps a face track (IoU above 0.15 on at least half of the common frames) is dropped: the face box is the better one. Head tracks are zoomed only, never blended with `on`.
- Active only with `face_guard: zoom` and the `recavsr` engine. OPTIONAL: if the model file is absent the stage is skipped without an error (a present but unreadable file fails the job with a clear message), and the job report carries `stages.heads.tracks`.
- Limits: tracks cannot cross a segment cut (ISSUE-084), the head box is derived from the person box by a fixed proportion, not detected, so it is only as good as that proportion (unmeasured on unusual poses). The cpu compose service has no `/m` mount, so heads need the file placed by hand there too.
