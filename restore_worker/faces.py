"""Find small faces in the source, so the finishing stage can keep the model from inventing features on them.

A face a few dozen pixels tall has no real detail to recover. A restoration model draws sharp eyes, nose and mouth anyway,
and at that size they come out wrong in a way the eye catches at once (the uncanny valley), where the original's soft blur
would just read as distance. This module only finds and tracks the faces; what to do with them is decided in finish.py.

The detector is YuNet (MIT, 232 KB, OpenCV's FaceDetectorYN), run on the SOURCE frames every few frames. Detections are
linked into tracks, and a track only counts as a face when it holds several confident detections: a lamp or a patch of texture
scores 0.5 to 0.66 on the draft now and then and must not be blended. Inside a confirmed track the weak detections are kept
(a head that is turning away or toward the camera scores low long before it scores high), and the guard's weight follows the
score, with a floor. Before the first detection of a track and after its last, the weight eases in and out exponentially over
about a second and a half, so the guard starts early and gently while a head turns, instead of switching on when the detector
finally trusts the face. The segment is processed as a whole, so the future frames are known.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import math
from pathlib import Path

import cv2
import numpy as np

DETECT_EVERY = 4              # frames between detections
LOW_SCORE = 0.35              # weakest detection kept, and only inside a track that has confident ones
HIGH_SCORE = 0.7              # a confident detection
MIN_CONFIDENT = 2             # confident detections a track needs to count as a face ...
MIN_CONFIDENT_SHARE = 0.25    # ... and this share of its detections (a lamp that scores 0.8 twice in twenty is not a face)
MIN_FACE_PIXELS = 18          # a box smaller than this on its short side is noise, not a face
CUT_MIN_CHANGE = 24.0         # mean change (0..255) between consecutive reduced frames that can be a hard cut
CUT_RELATIVE = 5.0            # and it must be this many times the median change of the segment
LINK_IOU = 0.25               # overlap that links a detection to the track it continues
LINK_GAP = 3 * DETECT_EVERY   # frames a track may go without a detection
RAMP_FRAMES = 36              # frames over which the weight eases in before the first detection and out after the last
RAMP_SHARPNESS = 3.0          # exponential easing: slow at first, quicker as the face gets closer to being detected
EDGE_WEIGHT = 0.5             # weight at the first and last detection, which then rises with the score up to 1


class FaceModelMissing(RuntimeError):
    pass


def _iou(a: np.ndarray, b: np.ndarray) -> float:
    ax2, ay2, bx2, by2 = a[0] + a[2], a[1] + a[3], b[0] + b[2], b[1] + b[3]
    iw, ih = min(ax2, bx2) - max(a[0], b[0]), min(ay2, by2) - max(a[1], b[1])
    if iw <= 0 or ih <= 0:
        return 0.0
    inter = iw * ih
    return float(inter / (a[2] * a[3] + b[2] * b[3] - inter))


LINK_MAX_DISTANCE = 8.0       # a CONFIDENT face may travel this many face sizes between two detections and still be the same track ...
LINK_NEAR = 2.0               # ... while a weak detection (a lamp, a painting) may only continue with a detection that is this close
LINK_MAX_SIZE_RATIO = 2.6     # ... if its size changes by less than this factor (a fast pan or a zoom moves and grows a face a lot)


def _link_cost(a: np.ndarray, b: np.ndarray, high: float = HIGH_SCORE) -> float | None:
    """Cost of continuing the track whose last box is `a` with the detection `b`, or None when they cannot be the same face."""
    overlap = _iou(a, b)
    size = max((a[2] + a[3]) / 2, (b[2] + b[3]) / 2, 1.0)
    distance = float(np.hypot((a[0] + a[2] / 2) - (b[0] + b[2] / 2), (a[1] + a[3] / 2) - (b[1] + b[3] / 2))) / size
    ratio = max(a[3], b[3]) / max(min(a[3], b[3]), 1.0)
    if overlap < LINK_IOU and (distance > LINK_MAX_DISTANCE or ratio > LINK_MAX_SIZE_RATIO or ((a[4] < high or b[4] < high) and distance > LINK_NEAR)):
        return None
    # Nearest is not enough once the gate is wide: a stray weak detection beside the face must not win it over the face
    # itself, so size mismatch costs and a confident detection is preferred.
    return distance + 3.0 * float(np.log(ratio)) - 3.0 * float(b[4]) - 4.0 * overlap


def _ease_in(u: float) -> float:
    """0 at u = 0 and 1 at u = 1, slow at first and exponential later."""
    return (math.exp(RAMP_SHARPNESS * u) - 1.0) / (math.exp(RAMP_SHARPNESS) - 1.0)


def _detection_weight(score: float, low: float = LOW_SCORE, high: float = HIGH_SCORE) -> float:
    s = min(max((score - low) / (high - low), 0.0), 1.0)
    return EDGE_WEIGHT + (1.0 - EDGE_WEIGHT) * s * s * (3.0 - 2.0 * s)


def shot_cuts(frames: np.ndarray) -> list[int]:
    """Indices of the frames that open a new shot (a hard cut), from the change between consecutive reduced pictures.

    A face track must not cross a cut: the ramps that ease the guard in and out assume the same face on both sides, and a
    zoom crop that spans a cut would feed the restoration model two unrelated pictures as one video."""
    if len(frames) < 2:
        return []
    thumbs = np.stack([cv2.resize(cv2.cvtColor(np.ascontiguousarray(f), cv2.COLOR_RGB2GRAY), (64, 36), interpolation=cv2.INTER_AREA) for f in frames]).astype(np.float32)
    change = np.abs(np.diff(thumbs, axis=0)).mean(axis=(1, 2))
    limit = max(CUT_MIN_CHANGE, CUT_RELATIVE * float(np.median(change)))
    return [i + 1 for i, c in enumerate(change) if c > limit]


def build_face_tracks(detections: dict[int, np.ndarray], frames: int, cuts: tuple | list = (),
                      high: float = HIGH_SCORE, low: float = LOW_SCORE) -> list[dict]:
    """Confirmed face tracks from the raw detections {frame: [[x, y, w, h, score], ...]}.

    Each track is {"frames": int array, "boxes": [n,4] (x, y, w, h), "weights": [n]} with one entry for EVERY frame it covers,
    the eased-in frames before the first detection and the eased-out ones after the last included. Pure function of the
    detections, so the tracking and the ramps are tested without a detector."""
    import bisect

    cuts = sorted(c for c in cuts if 0 < c < frames)
    shot = lambda f: bisect.bisect_right(cuts, f)               # index of the shot a frame belongs to
    bounds = [0] + cuts + [frames]
    tracks: list[list[tuple[int, np.ndarray]]] = []
    for frame in sorted(detections):
        free = [i for i in range(len(tracks)) if frame - tracks[i][-1][0] <= LINK_GAP and tracks[i][-1][0] < frame
                and shot(tracks[i][-1][0]) == shot(frame)]
        pairs = sorted((c, i, j) for i in free for j, d in enumerate(detections[frame])
                       if (c := _link_cost(tracks[i][-1][1], d, high)) is not None)
        used_t, used_d = set(), set()
        for cost, i, j in pairs:
            if i in used_t or j in used_d:
                continue
            tracks[i].append((frame, detections[frame][j]))
            used_t.add(i)
            used_d.add(j)
        for j, d in enumerate(detections[frame]):
            if j not in used_d:
                tracks.append([(frame, d)])
    out: list[dict] = []
    for track in tracks:
        confident = sum(1 for _, d in track if d[4] >= high)
        if confident < max(MIN_CONFIDENT, MIN_CONFIDENT_SHARE * len(track)):
            continue
        times = [f for f, _ in track]
        boxes = np.array([d[:4] for _, d in track], dtype=np.float32)
        weights = np.array([_detection_weight(float(d[4]), low, high) for _, d in track], dtype=np.float32)
        first, last = times[0], times[-1]
        shot_lo, shot_hi = bounds[shot(first)], bounds[shot(first) + 1]          # the ramps stop at the cuts
        idx, bx, wt = [], [], []
        for f in range(max(first - RAMP_FRAMES, shot_lo), min(last + RAMP_FRAMES, shot_hi - 1) + 1):
            if f < first:        # the ease reaches exactly the weight of the first detection: no step when the detector takes over
                box, w = boxes[0], float(weights[0]) * _ease_in(1.0 - (first - f) / RAMP_FRAMES)
            elif f > last:
                box, w = boxes[-1], float(weights[-1]) * _ease_in(1.0 - (f - last) / RAMP_FRAMES)
            else:
                box = np.array([np.interp(f, times, boxes[:, k]) for k in range(4)], dtype=np.float32)
                w = float(np.interp(f, times, weights))
            if w > 0.0:
                idx.append(f)
                bx.append(box)
                wt.append(w)
        if idx:
            out.append({"frames": np.array(idx), "boxes": np.array(bx, dtype=np.float32), "weights": np.array(wt, dtype=np.float32)})
    return _merge_duplicates(out)


def _merge_duplicates(tracks: list[dict]) -> list[dict]:
    """Drop a track that follows the same face as a stronger one (boxes overlapping on most of their common frames)."""
    order = sorted(range(len(tracks)), key=lambda i: -(len(tracks[i]["frames"]) * float(np.mean(tracks[i]["weights"]))))
    kept: list[dict] = []
    for i in order:
        t = tracks[i]
        duplicate = False
        for k in kept:
            common, ia, ib = np.intersect1d(t["frames"], k["frames"], return_indices=True)
            if len(common) and np.mean([_iou(t["boxes"][a], k["boxes"][b]) > 0.5 for a, b in zip(ia, ib)]) >= 0.7:
                duplicate = True
                break
        if not duplicate:
            kept.append(t)
    return sorted(kept, key=lambda t: int(t["frames"][0]))


def tracks_to_boxes(tracks: list[dict], frames: int) -> list[np.ndarray]:
    """Per frame an array [n, 5] of (x, y, w, h, weight) from the tracks."""
    out: list[list[np.ndarray]] = [[] for _ in range(frames)]
    for track in tracks:
        for f, box, w in zip(track["frames"], track["boxes"], track["weights"]):
            out[int(f)].append(np.append(box, w).astype(np.float32))
    return [np.array(f, dtype=np.float32).reshape(-1, 5) for f in out]


def build_face_boxes(detections: dict[int, np.ndarray], frames: int, cuts: tuple | list = ()) -> list[np.ndarray]:
    return tracks_to_boxes(build_face_tracks(detections, frames, cuts), frames)


class FaceStageCancelled(Exception):
    """The job was cancelled while faces were being detected or redrawn."""


def detect_faces(frames: np.ndarray, model_path: str | Path, cancelled=lambda: False) -> dict[int, np.ndarray]:
    """Raw detections {frame: [[x, y, w, h, score], ...]} on every DETECT_EVERY-th frame and on the last one.

    frames: (T, H, W, 3) uint8 RGB."""
    path = Path(model_path)
    if not path.is_file():
        raise FaceModelMissing(f"the face detector model is not at {path}: run scripts/stage_restore_weights.sh")
    t, h, w = frames.shape[:3]
    try:
        detector = cv2.FaceDetectorYN.create(str(path), "", (w, h), score_threshold=LOW_SCORE, nms_threshold=0.3, top_k=40)
    except cv2.error as exc:
        raise FaceModelMissing(f"the face detector model at {path} cannot be read (is it the YuNet onnx file?)") from exc
    detections: dict[int, np.ndarray] = {}
    for i in sorted(set(range(0, t, DETECT_EVERY)) | {t - 1}):
        if cancelled():
            raise FaceStageCancelled()
        try:
            _, found = detector.detect(np.ascontiguousarray(frames[i][..., ::-1]))      # the detector expects BGR
        except cv2.error as exc:
            raise FaceModelMissing(f"the face detector model at {path} cannot be used (is it the YuNet onnx file?)") from exc
        rows = [[f[0], f[1], f[2], f[3], f[14]] for f in found
                if np.isfinite(f[[0, 1, 2, 3, 14]]).all() and min(f[2], f[3]) >= MIN_FACE_PIXELS] if found is not None else []
        detections[i] = np.array(rows, dtype=np.float32).reshape(-1, 5)
    return detections


def find_faces(frames: np.ndarray, model_path: str | Path) -> list[np.ndarray]:
    """For every frame, an array [n, 5] of (x, y, w, h, weight) in pixels of the frame given, see build_face_tracks."""
    return build_face_boxes(detect_faces(frames, model_path), len(frames))


def find_face_tracks(frames: np.ndarray, model_path: str | Path, cancelled=lambda: False) -> list[dict]:
    return build_face_tracks(detect_faces(frames, model_path, cancelled), len(frames), shot_cuts(frames))
