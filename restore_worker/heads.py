"""Find small HEADS that the face detector cannot see: a person seen from behind, in profile or looking away.

YuNet only finds faces that turn toward the camera. A head from behind has hair and no face, and the restoration model draws
that hair plastic and messy at this size, just as it draws the wrong eyes on a small face. This module finds small persons
with YOLOX (Apache-2.0, 36 MB, OpenCV's model zoo, run through cv2.dnn) and derives a head box from each person box, so that
the same zoom stage that redraws faces can redraw these heads (face_zoom.py).

The frame is searched at half resolution in overlapping 640 px tiles (a person 100 px tall in 2160p is 50 px there, which
YOLOX still sees; the whole frame at 640 px would make it 17 px, which it does not). Detection runs every few frames, the
detections go through the same tracker as the faces (faces.build_face_tracks, with the lower score thresholds of a person
detector), and a head track that overlaps a face track is dropped: the face box is the better one.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

from pathlib import Path

import cv2
import numpy as np

from restore_worker import faces

TILE = 640
TILE_STEP = 512
SEARCH_SCALE = 0.5            # the frame is searched at this fraction of its size
PERSON_SCORE_FLOOR = 0.25     # weakest person detection kept (objectness x class score)
HEAD_HIGH_SCORE = 0.5         # a confident person detection: lower than a face's, a person detector scores lower
HEAD_LOW_SCORE = 0.25
MIN_PERSON_HEIGHT = 40        # full-resolution pixels
STRIDES = (8, 16, 32)


class HeadModelMissing(RuntimeError):
    pass


class PersonDetector:
    def __init__(self, model_path: str | Path) -> None:
        path = Path(model_path)
        if not path.is_file():
            raise HeadModelMissing(f"the person detector model is not at {path}: run scripts/stage_restore_weights.sh")
        try:
            self.net = cv2.dnn.readNet(str(path))
        except cv2.error as exc:
            raise HeadModelMissing(f"the person detector model at {path} cannot be read (is it the YOLOX onnx file?)") from exc
        grids, strides = [], []
        for s in STRIDES:
            n = TILE // s
            xv, yv = np.meshgrid(np.arange(n), np.arange(n))
            grids.append(np.stack((xv, yv), 2).reshape(-1, 2))
            strides.append(np.full((n * n, 1), s))
        self.grids, self.strides = np.concatenate(grids), np.concatenate(strides)

    def _tile(self, rgb: np.ndarray) -> list[tuple[float, float, float, float, float]]:
        self.net.setInput(np.transpose(rgb.astype(np.float32), (2, 0, 1))[None])
        raw = self.net.forward(self.net.getUnconnectedOutLayersNames())[0]
        # A valid onnx that is not this detector (say the face model) loads fine and then fails deep in the maths: say so here.
        if raw.ndim != 3 or raw.shape[1] != len(self.grids) or raw.shape[2] < 6:
            raise HeadModelMissing(f"the person detector model gave an output of shape {tuple(raw.shape)}, not the YOLOX one: wrong model file?")
        out = raw[0].copy()
        out[:, :2] = (out[:, :2] + self.grids) * self.strides
        out[:, 2:4] = np.exp(out[:, 2:4]) * self.strides
        score = out[:, 4] * out[:, 5]                                   # class 0 is "person"
        keep = score > PERSON_SCORE_FLOOR
        if not keep.any():
            return []
        b, s = out[keep, :4], score[keep]
        xywh = np.stack([b[:, 0] - b[:, 2] / 2, b[:, 1] - b[:, 3] / 2, b[:, 2], b[:, 3]], axis=1)
        idx = cv2.dnn.NMSBoxes(xywh.tolist(), s.tolist(), PERSON_SCORE_FLOOR, 0.5)
        return [(*map(float, xywh[i]), float(s[i])) for i in np.array(idx).flatten()] if len(idx) else []

    def persons(self, frame_rgb: np.ndarray) -> list[tuple[float, float, float, float, float]]:
        """(x, y, w, h, score) of every person in a full-resolution RGB frame, in its own pixels."""
        small = cv2.resize(frame_rgb, None, fx=SEARCH_SCALE, fy=SEARCH_SCALE, interpolation=cv2.INTER_AREA)
        h, w = small.shape[:2]
        found: list[tuple[float, float, float, float, float]] = []
        for y0 in range(0, max(h - TILE, 0) + TILE_STEP, TILE_STEP):
            for x0 in range(0, max(w - TILE, 0) + TILE_STEP, TILE_STEP):
                yy, xx = min(y0, max(h - TILE, 0)), min(x0, max(w - TILE, 0))
                tile = small[yy:yy + TILE, xx:xx + TILE]
                if tile.shape[0] < TILE or tile.shape[1] < TILE:
                    tile = cv2.copyMakeBorder(tile, 0, TILE - tile.shape[0], 0, TILE - tile.shape[1], cv2.BORDER_CONSTANT, value=114)
                for bx, by, bw, bh, s in self._tile(tile):
                    found.append(((bx + xx) / SEARCH_SCALE, (by + yy) / SEARCH_SCALE, bw / SEARCH_SCALE, bh / SEARCH_SCALE, s))
        if len(found) > 1:                                              # the same person seen in two overlapping tiles
            keep = cv2.dnn.NMSBoxes([list(f[:4]) for f in found], [f[4] for f in found], PERSON_SCORE_FLOOR, 0.4)
            found = [found[i] for i in np.array(keep).flatten()]
        return [f for f in found if f[3] >= MIN_PERSON_HEIGHT]


def head_box(x: float, y: float, w: float, h: float) -> tuple[float, float, float, float]:
    """A square head box from a person box: about 17 percent of a standing person's height, at most half the width (a person
    cropped at the waist or sitting is wider than tall per head), centred on the top of the box."""
    side = max(min(0.17 * h, 0.5 * w), 8.0)
    return x + w / 2 - side / 2, y + 0.02 * h, side, side


def detect_heads(frames: np.ndarray, model_path: str | Path, cancelled=lambda: False) -> dict[int, np.ndarray]:
    """Raw head detections {frame: [[x, y, w, h, score], ...]} on every DETECT_EVERY-th frame and on the last one."""
    detector = PersonDetector(model_path)
    t = len(frames)
    out: dict[int, np.ndarray] = {}
    for i in sorted(set(range(0, t, faces.DETECT_EVERY)) | {t - 1}):
        if cancelled():
            raise faces.FaceStageCancelled()
        rows = [[*head_box(x, y, w, h), s] for x, y, w, h, s in detector.persons(frames[i])]
        out[i] = np.array(rows, dtype=np.float32).reshape(-1, 5)
    return out


def find_head_tracks(frames: np.ndarray, model_path: str | Path, cancelled=lambda: False) -> list[dict]:
    return faces.build_face_tracks(detect_heads(frames, model_path, cancelled), len(frames), faces.shot_cuts(frames),
                                   high=HEAD_HIGH_SCORE, low=HEAD_LOW_SCORE)


def without_faces(head_tracks: list[dict], face_tracks: list[dict]) -> list[dict]:
    """The head tracks that do not follow a head the face detector already has (a face box beats a derived head box)."""
    kept = []
    for h in head_tracks:
        overlapping = False
        for f in face_tracks:
            common, ia, ib = np.intersect1d(h["frames"], f["frames"], return_indices=True)
            if len(common) and np.mean([faces._iou(h["boxes"][a], f["boxes"][b]) > 0.15 for a, b in zip(ia, ib)]) >= 0.5:
                overlapping = True
                break
        if not overlapping:
            kept.append(h)
    return kept
