"""Redraw small faces with the restoration model itself, on a zoomed crop.

A face 40 to 60 px tall is far too small for the model at scale 1: it invents wrong eyes and mouths. The same model on a crop
of about four face heights, enlarged 4x (its own default scale, which puts the face at about 200 px, the size it was trained
for), draws a natural face that stays the same from frame to frame, because the crop of one tracked face is a video of its own.
The result is shrunk back with an area filter, its coarse brightness and colour are tied to the source's so the patch does not
stand out, and finish.py pastes it over the face with the soft mask of the track (full strength for a small face, fading out
for a larger one, easing in before the face is first detected).

Honest limit: at this size the original holds almost no information about the person. The face is plausible and consistent, not
necessarily the real features. `face_guard: on` (blend the original back) is the conservative alternative.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import cv2
import numpy as np

CROP_FACE_HEIGHTS = 4          # the crop is this many face heights wide
MIN_CROP = 160                 # source pixels
CROP_SIDES = (160, 192, 256, 320, 384)   # a track's crop is rounded UP to one of these: every distinct size is a new compiled model
                                         # session (about 190 s the first time, measured on the RTX 5080, then cached), so only a handful may ever exist
SMOOTH_FRAMES = 9              # moving average of the crop centre, so the crop does not jitter with the detector
ZOOM = 4.0
COLOUR_TIE_SIGMA_SHARE = 1 / 30   # blur used to tie coarse colour, as a share of the crop side


class ZoomError(RuntimeError):
    """The engine did not return what a 4x restoration of the crops must look like."""


def crop_windows(boxes: np.ndarray, frame_h: int, frame_w: int) -> tuple[np.ndarray, np.ndarray, int]:
    """Smoothed square crop windows for a track: (xs, ys, side). The side is one value for the whole track, a multiple of 16."""
    centres = np.stack([boxes[:, 0] + boxes[:, 2] / 2, boxes[:, 1] + boxes[:, 3] / 2], axis=1)
    kernel = np.ones(SMOOTH_FRAMES) / SMOOTH_FRAMES
    pad = SMOOTH_FRAMES // 2
    smooth = np.stack([np.convolve(np.pad(centres[:, k], pad, mode="edge"), kernel, mode="valid") for k in range(2)], axis=1)
    wanted = float(np.median(boxes[:, 3])) * CROP_FACE_HEIGHTS
    side = next((s for s in CROP_SIDES if s >= wanted), CROP_SIDES[-1])
    side = min(side, (min(frame_h, frame_w) // 16) * 16)
    xs = np.clip(smooth[:, 0] - side / 2, 0, frame_w - side).astype(int)
    ys = np.clip(smooth[:, 1] - side / 2, 0, frame_h - side).astype(int)
    return xs, ys, side


def zoom_track(engine, source: np.ndarray, track: dict, *, tile: tuple[int, int, int] = (1152, 1344, 96)) -> list[tuple[int, int, int, np.ndarray]]:
    """For every frame of the track: (frame, x, y, patch) with the redrawn face as an RGB uint8 square at the source's own scale.

    source: (T, H, W, 3) uint8 frames at the output size. `engine.restore` is the ReCaVSR engine's method."""
    frames = track["frames"]
    xs, ys, side = crop_windows(track["boxes"], source.shape[1], source.shape[2])
    crops = np.stack([source[int(f), y:y + side, x:x + side] for f, x, y in zip(frames, xs, ys)])
    big, _ = engine.restore(crops, scale=ZOOM, tile_height=tile[0], tile_width=tile[1], min_overlap=tile[2])
    expected = (len(crops), int(side * ZOOM), int(side * ZOOM), 3)
    if not isinstance(big, np.ndarray) or big.dtype != np.uint8 or big.shape != expected:
        got = (big.shape, big.dtype) if isinstance(big, np.ndarray) else type(big).__name__
        raise ZoomError(f"the engine returned {got} for the face crops, expected uint8 {expected}")
    sigma = max(side * COLOUR_TIE_SIGMA_SHARE, 2.0)
    patches = []
    for i, f in enumerate(frames):
        zoom = cv2.resize(big[i], (side, side), interpolation=cv2.INTER_AREA).astype(np.float32)
        ref = crops[i].astype(np.float32)
        fix = cv2.GaussianBlur(ref, (0, 0), sigma) - cv2.GaussianBlur(zoom, (0, 0), sigma)
        patches.append((int(f), int(xs[i]), int(ys[i]), np.clip(zoom + fix, 0, 255).astype(np.uint8)))
    return patches
