"""Spatial tiling for restoration engines that cannot take a whole 2160p frame in 16 GB.

A frame is cut into equally sized, overlapping tiles. Every tile has the same shape, so one compiled
model session serves all of them, and the shape is a multiple of the engine's token stride (32 for
ReCaVSR) so no tile needs padding of its own. Tiles are composited back in raster order with a linear
alpha ramp on the sides that overlap an earlier tile: the later tile fades in over the earlier one,
which keeps seams invisible without holding a weight accumulator for the whole segment.

Pure Python and NumPy on purpose: the API container and the Mac test suite import this too.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

TOKEN_STRIDE = 32


@dataclass(frozen=True)
class Tile:
    y0: int
    x0: int
    height: int
    width: int

    @property
    def y1(self) -> int:
        return self.y0 + self.height

    @property
    def x1(self) -> int:
        return self.x0 + self.width


@dataclass(frozen=True)
class TileLayout:
    """Tiles for a frame whose dimensions were padded up to a multiple of the stride."""

    frame_height: int       # real output height, before padding
    frame_width: int
    padded_height: int
    padded_width: int
    tile_height: int
    tile_width: int
    rows: tuple[int, ...]   # y0 of each tile row
    cols: tuple[int, ...]   # x0 of each tile column

    @property
    def tiles(self) -> list[Tile]:
        """Raster order: the order in which tiles are composited."""
        return [Tile(y, x, self.tile_height, self.tile_width) for y in self.rows for x in self.cols]

    @property
    def overlap_h(self) -> int:
        return self.tile_height - (self.rows[1] - self.rows[0]) if len(self.rows) > 1 else 0

    @property
    def overlap_w(self) -> int:
        return self.tile_width - (self.cols[1] - self.cols[0]) if len(self.cols) > 1 else 0


def _round_up(value: int, stride: int) -> int:
    return -(-value // stride) * stride


def _axis_positions(padded: int, tile: int, min_overlap: int, stride: int) -> tuple[int, ...]:
    """Start offsets along one axis: evenly spread, multiples of the stride, last tile flush with the edge."""
    if padded <= tile:
        return (0,)
    count = math.ceil((padded - min_overlap) / (tile - min_overlap))
    step = (padded - tile) / (count - 1)
    positions = [min(round(i * step / stride) * stride, padded - tile) for i in range(count - 1)]
    positions.append(padded - tile)
    # Rounding must never open a gap or collapse the minimum overlap.
    for a, b in zip(positions, positions[1:]):
        if b - a > tile - min_overlap or b <= a:
            raise ValueError(f"cannot tile {padded} px with tiles of {tile} px and {min_overlap} px overlap")
    return tuple(positions)


def plan_tiles(
    height: int,
    width: int,
    *,
    tile_height: int = 1152,
    tile_width: int = 1344,
    min_overlap: int = 96,
    stride: int = TOKEN_STRIDE,
) -> TileLayout:
    """Plan equally sized tiles for a (height, width) output frame.

    The defaults give six 1344x1152 tiles (1.55 Mpx) for 3840x2160, which is what fits a 16 GB card.
    A frame smaller than a tile gets one tile of its own padded size.
    """
    if height < 1 or width < 1:
        raise ValueError("frame dimensions must be positive")
    if tile_height % stride or tile_width % stride or min(tile_height, tile_width) < stride:
        raise ValueError(f"tile dimensions must be positive multiples of {stride}")
    if not 0 <= min_overlap < min(tile_height, tile_width):
        raise ValueError("min_overlap must be smaller than the tile")
    padded_h, padded_w = _round_up(height, stride), _round_up(width, stride)
    th, tw = min(tile_height, padded_h), min(tile_width, padded_w)
    return TileLayout(
        frame_height=height,
        frame_width=width,
        padded_height=padded_h,
        padded_width=padded_w,
        tile_height=th,
        tile_width=tw,
        rows=_axis_positions(padded_h, th, min_overlap, stride),
        cols=_axis_positions(padded_w, tw, min_overlap, stride),
    )


def _ramp(length: int, overlap: int) -> np.ndarray:
    """0 to 1 across `overlap` samples (strictly between the two tiles' own pixels), then 1."""
    out = np.ones(length, dtype=np.float32)
    if overlap > 0:
        out[:overlap] = (np.arange(overlap, dtype=np.float32) + 0.5) / overlap
    return out


def alpha_mask(layout: TileLayout, tile: Tile) -> np.ndarray:
    """Per-pixel opacity of `tile` when composited over the earlier tiles, shape (height, width)."""
    first_row, first_col = tile.y0 == layout.rows[0], tile.x0 == layout.cols[0]
    row_ramp = np.ones(tile.height, np.float32) if first_row else _ramp(tile.height, _overlap_with_previous(layout.rows, tile.y0, tile.height))
    col_ramp = np.ones(tile.width, np.float32) if first_col else _ramp(tile.width, _overlap_with_previous(layout.cols, tile.x0, tile.width))
    return np.outer(row_ramp, col_ramp).astype(np.float32)


def _overlap_with_previous(positions: tuple[int, ...], start: int, size: int) -> int:
    previous = max(p for p in positions if p < start)
    return previous + size - start


def composite(canvas: np.ndarray, patch: np.ndarray, layout: TileLayout, tile: Tile, mask: np.ndarray | None = None) -> None:
    """Blend a restored tile into `canvas` (frames, H, W, 3 uint8) in place, cropping the padded margin.

    `patch` is (frames, tile_height, tile_width, 3) uint8. Call tiles in raster order.
    """
    mask = alpha_mask(layout, tile) if mask is None else mask
    y1, x1 = min(tile.y1, canvas.shape[1]), min(tile.x1, canvas.shape[2])
    if tile.y0 >= y1 or tile.x0 >= x1:
        return
    h, w = y1 - tile.y0, x1 - tile.x0
    src = patch[:, :h, :w]
    dst = canvas[:, tile.y0:y1, tile.x0:x1]
    a = mask[:h, :w, None]
    if a.min() >= 1.0:
        dst[:] = src
    else:
        dst[:] = (a * src + (1.0 - a) * dst + 0.5).astype(np.uint8)
