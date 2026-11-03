"""Tiling geometry for the restoration engines: coverage, shape, overlap and seamless compositing."""
import numpy as np
import pytest

from restore_core.tiling import Tile, alpha_mask, composite, plan_tiles


def test_2160p_default_is_six_equal_tiles_that_fit_the_card():
    layout = plan_tiles(2160, 3840)
    assert layout.padded_height == 2176 and layout.padded_width == 3840
    assert (layout.tile_height, layout.tile_width) == (1152, 1344)
    assert layout.rows == (0, 1024) and layout.cols == (0, 1248, 2496)
    assert len(layout.tiles) == 6
    assert layout.overlap_h == 128 and layout.overlap_w == 96
    assert layout.tile_height * layout.tile_width < 1.6e6   # the largest area measured to fit 16 GB


@pytest.mark.parametrize("height,width", [(2160, 3840), (1080, 1920), (1608, 3840), (2304, 4096), (480, 640), (3000, 5000), (2161, 3841)])
def test_every_pixel_is_covered_and_shapes_are_uniform(height, width):
    layout = plan_tiles(height, width)
    covered = np.zeros((layout.padded_height, layout.padded_width), dtype=np.int32)
    for tile in layout.tiles:
        assert (tile.height, tile.width) == (layout.tile_height, layout.tile_width)
        assert tile.y0 % 32 == 0 and tile.x0 % 32 == 0
        assert tile.y1 <= layout.padded_height and tile.x1 <= layout.padded_width
        covered[tile.y0:tile.y1, tile.x0:tile.x1] += 1
    assert covered.min() >= 1


def test_minimum_overlap_is_respected_on_both_axes():
    layout = plan_tiles(2160, 3840, min_overlap=128)
    for a, b in zip(layout.cols, layout.cols[1:]):
        assert layout.tile_width - (b - a) >= 128
    for a, b in zip(layout.rows, layout.rows[1:]):
        assert layout.tile_height - (b - a) >= 128


def test_small_frame_gets_a_single_tile_of_its_own_padded_size():
    layout = plan_tiles(540, 960)
    assert len(layout.tiles) == 1
    assert (layout.tile_height, layout.tile_width) == (544, 960)


@pytest.mark.parametrize("kwargs", [dict(tile_height=1000), dict(tile_width=1345), dict(min_overlap=2000), dict(tile_height=0)])
def test_bad_parameters_are_rejected(kwargs):
    with pytest.raises(ValueError):
        plan_tiles(2160, 3840, **kwargs)


def test_compositing_constant_tiles_gives_a_constant_frame():
    """If every tile agrees, blending must not change a single value (weights sum to one)."""
    layout = plan_tiles(2160, 3840)
    frames = 2
    canvas = np.zeros((frames, 2160, 3840, 3), dtype=np.uint8)
    for tile in layout.tiles:
        patch = np.full((frames, tile.height, tile.width, 3), 137, dtype=np.uint8)
        composite(canvas, patch, layout, tile)
    assert canvas.min() == 137 and canvas.max() == 137


def test_compositing_a_gradient_is_lossless_within_one_level():
    """Tiles cut from one smooth image and blended back must reproduce it: no seams."""
    layout = plan_tiles(1080, 1920)
    yy, xx = np.mgrid[0:layout.padded_height, 0:layout.padded_width]
    image = ((xx * 0.07 + yy * 0.05) % 255).astype(np.uint8)
    source = np.stack([image] * 3, axis=-1)[None]
    canvas = np.zeros((1, 1080, 1920, 3), dtype=np.uint8)
    for tile in layout.tiles:
        composite(canvas, source[:, tile.y0:tile.y1, tile.x0:tile.x1], layout, tile)
    assert np.abs(canvas.astype(int) - source[:, :1080, :1920].astype(int)).max() <= 1


def test_alpha_ramps_only_on_sides_shared_with_earlier_tiles():
    layout = plan_tiles(2160, 3840)
    first, later = layout.tiles[0], layout.tiles[4]
    assert alpha_mask(layout, first).min() == 1.0
    mask = alpha_mask(layout, later)
    assert mask[-1, -1] == 1.0 and mask[0, 0] < 0.01
    assert 0.0 < mask[0, 50] < 1.0 and mask[200, 400] == 1.0


def test_padded_margin_is_cropped_not_written():
    layout = plan_tiles(2160, 3840)
    canvas = np.zeros((1, 2160, 3840, 3), dtype=np.uint8)
    bottom = layout.tiles[-1]
    assert bottom.y1 == 2176
    composite(canvas, np.full((1, bottom.height, bottom.width, 3), 9, np.uint8), layout, bottom)
    assert canvas.shape == (1, 2160, 3840, 3)
