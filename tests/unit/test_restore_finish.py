"""Finishing stage: banding, edges, grain strength, reproducibility and exact conversion."""
import numpy as np
import pytest
import torch

from restore_core.recipe import resolve
from restore_worker.finish import Finisher, deband


def _recipe(**advanced):
    return resolve({"advanced": advanced})


def _run(frames, recipe, first_index=0):
    return np.concatenate(list(Finisher(recipe, "cpu").process(frames, first_index)))


def _gradient_frames(count=1, height=48, width=1000, lo=0.20, hi=0.28):
    """A slow horizontal ramp quantised to 8 bits: the classic banded sky."""
    ramp = np.linspace(lo, hi, width)
    row = np.floor(ramp * 255).astype(np.uint8)
    return np.broadcast_to(row[None, None, :, None], (count, height, width, 3)).copy()


def test_everything_off_is_an_exact_8_to_16_bit_conversion():
    frames = np.random.default_rng(0).integers(0, 256, (2, 16, 16, 3), dtype=np.uint8)
    out = _run(frames, _recipe(bitdepth={"deband": "off", "dither": False}, grain={"mode": "none"}))
    assert out.dtype == np.dtype("<u2")
    assert np.array_equal(out, frames.astype(np.uint16) * 257)       # 255 maps to 65535, 0 to 0


def test_output_stays_in_range_even_with_strong_grain_on_pure_black_and_white():
    frames = np.concatenate([np.zeros((1, 32, 32, 3), np.uint8), np.full((1, 32, 32, 3), 255, np.uint8)])
    out = _run(frames, _recipe(grain={"mode": "baked", "strength": 1.0}))
    assert out.min() >= 0 and out.max() <= 65535


def test_deband_removes_most_of_the_steps_in_a_banded_gradient():
    frames = _gradient_frames()
    before = np.abs(np.diff(frames[0, 0, :, 0].astype(np.float64))).astype(bool).sum()      # number of band edges
    out = _run(frames, _recipe(bitdepth={"deband": "medium", "dither": False}, grain={"mode": "none"}))
    row = out[0, 24, :, 0].astype(np.float64) / 65535.0
    step_one_8bit = 1.0 / 255.0
    big_jumps = (np.abs(np.diff(row)) > 0.5 * step_one_8bit).sum()          # a band edge is a jump of a full 8-bit step
    assert before >= 15 and big_jumps <= 0.2 * before


def test_deband_keeps_a_real_edge_sharp():
    frame = np.zeros((1, 32, 200, 3), np.uint8)
    frame[:, :, 100:, :] = 128                                                # a hard edge, far above any threshold
    out = _run(frame, _recipe(bitdepth={"deband": "strong", "dither": False}, grain={"mode": "none"}))
    row = out[0, 16, :, 0].astype(np.float64) / 65535.0
    assert abs(row[99] - 0.0) < 2e-3 and abs(row[100] - 128 / 255) < 2e-3


def test_grain_strength_matches_its_definition_at_a_known_brightness():
    from restore_worker.finish import GRAIN_SIGMA_AT_FULL_STRENGTH, grain_weight
    flat = np.full((1, 256, 256, 3), 128, np.uint8)
    off = dict(bitdepth={"deband": "off", "dither": False})
    out = _run(flat, _recipe(**off, grain={"mode": "baked", "strength": 1.0, "size": 1.0}))
    weight = float(grain_weight(torch.tensor(128 / 255)))
    sigma = (out[..., 1].astype(np.float64) / 65535.0).std()
    assert sigma == pytest.approx(GRAIN_SIGMA_AT_FULL_STRENGTH * weight, rel=0.15)
    half = _run(flat, _recipe(**off, grain={"mode": "baked", "strength": 0.5}))
    assert (half[..., 1].astype(np.float64) / 65535.0).std() == pytest.approx(sigma / 2, rel=0.15)


def test_grain_off_in_basic_wins_over_the_advanced_mode():
    flat = np.full((1, 32, 32, 3), 100, np.uint8)
    out = _run(flat, resolve({"basic": {"grain": "off"}, "advanced": {"bitdepth": {"dither": False, "deband": "off"}}}))
    assert np.array_equal(out, flat.astype(np.uint16) * 257)


def test_same_seed_and_frame_index_reproduce_exactly_and_frames_differ():
    frames = np.full((3, 32, 32, 3), 120, np.uint8)
    recipe = _recipe(grain={"mode": "baked", "strength": 0.8})
    a, b = _run(frames, recipe), _run(frames, recipe)
    assert np.array_equal(a, b)
    assert not np.array_equal(a[0], a[1])                                     # grain is new on every frame
    shifted = _run(frames, recipe, first_index=100)
    assert not np.array_equal(a, shifted)                                     # another segment never repeats the pattern


def test_grain_follows_the_absolute_frame_index_not_the_chunk_or_the_segment_cut():
    """A frame gets the same grain whatever chunk size or segmentation surrounds it."""
    frames = np.full((5, 24, 24, 3), 90, np.uint8)
    recipe = _recipe(grain={"mode": "baked", "strength": 0.6})
    chunked2 = np.concatenate(list(Finisher(recipe, "cpu", chunk=2).process(frames)))
    chunked5 = np.concatenate(list(Finisher(recipe, "cpu", chunk=5).process(frames)))
    assert chunked2.shape == (5, 24, 24, 3) and np.array_equal(chunked2, chunked5)
    later_cut = _run(frames[2:], recipe, first_index=2)                     # the same frames 2..4 as a segment of their own
    assert np.array_equal(chunked2[2:], later_cut)


def test_deband_function_is_identity_when_off():
    x = torch.rand(1, 3, 16, 16)
    assert torch.equal(deband(x, "off", torch.Generator().manual_seed(1)), x)


def test_hdr_synthesize_maps_sdr_white_to_203_nits_in_pq():
    white = np.full((1, 8, 8, 3), 255, np.uint8)
    out = _run(white, resolve({"basic": {"hdr": "synthesize", "grain": "off"},
                               "advanced": {"bitdepth": {"deband": "off", "dither": False}}}))
    assert out[0, 0, 0, 1] / 65535.0 == pytest.approx(0.5807, abs=6e-4)
    sdr = _run(white, resolve({"basic": {"hdr": "off", "grain": "off"}, "advanced": {"bitdepth": {"deband": "off", "dither": False}}}))
    assert sdr[0, 0, 0, 1] == 65535                                       # without HDR the value is untouched


# --- the grain must look like film: irregular, correlated, brightness dependent ---------------------------------------

from restore_worker.finish import film_noise, grain_weight, transfer_source_grain


def _field(seed=1, size=1.0, hw=256):
    g = torch.Generator().manual_seed(seed)
    return film_noise((1, 3, hw, hw), size, g, "cpu")


def _autocorr(a: torch.Tensor, dx: int) -> float:
    a = a - a.mean()
    return float((a[..., :, :-dx] * a[..., :, dx:]).mean() / a.var())


def test_film_noise_is_zero_mean_unit_variance_and_non_gaussian():
    n = _field()
    assert abs(float(n.mean())) < 1e-3 and float(n.std()) == pytest.approx(1.0, abs=1e-3)
    skew = float(((n - n.mean()) ** 3).mean() / n.std() ** 3)
    assert skew > 0.3                                    # dye-cloud clumping: a few stronger clumps, not a bell curve


def test_film_noise_is_spatially_correlated_like_grain_not_white_noise():
    n = _field()
    assert 0.3 < _autocorr(n, 1) < 0.95                  # white noise would be about 0
    assert _autocorr(n, 1) > _autocorr(n, 3) > -0.05     # and it dies away with distance


def test_film_noise_has_no_repeating_pattern_unlike_a_tiled_template():
    """The reported problem: grain that looks regular. A repeating template shows a strong echo at its period."""
    n = _field(hw=512)
    for lag in (16, 32, 64, 73):                          # AV1's template and block sizes are among these
        assert abs(_autocorr(n, lag)) < 0.05, f"echo at lag {lag}"
    g = torch.Generator().manual_seed(3)
    template = film_noise((1, 3, 32, 32), 1.0, g, "cpu")
    tiled = template.repeat(1, 1, 16, 16)                 # control: the same noise, tiled every 32 px
    assert _autocorr(tiled, 32) > 0.9                     # the test can tell: a tiled field is detected


def test_each_frame_and_each_seed_gives_different_grain():
    a, b = _field(seed=1), _field(seed=2)
    assert abs(float((a * b).mean())) < 0.02


def test_colour_channels_are_partly_correlated_like_film_layers():
    n = _field()
    c01 = float((n[:, 0] * n[:, 1]).mean())
    assert 0.45 < c01 < 0.75                              # film layers are neither identical nor independent


def test_grain_is_most_visible_in_shadows_and_midtones():
    w = lambda v: float(grain_weight(torch.tensor(v)))
    assert w(0.3) > w(0.7) > w(0.95) and w(0.3) > w(0.02)
    assert w(0.0) > 0 and w(1.0) > 0 and max(w(v / 100) for v in range(101)) <= 1.0


def test_grain_does_not_show_a_regular_grid_in_a_finished_frame():
    flat = np.full((1, 256, 256, 3), 90, np.uint8)
    out = _run(flat, _recipe(grain={"mode": "baked", "strength": 1.0}, bitdepth={"deband": "off", "dither": False}))
    plane = torch.from_numpy(out[0, ..., 1].astype(np.float64))
    for lag in (16, 32, 64):
        assert abs(_autocorr(plane, lag)) < 0.06


# --- source grain transfer ---------------------------------------------------------------------------------------------

def _clean_with_edge(hw=256):
    img = torch.full((1, 3, hw, hw), 0.4)
    img[..., hw // 2:] = 0.7                               # one hard edge in the middle
    return img


def test_transfer_returns_the_source_grain_in_flat_areas_and_leaves_the_edge_alone():
    clean = _clean_with_edge()
    grain = film_noise(tuple(clean.shape), 1.0, torch.Generator().manual_seed(5), "cpu") * 0.02
    source = (clean + grain)
    out = transfer_source_grain(clean, source, 1.0)
    added = (out - clean)[..., :, :100]                    # flat area, far from the edge
    truth = grain[..., :, :100]
    corr = float((added * truth).mean() / (added.std() * truth.std()))
    assert corr > 0.7 and added.std() > 0.5 * truth.std()  # the film's own grain came back
    assert float((out - clean)[..., :, 126:130].abs().max()) < 0.1 * 0.3   # the edge (0.3 high) was not copied across


def test_transfer_adds_nothing_when_the_source_has_no_grain():
    clean = _clean_with_edge()
    out = transfer_source_grain(clean, clean.clone(), 1.0)
    assert float((out - clean).abs().max()) < 1.0 / 255 / 10          # under a tenth of an 8-bit level: nothing visible


def test_transfer_strength_scales_linearly_and_zero_is_off():
    clean = _clean_with_edge()
    source = clean + film_noise(tuple(clean.shape), 1.0, torch.Generator().manual_seed(6), "cpu") * 0.02
    full, half = transfer_source_grain(clean, source, 1.0) - clean, transfer_source_grain(clean, source, 0.5) - clean
    assert torch.allclose(half * 2, full, atol=1e-6)
    assert torch.equal(transfer_source_grain(clean, source, 0.0), clean)


def test_source_mode_in_the_finisher_uses_the_reference_and_falls_back_without_one():
    rng = np.random.default_rng(0)
    restored = np.full((2, 64, 64, 3), 100, np.uint8)
    source = np.clip(100 + rng.normal(0, 4, restored.shape), 0, 255).astype(np.uint8)
    recipe = _recipe(grain={"mode": "source", "strength": 1.0}, bitdepth={"deband": "off", "dither": False})
    with_ref = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=source)))
    assert with_ref.astype(np.float64).std() > 100                         # grain came from the source
    without = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0)))      # no reference: baked instead, no crash
    assert without.astype(np.float64).std() > 0
    mismatch = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=source[:, :32])))
    assert mismatch.shape == restored.shape[:3] + (3,)


# --- softness matching: attenuate only what the model added beyond the original ---------------------------------------

from restore_worker.finish import (
    SOFTEN_BINS, apply_radial_gain, blur, estimate_noise, estimate_soften_gains, radial_spectrum, soften_mask,
)


def _texture(seed, hw=192, sigma=1.0):
    g = torch.Generator().manual_seed(seed)
    t = blur(torch.randn((1, 1, hw, hw), generator=g), sigma)
    return (0.5 + 0.12 * t / t.std()).expand(1, 3, hw, hw).contiguous()


def _u8(x):
    return (x.clamp(0, 1) * 255).round().to(torch.uint8).permute(0, 2, 3, 1).numpy()


def test_gains_never_exceed_one_and_drop_where_the_restored_picture_has_extra_energy():
    sharp = _texture(1, sigma=0.8)
    soft = blur(sharp, 1.6)
    gains = estimate_soften_gains(sharp, soft, 1.0)
    assert gains.shape == (SOFTEN_BINS,) and float(gains.max()) <= 1.0
    assert float(gains[SOFTEN_BINS // 2:].mean()) < 0.5 * float(gains[:2].mean()) + 0.2      # high bands cut, lowest bands kept
    assert float(gains[0]) > 0.85


def test_equal_or_softer_restoration_gets_no_attenuation_at_all():
    img = _texture(2)
    assert torch.allclose(estimate_soften_gains(img, img.clone(), 1.0), torch.ones(SOFTEN_BINS), atol=1e-5)
    softer = blur(img, 2.0)
    assert float(estimate_soften_gains(softer, img, 1.0).min()) > 0.999       # restored already softer than the original


def test_amount_zero_changes_nothing_and_one_goes_further_than_half():
    sharp, soft = _texture(3, sigma=0.7), blur(_texture(3, sigma=0.7), 1.8)
    g0, g5, g10 = (estimate_soften_gains(sharp, soft, a) for a in (0.0, 0.5, 1.0))
    assert torch.allclose(g0, torch.ones(SOFTEN_BINS)) and float(g10.mean()) < float(g5.mean()) < 1.0


def test_applying_the_gains_moves_the_spectrum_towards_the_source():
    sharp = _texture(4, sigma=0.7)
    soft = blur(sharp, 1.5)
    out = apply_radial_gain(sharp, estimate_soften_gains(sharp, soft, 1.0))
    band = slice(SOFTEN_BINS // 4, SOFTEN_BINS // 2)
    before = float(radial_spectrum(sharp[:, :1])[band].sum() / radial_spectrum(soft[:, :1])[band].sum())
    after = float(radial_spectrum(out[:, :1])[band].sum() / radial_spectrum(soft[:, :1])[band].sum())
    assert before > 3.0 and 0.6 < after < 1.6                                # from several times too much to about right


def test_the_mask_is_high_only_where_the_restored_picture_has_extra_detail():
    base = _texture(5, hw=256, sigma=0.8)
    source = base.clone()
    source[..., :128] = blur(base, 1.8)[..., :128]                            # the left half of the original is softer
    mask = soften_mask(base, source)
    assert float(mask[..., 20:100].mean()) > 0.7 and float(mask[..., 160:240].mean()) < 0.1


def test_finisher_softens_only_with_a_same_size_source_and_leaves_matching_input_untouched():
    sharp, soft = _texture(6, hw=128, sigma=0.7), blur(_texture(6, hw=128, sigma=0.7), 1.6)
    off = dict(bitdepth={"deband": "off", "dither": False}, grain={"mode": "none"})
    recipe = _recipe(**off, fidelity={"soften": "match", "soften_amount": 1.0, "soften_mask": False})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(_u8(sharp), 0, reference=_u8(soft))))
    plain = np.concatenate(list(Finisher(_recipe(**off), "cpu").process(_u8(sharp), 0)))
    assert np.abs(out.astype(float) - plain).mean() > 200                     # visibly changed (16-bit units)
    same = np.concatenate(list(Finisher(recipe, "cpu").process(_u8(sharp), 0, reference=_u8(sharp))))
    assert np.abs(same.astype(float) - plain).mean() < 30                     # nothing to match: essentially untouched
    no_ref = np.concatenate(list(Finisher(recipe, "cpu").process(_u8(sharp), 0)))
    assert np.array_equal(no_ref, plain)                                       # without a source it is skipped, not guessed


def test_noise_estimate_and_the_auto_grain_decision():
    rng = np.random.default_rng(1)
    clean = np.full((2, 96, 96, 3), 110, np.uint8)
    grainy = np.clip(110 + rng.normal(0, 4, clean.shape), 0, 255).astype(np.uint8)
    y = lambda a: (torch.from_numpy(a[:1]).permute(0, 3, 1, 2).float() / 255)[:, :1]
    assert estimate_noise(y(grainy)) == pytest.approx(4 / 255, rel=0.2) and estimate_noise(y(clean)) < 1e-4
    off = dict(bitdepth={"deband": "off", "dither": False})
    recipe = _recipe(**off, grain={"mode": "auto", "strength": 0.5})
    restored = np.full(clean.shape, 110, np.uint8)
    with_grain = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=grainy))).astype(np.float64)
    resid_src = (grainy.astype(np.float64) - 110).reshape(-1)
    resid_out = (with_grain / 257 - 110).reshape(-1)
    assert np.corrcoef(resid_src, resid_out)[0, 1] > 0.5                       # a grainy source: ITS grain came back
    synth = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=clean))).astype(np.float64)
    assert (synth / 257 - 110).std() > 0.5                                     # a clean source: film-like grain was synthesised


from restore_worker.finish import anchor_low_frequency


def test_anchor_removes_a_brightness_drift_and_keeps_the_detail():
    g = torch.Generator().manual_seed(3)
    source = torch.rand(1, 3, 96, 160, generator=g) * 0.4 + 0.3
    detail = (torch.rand(1, 3, 96, 160, generator=g) - 0.5) * 0.08                 # fine structure the model added
    restored = source + 0.05 + detail                                              # drifted 5 percent brighter
    fixed = anchor_low_frequency(restored, source, 1.0)
    assert abs(float((fixed - source).mean())) < 0.005 < abs(float((restored - source).mean()))
    assert float((fixed - source).std()) == pytest.approx(float(detail.std()), rel=0.15)   # detail untouched


def test_anchor_amount_zero_changes_nothing_and_a_smaller_source_works():
    restored = torch.rand(1, 3, 64, 96) * 0.5
    assert torch.equal(anchor_low_frequency(restored, torch.rand(1, 3, 64, 96), 0.0), restored)
    small = torch.full((1, 3, 32, 48), 0.5)                                         # an upscale: the source is half the size
    out = anchor_low_frequency(torch.full((1, 3, 64, 96), 0.4), small, 1.0)
    assert out.shape == (1, 3, 64, 96) and float((out - 0.5).abs().max()) < 1e-4


def test_finisher_anchors_to_the_source_when_asked():
    frames = np.full((2, 32, 32, 3), 120, np.uint8)
    source = np.full((2, 32, 32, 3), 100, np.uint8)
    recipe = _recipe(fidelity={"anchor": "source", "anchor_amount": 1.0}, grain={"mode": "none"})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(frames, 0, reference=source)))
    assert abs(out.mean() / 65535 * 255 - 100) < 0.6
    off = np.concatenate(list(Finisher(_recipe(grain={"mode": "none"}), "cpu").process(frames, 0, reference=source)))
    assert abs(off.mean() / 65535 * 255 - 120) < 0.6


from restore_worker.finish import estimate_noise, _luma


def _grainy_source(h=90, w=160, sigma=0.03, frames=2, seed=5):
    g = torch.Generator().manual_seed(seed)
    base = torch.linspace(0.25, 0.55, w).expand(h, w)[None, None].expand(frames, 3, h, w)
    noisy = (base + torch.randn(frames, 3, h, w, generator=g) * sigma).clamp(0, 1)
    return (noisy.permute(0, 2, 3, 1).numpy() * 255).round().astype(np.uint8)


def _out_noise(out16):
    x = torch.from_numpy(out16.astype(np.float32) / 65535.0).permute(0, 3, 1, 2)
    return float(np.median([estimate_noise(_luma(x[i:i + 1])) for i in range(len(x))]))


def test_after_an_upscale_the_sources_own_grain_is_upscaled_and_added():
    source = _grainy_source()
    restored = np.stack([np.kron(f.mean(axis=2, keepdims=True).repeat(3, axis=2), np.ones((2, 2, 1))) for f in source]).astype(np.uint8)   # smooth, twice the size
    recipe = _recipe(grain={"mode": "auto"}, bitdepth={"dither": False, "deband": "off"})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=source)))
    added = out.astype(np.float32) / 65535 - restored.astype(np.float32) / 255
    sigma = float(added.std())
    assert 0.5 * 0.03 < sigma < 1.3 * 0.03, sigma                      # the source's grain was 0.03 (the synthetic default would be 0.008)


def test_a_clean_source_gets_the_default_synthetic_grain_not_a_matched_zero():
    clean = _grainy_source(sigma=0.0)
    restored = np.kron(clean, np.ones((1, 2, 2, 1))).astype(np.uint8)
    recipe = _recipe(grain={"mode": "auto", "strength": 0.4}, bitdepth={"dither": False, "deband": "off"})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=clean)))
    assert _out_noise(out) > 0.002


def test_source_strength_scales_the_grain_brought_back_from_a_same_size_source():
    source = _grainy_source()
    smooth = np.stack([np.repeat(f.mean(axis=2, keepdims=True), 3, axis=2) for f in source]).astype(np.uint8)
    levels = []
    for amount in (0.0, 0.5, 1.0):
        recipe = _recipe(grain={"mode": "auto", "source_strength": amount}, bitdepth={"dither": False, "deband": "off"})
        levels.append(_out_noise(np.concatenate(list(Finisher(recipe, "cpu").process(smooth, 0, reference=source)))))
    assert levels[0] < levels[1] < levels[2]


from restore_worker.finish import tone_adjust


def test_the_contrast_curve_keeps_black_and_white_deepens_darks_and_lifts_lights():
    y = torch.linspace(0, 1, 11).view(1, 1, 1, 11).expand(1, 3, 2, 11).clone()
    out = tone_adjust(y, contrast=0.3, pivot=0.4, local_contrast=0.0, saturation=1.0)
    assert float(out[..., 0].max()) == 0.0 and float(out[..., -1].min()) == pytest.approx(1.0)   # the ends do not move
    line = out[0, 0, 0]
    assert float(line[2]) < 0.2 and float(line[8]) > 0.8 and (line[1:] > line[:-1]).all()        # darker, lighter, still monotonic


def test_the_contrast_curve_leaves_the_pivot_alone_and_neutral_settings_change_nothing():
    x = torch.full((1, 3, 8, 8), 0.4)
    assert torch.allclose(tone_adjust(x, 0.3, 0.4, 0.0, 1.0), x, atol=1e-6)
    r = torch.rand(1, 3, 16, 16)
    assert torch.equal(tone_adjust(r, 0.0, 0.4, 0.0, 1.0), r)


def test_tone_keeps_the_hue_when_it_changes_brightness_and_saturation_scales_the_colour():
    x = torch.tensor([0.6, 0.3, 0.2]).view(1, 3, 1, 1).expand(1, 3, 4, 4).clone()
    out = tone_adjust(x, 0.3, 0.4, 0.0, 1.0)
    assert torch.allclose(out[0, :, 0, 0] / out[0, 0, 0, 0], x[0, :, 0, 0] / x[0, 0, 0, 0], atol=1e-5)   # same channel ratios
    sat = tone_adjust(x, 0.0, 0.4, 0.0, 1.3)
    assert float(sat[0, 0, 0, 0] - sat[0, 2, 0, 0]) > float(x[0, 0, 0, 0] - x[0, 2, 0, 0])


def test_local_contrast_pushes_an_area_away_from_its_surroundings_and_spares_black_and_white():
    x = torch.full((1, 3, 64, 64), 0.4)
    x[..., 24:40, 24:40] = 0.5
    out = tone_adjust(x, 0.0, 0.4, 0.5, 1.0)
    assert float(out[0, 0, 32, 32]) > 0.5 and float(out[0, 0, 4, 4]) <= 0.4 + 1e-3
    black = torch.zeros(1, 3, 32, 32)
    assert torch.equal(tone_adjust(black, 0.0, 0.4, 0.8, 1.0), black)


def test_anchor_can_pin_brightness_and_keep_the_models_colour():
    source = torch.full((1, 3, 64, 96), 0.4)
    restored = torch.tensor([0.60, 0.55, 0.50]).view(1, 3, 1, 1).expand(1, 3, 64, 96).clone()          # brighter and more colourful
    both = anchor_low_frequency(restored, source, 1.0, 0.0)
    luma = lambda t: float((0.2126 * t[:, 0] + 0.7152 * t[:, 1] + 0.0722 * t[:, 2]).mean())
    assert luma(both) == pytest.approx(0.4, abs=0.01)                                                 # brightness is the source's
    assert float(both[0, 0, 0, 0] - both[0, 2, 0, 0]) == pytest.approx(0.10, abs=0.01)                # the colour difference is kept


def test_an_unset_pivot_follows_the_scenes_own_median_so_the_average_brightness_stays():
    dark = np.clip(np.random.default_rng(1).normal(40, 12, (2, 32, 32, 3)), 0, 255).astype(np.uint8)
    auto = _recipe(tone={"contrast": 0.4})
    fixed = _recipe(tone={"contrast": 0.4, "pivot": 0.5})
    mean = lambda r: np.concatenate(list(Finisher(r, "cpu").process(dark, 0, reference=dark))).mean() / 65535
    assert abs(mean(auto) - dark.mean() / 255) < 0.01                      # pivot at the scene median: the average does not move
    assert mean(fixed) < dark.mean() / 255 - 0.01                          # a pivot above the scene darkens all of it


from restore_worker.finish import soften_adaptive


def _scene(h=128, w=192, seed=7):
    g = torch.Generator().manual_seed(seed)
    base = torch.linspace(0.2, 0.5, w).expand(h, w)[None, None].expand(1, 3, h, w).clone()
    fine = blur(torch.randn(1, 1, h, w, generator=g), 1.2).expand(1, 3, h, w)
    return base, fine / fine.std()


from restore_worker.finish import blur


def test_adaptive_softening_pulls_back_detail_the_source_gives_no_support_for():
    base, texture = _scene()
    restored = base + 0.03 * texture                       # the model invented texture on a flat wall
    out = soften_adaptive(restored, base, 1.2, 0.7, 0.3, 1.0)
    assert float((out - base).std()) < 0.6 * float((restored - base).std())


def test_adaptive_softening_keeps_detail_where_the_source_has_some_and_never_adds():
    base, texture = _scene()
    source = base + 0.02 * texture                         # the source has texture of its own
    restored = base + 0.024 * texture                      # the model has 20 percent more: within the tolerance
    out = soften_adaptive(restored, source, 1.3, 0.7, 0.3, 1.0)
    assert float((out - base).std()) > 0.95 * float((restored - base).std())
    softer = base + 0.01 * texture                         # the model has LESS than the source: untouched
    assert torch.allclose(soften_adaptive(softer, source, 1.3, 0.7, 0.3, 1.0), softer, atol=2e-3)


def test_adaptive_softening_leaves_colour_alone_and_amount_zero_changes_nothing():
    base, texture = _scene()
    restored = base + 0.03 * texture
    restored[:, 0] += 0.1                                  # a colour cast the softening must not touch
    out = soften_adaptive(restored, base, 1.2, 0.7, 0.3, 1.0)
    assert float((out[:, 0] - out[:, 1] - (restored[:, 0] - restored[:, 1])).abs().max()) < 1e-5
    assert torch.equal(soften_adaptive(restored, base, 1.2, 0.7, 0.3, 0.0), restored)


from restore_worker.finish import face_guard_mask


def test_face_guard_is_full_on_a_distant_face_gone_on_a_close_up_and_smooth_between():
    boxes_small = np.array([[100, 100, 30, 40]], dtype=np.float32)              # 40 px of 1080: 3.7 percent
    boxes_big = np.array([[100, 100, 300, 400]], dtype=np.float32)              # 37 percent
    small = face_guard_mask(boxes_small, 1080, 1920, 0.7, "cpu")
    assert float(small.max()) == pytest.approx(0.7, abs=1e-3)
    assert face_guard_mask(boxes_big, 1080, 1920, 0.7, "cpu") is None
    mid = face_guard_mask(np.array([[100, 100, 60, 100]], dtype=np.float32), 1080, 1920, 0.7, "cpu")     # 9 percent
    assert 0.1 < float(mid.max()) < 0.6
    assert float(small[0, 0, 0, 0]) == 0.0 and float(small[0, 0, 120, 115]) > 0.5     # nothing far from the face, strong on it


def test_the_finisher_blends_the_source_back_inside_a_small_face_only():
    h, w = 108, 192
    source = np.full((1, h, w, 3), 80, np.uint8)
    restored = np.full((1, h, w, 3), 160, np.uint8)
    faces = [np.array([[80, 40, 20, 24]], dtype=np.float32)]                      # 24 of 108 px: 22 percent... made small below
    faces = [np.array([[80, 40, 6, 4]], dtype=np.float32)]                       # 4 px: 3.7 percent of the height
    recipe = _recipe(fidelity={"face_guard": "on", "face_guard_amount": 1.0}, grain={"mode": "none"}, bitdepth={"dither": False, "deband": "off"})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=source, faces=faces))).astype(np.float32) / 65535 * 255
    assert out[0, 42, 83, 0] < 100 and out[0, 5, 5, 0] == pytest.approx(160, abs=0.5)   # source inside the face, the model's pixels elsewhere


from restore_worker import faces as faces_mod


def _dets(*rows):
    return {f: np.array([r], dtype=np.float32).reshape(-1, 5) for f, r in rows}


def test_a_lamp_that_scores_well_only_now_and_then_is_not_a_face_but_a_steady_face_is():
    lamp = [(f, (100, 100, 50, 60, 0.8 if f in (40, 44) else 0.55)) for f in range(0, 80, 4)]
    face = [(f, (300, 200, 40, 48, 0.85)) for f in range(0, 80, 4)]
    only_lamp = faces_mod.build_face_boxes(_dets(*lamp), 80)
    assert all(len(b) == 0 for b in only_lamp)
    both = faces_mod.build_face_boxes({f: np.vstack([_dets(*lamp)[f], _dets(*face)[f]]) for f in range(0, 80, 4)}, 80)
    assert all(len(b) == 1 and abs(b[0][0] - 300) < 1 for b in both)


def test_the_weight_eases_in_slowly_and_then_exponentially_before_the_first_detection():
    track = [(f, (200, 100, 40, 50, 0.9)) for f in range(60, 100, 4)]            # the face is only seen from frame 60
    boxes = faces_mod.build_face_boxes(_dets(*track), 120)
    w = [float(boxes[f][0][4]) if len(boxes[f]) else 0.0 for f in range(120)]
    assert w[0] == 0.0 and w[28] > 0.0                                            # it starts about 36 frames before frame 60 ...
    ramp = w[25:61]
    assert all(b >= a for a, b in zip(ramp, ramp[1:]))                            # ... never goes down while approaching it ...
    assert (w[60] - w[50]) > 2.0 * (w[40] - w[30])                                # ... and rises faster the closer it gets
    assert w[60] >= faces_mod.EDGE_WEIGHT - 1e-6 and w[99] > w[110] > w[119]      # eases out again after the last detection


def test_a_turning_head_keeps_its_weak_detections_and_the_weight_follows_the_score():
    track = [(f, (200, 100, 40, 50, s)) for f, s in zip(range(0, 40, 4), (0.4, 0.45, 0.5, 0.6, 0.75, 0.8, 0.85, 0.85, 0.9, 0.9))]
    boxes = faces_mod.build_face_boxes(_dets(*track), 40)
    w = [float(boxes[f][0][4]) for f in range(0, 40, 4)]
    assert w[0] < w[2] < w[3] < w[4] and w[-1] == pytest.approx(1.0, abs=0.02)      # starts at the floor, reaches 1 with the confident score
    assert float(boxes[0][0][4]) >= faces_mod.EDGE_WEIGHT - 1e-6                   # and a weak detection is not thrown away


def test_boxes_move_smoothly_between_detections():
    track = [(0, (100, 100, 40, 50, 0.9)), (8, (110, 100, 40, 50, 0.9)), (16, (120, 100, 40, 50, 0.9))]
    boxes = faces_mod.build_face_boxes(_dets(*track), 17)
    assert boxes[4][0][0] == pytest.approx(105, abs=0.5) and boxes[12][0][0] == pytest.approx(115, abs=0.5)


def test_blur_and_the_stages_that_use_it_work_on_tiny_and_very_narrow_pictures():
    for shape in ((1, 3, 64, 64), (1, 3, 2048, 64), (1, 3, 66, 66)):
        x = torch.rand(shape)
        assert tone_adjust(x, 0.3, 0.4, 0.5, 1.0).shape == shape
        assert soften_adaptive(x, x * 0.9, 1.2, 0.7, 0.5, 1.0).shape == shape


def test_the_contrast_curve_never_folds_the_shadows_whatever_the_settings():
    ramp = torch.linspace(0, 1, 1024).view(1, 1, 1, -1).expand(1, 3, 2, -1).clone()
    for contrast, pivot in ((1.0, 0.9), (0.5, 0.7), (1.0, 0.5)):
        line = tone_adjust(ramp, contrast, pivot, 0.0, 1.0)[0, 0, 0]
        assert (line[1:] >= line[:-1]).all() and float(line[10]) > 0.0           # monotonic, and no plateau of black at the bottom


from restore_worker import face_zoom


def test_crop_windows_stay_inside_the_frame_are_smooth_and_a_multiple_of_16():
    boxes = np.array([[1000 + i * 3, 800, 44, 50] for i in range(30)], dtype=np.float32)
    xs, ys, side = face_zoom.crop_windows(boxes, 2160, 3840)
    assert side in face_zoom.CROP_SIDES and side >= face_zoom.MIN_CROP and (xs >= 0).all() and (xs + side <= 3840).all() and (ys + side <= 2160).all()
    assert np.abs(np.diff(xs)).max() <= 4                                              # follows the face without jumping
    corner = face_zoom.crop_windows(np.array([[3830, 2150, 30, 40]] * 12, dtype=np.float32), 2160, 3840)
    assert corner[0].max() + corner[2] <= 3840 and corner[1].max() + corner[2] <= 2160   # a face at the very corner still fits


class _ZoomEngine:
    """Doubles nothing: returns the crops enlarged 4x by repeating pixels, like an engine that adds no detail."""
    def restore(self, frames, *, scale, tile_height, tile_width, min_overlap, progress=None):
        return np.repeat(np.repeat(frames, int(scale), axis=1), int(scale), axis=2), {}


def test_zoom_track_returns_one_patch_per_frame_at_the_source_scale_with_the_sources_colour():
    source = np.full((6, 400, 600, 3), 90, np.uint8)
    track = {"frames": np.arange(6), "boxes": np.tile(np.array([[300, 200, 40, 50]], np.float32), (6, 1)), "weights": np.ones(6, np.float32)}
    out = face_zoom.zoom_track(_ZoomEngine(), source, track)
    assert [o[0] for o in out] == list(range(6))
    x, y, patch = out[0][1], out[0][2], out[0][3]
    assert patch.shape == (256, 256, 3) and patch.dtype == np.uint8 and abs(float(patch.mean()) - 90) < 1.0


def test_the_finisher_pastes_a_redrawn_face_with_the_tracks_mask_and_leaves_the_rest_alone():
    h, w = 108, 192
    restored = np.full((1, h, w, 3), 100, np.uint8)
    patch = np.full((32, 32, 3), 200, np.uint8)
    box = np.array([86, 40, 6, 4, 1.0], dtype=np.float32)                        # a 4 px face: 3.7 percent of the height
    recipe = _recipe(fidelity={"face_guard": "zoom", "face_guard_amount": 1.0}, grain={"mode": "none"}, bitdepth={"dither": False, "deband": "off"})
    out = np.concatenate(list(Finisher(recipe, "cpu").process(restored, 0, reference=restored, patches={0: [(70, 28, patch, box)]}))).astype(np.float32) / 65535 * 255
    assert out[0, 42, 89, 0] > 150 and out[0, 5, 5, 0] == pytest.approx(100, abs=0.5)


def test_the_guard_weight_has_no_step_where_the_detector_takes_over():
    track = [(f, (200, 100, 40, 50, 0.9)) for f in range(60, 100, 4)]
    boxes = faces_mod.build_face_boxes(_dets(*track), 140)
    w = [float(boxes[f][0][4]) if len(boxes[f]) else 0.0 for f in range(140)]
    assert w[59] > 0.6 * w[60] and w[100] > 0.6 * w[99]                     # eases to the weight of the first and last detection


def test_zoom_track_refuses_an_engine_output_that_is_not_the_crops_enlarged_4x():
    source = np.full((4, 400, 600, 3), 90, np.uint8)
    track = {"frames": np.arange(4), "boxes": np.tile(np.array([[300, 200, 40, 50]], np.float32), (4, 1)), "weights": np.ones(4, np.float32)}

    class Bad:
        def __init__(self, out):
            self.out = out

        def restore(self, frames, **kw):
            return self.out(frames), {}

    for make in (lambda f: f[:2].repeat(4, 1).repeat(4, 2), lambda f: None, lambda f: np.zeros((len(f), 10, 10, 3), np.uint8),
                 lambda f: np.zeros((len(f), f.shape[1] * 4, f.shape[2] * 4, 3), np.float32)):
        with pytest.raises(face_zoom.ZoomError):
            face_zoom.zoom_track(Bad(make), source, track)


def test_the_redrawn_face_is_mixed_with_the_originals_pixels_by_face_zoom_mix():
    h, w = 108, 192
    base = np.full((1, h, w, 3), 100, np.uint8)
    source = np.full((1, h, w, 3), 40, np.uint8)
    patch = np.full((32, 32, 3), 200, np.uint8)
    box = np.array([86, 40, 6, 4, 1.0], dtype=np.float32)
    levels = []
    for mix in (1.0, 0.5):
        recipe = _recipe(fidelity={"face_guard": "zoom", "face_guard_amount": 1.0, "face_zoom_mix": mix}, grain={"mode": "none"}, bitdepth={"dither": False, "deband": "off"})
        out = np.concatenate(list(Finisher(recipe, "cpu").process(base, 0, reference=source, patches={0: [(70, 28, patch, box)]}))).astype(np.float32) / 65535 * 255
        levels.append(float(out[0, 42, 89, 0]))
    assert levels[0] == pytest.approx(200, abs=3) and levels[1] == pytest.approx(120, abs=3)        # 0.5 * 200 + 0.5 * 40


def test_shot_cuts_find_a_hard_cut_and_ignore_motion_and_fades():
    rng = np.random.default_rng(2)
    a = np.clip(rng.normal(60, 10, (1, 72, 128, 3)), 0, 255).astype(np.uint8).repeat(12, axis=0)
    b = np.clip(rng.normal(180, 10, (1, 72, 128, 3)), 0, 255).astype(np.uint8).repeat(12, axis=0)
    assert faces_mod.shot_cuts(np.concatenate([a, b])) == [12]
    fade = np.stack([np.full((72, 128, 3), 60 + 4 * i, np.uint8) for i in range(30)])            # a slow fade is not a cut
    assert faces_mod.shot_cuts(fade) == [] and faces_mod.shot_cuts(a[:1]) == []


def test_face_tracks_neither_link_nor_ramp_across_a_cut():
    first = [(f, (200, 100, 40, 50, 0.9)) for f in range(40, 60, 4)]                  # a face in the second shot only, from frame 40
    boxes = faces_mod.build_face_boxes(_dets(*first), 100, cuts=[30])
    assert all(len(boxes[f]) == 0 for f in range(0, 30)) and len(boxes[31]) == 1         # no ramp into the shot before the cut
    both = [(f, (200, 100, 40, 50, 0.9)) for f in (20, 24, 28, 32, 36, 40, 44)]           # the same place on both sides of a cut at 30
    split = faces_mod.build_face_tracks(_dets(*both), 60, cuts=[30])
    assert len(split) == 2                                                                # two tracks, not one that spans the cut


def test_a_face_that_moves_and_grows_fast_stays_one_track_but_two_faces_far_apart_do_not_merge():
    fast = [(0, (2457, 1354, 38, 45, 0.87)), (4, (2259, 1241, 43, 52, 0.87)), (8, (1992, 1087, 54, 64, 0.89)), (12, (1887, 1042, 66, 77, 0.88)),
            (16, (1884, 1037, 72, 89, 0.87)), (20, (1871, 1025, 97, 120, 0.86))]
    tracks = faces_mod.build_face_tracks(_dets(*fast), 40)
    assert len(tracks) == 1 and tracks[0]["frames"][0] <= 0                              # followed from the very first detection
    two = {f: np.array([[100, 100, 40, 50, 0.9], [900, 700, 40, 50, 0.9]], dtype=np.float32) for f in range(0, 40, 4)}
    assert len(faces_mod.build_face_tracks(two, 40)) == 2


def test_a_stray_weak_detection_next_to_a_fast_face_does_not_steal_its_track():
    det = {0: np.array([[2457, 1354, 38, 45, .87], [1839, 1012, 52, 69, .61]], np.float32),
           4: np.array([[2259, 1241, 43, 52, .87], [2591, 1239, 60, 87, .53]], np.float32),
           8: np.array([[1992, 1087, 54, 64, .89]], np.float32), 12: np.array([[1887, 1042, 66, 77, .88]], np.float32)}
    tracks = faces_mod.build_face_tracks(det, 20)
    assert len(tracks) == 1 and tracks[0]["frames"][0] == 0 and tracks[0]["boxes"][0][0] == pytest.approx(2457)


def test_the_contrast_curve_keeps_the_highlights_for_a_low_pivot_too():
    ramp = torch.linspace(0, 1, 1024).view(1, 1, 1, -1).expand(1, 3, 2, -1).clone()
    for contrast, pivot in ((1.0, 0.1), (0.5, 0.1), (1.0, 0.3), (1.0, 0.9)):
        line = tone_adjust(ramp, contrast, pivot, 0.0, 1.0)[0, 0, 0]
        assert (line[1:] >= line[:-1]).all()
        assert float(line[-1] - line[-40]) > 0.008 and float(line[40] - line[0]) > 0.008          # neither end is a flat plateau


def test_a_weak_detection_far_from_a_confident_track_does_not_take_it_over():
    det = {0: np.array([[100, 100, 40, 50, 0.9]], np.float32), 4: np.array([[100, 100, 40, 50, 0.9]], np.float32),
           8: np.array([[420, 100, 40, 50, 0.55]], np.float32),                                   # a lamp five face sizes away
           12: np.array([[100, 100, 40, 50, 0.9]], np.float32), 16: np.array([[100, 100, 40, 50, 0.9]], np.float32)}
    tracks = faces_mod.build_face_tracks(det, 40)
    assert all(abs(float(b[0]) - 100) < 5 for t in tracks for b in t["boxes"])                    # no box ever slides to the lamp


def test_non_finite_rows_never_become_boxes_and_duplicate_tracks_over_one_face_are_merged():
    dup = {f: np.array([[200, 100, 40, 50, 0.9], [202, 101, 40, 50, 0.88]], np.float32) for f in range(0, 40, 4)}
    assert len(faces_mod.build_face_tracks(dup, 40)) == 1
    bad = {f: np.array([[200, 100, 40, 50, 0.9]], np.float32) for f in range(0, 40, 4)}
    assert all(np.isfinite(t["boxes"]).all() for t in faces_mod.build_face_tracks(bad, 40))


from restore_worker import heads as heads_mod


def test_the_head_box_of_a_standing_person_sits_at_the_top_and_is_about_a_sixth_of_the_height():
    x, y, side, _ = heads_mod.head_box(2441, 1343, 123, 470)                    # the woman seen from behind, 470 px tall
    assert 55 < side < 85 and abs((x + side / 2) - (2441 + 123 / 2)) < 1 and 1343 <= y < 1343 + 0.1 * 470
    wide = heads_mod.head_box(0, 0, 200, 300)                                    # a person cropped at the waist: width limits the head
    assert wide[2] <= 100 + 1e-6


def test_a_head_track_that_follows_a_face_the_face_detector_has_is_dropped_and_a_lone_one_is_kept():
    def track(x):
        frames = np.arange(0, 20)
        return {"frames": frames, "boxes": np.tile(np.array([[x, 100, 50, 50]], np.float32), (20, 1)), "weights": np.ones(20, np.float32)}
    kept = heads_mod.without_faces([track(100), track(900)], [track(105)])
    assert len(kept) == 1 and kept[0]["boxes"][0][0] == 900


def test_person_detections_use_their_own_thresholds_in_the_tracker():
    det = {f: np.array([[200, 100, 40, 50, 0.55]], np.float32) for f in range(0, 40, 4)}      # a person detector's typical score
    assert faces_mod.build_face_tracks(det, 40) == []                                          # not confident as a FACE (0.7)
    assert len(faces_mod.build_face_tracks(det, 40, high=heads_mod.HEAD_HIGH_SCORE, low=heads_mod.HEAD_LOW_SCORE)) == 1


def test_a_missing_or_unreadable_person_model_is_reported_clearly(tmp_path):
    with pytest.raises(heads_mod.HeadModelMissing, match="not at"):
        heads_mod.PersonDetector(tmp_path / "none.onnx")
    bad = tmp_path / "bad.onnx"
    bad.write_bytes(b"not a model")
    with pytest.raises(heads_mod.HeadModelMissing, match="cannot be read"):
        heads_mod.PersonDetector(bad)


from restore_worker.finish import blur, glow_match

GLOW_4PX = 4.0 * 2160 / 192          # glow's width is given in pixels of a 2160-line picture: this is 4 px on the 192-line test scenes


def _light_scene(halo_sigma: float, size: int = 192):
    """A dark picture with one bright disc whose halo is a blur of `halo_sigma` in linear light, and a far corner of fine texture."""
    yy, xx = torch.meshgrid(torch.arange(size, dtype=torch.float32), torch.arange(size, dtype=torch.float32), indexing="ij")
    disc = (((yy - 96) ** 2 + (xx - 96) ** 2) < 14 ** 2).float()[None, None]
    light = 0.8 * disc + 0.8 * (blur(disc, halo_sigma) if halo_sigma > 0 else 0.0) * 0.5 + 0.02
    return (light.clamp(0, 1) ** (1 / 2.2)).expand(1, 3, size, size).clone()


def test_glow_match_gives_the_sources_bloom_back_around_a_light():
    source, restored = _light_scene(halo_sigma=10.0), _light_scene(halo_sigma=0.0)
    ring = torch.zeros(1, 1, 192, 192, dtype=torch.bool)
    ring[..., 96 - 30:96 + 30, 96 - 30:96 + 30] = True
    ring[..., 96 - 18:96 + 18, 96 - 18:96 + 18] = False                              # outside the disc, inside the halo
    fixed = glow_match(restored, source, 1.0, GLOW_4PX)
    before = float((source - restored).abs().mean(dim=1, keepdim=True)[ring].mean())
    after = float((source - fixed).abs().mean(dim=1, keepdim=True)[ring].mean())
    assert after < 0.5 * before


def test_glow_match_leaves_everything_away_from_a_light_exactly_as_it_was():
    source, restored = _light_scene(halo_sigma=10.0), _light_scene(halo_sigma=0.0)
    restored[..., :24, :24] += torch.rand(1, 3, 24, 24, generator=torch.Generator().manual_seed(1)) * 0.02      # fine texture in a far corner
    fixed = glow_match(restored, source, 1.0, GLOW_4PX)
    assert torch.allclose(fixed[..., :24, :24], restored[..., :24, :24], atol=1e-6)


def test_glow_match_adds_nothing_narrower_than_its_width():
    source, restored = _light_scene(halo_sigma=10.0), _light_scene(halo_sigma=0.0)
    texture = (torch.rand(1, 3, 192, 192, generator=torch.Generator().manual_seed(2)) - 0.5) * 0.02
    fixed = glow_match(restored + texture, source, 1.0, GLOW_4PX) - glow_match(restored, source, 1.0, GLOW_4PX)
    assert float((fixed - texture).abs().mean()) < 0.003                              # the fine texture comes through the stage unchanged


def test_glow_match_off_and_matching_pictures_change_nothing():
    restored = _light_scene(halo_sigma=0.0)
    assert torch.equal(glow_match(restored, _light_scene(10.0), 0.0, GLOW_4PX), restored)
    assert float((glow_match(restored, restored, 1.0, GLOW_4PX) - restored).abs().max()) < 1e-5


def test_glow_match_keeps_values_the_model_pushed_past_the_range():
    restored = _light_scene(halo_sigma=0.0)
    restored[..., 5, 5] = 1.04                                                         # an overshoot far from any light
    assert float(glow_match(restored, _light_scene(10.0), 1.0, GLOW_4PX)[0, 0, 5, 5]) == pytest.approx(1.04, abs=1e-5)


def test_finisher_applies_glow_only_with_a_same_size_source():
    source = (_light_scene(10.0) ** 1.0).permute(0, 2, 3, 1).mul(255).round().byte().numpy()
    restored = (_light_scene(0.0)).permute(0, 2, 3, 1).mul(255).round().byte().numpy()
    on = _recipe(fidelity={"glow": 1.0, "glow_sigma": 16.0}, grain={"mode": "none"}, bitdepth={"deband": "off", "dither": False})
    off = _recipe(grain={"mode": "none"}, bitdepth={"deband": "off", "dither": False})
    glowing = np.concatenate(list(Finisher(on, "cpu").process(restored, 0, reference=source)))
    plain = np.concatenate(list(Finisher(off, "cpu").process(restored, 0, reference=source)))
    no_ref = np.concatenate(list(Finisher(on, "cpu").process(restored, 0)))
    assert glowing.astype(int).sum() > plain.astype(int).sum()                          # the bloom added light
    assert np.array_equal(no_ref, plain)                                               # no source: skipped, no crash


def test_glow_match_never_takes_light_away():
    source, restored = _light_scene(halo_sigma=10.0), _light_scene(halo_sigma=0.0)
    brighter = restored * 1.0
    brighter[..., 90:102, 90:102] = 1.0                                                # the model drew the core brighter than the source
    assert float((glow_match(brighter, source, 1.0, GLOW_4PX) - brighter).min()) >= -1e-6


from restore_worker.finish import plateau_purge


def _staircase(rows=96, cols=480, step=2.0, plateau=40, base=60.0):
    """A dark wall with a slow gradient quantised into wide steps of `step` codes: the contour patches of a poor encode."""
    ramp = base + step * (np.arange(cols) // plateau)
    return torch.from_numpy(np.broadcast_to(ramp[None, :], (rows, cols)).copy()).float().div(255.0)[None, None].expand(1, 3, rows, cols).clone()


def test_plateau_purge_turns_a_staircase_into_a_ramp():
    wall = _staircase()
    fixed = plateau_purge(wall, 1.0)
    row = lambda t: t[0, 0, 48] * 255.0
    jump = lambda t: float((row(t)[1:] - row(t)[:-1]).abs().max())
    assert jump(wall) == pytest.approx(2.0, abs=1e-3) and jump(fixed) < 1.0       # the 2-code steps are spread over many pixels


def test_plateau_purge_leaves_texture_edges_and_flat_areas_exactly_alone():
    g = torch.Generator().manual_seed(4)
    grain = (torch.rand(1, 3, 96, 160, generator=g) * 6.0 + 60.0) / 255.0           # noise of about 6 codes: no plateaus at all
    assert float((plateau_purge(grain, 1.0) - grain).abs().max()) < 1e-6
    flat = torch.full((1, 3, 96, 160), 70.0 / 255.0)
    assert float((plateau_purge(flat, 1.0) - flat).abs().max()) < 1e-6
    edge = torch.full((1, 3, 96, 320), 60.0 / 255.0)
    edge[..., 160:] = 100.0 / 255.0                                                 # a real 40-code edge between two flat areas
    assert float((plateau_purge(edge, 1.0) - edge).abs().max()) * 255.0 < 0.05                # a few hundredths of a code of blur tail at most


def test_plateau_purge_keeps_a_thin_line_across_a_staircase():
    wall = _staircase()
    wall[..., 40:43, :] += 6.0 / 255.0                                              # a 3 px bright line: detail, not banding
    fixed = plateau_purge(wall, 1.0)
    assert float((fixed[..., 41, 100:380] - wall[..., 41, 100:380]).abs().max()) * 255.0 < 0.5


def test_plateau_purge_off_changes_nothing_and_the_finisher_runs_it():
    wall = _staircase()
    assert torch.equal(plateau_purge(wall, 0.0), wall)
    frames = (wall.permute(0, 2, 3, 1).mul(255).round().byte().numpy())
    on = _recipe(bitdepth={"plateau_purge": 1.0, "deband": "off", "dither": False}, grain={"mode": "none"})
    off = _recipe(bitdepth={"deband": "off", "dither": False}, grain={"mode": "none"})
    smooth = np.concatenate(list(Finisher(on, "cpu").process(frames, 0))).astype(np.int64)
    plain = np.concatenate(list(Finisher(off, "cpu").process(frames, 0))).astype(np.int64)
    assert np.abs(np.diff(smooth[0, 48, :, 0])).max() < np.abs(np.diff(plain[0, 48, :, 0])).max()


def test_a_valid_onnx_that_is_not_the_person_detector_is_refused_with_its_shape():
    class WrongNet:
        def setInput(self, blob): pass
        def getUnconnectedOutLayersNames(self): return ["out"]
        def forward(self, names): return [np.zeros((1, 6400, 15), np.float32)]          # yunet-like rows, not YOLOX's 8400 x 85
    detector = heads_mod.PersonDetector.__new__(heads_mod.PersonDetector)
    detector.net, detector.grids, detector.strides = WrongNet(), np.zeros((8400, 2)), np.zeros((8400, 1))
    with pytest.raises(heads_mod.HeadModelMissing, match=r"shape \(1, 6400, 15\)"):
        detector._tile(np.zeros((640, 640, 3), np.uint8))
