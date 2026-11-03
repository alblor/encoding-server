"""SDR to HDR10 mapping against published reference values (ST 2084, BT.1886, BT.2087)."""
import pytest
import torch

from restore_worker.hdr import BT709_TO_BT2020, bt1886_to_linear, pq_eotf, pq_inverse_eotf, sdr_to_pq


@pytest.mark.parametrize("nits,code", [
    (0.0, 7.3e-7),
    (100.0, 0.5081),                 # 100 nits, the SDR reference white of BT.1886
    (203.0, 0.5807),                 # BT.2408 HDR reference white
    (1000.0, 0.7518),
    (10000.0, 1.0),
])
def test_pq_inverse_eotf_matches_the_standard_anchor_points(nits, code):
    assert float(pq_inverse_eotf(torch.tensor(nits, dtype=torch.float64))) == pytest.approx(code, abs=6e-4)


def test_pq_round_trip_is_exact_across_the_range():
    nits = torch.logspace(-4, 4, 200, dtype=torch.float64)
    back = pq_eotf(pq_inverse_eotf(nits))
    assert torch.allclose(back, nits, rtol=1e-6, atol=1e-6)


def test_bt1886_is_a_plain_gamma_of_2_4():
    assert float(bt1886_to_linear(torch.tensor(0.5, dtype=torch.float64))) == pytest.approx(0.5 ** 2.4)
    assert float(bt1886_to_linear(torch.tensor(1.0))) == 1.0 and float(bt1886_to_linear(torch.tensor(-0.2))) == 0.0


def test_gamut_matrix_rows_sum_to_one_so_white_stays_white():
    for row in BT709_TO_BT2020:
        assert sum(row) == pytest.approx(1.0, abs=1e-6)


def test_bt709_red_lands_where_bt2087_says():
    red = torch.tensor([1.0, 0.0, 0.0], dtype=torch.float64).view(1, 3, 1, 1)
    m = torch.tensor(BT709_TO_BT2020, dtype=torch.float64)
    out = torch.einsum("ij,njhw->nihw", m, red).flatten()
    assert out.tolist() == pytest.approx([0.6274039, 0.0690973, 0.0163914], abs=1e-6)


def test_sdr_white_lands_at_203_nits_and_black_stays_black():
    white = sdr_to_pq(torch.ones(1, 3, 2, 2, dtype=torch.float64), 203.0)
    assert float(white[0, 0, 0, 0]) == pytest.approx(0.5807, abs=6e-4)
    assert torch.allclose(white[0, 0], white[0, 1]) and torch.allclose(white[0, 1], white[0, 2])   # neutral stays neutral
    # ST 2084 maps zero to about 7e-7, not exactly zero: that is a property of the curve.
    assert float(sdr_to_pq(torch.zeros(1, 3, 2, 2, dtype=torch.float64))[0, 0, 0, 0]) < 1e-5


def test_reference_white_setting_moves_the_whole_picture():
    x = torch.full((1, 3, 1, 1), 0.5, dtype=torch.float64)
    dim, bright = sdr_to_pq(x, 150.0), sdr_to_pq(x, 300.0)
    assert float(bright[0, 0, 0, 0]) > float(dim[0, 0, 0, 0])


def test_output_is_monotonic_in_the_input():
    ramp = torch.linspace(0, 1, 256, dtype=torch.float64).view(1, 1, 1, 256).expand(1, 3, 1, 256)
    out = sdr_to_pq(ramp)[0, 1, 0]
    assert bool((out[1:] >= out[:-1]).all())
