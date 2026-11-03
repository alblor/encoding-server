"""FP8 quantise and dequantise math of restore_worker/quantize.py, on the CPU (the GPU kernel is the same math).

Author: Lorenzo Albanese (alblor)
"""
import pytest
import torch
from torch import nn

from restore_worker.quantize import (FP8, FP8_MAX, Fp8Linear, dequantize, fp8_matmul, quantize_rows,
                                     quantize_transformer, to_fp8)

E4M3_MIN_NORMAL = 2.0 ** -6


def test_row_scale_maps_each_row_maximum_onto_the_fp8_maximum():
    t = torch.tensor([[1.0, -3.0, 0.5], [100.0, 2.0, -50.0]])
    q, scale = quantize_rows(t)
    assert q.dtype == FP8 and scale.shape == (2, 1) and scale.dtype == torch.float32
    assert torch.allclose(q.float().abs().amax(-1), torch.full((2,), FP8_MAX))
    assert torch.allclose(scale.squeeze(1), torch.tensor([3.0, 100.0]) / FP8_MAX)


def test_round_trip_error_is_within_half_an_e4m3_step():
    torch.manual_seed(0)
    t = torch.randn(64, 512) * torch.logspace(-3, 3, 64).unsqueeze(1)    # rows six decades apart
    q, scale = quantize_rows(t)
    back = dequantize(q, scale)
    normal = (t / scale).abs() >= E4M3_MIN_NORMAL                       # e4m3 has 3 mantissa bits for normals
    assert ((back - t).abs()[normal] <= 2.0 ** -4 * t.abs()[normal] + 1e-12).all()


def test_values_beyond_the_range_saturate_instead_of_becoming_nan():
    q = to_fp8(torch.tensor([1e6, -1e6, 10.0]), torch.tensor(1.0))
    assert torch.equal(q.float(), torch.tensor([FP8_MAX, -FP8_MAX, 10.0]))


def test_all_zero_rows_do_not_divide_by_zero():
    q, scale = quantize_rows(torch.zeros(3, 16))
    assert torch.isfinite(scale).all() and (q.float() == 0).all()


def test_fp8_matmul_on_cpu_is_the_exact_product_of_the_fp8_values():
    torch.manual_seed(1)
    a = (torch.randn(8, 64) * 8).to(FP8)
    b = (torch.randn(16, 64) * 8).to(FP8)
    exact = a.double() @ b.double().t()
    got = fp8_matmul(a, b)
    assert got.dtype == torch.bfloat16
    assert ((got.double() - exact).abs() <= 2.0 ** -8 * exact.abs() + 1e-6).all()   # only the bf16 rounding


def _linear(n_out, n_in, bias=True, channel_spread=None):
    torch.manual_seed(2)
    layer = nn.Linear(n_in, n_out, bias=bias)
    with torch.no_grad():
        if channel_spread is not None:
            layer.weight.mul_(torch.logspace(0, channel_spread, n_out).unsqueeze(1))
    return layer.to(torch.bfloat16)


def test_fp8_linear_matches_the_bf16_layer_within_fp8_accuracy():
    layer = _linear(96, 256)
    x = torch.randn(2, 5, 256, dtype=torch.bfloat16)
    ref = (x.float() @ layer.weight.float().t()) + layer.bias.float()
    got = Fp8Linear(layer)(x)
    assert got.shape == (2, 5, 96) and got.dtype == torch.bfloat16
    rel = (got.float() - ref).norm() / ref.norm()
    assert rel < 0.06        # e4m3 inputs: a few percent, here typically about 3%


def test_fp8_linear_epilogue_equals_the_dequantised_product():
    layer = _linear(32, 128, bias=False)
    x = torch.randn(7, 128, dtype=torch.bfloat16)
    lin = Fp8Linear(layer)
    xq, xs = quantize_rows(x)
    expected = dequantize(xq, xs) @ dequantize(lin.weight_fp8, lin.w_scale.unsqueeze(1)).t()
    assert torch.allclose(lin(x).float(), expected, rtol=2 ** -7, atol=1e-4)


def test_per_channel_weight_scale_beats_one_scale_per_tensor_on_uneven_channels():
    """Channels four decades apart: a single tensor scale flushes the small ones, per-channel scales do not."""
    layer = _linear(64, 256, bias=False, channel_spread=4)
    x = torch.randn(32, 256, dtype=torch.bfloat16)
    ref = x.float() @ layer.weight.float().t()
    per_channel = Fp8Linear(layer)(x).float()
    w = layer.weight.float()
    w_scale = w.abs().amax() / FP8_MAX
    xq, xs = quantize_rows(x)
    per_tensor = dequantize(xq, xs) @ (to_fp8(w, w_scale).float() * w_scale).t()

    def worst_channel(y):
        return ((y - ref).norm(dim=0) / ref.norm(dim=0)).max()

    assert worst_channel(per_channel) < 0.06 < worst_channel(per_tensor)


# --- swapping the layers of a transformer-shaped model ----------------------------------------------------


class _Attn(nn.Module):
    def __init__(self, dim, cross):
        super().__init__()
        self.to_q, self.to_k, self.to_v = (nn.Linear(dim, dim) for _ in range(3))
        self.to_out = nn.ModuleList([nn.Linear(dim, dim), nn.Dropout(0.0)])
        self.cross, self.fused_projections = cross, False

    def fuse_projections(self):      # same contract as the diffusers/ReCaVSR WanAttention
        if self.cross:
            raise AssertionError("cross-attention must not be fused")
        fused = nn.Linear(self.to_q.in_features, 3 * self.to_q.out_features)
        with torch.no_grad():
            fused.weight.copy_(torch.cat([self.to_q.weight, self.to_k.weight, self.to_v.weight]))
            fused.bias.copy_(torch.cat([self.to_q.bias, self.to_k.bias, self.to_v.bias]))
        self.to_qkv, self.fused_projections = fused, True


class _Proj(nn.Module):
    def __init__(self, dim, hidden):
        super().__init__()
        self.proj = nn.Linear(dim, hidden)


class _Ffn(nn.Module):
    def __init__(self, dim, hidden):
        super().__init__()
        self.net = nn.ModuleList([_Proj(dim, hidden), nn.Dropout(0.0), nn.Linear(hidden, dim)])


class _Block(nn.Module):
    def __init__(self, dim=32, hidden=64):
        super().__init__()
        self.attn1, self.attn2, self.ffn = _Attn(dim, False), _Attn(dim, True), _Ffn(dim, hidden)


class _Model(nn.Module):
    def __init__(self, n=6):
        super().__init__()
        self.blocks = nn.ModuleList([_Block() for _ in range(n)])


def test_fp8_mode_swaps_six_matmuls_per_middle_block_and_keeps_the_edges_in_bf16():
    model = _Model(6).to(torch.bfloat16)
    edge_qkv = model.blocks[0].attn1.to_q.weight.clone()
    middle = model.blocks[3]
    expected_qkv = torch.cat([middle.attn1.to_q.weight, middle.attn1.to_k.weight, middle.attn1.to_v.weight]).float()
    report = quantize_transformer(model, "fp8", keep_edge_blocks=2)
    assert report["quantized_layers"] == 2 * 6
    for i in (0, 1, 4, 5):
        assert isinstance(model.blocks[i].attn1.to_q, nn.Linear) and not model.blocks[i].attn1.fused_projections
    assert torch.equal(model.blocks[0].attn1.to_q.weight, edge_qkv)
    for i in (2, 3):
        b = model.blocks[i]
        assert b.attn1.fused_projections and not hasattr(b.attn1, "to_q")       # bf16 originals are freed
        for m in (b.attn1.to_qkv, b.attn1.to_out[0], b.attn2.to_q, b.attn2.to_out[0], b.ffn.net[0].proj, b.ffn.net[2]):
            assert isinstance(m, Fp8Linear)
        assert isinstance(b.attn2.to_k, nn.Linear) and isinstance(b.attn2.to_v, nn.Linear)   # precomputed once
    qkv = model.blocks[3].attn1.to_qkv
    back = dequantize(qkv.weight_fp8, qkv.w_scale.unsqueeze(1))
    assert ((back - expected_qkv).norm() / expected_qkv.norm()) < 0.04


def test_unknown_precision_and_too_few_blocks_are_rejected():
    with pytest.raises(ValueError, match="unknown precision"):
        quantize_transformer(_Model(6), "int3")
    with pytest.raises(ValueError, match="too few blocks"):
        quantize_transformer(_Model(4), "fp8", keep_edge_blocks=2)
    assert quantize_transformer(_Model(4), "bf16")["quantized_layers"] == 0
