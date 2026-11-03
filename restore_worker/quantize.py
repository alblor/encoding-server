"""Optional FP8 for the ReCaVSR transformer: smaller weights, faster linear layers, quality gated.

Only the large linear layers inside the middle transformer blocks are quantized (attention
projections and the feed-forward). Everything that decides fidelity stays in bf16: the patch
embedding, the LQ and recycled-latent projections, the output projection, norms, modulation, the
rotary embeddings, the KV cache, the cross-attention K/V (computed once per session), the first and
last blocks and the decoder.

Modes
  bf16       no quantization (default, the reference quality)
  fp8        own FP8 linear (Fp8Linear below): weights in e4m3 with one scale per output channel,
             activations in e4m3 with one scale per token, both scales applied after a tensor-wise
             FP8 matmul. Plain tensors and aten ops only, so torch.compile fuses the quantisation into
             the kernel that produces the activation and the scales into the one that consumes the output.
             It needs torch.compile: in eager mode the casts run as separate passes and a block is SLOWER
             than bf16 (60.5 ms against 52.7 ms for the 9072-token prefix).
  fp8_fast   torchao per-tensor FP8, the first attempt, kept for comparison. Same accuracy as fp8, slower:
             torchao hands the bias to torch._scaled_mm, and with a bias cuBLAS picks an Ada (sm89) kernel
             on this card instead of the native one (3.40 ms against 2.17 ms on a 9072x3072x14336 matmul).

Why the scales sit outside the matmul: on this consumer Blackwell part (RTX 5080, sm_120) cuBLAS only
runs FP8 with one scale per tensor (row-wise scaling fails with CUBLAS_STATUS_NOT_SUPPORTED). A
per-token by per-channel scale is an outer product, so it can be applied to the matmul output as one
multiply, which keeps row-wise accuracy at tensor-wise speed. The bias is added there too, for the
kernel reason above. The FP8 kernel accumulates in FP32 (checked against FP64), so precision is set
by the 4 significant bits of e4m3 per element, not by the sum: no choice of scales gets a single FP8
matmul near bf16 accuracy (5.3 effective bits per layer on real activations, against 9.2 for bf16).

Measured on the RTX 5080 (2160p synthetic clip, 49 frames, six 1344x1152 tiles, warm, compiled), 2026-10-31:
  raw matmul ceiling     FP8 2.8 to 3.4x bf16 on the model's shapes (bf16 112 TFLOPS, FP8 320 to 378)
  bf16                   DiT 18.21 s, 0.578 s/frame, peak 13.2 GiB
  fp8 (middle 26 blocks) DiT 12.77 s (1.43x), 0.475 s/frame (1.22x), peak 9.7 GiB, 46.83 dB against bf16
  fp8_fast               DiT 14.28 s (1.28x), 0.505 s/frame, 46.73 dB against bf16
  floor                  bf16 eager against bf16 compiled differ by 51.89 dB (same raw RGB method)
Whether a mode is acceptable is decided by comparing its output with bf16 on real clips, never by
kernel numbers alone: tools/scripts/ops/bench/fp8_output_compare.py on --save-raw output of
tools/scripts/ops/bench/recavsr_tiled_bench.py.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import logging

import torch
from torch import nn

log = logging.getLogger("restore_worker.quantize")

MODES = ("bf16", "fp8", "fp8_fast")
FP8 = torch.float8_e4m3fn
FP8_MAX = 448.0          # largest finite e4m3fn value
_TINY = 1e-12            # floor for scales, so an all-zero row or channel does not divide by zero


def fp8_scale(amax: torch.Tensor) -> torch.Tensor:
    """FP32 scale that maps `amax` onto the largest FP8 value."""
    return amax.float().clamp(min=_TINY) / FP8_MAX


def to_fp8(t: torch.Tensor, scale: torch.Tensor) -> torch.Tensor:
    """t / scale in e4m3, saturated: values beyond the range clamp instead of turning into NaN."""
    return (t.float() / scale).clamp(-FP8_MAX, FP8_MAX).to(FP8)


def quantize_rows(t: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
    """One scale per row (last dimension reduced): per output channel for a weight, per token for an activation."""
    scale = fp8_scale(t.abs().amax(dim=-1, keepdim=True))
    return to_fp8(t, scale), scale


def dequantize(q: torch.Tensor, scale: torch.Tensor) -> torch.Tensor:
    return q.float() * scale


def fp8_matmul(a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    """a (M, K) e4m3 @ b (N, K) e4m3 transposed, unscaled, FP32 accumulation, bf16 out.

    On CUDA this is cuBLAS through torch._scaled_mm with unit tensor-wise scales. On the CPU it is the
    same math in FP32 (used by the unit tests): products of e4m3 values are exact in FP32.
    """
    if a.device.type == "cuda":
        one = torch.ones((), device=a.device, dtype=torch.float32)
        return torch._scaled_mm(a, b.t(), scale_a=one, scale_b=one, out_dtype=torch.bfloat16)
    return (a.float() @ b.float().t()).to(torch.bfloat16)


class Fp8Linear(nn.Module):
    """Drop-in replacement for a bf16 nn.Linear: FP8 weight per output channel, FP8 activation per token.

    y = (x_q @ w_q^T) * x_scale[token] * w_scale[channel] + bias. The raw product is rounded to bf16
    once (relative error 2^-9, far below the FP8 rounding of the inputs), then scaled in FP32.
    """

    def __init__(self, linear: nn.Linear) -> None:
        super().__init__()
        weight = linear.weight.detach()
        self.in_features, self.out_features = weight.shape[1], weight.shape[0]
        w_q, w_scale = quantize_rows(weight)
        self.register_buffer("weight_fp8", w_q.contiguous())
        self.register_buffer("w_scale", w_scale.reshape(-1).contiguous())          # (N,) float32
        bias = linear.bias.detach().float() if linear.bias is not None else None
        self.register_buffer("bias", bias)
        self.out_dtype = weight.dtype

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        lead = x.shape[:-1]
        x2 = x.reshape(-1, self.in_features)
        x_q, x_scale = quantize_rows(x2)                                            # (M, K) e4m3, (M, 1) float32
        y = fp8_matmul(x_q, self.weight_fp8).float() * x_scale * self.w_scale
        if self.bias is not None:
            y = y + self.bias
        return y.to(self.out_dtype).reshape(*lead, self.out_features)

    def extra_repr(self) -> str:
        return f"in_features={self.in_features}, out_features={self.out_features}, fp8 per-token x per-channel"


def _fp8_own(blocks: list[nn.Module]) -> int:
    """Swap the hot linear layers of `blocks` for Fp8Linear; returns how many were swapped."""
    swapped = 0
    for block in blocks:
        attn1 = block.attn1
        # One FP8 cast of the shared input and a wider matmul instead of three: fuse q, k and v, then drop the
        # bf16 originals so their memory is freed. attn2 is not fused: its K/V are computed once per session.
        attn1.fuse_projections()
        for name in ("to_q", "to_k", "to_v"):
            if hasattr(attn1, name):
                delattr(attn1, name)
        attn1.to_qkv = Fp8Linear(attn1.to_qkv)
        attn1.to_out[0] = Fp8Linear(attn1.to_out[0])
        block.attn2.to_q = Fp8Linear(block.attn2.to_q)
        block.attn2.to_out[0] = Fp8Linear(block.attn2.to_out[0])
        block.ffn.net[0].proj = Fp8Linear(block.ffn.net[0].proj)
        block.ffn.net[2] = Fp8Linear(block.ffn.net[2])
        swapped += 6
    return swapped


def _fp8_torchao(blocks: list[nn.Module]) -> int:
    from torchao.quantization import Float8DynamicActivationFloat8WeightConfig, PerTensor, quantize_

    # set_inductor_config=False: the default (True) calls torchao's recommended_inductor_config_setter(), which
    # switches on coordinate-descent tuning in all directions for EVERY later torch.compile in the process. With
    # 30 blocks and several KV-cache signatures that is what made compilation look hung for 18 minutes and more
    # (one block, one signature: 183.8 s with it, 13.5 s without; bf16 with it forced on: 121.2 s, without 11.1 s).
    config = Float8DynamicActivationFloat8WeightConfig(granularity=PerTensor(), set_inductor_config=False)
    swapped = 0
    for block in blocks:
        for module in block.modules():
            if isinstance(module, nn.Linear) and module.weight.shape[0] % 16 == 0 and module.weight.shape[1] % 16 == 0:
                quantize_(module, config)
                swapped += 1
    return swapped


def _nbytes(t: torch.Tensor) -> int:
    """Storage of a tensor; torchao's wrapper subclasses report the outer dtype, so count their inner tensors."""
    from torch.utils._python_dispatch import is_traceable_wrapper_subclass

    if is_traceable_wrapper_subclass(t):
        names, _ = t.__tensor_flatten__()
        return sum(_nbytes(getattr(t, name)) for name in names)
    return t.numel() * t.element_size()


def _weight_bytes(blocks: list[nn.Module]) -> int:
    return sum(_nbytes(t) for b in blocks for t in list(b.parameters()) + list(b.buffers()))


def quantize_transformer(model: nn.Module, mode: str, *, keep_edge_blocks: int = 2) -> dict:
    """Quantize the middle blocks' linear layers in place and report what changed.

    Must run before any TransformerSession exists: sessions precompute the cross-attention K/V and
    capture the modules they call.
    """
    if mode not in MODES:
        raise ValueError(f"unknown precision {mode!r}, expected one of {MODES}")
    blocks = list(model.blocks)
    if mode == "bf16":
        return {"mode": mode, "quantized_layers": 0, "blocks": len(blocks)}
    if len(blocks) <= 2 * keep_edge_blocks:
        raise ValueError("model has too few blocks to keep the edge blocks in bf16")
    middle = blocks[keep_edge_blocks:len(blocks) - keep_edge_blocks]
    before = _weight_bytes(middle)
    layers = _fp8_own(middle) if mode == "fp8" else _fp8_torchao(middle)
    after = _weight_bytes(middle)
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    log.info("quantized %d linear layers to %s", layers, mode)
    return {
        "mode": mode,
        "quantized_layers": layers,
        "blocks": len(blocks),
        "kept_bf16_edge_blocks": keep_edge_blocks,
        "middle_block_gib_before": before / 2**30,
        "middle_block_gib_after": after / 2**30,
    }
