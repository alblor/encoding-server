"""SDR to HDR10 container mapping: the standards-exact part, with no learned model in it.

BT.709 SDR in, BT.2020 PQ out, following ITU-R BT.2408: SDR reference white (1.0) lands at 203 nits, the picture
keeps the look it had, and only the signalling and the container change. This is what `hdr.mode = synthesize`
does today. A learned expansion of highlights and colour volume (HDRTVNet++ is the candidate) would sit on
top of this and is not here yet: SDR holds nothing above its own white, so a fixed mapping cannot invent it.

Pipeline of one frame, all in float:
    SDR code values (0..1)  --BT.1886, gamma 2.4-->  linear light (0..1 of SDR white)
    x reference white nits  --BT.709 to BT.2020 matrix-->  absolute linear nits in the BT.2020 primaries
    / 10000  --SMPTE ST 2084 inverse EOTF-->  PQ code values (0..1)

PQ code values are what the encoder is told are BT.2020 / PQ, so they go to the converter as they are.
"""
from __future__ import annotations

import torch

# Linear BT.709 to linear BT.2020 (ITU-R BT.2087-0, table 2).
BT709_TO_BT2020 = (
    (0.6274039, 0.3292830, 0.0433131),
    (0.0690973, 0.9195404, 0.0113623),
    (0.0163914, 0.0880133, 0.8955953),
)

# SMPTE ST 2084 constants.
M1 = 2610 / 16384
M2 = 2523 / 4096 * 128
C1 = 3424 / 4096
C2 = 2413 / 4096 * 32
C3 = 2392 / 4096 * 32

PQ_PEAK_NITS = 10000.0
BT1886_GAMMA = 2.4


def bt1886_to_linear(x: torch.Tensor) -> torch.Tensor:
    """SDR code values to linear light relative to SDR white, for a display with a zero black level."""
    return x.clamp(0, 1) ** BT1886_GAMMA


def pq_inverse_eotf(nits: torch.Tensor) -> torch.Tensor:
    """Absolute luminance in nits to ST 2084 code values, 0..1."""
    y = (nits / PQ_PEAK_NITS).clamp(0, 1)
    p = y ** M1
    return ((C1 + C2 * p) / (1 + C3 * p)) ** M2


def pq_eotf(code: torch.Tensor) -> torch.Tensor:
    """ST 2084 code values to absolute luminance in nits (the inverse of pq_inverse_eotf)."""
    e = code.clamp(0, 1) ** (1 / M2)
    y = ((e - C1).clamp_min(0) / (C2 - C3 * e)) ** (1 / M1)
    return y * PQ_PEAK_NITS


def sdr_to_pq(x: torch.Tensor, reference_white_nits: float = 203.0) -> torch.Tensor:
    """x: float [N,3,H,W] BT.709 SDR code values in 0..1. Returns BT.2020 PQ code values in 0..1."""
    linear = bt1886_to_linear(x)
    matrix = torch.tensor(BT709_TO_BT2020, dtype=x.dtype, device=x.device)
    wide = torch.einsum("ij,njhw->nihw", matrix, linear).clamp_min(0)
    return pq_inverse_eotf(wide * reference_white_nits)
