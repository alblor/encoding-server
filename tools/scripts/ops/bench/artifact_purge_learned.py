"""FBCNN (blind JPEG artifact removal) as a candidate for the artifact-purge experiment, plus the conservative gate.

FBCNN: Jiang et al., "Towards Flexible Blind JPEG Artifacts Removal", ICCV 2021, https://github.com/jiaxi-jiang/FBCNN,
Apache-2.0 (LICENSE and README of the repository). It is trained on 8x8 DCT blocks of JPEG, so x264/x265/AV1 damage is outside
what it saw. The network code (models/network_fbcnn.py) and the colour weights (fbcnn_color.pth, release v1.0) are public
files downloaded once in a throwaway container and kept in /work/models only while the experiment runs.

  fbcnn(x, qf)         whole picture in overlapping tiles, with ONE quality factor per frame: the median of what the network
                       predicts on each tile (None) or a fixed one (a lower qf means a stronger clean-up)
  gate_delta(x, y)     keeps only the part of the network's change that is small and sits in flat areas: the output is
                       x + mask * clip(y - x, -limit, limit), mask = plateau area or quiet area of x. Anything textured is left as it was.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import sys
import types

import torch

import artifact_purge_candidates as C

MODELS = "/work/models"
_net = None


def load(device):
    global _net
    if _net is None:
        sys.path.insert(0, MODELS)
        # network_fbcnn.py imports torchvision.models and never uses it; the worker image has no torchvision
        stub = types.ModuleType("torchvision")
        stub.models = types.ModuleType("torchvision.models")
        sys.modules.update({"torchvision": stub, "torchvision.models": stub.models})
        from network_fbcnn import FBCNN                       # the repository's own definition
        net = FBCNN(in_nc=3, out_nc=3, nc=[64, 128, 256, 512], nb=4, act_mode="R", downsample_mode="strideconv", upsample_mode="convtranspose")
        net.load_state_dict(torch.load(f"{MODELS}/fbcnn_color.pth", map_location="cpu", weights_only=True), strict=True)
        _net = net.eval().to(device)
    return _net


@torch.no_grad()
def fbcnn(x: torch.Tensor, qf: float | None = None, tile: int = 1024, overlap: int = 64) -> torch.Tensor:
    """x: [1,3,H,W] in 0..1. Tiles are blended with a linear ramp over the overlap; qf None uses the median predicted one."""
    net = load(x.device)
    _, _, h, w = x.shape
    ys = list(range(0, max(h - overlap, 1), tile - overlap))
    xs = list(range(0, max(w - overlap, 1), tile - overlap))
    boxes = [(y, min(y + tile, h), xx, min(xx + tile, w)) for y in ys for xx in xs]
    if qf is None:
        predicted = []
        for (y0, y1, x0, x1) in boxes:
            _, q = net(x[:, :, y0:y1, x0:x1])
            predicted.append(float(q.flatten()[0]))
        qf_in = torch.tensor([[sorted(predicted)[len(predicted) // 2]]], device=x.device)
    else:
        qf_in = torch.tensor([[qf / 100.0]], device=x.device)
    out = torch.zeros_like(x)
    weight = torch.zeros_like(x[:, :1])
    for (y0, y1, x0, x1) in boxes:
        piece, _ = net(x[:, :, y0:y1, x0:x1], qf_in)
        piece = piece[:, :, :y1 - y0, :x1 - x0]
        ramp_y = torch.ones(y1 - y0, device=x.device)
        ramp_x = torch.ones(x1 - x0, device=x.device)
        n = overlap
        if y0 > 0:
            ramp_y[:n] = torch.linspace(0.01, 1, n, device=x.device)
        if y1 < h:
            ramp_y[-n:] = torch.minimum(ramp_y[-n:], torch.linspace(1, 0.01, n, device=x.device))
        if x0 > 0:
            ramp_x[:n] = torch.linspace(0.01, 1, n, device=x.device)
        if x1 < w:
            ramp_x[-n:] = torch.minimum(ramp_x[-n:], torch.linspace(1, 0.01, n, device=x.device))
        wgt = (ramp_y[:, None] * ramp_x[None, :])[None, None]
        out[:, :, y0:y1, x0:x1] += piece * wgt
        weight[:, :, y0:y1, x0:x1] += wgt
    return out / weight


def gate_delta(x: torch.Tensor, y: torch.Tensor, limit_codes: float = 6.0) -> torch.Tensor:
    """x: input, y: the network's output. Keep its change (at most limit_codes) only where x is a plateau area (plateau_masks) or
    quiet: local mid-band energy under 1.5 codes (full pass) to 3 codes (none). Textured areas are left as they were."""
    plateau = C.plateau_masks(x, max_range=12.0, thin_limit=99.0)["mask"]
    luma = C._luma(x) * 255.0
    s = x.shape[-2] / 2160.0
    energy = C.blur((luma - C.blur(luma, 1.5 * s + 0.5)) ** 2, 4.0 * s + 1.0).sqrt()
    quiet = 1.0 - C._smoothstep(energy, 1.5, 3.0)
    mask = torch.maximum(plateau, quiet)
    delta = ((y - x) * 255.0).clamp(-limit_codes, limit_codes) / 255.0
    return x + mask * delta
