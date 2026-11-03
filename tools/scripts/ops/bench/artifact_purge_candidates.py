"""Candidate stages that purge OBVIOUS compression artifacts without touching real detail (experiment, not wired in).

Every function takes and returns a float [N,3,H,W] picture in 0..1 (plain torch, CPU or GPU, no custom kernels), in the
style of restore_worker/finish.py. Every one of them is built so that, when in doubt, the pixel is left alone:

  plateau_purge   banding / posterised contour patches. A pixel is touched only inside a wide staircase: the area around it
                  is made of long plateaus (equal to the neighbours, so grain, texture and noise break the test), spans at most
                  a few grey levels, and contains no thin line. There it is replaced by a wide Gaussian average, which turns
                  the steps into a ramp that the later dither/grain stages quantise without bands. Constant areas stay exactly
                  as they are. An optional reference (the source) must be a plateau at the same place too.
  deblock_gated   blocking. The 8/16/32/64 px grid and its phase are DETECTED from the picture (mean step on the grid over
                  the mean step off it, as client-tools/probe_media.py does); with no grid above BLOCK_RATIO_MIN nothing is
                  done. On a detected grid only boundaries with a small step between two flat sides are smoothed.
  ring_suppress   mosquito noise next to strong edges: bilateral average, small threshold, only in a band around strong
                  edges and only where the area is not textured.
  deband_reference  a verbatim copy of the existing finish.deband (for comparison).

Used by artifact_purge_experiment.py, which holds the measurements. The code is meant to be moved into finish.py as is
if the experiment says to ship it.

Author: Lorenzo Albanese (alblor)
"""
from __future__ import annotations

import math

import torch
import torch.nn.functional as F

CODE = 255.0     # one grey level of an 8-bit picture, in units of full scale: values below work in codes (0..255) internally


# ---- small helpers (same behaviour as finish.py's) -------------------------------------------------------------------

def _gauss_kernel(sigma: float, device, dtype) -> torch.Tensor:
    radius = max(1, math.ceil(3 * sigma))
    x = torch.arange(-radius, radius + 1, device=device, dtype=dtype)
    k = torch.exp(-0.5 * (x / sigma) ** 2)
    return k / k.sum()


def blur(x: torch.Tensor, sigma: float) -> torch.Tensor:
    """Separable Gaussian blur of [N,C,H,W] with reflected edges."""
    if sigma <= 0:
        return x
    k = _gauss_kernel(sigma, x.device, x.dtype)
    r = (len(k) - 1) // 2
    c = x.shape[1]
    kh = k.view(1, 1, 1, -1).expand(c, 1, 1, -1)
    kv = k.view(1, 1, -1, 1).expand(c, 1, -1, 1)
    x = F.conv2d(F.pad(x, (r, r, 0, 0), mode="reflect" if r < x.shape[-1] else "replicate"), kh, groups=c)
    return F.conv2d(F.pad(x, (0, 0, r, r), mode="reflect" if r < x.shape[-2] else "replicate"), kv, groups=c)


def _luma(x: torch.Tensor) -> torch.Tensor:
    return 0.2126 * x[:, 0:1] + 0.7152 * x[:, 1:2] + 0.0722 * x[:, 2:3]


def _box(x: torch.Tensor, k: int) -> torch.Tensor:
    """Mean over a k x k window, edge-normalised (the picture border does not pull the mean down)."""
    return F.avg_pool2d(x, k, stride=1, padding=k // 2, count_include_pad=False)


def _max_sep(x: torch.Tensor, k: int) -> torch.Tensor:
    """Maximum over a k x k window as two 1-D passes (identical result, far cheaper for a large k)."""
    x = F.max_pool2d(x, (1, k), stride=1, padding=(0, k // 2))
    return F.max_pool2d(x, (k, 1), stride=1, padding=(k // 2, 0))


def _min_sep(x: torch.Tensor, k: int) -> torch.Tensor:
    return -_max_sep(-x, k)


def _smoothstep(v: torch.Tensor, lo: float, hi: float) -> torch.Tensor:
    t = ((v - lo) / (hi - lo)).clamp(0, 1)
    return t * t * (3 - 2 * t)


def _shift(x: torch.Tensor, dx: int, dy: int) -> torch.Tensor:
    h, w = x.shape[-2:]
    pad = (max(dx, 0), max(-dx, 0), max(dy, 0), max(-dy, 0))
    padded = F.pad(x, pad, mode="replicate")
    top, left = max(-dy, 0), max(-dx, 0)
    return padded[..., top:top + h, left:left + w]


# ---- the existing stage, for comparison (verbatim from restore_worker/finish.py) ------------------------------------------

DEBAND_LEVELS = {
    "light": dict(threshold=3 / 255, radius=16, iterations=2, taps=6),
    "medium": dict(threshold=5 / 255, radius=24, iterations=3, taps=6),
    "strong": dict(threshold=8 / 255, radius=32, iterations=4, taps=6),
}


def deband_reference(x: torch.Tensor, level: str, generator: torch.Generator) -> torch.Tensor:
    if level == "off":
        return x
    cfg = DEBAND_LEVELS[level]
    for iteration in range(cfg["iterations"]):
        radius = cfg["radius"] * (iteration + 1) / cfg["iterations"]
        rotation = float(torch.rand(1, generator=generator, device=generator.device)) * 2 * math.pi
        acc, count = x.clone(), torch.ones_like(x[:, :1])
        for tap in range(cfg["taps"]):
            angle = rotation + tap * 2 * math.pi / cfg["taps"]
            sample = _shift(x, round(radius * math.cos(angle)), round(radius * math.sin(angle)))
            close = ((sample - x).abs().amax(dim=1, keepdim=True) < cfg["threshold"]).to(x.dtype)
            acc += sample * close
            count += close
        x = acc / count
    return x


# ---- banding: plateau-guided purge -----------------------------------------------------------------------------------------

def plateau_masks(x: torch.Tensor, ref: torch.Tensor | None = None, *, flat_tol: float = 0.45, density_lo: float = 0.35,
                  density_hi: float = 0.6, max_range: float = 4.0, sigma: float = 6.0, thin_limit: float = 2.5, **_unused) -> dict:
    """Where plateau_purge is allowed to act, as a soft 0..1 mask [N,3,H,W] (one per colour channel: the steps of the three
    channels fall in different places), plus the intermediate maps (for the sheets).

    Sizes are given for a 2160-line picture and scale with the height. Everything is per channel:
      flat      a pixel within flat_tol codes of all four neighbours (a plateau interior)
      density   share of flat pixels in a 17 px window: high inside a staircase, low in grain, texture and noise
      range     largest minus smallest value in the window the blur reads from (3 sigma): at most max_range codes, so the
                blur can never read across a real edge
      thin      a line or speck narrower than 7 px (found by opening/closing): left alone, a staircase contour is not one
    """
    n, c, h, w = x.shape
    s = h / 2160.0
    sig = max(1.5, sigma * s)
    r_density = max(2, round(1.33 * sig))
    r_blur = math.ceil(3 * sig)
    code = x * CODE

    def flat_of(img):
        ok = torch.ones_like(img, dtype=torch.bool)
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            ok &= ((img - _shift(img, dx, dy)).abs() <= flat_tol)
        return ok.to(x.dtype)

    flat = flat_of(code)
    density = _box(flat, 2 * r_density + 1)
    rng = _max_sep(code, 2 * r_blur + 1) - _min_sep(code, 2 * r_blur + 1)
    k_thin = max(3, 2 * round(3.5 * s) + 1)
    opened = _max_sep(_min_sep(code, k_thin), k_thin)
    closed = _min_sep(_max_sep(code, k_thin), k_thin)
    thin = torch.maximum((code - opened).abs(), (closed - code).abs())
    thin_zone = _max_sep((thin > thin_limit).to(x.dtype), k_thin)          # also the pixels beside a line
    mask = _smoothstep(density, density_lo, density_hi) * (rng <= max_range).to(x.dtype) * (1.0 - thin_zone)
    if ref is not None:
        mask = mask * _smoothstep(_box(flat_of(ref * CODE), 2 * r_density + 1), density_lo, density_hi)
    # Pull the mask in by a few pixels and soften it: the border of an allowed area never reaches a pixel whose blur window
    # could include a neighbouring edge.
    erode = max(1, round(2 * 3 * s))
    mask = 1.0 - _max_sep(1.0 - mask, 2 * erode + 1)
    mask = blur(mask, max(1.0, 3 * s)).clamp(0, 1)
    return dict(mask=mask, flat=flat, density=density, range=rng, thin=thin, sigma=sig)


PLATEAU_SCALES = ((3.0, 6.0), (6.0, 6.0), (12.0, 4.0))     # (sigma in px at 2160p, largest range in codes inside the 3-sigma window)


def plateau_purge(x: torch.Tensor, ref: torch.Tensor | None = None, *, strength: float = 1.0,
                  scales: tuple = PLATEAU_SCALES, **kwargs) -> torch.Tensor:
    """Smooth posterised staircases and nothing else. x, ref: float [N,3,H,W] in 0..1 (ref optional, same size).

    Three scales, finest first, each with its own allowed area: a pixel takes the Gaussian average of the widest scale whose
    whole window is plateau-like and at most a few codes tall (a shallow gradient with 40 px plateaus gets sigma 12, a steep one
    with 10 px plateaus gets sigma 3). Inside an allowed area no pixel moves by more than the area's range, and elsewhere it
    does not move at all. Output is not quantised: the dither and grain that follow turn the ramp into 10-bit steps."""
    code = x * CODE
    out = code
    for sigma, max_range in scales:
        m = plateau_masks(x, ref, sigma=sigma, max_range=max_range, **kwargs)
        out = out + strength * m["mask"] * (blur(code, m["sigma"]) - out)
    return out / CODE


# ---- blocking: grid-gated deblocking ----------------------------------------------------------------------------------------

BLOCK_SIZES = (8, 16, 32, 64)
BLOCK_RATIO_MIN = 1.12       # probe_media.py calls above 1.15 "visible blocking"; a little below that is where a grid is found


def _grid_profile(step: torch.Tensor, axis_len: int) -> tuple[int, int, float]:
    """step: mean absolute step at every boundary j (between sample j and j+1), 1-D. Best (block size, phase, ratio)."""
    best = (0, 0, 1.0)
    idx = torch.arange(step.numel(), device=step.device)
    for size in BLOCK_SIZES:
        if axis_len < 4 * size:
            continue
        for phase in range(size):
            on = (idx % size) == phase
            ratio = float(step[on].mean() / step[~on].mean().clamp_min(1e-6))
            if ratio > best[2] * 1.03 or (ratio > best[2] and size == best[0]):
                best = (size, phase, ratio)
    return best


def detect_grid(x: torch.Tensor) -> dict:
    """Block grid of a picture [1,3,H,W]: {'x': (size, phase, ratio), 'y': ...}. Ratio 1.0 means no grid."""
    y = _luma(x)[0, 0] * CODE
    cols = (y[:, 1:] - y[:, :-1]).abs().mean(dim=0)
    rows = (y[1:, :] - y[:-1, :]).abs().mean(dim=1)
    return {"x": _grid_profile(cols, y.shape[1]), "y": _grid_profile(rows, y.shape[0])}


def _deblock_axis(code: torch.Tensor, size: int, phase: int, max_step: float, side_ratio: float, strength: float) -> torch.Tensor:
    """code: [N,3,H,W] in codes; deblock the vertical boundaries between columns (phase + k*size) and +1. Callers transpose for rows."""
    w = code.shape[-1]
    out = code.clone()
    left_cols = torch.arange(phase, w - 1, size, device=code.device)
    left_cols = left_cols[(left_cols >= 2) & (left_cols <= w - 4)]
    if left_cols.numel() == 0:
        return out
    p0, p1, p2 = code[..., left_cols], code[..., left_cols - 1], code[..., left_cols - 2]
    q0, q1, q2 = code[..., left_cols + 1], code[..., left_cols + 2], code[..., left_cols + 3]
    step = q0 - p0
    mag = step.abs()
    side = torch.maximum((p0 - p1).abs(), (q1 - q0).abs())
    side2 = torch.maximum((p1 - p2).abs(), (q2 - q1).abs())
    # a boundary is blocking when the step is small but real (more than the side activity, less than an edge) and both
    # sides are flat; all three colour channels must agree, so a colour edge is never mistaken for a block edge
    ok = (mag > 0) & (mag <= max_step) & (side <= side_ratio * mag + 0.5) & (side2 <= side_ratio * mag + 0.5)
    ok = ok.all(dim=1, keepdim=True).to(code.dtype)
    half = 0.5 * step * ok * strength
    for dist, weight in enumerate((1.0, 2 / 3, 1 / 3)):
        out[..., left_cols - dist] += half * weight
        out[..., left_cols + 1 + dist] -= half * weight
    return out


def deblock_gated(x: torch.Tensor, *, max_step: float = 6.0, side_ratio: float = 0.5, strength: float = 1.0,
                  ratio_min: float = BLOCK_RATIO_MIN) -> torch.Tensor:
    """Deblock only on a detected grid, only at small steps between flat sides. x: [N,3,H,W] in 0..1. Frames are done one by one."""
    outs = []
    for i in range(len(x)):
        grid = detect_grid(x[i:i + 1])
        code = x[i:i + 1] * CODE
        size, phase, ratio = grid["x"]
        if size and ratio >= ratio_min:
            code = _deblock_axis(code, size, phase, max_step, side_ratio, strength)
        size, phase, ratio = grid["y"]
        if size and ratio >= ratio_min:
            code = _deblock_axis(code.transpose(-1, -2), size, phase, max_step, side_ratio, strength).transpose(-1, -2)
        outs.append(code / CODE)
    return torch.cat(outs)


# ---- ringing: bilateral average around strong edges only ---------------------------------------------------------------------

def ring_suppress(x: torch.Tensor, *, edge_level: float = 24.0, band: int = 6, threshold: float = 5.0, radius: int = 3,
                  taps: int = 8, texture_limit: float = 6.0) -> torch.Tensor:
    """Average each pixel with neighbours within `threshold` codes, only in a band of `band` px around strong edges (gradient
    over edge_level codes per px at 2160p) and only where the local mid-band energy is below texture_limit codes."""
    n, c, h, w = x.shape
    s = h / 2160.0
    code = x * CODE
    luma = _luma(code)
    g = blur(luma, max(0.8, s))
    gx = (_shift(g, -1, 0) - _shift(g, 1, 0)) * 0.5
    gy = (_shift(g, 0, -1) - _shift(g, 0, 1)) * 0.5
    strong = (torch.hypot(gx, gy) > edge_level).to(x.dtype)
    near_edge = _max_sep(strong, 2 * max(1, round(band * s)) + 1)
    on_edge = _max_sep(strong, 3)
    zone = near_edge * (1.0 - on_edge)
    band_energy = blur((luma - blur(luma, 1.5 * s + 0.5)) ** 2, 2.0 * s + 1.0).sqrt()
    zone = zone * (band_energy < texture_limit).to(x.dtype)
    acc, count = code.clone(), torch.ones_like(code[:, :1])
    rad = max(1, round(radius * max(s, 0.5)))
    for tap in range(taps):
        angle = tap * 2 * math.pi / taps
        sample = _shift(code, round(rad * math.cos(angle)), round(rad * math.sin(angle)))
        close = ((sample - code).abs().amax(dim=1, keepdim=True) < threshold).to(x.dtype)
        acc += sample * close
        count += close
    return (code + blur(zone, 1.0) * (acc / count - code)) / CODE
