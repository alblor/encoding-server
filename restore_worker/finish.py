"""Finishing stage: from the engine's 8-bit pictures to the 16-bit frames the 10-bit encoder takes.

The restoration model returns 8-bit RGB. Saving that straight as 10-bit only stores 256 steps in a
bigger box, and smooth areas (dusk skies, fog, dark walls) show bands, which an HDR stretch makes
worse. So the pictures are lifted to float here and treated in this order:

  soften   optional: bring the restored picture's mid-frequency detail back to the original's level (needs the source)
  hdr      optional SDR to HDR10 mapping (BT.2408 reference white, BT.2020 primaries, PQ): see hdr.py
  deband   smooth banding in flat gradients (average only neighbours that are close in value,
           so edges and texture survive), producing the in-between shades that 8 bits cannot hold
  grain    optional film grain written into the pixels, so it works on every player and has no repeating pattern:
           synthesised with a film-like model (grain.py's ideas below), or transferred from the source's own grain
  dither   a triangular dither of one 10-bit step before quantising, so gradients never step
  16-bit   quantise once, at the end

Runs on the GPU in production and on the CPU in the tests: plain torch, no custom kernels.
Grain is new for every frame and seeded from (recipe seed, absolute frame index), so a run can be
reproduced exactly and two workers cutting a film into segments never repeat a pattern.
"""
from __future__ import annotations

import math
from typing import Iterator

import numpy as np
import torch
import torch.nn.functional as F

from restore_core.recipe import EffectiveRecipe
from restore_worker.hdr import sdr_to_pq

# threshold is in units of full scale (3/255, 5/255, 8/255): neighbours further apart than this are edges.
DEBAND_LEVELS = {
    "light": dict(threshold=3 / 255, radius=16, iterations=2, taps=6),
    "medium": dict(threshold=5 / 255, radius=24, iterations=3, taps=6),
    "strong": dict(threshold=8 / 255, radius=32, iterations=4, taps=6),
}
GRAIN_SIGMA_AT_FULL_STRENGTH = 0.02      # of full scale: 5 grey levels in 8-bit terms at strength 1
TEN_BIT_STEP = 1.0 / 1023.0
PIXELS_PER_CHUNK = 12_000_000            # about 1.4 frames of 2160p: bounds the working memory of the stage


def _shift(x: torch.Tensor, dx: int, dy: int) -> torch.Tensor:
    """x moved by (dx, dy) pixels with replicated edges (a roll would wrap the picture around)."""
    h, w = x.shape[-2:]
    pad = (max(dx, 0), max(-dx, 0), max(dy, 0), max(-dy, 0))     # left, right, top, bottom
    padded = F.pad(x, pad, mode="replicate")
    top, left = max(-dy, 0), max(-dx, 0)
    return padded[..., top:top + h, left:left + w]


def deband(x: torch.Tensor, level: str, generator: torch.Generator) -> torch.Tensor:
    """x: float [N,3,H,W] in 0..1. Average each pixel with sampled neighbours that are within the threshold."""
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
    # Reflection needs the padding to be smaller than the picture: on a tiny or very narrow one the edge is repeated instead.
    x = F.conv2d(F.pad(x, (r, r, 0, 0), mode="reflect" if r < x.shape[-1] else "replicate"), kh, groups=c)
    return F.conv2d(F.pad(x, (0, 0, r, r), mode="reflect" if r < x.shape[-2] else "replicate"), kv, groups=c)


FINE_SIGMA, COARSE_SIGMA = 0.6, 1.5      # pixels at grain size 1: two scales, as in film (small crystals and dye clouds)
FINE_SHARE = 0.7
CLUMPING = 0.25                          # skew that makes the noise non-Gaussian, like clouds of dye
CHANNEL_CORRELATION = 0.6                # the three colour layers of film are partly correlated


def film_noise(shape: tuple[int, int, int, int], size: float, generator: torch.Generator, device) -> torch.Tensor:
    """Unit-variance, zero-mean film-like noise [N,3,H,W]: spatially correlated at two scales, mildly non-Gaussian,
    with partly correlated colour channels. White noise looks like video noise, a single scale looks like a pattern."""
    n, c, h, w = shape

    def field(channels: int) -> torch.Tensor:
        raw = torch.randn((n, channels, h, w), generator=generator, device=device)
        fine, coarse = blur(raw, FINE_SIGMA * size), blur(raw, COARSE_SIGMA * size)
        f = FINE_SHARE * fine / fine.std().clamp_min(1e-6) + (1 - FINE_SHARE) * coarse / coarse.std().clamp_min(1e-6)
        f = f / f.std().clamp_min(1e-6)
        f = f + CLUMPING * (f * f - 1.0)                 # skew: a few stronger clumps among many weak grains
        return (f - f.mean()) / f.std().clamp_min(1e-6)

    shared = field(1)
    own = field(c)
    rho = math.sqrt(CHANNEL_CORRELATION)             # each channel = rho * shared + the rest: pairwise correlation is rho squared
    out = rho * shared + math.sqrt(1 - rho * rho) * own
    return out / out.std().clamp_min(1e-6)


def grain_weight(luma: torch.Tensor, floor: float = 0.12) -> torch.Tensor:
    """How visible grain is at a brightness (0..1): strongest in the shadows and mid-tones where film grain is most
    visible, fading to the highlights and to pure black. A smooth curve, never a hard step."""
    raw = luma.clamp(0, 1).pow(0.6) * (1 - luma.clamp(0, 1)).pow(1.4)
    peak = (0.3 ** 0.6) * (0.7 ** 1.4)
    return (floor + (1.0 - floor) * raw / peak).clamp(max=1.0)


def add_grain(x: torch.Tensor, strength: float, size: float, generator: torch.Generator, shadow_weight: float = 0.12) -> torch.Tensor:
    """Synthesised film grain, brightness-weighted, new for every frame."""
    if strength <= 0:
        return x
    luma = 0.2126 * x[:, 0:1] + 0.7152 * x[:, 1:2] + 0.0722 * x[:, 2:3]
    noise = film_noise(tuple(x.shape), size, generator, x.device)
    return x + noise * grain_weight(luma, shadow_weight) * (GRAIN_SIGMA_AT_FULL_STRENGTH * strength)


# ---- softness matching: bring the restored picture's mid-frequency energy back to the original's level ----------------

SOFTEN_BINS = 16
SOFTEN_SAMPLES = 6
MASK_RATIO_LO, MASK_RATIO_HI = 1.0, 2.0      # local mid-band energy ratio (restored over source): the mask starts at equal energy and is full at double
AUTO_SOURCE_GRAIN_MIN = 1.2 / 255            # source noise (full-scale units) above which `auto` keeps the source's grain


def _luma(x: torch.Tensor) -> torch.Tensor:
    return 0.2126 * x[:, 0:1] + 0.7152 * x[:, 1:2] + 0.0722 * x[:, 2:3]


def _radius(h: int, w: int, device) -> torch.Tensor:
    """Normalised radial frequency of every rfft2 coefficient: 1.0 is Nyquist along an axis, sqrt(2) the corner."""
    fy = torch.fft.fftfreq(h, device=device).abs() * 2
    fx = torch.fft.rfftfreq(w, device=device) * 2
    return torch.hypot(fy[:, None], fx[None, :])


def radial_spectrum(y: torch.Tensor) -> torch.Tensor:
    """Power per radial frequency bin of a luma image [1,1,H,W], windowed so the picture edges do not leak."""
    h, w = y.shape[-2:]
    win = torch.hann_window(h, device=y.device)[:, None] * torch.hann_window(w, device=y.device)[None, :]
    f = torch.fft.rfft2((y[0, 0] - y.mean()) * win)
    power = f.real ** 2 + f.imag ** 2
    bins = (_radius(h, w, y.device) / math.sqrt(2) * SOFTEN_BINS).long().clamp(max=SOFTEN_BINS - 1)
    return torch.zeros(SOFTEN_BINS, device=y.device).scatter_add_(0, bins.flatten(), power.flatten())


def estimate_soften_gains(restored: torch.Tensor, source: torch.Tensor, amount: float) -> torch.Tensor:
    """Per-band gain (at most 1) that lowers the restored spectrum towards the source's wherever it is higher.
    restored, source: [N,3,H,W] sample frames. Bands where the restored picture is already softer are left at 1."""
    pr = torch.zeros(SOFTEN_BINS, device=restored.device)
    ps = torch.zeros_like(pr)
    for i in range(restored.shape[0]):
        pr += radial_spectrum(_luma(restored[i:i + 1]))
        ps += radial_spectrum(_luma(source[i:i + 1]))
    ratio = (ps / pr.clamp_min(1e-12)).clamp(0, 1)
    gains = ratio.pow(amount / 2)                        # power ratio to amplitude gain, scaled by how far to go
    kernel = torch.tensor([0.25, 0.5, 0.25], device=gains.device)
    smooth = F.conv1d(F.pad(gains[None, None], (1, 1), mode="replicate"), kernel[None, None])[0, 0]
    return torch.minimum(smooth, torch.ones_like(smooth))


def apply_radial_gain(x: torch.Tensor, gains: torch.Tensor) -> torch.Tensor:
    """Multiply the spectrum of every channel by an isotropic gain curve (linear between band centres)."""
    n, c, h, w = x.shape
    position = (_radius(h, w, x.device) / math.sqrt(2) * SOFTEN_BINS - 0.5).clamp(0, SOFTEN_BINS - 1)
    lo = position.floor().long().clamp(max=SOFTEN_BINS - 1)
    hi = (lo + 1).clamp(max=SOFTEN_BINS - 1)
    frac = position - lo.to(position.dtype)
    gain_map = gains[lo] * (1 - frac) + gains[hi] * frac
    return torch.fft.irfft2(torch.fft.rfft2(x) * gain_map, s=(h, w))


def soften_mask(restored: torch.Tensor, source: torch.Tensor) -> torch.Tensor:
    """Where the restored picture has clearly more mid-band local energy than the source: 0 (leave alone) to 1 (soften).
    The mid band is a difference of Gaussians (sigma 1 and 3, roughly 10 to 40 percent of Nyquist: where the model adds punch)."""
    def local_energy(img):
        y = _luma(img)
        band = blur(y, 1.0) - blur(y, 3.0)
        return blur(band * band, 8.0)
    ratio = local_energy(restored) / (local_energy(source) + 1e-8)
    return blur(((ratio - MASK_RATIO_LO) / (MASK_RATIO_HI - MASK_RATIO_LO)).clamp(0, 1), 6.0)


ANCHOR_CELL = 16        # pixels of the restored picture per cell of the coarse grid the levels are compared on


def anchor_low_frequency(restored: torch.Tensor, source: torch.Tensor, amount: float, chroma_amount: float | None = None) -> torch.Tensor:
    """Pull the coarse brightness and colour of `restored` towards `source`, leaving everything finer than a cell alone.

    Both pictures are averaged onto the same coarse grid (any source size works: the grid is set by the restored one), the
    difference is smoothed up to full size and added. The model drifts in brightness along a segment and restarts at every
    cut; the source has no such drift, so this removes the flicker at the seams without touching detail.
    `amount` applies to the brightness difference and `chroma_amount` (same as amount when None) to the colour that is left
    once brightness is taken out, so the model's colour can be kept while its brightness is pinned.
    restored: [N,3,H,W], source: [N,3,h,w], both float in 0..1."""
    chroma_amount = amount if chroma_amount is None else chroma_amount
    if amount <= 0 and chroma_amount <= 0:
        return restored
    h, w = restored.shape[-2:]
    grid = (max(1, round(h / ANCHOR_CELL)), max(1, round(w / ANCHOR_CELL)))
    delta = F.adaptive_avg_pool2d(source, grid) - F.adaptive_avg_pool2d(restored, grid)
    if chroma_amount != amount:
        weights = torch.tensor([0.2126, 0.7152, 0.0722], device=delta.device, dtype=delta.dtype).view(1, 3, 1, 1)
        brightness = (delta * weights).sum(dim=1, keepdim=True)          # a flat offset of all three channels carries all of it
        delta = amount * brightness + chroma_amount * (delta - brightness)
    else:
        delta = amount * delta
    return restored + F.interpolate(delta, size=(h, w), mode="bilinear", align_corners=False)


GLOW_GAMMA = 2.2                # display gamma that turns the pictures into linear light, where a bloom is an addition of light
GLOW_REFERENCE_HEIGHT = 2160    # `sigma` is given in pixels of a picture this tall
GLOW_HIGHLIGHT = 0.25           # linear luma above which a pixel counts as a light that can bloom
GLOW_GATE_SIGMAS = 4.0          # the gate looks this many widths around a light
GLOW_GATE_FULL = 0.02           # blurred excess of light that opens the gate completely
GLOW_MAX_STEP = 0.15            # linear light: the most that is added anywhere


def glow_match(restored: torch.Tensor, source: torch.Tensor, amount: float, sigma: float) -> torch.Tensor:
    """Give `restored` the original's bloom around bright lights back, and change nothing else.

    A model that sharpens a light also draws its halo tighter, which loses the soft look of the original (diffusion filter,
    halation, a lens bloom). In linear light the bloom is light added around the source: the difference of the two pictures
    blurred to `sigma` is exactly the bloom the model took away or moved, and it is smooth by construction, so adding it
    cannot alter anything narrower than `sigma`. Light is only ever added, never taken away (a light the model drew brighter or
    smaller than the source's is its own business, and subtracting there turns cores dark and tints them), and only near
    highlights of the source: a gate is closed away from a light, so the rest of the picture is left as it was. Each step is capped.
    `sigma` is in pixels of a 2160-line picture and scales with the height. restored, source: [N,3,H,W] in 0..1, same size."""
    if amount <= 0:
        return restored
    h = restored.shape[-2]
    width = sigma * h / GLOW_REFERENCE_HEIGHT
    lin_r, lin_s = restored.clamp(0, 1) ** GLOW_GAMMA, source.clamp(0, 1) ** GLOW_GAMMA
    difference = (blur(lin_s, width) - blur(lin_r, width)).clamp(0, GLOW_MAX_STEP)
    excess = (_luma(lin_s) - GLOW_HIGHLIGHT).clamp_min(0)
    gate = (blur(excess, GLOW_GATE_SIGMAS * width) / GLOW_GATE_FULL).clamp(0, 1)
    out = (lin_r + amount * gate * difference).clamp(0, 1) ** (1.0 / GLOW_GAMMA)
    return restored + (out - restored.clamp(0, 1))      # a value the model pushed past 0..1 stays as it was where nothing is added


PLATEAU_CODE = 255.0            # plateau_purge measures in grey levels of an 8-bit picture
PLATEAU_FLAT_TOL = 0.45         # a pixel within this many codes of its four neighbours is the inside of a plateau
PLATEAU_DENSITY = (0.35, 0.6)   # share of such pixels in a 17 px window that opens the gate (closed under, fully open over)
PLATEAU_THIN_LIMIT = 2.5        # codes: a line or speck that stands out by more than this is detail, not a staircase
# (sigma in pixels at 2160 lines, largest range in codes the blur may read across), finest first
PLATEAU_SCALES = ((3.0, 6.0), (6.0, 6.0), (12.0, 4.0))


def _box(x: torch.Tensor, k: int) -> torch.Tensor:
    """Mean over a k x k window; the picture border does not pull the mean down."""
    return F.avg_pool2d(x, k, stride=1, padding=k // 2, count_include_pad=False)


def _max_sep(x: torch.Tensor, k: int) -> torch.Tensor:
    """Maximum over a k x k window as two 1-D passes: the same result, far cheaper for a large k."""
    x = F.max_pool2d(x, (1, k), stride=1, padding=(0, k // 2))
    return F.max_pool2d(x, (k, 1), stride=1, padding=(k // 2, 0))


def _smoothstep(v: torch.Tensor, lo: float, hi: float) -> torch.Tensor:
    t = ((v - lo) / (hi - lo)).clamp(0, 1)
    return t * t * (3 - 2 * t)


def plateau_mask(x: torch.Tensor, sigma: float, max_range: float) -> tuple[torch.Tensor, float]:
    """Where plateau_purge may act at one scale: a soft 0..1 mask [N,3,H,W], one per colour channel (the steps of the three
    channels fall in different places), and the blur width in pixels. Everything is per channel:
      flat     a pixel within PLATEAU_FLAT_TOL codes of all four neighbours (the inside of a plateau)
      density  share of flat pixels in a 17 px window: high inside a staircase, low in grain, texture and noise
      range    largest minus smallest value in the window the blur reads from (3 sigma): at most `max_range` codes, so the
               blur can never read across a real edge
      thin     a line or speck narrower than 7 px, found by opening and closing: left alone, a contour is not one
    The mask is then pulled in by a few pixels and softened, so the border of an allowed area never reaches a pixel whose blur
    window could include a neighbouring edge."""
    scale = x.shape[-2] / GLOW_REFERENCE_HEIGHT
    width = max(1.5, sigma * scale)
    r_density, r_blur = max(2, round(1.33 * width)), math.ceil(3 * width)
    code = x * PLATEAU_CODE
    flat = torch.ones_like(code, dtype=torch.bool)
    for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
        flat &= (code - _shift(code, dx, dy)).abs() <= PLATEAU_FLAT_TOL
    density = _box(flat.to(x.dtype), 2 * r_density + 1)
    k_range = 2 * r_blur + 1
    spread = _max_sep(code, k_range) + _max_sep(-code, k_range)               # max minus min
    k_thin = max(3, 2 * round(3.5 * scale) + 1)
    opened = _max_sep(-_max_sep(-code, k_thin), k_thin)
    closed = -_max_sep(-_max_sep(code, k_thin), k_thin)
    thin = torch.maximum((code - opened).abs(), (closed - code).abs())
    near_thin = _max_sep((thin > PLATEAU_THIN_LIMIT).to(x.dtype), k_thin)     # also the pixels beside a line
    mask = _smoothstep(density, *PLATEAU_DENSITY) * (spread <= max_range).to(x.dtype) * (1.0 - near_thin)
    erode = max(1, round(6 * scale))
    mask = 1.0 - _max_sep(1.0 - mask, 2 * erode + 1)
    return blur(mask, max(1.0, 3 * scale)).clamp(0, 1), width


def plateau_purge(x: torch.Tensor, strength: float) -> torch.Tensor:
    """Smooth posterised staircases (banding, contour patches) and nothing else; x is a float [N,3,H,W] in 0..1.

    A pixel is touched only inside a wide staircase: the area around it is made of long plateaus (so grain, texture and noise
    break the test), spans at most a few grey levels and holds no thin line. There it takes a wide Gaussian average, which
    turns the steps into a ramp that the dither and the grain after it quantise without bands. Three scales, finest first,
    each with its own allowed area: a shallow gradient with 40 px plateaus gets sigma 12, a steep one with 10 px plateaus gets
    sigma 3. Elsewhere no pixel moves, so detail and everything flat are exactly as they were. The neighbouring `deband` averages
    anything within a threshold and flattens dark texture, which is why the presets keep it off and use this one."""
    if strength <= 0:
        return x
    out = x
    for sigma, max_range in PLATEAU_SCALES:
        mask, width = plateau_mask(x, sigma, max_range)
        out = out + strength * mask * (blur(x, width) - out)
    return out


TONE_MAX_SLOPE_LOSS = 0.15   # c * pivot and c * (1 - pivot) are held under this: the slopes at black and at white stay above 0.4, see tone_adjust
LOCAL_CONTRAST_SIGMA = 0.03     # of the picture height
LOCAL_CONTRAST_DOWNSCALE = 8    # the surroundings are averaged on a picture this much smaller


def tone_adjust(x: torch.Tensor, contrast: float, pivot: float, local_contrast: float, saturation: float) -> torch.Tensor:
    """Contrast curve, local contrast and saturation on a float [N,3,H,W] picture in 0..1.

    Everything works on brightness and scales the three channels together, so hue is kept. The global curve is
    y' = y + 4 c (y - pivot) y (1 - y): zero at black and white, slope above 1 around the pivot, so the darks sink and the
    lights rise without any clipping. Local contrast pushes each area away from a wide average of its surroundings,
    weighted by 4 y (1 - y) so that near black and white nothing changes."""
    if contrast <= 0 and local_contrast <= 0 and saturation == 1.0:
        return x
    y = _luma(x)
    if contrast > 0:
        # The slope at black is 1 - 4 c p and the slope at white is 1 - 4 c (1 - p): both must stay above zero, or the shadows
        # or the highlights flatten into a plateau. A low pivot (a dark scene) is the case that burns the highlights.
        contrast = min(contrast, TONE_MAX_SLOPE_LOSS / max(pivot, 1e-3), TONE_MAX_SLOPE_LOSS / max(1.0 - pivot, 1e-3))
        ratio = 1.0 + 4.0 * contrast * (y - pivot) * (1.0 - y)
        x, y = x * ratio, y * ratio
    if local_contrast > 0:
        h, w = y.shape[-2:]
        small = F.avg_pool2d(y, LOCAL_CONTRAST_DOWNSCALE, ceil_mode=True)
        base = F.interpolate(blur(small, LOCAL_CONTRAST_SIGMA * h / LOCAL_CONTRAST_DOWNSCALE), size=(h, w), mode="bilinear", align_corners=False)
        lifted = y + local_contrast * (y - base) * 4.0 * y.clamp(0, 1) * (1.0 - y.clamp(0, 1))
        x = x * (lifted / y.clamp_min(1e-3)).clamp(0.5, 2.0)
        y = lifted
    if saturation != 1.0:
        luma = _luma(x)
        x = luma + saturation * (x - luma)
    return x.clamp(0, 1)


ADAPTIVE_SIGMAS = (0.7, 1.4, 2.8, 5.6)      # four bands of luma: above 54, 27 to 54, 13 to 27 and 7 to 13 percent of Nyquist, about
ADAPTIVE_NOISE_FLOOR = 1.5 / 255            # source band amplitude below which the source counts as flat
ADAPTIVE_STATS_DOWNSCALE = 4                # local amplitudes are measured on a picture this much smaller


def _local_amplitude(band: torch.Tensor, sigma: float) -> torch.Tensor:
    """Local RMS amplitude of a luma band: the square averaged over a window of 4 sigma, measured on a reduced picture."""
    h, w = band.shape[-2:]
    small = F.avg_pool2d(band * band, ADAPTIVE_STATS_DOWNSCALE, ceil_mode=True)
    energy = blur(small, max(4.0 * sigma / ADAPTIVE_STATS_DOWNSCALE, 0.5))
    return F.interpolate(energy.clamp_min(0).sqrt(), size=(h, w), mode="bilinear", align_corners=False)


def soften_adaptive(restored: torch.Tensor, source: torch.Tensor, tolerance: float, keep: float, min_gain: float, amount: float) -> torch.Tensor:
    """Turn the model's detail down only where the source does not support it. Luma only: the same change is added to all
    three channels, so colour and saturation are left alone.

    Luma is split into four bands (differences of Gaussians). In each band the local amplitude of the restored picture is
    compared with the source's: where the model has more than `tolerance` times as much, the band is turned down so that it
    has `tolerance` times as much (never below `min_gain`). The tolerance grows up to double where the source itself has
    structure in that band, since there the model's detail is plausible and not invented. Bands where the model has less than
    the source, or about the same, are untouched, so nothing is ever added here.
    restored, source: [N,3,H,W] floats in 0..1 of the same size."""
    if amount <= 0:
        return restored
    yr, ys = _luma(restored), _luma(source)
    gr, gs = [yr], [ys]
    for sigma in ADAPTIVE_SIGMAS:
        gr.append(blur(yr, sigma))
        gs.append(blur(ys, sigma))
    delta = torch.zeros_like(yr)
    for k, sigma in enumerate(ADAPTIVE_SIGMAS):
        band_r, band_s = gr[k] - gr[k + 1], gs[k] - gs[k + 1]
        amp_r, amp_s = _local_amplitude(band_r, sigma), _local_amplitude(band_s, sigma)
        ratio = amp_r / (amp_s + ADAPTIVE_NOISE_FLOOR * 0.5)
        support = torch.clamp((amp_s / ADAPTIVE_NOISE_FLOOR - 1.0) / 3.0, 0.0, 1.0)      # 0 for a flat source, 1 from 4 floors up
        allowed = tolerance * (1.0 + keep * support)
        gain = (allowed / ratio.clamp_min(1e-6)).clamp(min_gain, 1.0)
        delta = delta + amount * (gain - 1.0) * band_r
    return restored + delta


FACE_FULL_BELOW = 0.04      # face height as a share of the picture height: the guard is at full strength under this ...
FACE_NONE_FROM = 0.15       # ... and gone from this size up
FACE_BOX_GROWTH = 1.5       # the blend covers the head and not just the detector's box
FACE_FEATHER = 0.35         # share of the box size over which the blend fades out


def face_guard_mask(boxes: np.ndarray, height: int, width: int, amount: float, device) -> torch.Tensor | None:
    """[1,1,H,W] blend weight, 0 outside faces and up to `amount` inside small ones, or None when there is nothing to blend.

    boxes: [n,4] or [n,5] (x, y, w, h and optionally the temporal weight 0..1). Each face gets an ellipse that fades out smoothly; its strength depends on its size relative
    to the picture, so a distant face is blended back fully and a close-up not at all."""
    mask = None
    yy = torch.arange(height, device=device, dtype=torch.float32).view(-1, 1)
    xx = torch.arange(width, device=device, dtype=torch.float32).view(1, -1)
    for box in boxes:
        x, y, w, h = box[:4]
        share = float(h) / height
        strength = amount * min(1.0, max(0.0, (FACE_NONE_FROM - share) / (FACE_NONE_FROM - FACE_FULL_BELOW)))
        if len(box) > 4:
            strength *= float(box[4])                    # the temporal weight of the track: eased in before the face is trusted
        if strength <= 0:
            continue
        cx, cy = x + w / 2, y + h / 2
        rx, ry = max(w * FACE_BOX_GROWTH / 2, 1.0), max(h * FACE_BOX_GROWTH / 2, 1.0)
        d = (((xx - cx) / rx) ** 2 + ((yy - cy) / ry) ** 2).sqrt()                    # 1 at the ellipse edge
        fade = ((1.0 - d) / FACE_FEATHER).clamp(0.0, 1.0)
        fade = fade * fade * (3.0 - 2.0 * fade)                                       # smoothstep
        part = (strength * fade)[None, None]
        mask = part if mask is None else torch.maximum(mask, part)
    return mask


def estimate_noise(y: torch.Tensor) -> float:
    """Immerkaer's fast noise estimate on a luma image [1,1,H,W], in full-scale units."""
    v = y[0, 0]
    k = (v[:-2, :-2] - 2 * v[:-2, 1:-1] + v[:-2, 2:] - 2 * v[1:-1, :-2] + 4 * v[1:-1, 1:-1]
         - 2 * v[1:-1, 2:] + v[2:, :-2] - 2 * v[2:, 1:-1] + v[2:, 2:])
    return float(math.sqrt(math.pi / 2) / 6 * k.abs().mean())


SOURCE_GRAIN_SIGMA = 2.0         # the source's own picture is estimated by blurring at this scale: wide enough that the
                                 # coarse part of the grain stays in the residual instead of being taken for picture
SOURCE_GRAIN_FLAT = 0.02         # local contrast (of full scale) above which a region counts as detail, not grain


def transfer_source_grain(restored: torch.Tensor, source: torch.Tensor, strength: float) -> torch.Tensor:
    """Carry the source's real grain over to the restored picture: the residual between the source and a blurred copy
    of it, kept only where the source is flat (so edges and detail are not copied), added to the restored frame.
    Because it is the film's own noise it is irregular and matches the original; where the source had none, nothing is added."""
    if strength <= 0:
        return restored
    upscaled = source.shape[-2:] != restored.shape[-2:]
    smooth = blur(source, SOURCE_GRAIN_SIGMA)
    residual = source - smooth
    # Detail mask from the local contrast of the smoothed source: grain lives in flat areas.
    gy = (smooth[:, :, 1:, :] - smooth[:, :, :-1, :]).abs()
    gx = (smooth[:, :, :, 1:] - smooth[:, :, :, :-1]).abs()
    contrast = F.pad(gy, (0, 0, 0, 1), mode="replicate") + F.pad(gx, (0, 1, 0, 0), mode="replicate")
    radius = math.ceil(3 * SOURCE_GRAIN_SIGMA)
    near_detail = F.max_pool2d(contrast.amax(dim=1, keepdim=True), kernel_size=2 * radius + 1, stride=1, padding=radius)
    # The blur residual of an edge reaches about 3 sigma from it, so the detail test looks that far around each pixel.
    mask = torch.exp(-((near_detail / SOURCE_GRAIN_FLAT) ** 2))
    grain = mask * residual
    if upscaled:        # the film's grain was sampled at the source's size: it grows with the picture, bicubically, nothing else changes
        grain = F.interpolate(grain, size=restored.shape[-2:], mode="bicubic", align_corners=False)
    return restored + strength * grain


def dither(x: torch.Tensor, generator: torch.Generator) -> torch.Tensor:
    """Triangular dither of one 10-bit step: removes stepping when the 16-bit value is reduced to 10 bits."""
    a = torch.rand(x.shape[:1] + (1,) + x.shape[2:], generator=generator, device=x.device)
    b = torch.rand(a.shape, generator=generator, device=x.device)
    return x + (a + b - 1.0) * TEN_BIT_STEP


class Finisher:
    def __init__(self, recipe: EffectiveRecipe, device: str | torch.device = "cpu", chunk: int = 4) -> None:
        self.recipe = recipe
        self.device = torch.device(device)
        self.chunk = chunk

    def _generator(self, frame_index: int) -> torch.Generator:
        g = torch.Generator(device=self.device)
        g.manual_seed((self.recipe.advanced.restore.seed * 1_000_003 + frame_index) % (2**63 - 1))
        return g

    def _finish_frame(self, x: torch.Tensor, ref: torch.Tensor | None, frame_index: int, baked: bool, transfer: bool,
                      grain_strength: float, grain_size: float) -> torch.Tensor:
        adv = self.recipe.advanced
        g = self._generator(frame_index)
        x = deband(x, adv.bitdepth.deband, g)
        if self.recipe.basic.hdr == "synthesize":
            # After debanding (smoothing is done in the SDR domain) and before grain: grain belongs in the
            # signal that is encoded, and PQ code values are close to perceptually uniform.
            x = sdr_to_pq(x, adv.hdr.reference_white_nits)
        if transfer:
            x = transfer_source_grain(x, ref, adv.grain.source_strength)
        elif baked:
            x = add_grain(x, grain_strength, grain_size, g, adv.grain.shadow_weight)
        if adv.bitdepth.dither:
            x = dither(x, g)
        return x

    def process(self, frames: np.ndarray, first_frame_index: int = 0, reference: np.ndarray | None = None,
                faces: list | None = None, patches: dict | None = None) -> Iterator[np.ndarray]:
        """frames: (T,H,W,3) uint8. Yields (n,H,W,3) little-endian uint16 chunks in order.

        `reference` is the source at the same size, needed by grain mode `source` (otherwise the grain is synthesised)."""
        adv = self.recipe.advanced
        # Both modes put grain into the picture here. For av1_fgs the encoder then estimates the grain from this
        # picture, encodes the denoised version and signals the grain, so the decoder re-synthesises it: given a
        # clean picture it would estimate almost nothing, which a measured test on dark footage confirmed.
        # The grain builds several full-frame noise fields at once, and the restoration model is still resident in VRAM,
        # so the chunk is sized by pixels: one 2160p frame, four 1080p frames. (A fixed chunk of four ran out of memory.)
        chunk = max(1, min(self.chunk, int(PIXELS_PER_CHUNK // (frames.shape[1] * frames.shape[2]))))
        wanted = self.recipe.basic.grain == "auto"
        mode = adv.grain.mode if wanted else "none"
        have_reference = reference is not None and reference.shape == frames.shape      # same-size source available
        samples = np.unique(np.linspace(0, len(frames) - 1, min(SOFTEN_SAMPLES, len(frames))).round().astype(int))

        def sample(arr):
            return torch.from_numpy(np.ascontiguousarray(arr[samples])).to(self.device).permute(0, 3, 1, 2).float() / 255.0

        gains = None
        if adv.fidelity.soften == "match" and have_reference and adv.fidelity.soften_amount > 0:
            gains = estimate_soften_gains(sample(frames), sample(reference), adv.fidelity.soften_amount)   # once per segment
        grain_strength, grain_size = adv.grain.strength, adv.grain.size
        if mode in ("auto", "source") and reference is not None and len(reference) == len(frames):
            # Keep the original's grain when it has some; otherwise add film-like grain. Decided once per segment, from
            # the noise measured on the source. After an upscale the source's own grain is upscaled with the picture
            # (the fewest changes to it that are possible), see transfer_source_grain.
            ref_samples = sample(reference)
            noise = float(np.median([estimate_noise(_luma(ref_samples[i:i + 1])) for i in range(len(ref_samples))]))
            del ref_samples
            mode = "baked" if (mode == "auto" and noise < AUTO_SOURCE_GRAIN_MIN) else "source"
        elif mode in ("auto", "source"):
            mode = "baked"                       # no source to take grain from
        anchor = adv.fidelity.anchor == "source" and reference is not None and len(reference) == len(frames)
        tone_pivot = adv.tone.pivot
        if tone_pivot is None:
            # The scene's own median brightness, from the source when there is one (the restored picture's brightness is
            # tied to it by the anchor anyway), measured once per segment so that it cannot flicker within one.
            basis = sample(reference if reference is not None and len(reference) == len(frames) else frames)
            tone_pivot = float(min(max(_luma(basis).median(), 0.05), 0.7))
            del basis
        glow_amount = adv.fidelity.glow
        baked = mode in ("baked", "av1_fgs")
        transfer = mode == "source"
        for start in range(0, len(frames), chunk):
            block = frames[start:start + chunk]
            x = torch.from_numpy(np.ascontiguousarray(block)).to(self.device).permute(0, 3, 1, 2).float() / 255.0
            if adv.fidelity.soften == "adaptive" and have_reference:
                ref_soft = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                x = soften_adaptive(x, ref_soft, adv.fidelity.adaptive_tolerance, adv.fidelity.adaptive_keep,
                                    adv.fidelity.adaptive_min_gain, adv.fidelity.soften_amount)
                del ref_soft
            if gains is not None:
                ref_soft = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                softened = apply_radial_gain(x, gains)
                x = x + soften_mask(x, ref_soft) * (softened - x) if adv.fidelity.soften_mask else softened
            if anchor and reference is not None:
                ref_anchor = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                x = anchor_low_frequency(x, ref_anchor, adv.fidelity.anchor_amount, adv.fidelity.anchor_chroma_amount)
                del ref_anchor
            if glow_amount > 0 and have_reference:
                ref_glow = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                x = glow_match(x, ref_glow, glow_amount, adv.fidelity.glow_sigma)
                del ref_glow
            if patches and have_reference:
                # Faces redrawn by the model on a zoomed crop (face_zoom.py): pasted with the track's soft mask, after the
                # softening and the anchor so that neither pulls the redrawn face back towards the blurred original. The paste
                # is a mix of the redrawn face and the original's own pixels (face_zoom_mix), which keeps the subject natural.
                ref_patch = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                mix = adv.fidelity.face_zoom_mix
                for i in range(len(x)):
                    for px, py, patch, box in patches.get(start + i, ()):
                        mask = face_guard_mask(box[None], x.shape[-2], x.shape[-1], adv.fidelity.face_guard_amount, self.device)
                        if mask is None:
                            continue
                        side = patch.shape[0]
                        new = torch.from_numpy(np.ascontiguousarray(patch)).to(self.device).permute(2, 0, 1)[None].float() / 255.0
                        if mix < 1.0:
                            new = mix * new + (1.0 - mix) * ref_patch[i:i + 1, :, py:py + side, px:px + side]
                        region = x[i:i + 1, :, py:py + side, px:px + side]
                        x[i:i + 1, :, py:py + side, px:px + side] = region + mask[:, :, py:py + side, px:px + side] * (new - region)
                del ref_patch
            if faces is not None and have_reference:
                ref_faces = torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                for i in range(len(x)):
                    mask = face_guard_mask(faces[start + i], x.shape[-2], x.shape[-1], adv.fidelity.face_guard_amount, self.device)
                    if mask is not None:
                        x[i:i + 1] = x[i:i + 1] + mask * (ref_faces[i:i + 1] - x[i:i + 1])
                del ref_faces
            x = plateau_purge(x, adv.bitdepth.plateau_purge)    # after the anchor (its coarse offset must not re-imprint a staircase), before tone and grain
            x = tone_adjust(x, adv.tone.contrast, tone_pivot, adv.tone.local_contrast, adv.tone.saturation)
            ref = (torch.from_numpy(np.ascontiguousarray(reference[start:start + chunk])).to(self.device).permute(0, 3, 1, 2).float() / 255.0
                   if transfer else None)
            # Everything that draws random numbers runs one frame at a time with a generator seeded by that frame's
            # ABSOLUTE index, so a frame gets the same grain whatever the segmentation or the chunk size around it.
            x = torch.cat([self._finish_frame(x[i:i + 1], None if ref is None else ref[i:i + 1],
                                              first_frame_index + start + i, baked, transfer, grain_strength, grain_size)
                           for i in range(len(x))])
            out = (x.clamp(0, 1) * 65535.0 + 0.5).to(torch.int32).permute(0, 2, 3, 1).contiguous().cpu().numpy()
            yield out.astype("<u2")
