# Finishing stage: bit depth, grain and HDR (what was built, what was measured)

The restoration engine returns 8-bit pictures. Everything after it (`restore_worker/finish.py`, `hdr.py`) exists so the 10-bit AV1 the owner watches does not band, does not look plastic and, when asked, is HDR10. Numbers are MEASURED on 2026-10-30 on the owner's very dark draft unless marked otherwise. Code: `restore_worker/finish.py`, `restore_worker/hdr.py`, `restore_core/ffmpeg_cmds.py`.

## Order of the float stage

The fidelity steps `soften` (MIN-056) and `anchor` (ISSUE-069) work on the restored picture against the source before the steps below; their exact order is in `restore_worker/finish.py`, the reasons in `polishing-log.md` items 4 and 6; the later stages (adaptive softening, tone, chroma anchor, grain from the source, face guard) are in `restore-finishing-features.md` and `restore-face-guard.md`. Then: hdr (optional) -> deband -> grain (only when baked) -> triangular dither of one 10-bit step -> quantise once to 16-bit -> encoder. 8 bits stored in a 10-bit box would still show only 256 steps, so the pictures are lifted to float first, banding is smoothed by averaging only neighbours that are close in value (edges and texture survive), and the dither hides the last steps. Grain is seeded from (recipe seed, absolute frame index), so a run reproduces exactly and two workers never repeat a pattern.

The owner's concerns on 2026-10-30: restored frames are 8-bit (banding in 10-bit and HDR), a diffusion-like 8-to-10-bit model might help, and for 10-bit sources their own precision could be re-applied on the final film. The first is handled by this stage, the other two are INQUIRY-050 and MIN-051 (`bitdepth.anchor_source` exists in the recipe as `off | lowfreq`, NOT implemented).

## Dark scenes, grain and the AV1 encoder (finding of 2026-10-30)

Test: 10x shadow amplification, restored frame against its encodes.

- The finishing output (the truth) is smooth with fine grain.
- At CRF 18 to 24 the AV1 encode REMOVES low-amplitude baked grain and dither in dark flat areas and leaves blotchy blocky patches (no 64-px superblock border signature, step ratio 0.92 to 0.97).
- Baked grain at strength 1.0 survives only partly and costs a lot: 6.4 MB for 21 frames at CRF 20 with low-luma tuning (about 59 Mb/s), 1.06 MB at CRF 24.
- Extra low-luma tuning (variance-boost-curve 1, luminance-qp-bias 40) did not help and added patch artifacts.
- SVT-AV1 film-grain synthesis fed a CLEAN picture estimates almost nothing (levels 8 and 16 gave byte-identical files, as the research warned).
- Fed a GRAINED picture with `film-grain-denoise=1`, the encoder estimates the grain, encodes the clean picture and signals it: level 8 and level 25 re-create natural fine grain on decode (ffmpeg with dav1d), no blocky patches, 0.36 MB and 0.14 MB for 21 frames.
- The estimate is not monotonic in the level (level 15 with strength 0.6 came out near clean): the values need a look on real footage.

Decision implemented: `grain.mode` default `av1_fgs` (grain added in the finishing stage, the encoder denoises and signals it), strength 1.0, level 8, `fgs_denoise` true; `baked` stays as an explicit option for players that ignore AV1 film grain. UNVERIFIED: whether the owner's TV or player applies AV1 film grain at all (INQUIRY-052). Hardware support for film-grain synthesis on TVs is unknown. SVT-AV1 4.x tune 3 is IQ (still images) and the encoder refuses it on video; the valid video tunes are 0 (default), 1, 2, 4, and the recipe and docs say so.

## HDR (FEATURE-007, static part)

`hdr: synthesize` is the standards-exact static mapping only: BT.1886 to linear light, SDR white at 203 nits (ITU-R BT.2408), BT.709 to BT.2020 (BT.2087 matrix), ST 2084 PQ; the HDR10 signalling to SVT-AV1 carries mastering display and content light of 203 nits. The tests anchor on ST 2084 values (100 nits 0.5081, 203 nits 0.5807, 1000 nits 0.7518) and on the round trip. The frames are tagged with `setparams` so the Matroska container carries the colour tags.

NOT done: the learned highlight and colour-volume expansion (HDRTVNet++ candidate, with the PQ check INQUIRY-015, since SDR holds nothing above its own white and a fixed mapping cannot invent it), `hdr: preserve` for PQ sources (removed from the schema on 2026-10-31, unsupported values are a 422), and a real-TV check of the HDR10 output (INQUIRY-053).

## Update 2026-10-31: the grain decision above was superseded

The owner found the `av1_fgs` grain "too distant from the original and very regular". AV1 film-grain synthesis rebuilds the grain from a small repeating template (32x32 blocks) and estimates it from the synthetic noise I gave it, which was single-scale Gaussian. The finishing stage now has a film-like model (two scales, mild skew, channel correlation 0.6, brightness weighting, new noise per frame), a `source` mode that carries the source's own grain over, and chunks sized by pixels. Defaults moved to baked, strength 0.4, size 1.0; `av1_fgs` stays as the cheap option (level 20, denoise on) and is described as regular. Measured bitrate on a bright segment, relative to no grain: av1_fgs fed the new grain x1.42, baked 0.35 x1.67, baked 0.5 x2.92, baked 0.8 x6.17. The whole story, with the tests and the softness measurements, is in `polishing-log.md`; the code (`restore_core/recipe.py`) is the authority for current defaults.
