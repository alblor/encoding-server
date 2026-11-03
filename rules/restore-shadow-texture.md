# Shadow texture: why the encoder flattened the dark parts, and the recipe that fixes it (FEATURE-095)

The owner, after watching the drafts: "textures from the original are flattened, lack dynamic range; keep the warm cinematic blur, not flat". I measured instead of guessing, and the culprit was not where I expected. Code: `restore_core/recipe.py` (constant `SHADOW_TEXTURE`, applied to the presets `cleanup-4k` and `film-restoration`). Status `review`, waiting for the ISSUE-059 re-check.

## What was measured (2026-10-31, late night)

Shot 0:52 to 0:54 of the draft, frames 1248 to 1296 (24 frames), restored with the real engine. A "flat plateau" is a pixel equal to its 4 neighbours; "dark" is source luma under 25/255, which is 80.7% of that picture.

| Stage | Dark pixels in plateaus | Fine-band RMS |
|---|---|---|
| source | 62.1% | n/a |
| restored, before the AV1 encode | 0.9% | 1.153 |
| after the default encode | 34.1% | 0.877 |

So the model and the finishing stage kept the texture; the ENCODER flattened it. Two recipe settings sit in that path and the variants below test them: the grain faded to 12% at black (`shadow_weight` 0.12), and the deband smoothed faint texture.

## Variants tried (plateau % after encode / MB for the 24 frames)

| Variant | Plateau % | MB |
|---|---|---|
| current default | 34.1 | 2.15 |
| deband off | 22.4 | 2.46 |
| shadow_weight 0.5 | 9.8 | 3.23 |
| shadow_weight 0.5 + strength 0.6 | 5.5 | 6.12 |
| ac-bias 1.0 + qm | 19.4 | 2.49 |
| variance-boost-strength 4 | 31.3 | 2.69 |
| crf 18 | 22.9 | 3.70 |
| deband off + shadow 0.35 + ac-bias 1 + qm | 8.9 | 3.23 |
| shadow 0.5 | 6.2 | 3.61 |
| ac-bias 2 | 8.6 | 3.32 |
| crf 22 | 8.2 | 3.66 |
| deband off + ac-bias/qm only | 14.1 | 2.72 |

## Chosen

`bitdepth.deband` off, `grain.shadow_weight` 0.35 (new field, default stays 0.12), `encode.ac_bias` 1.0 and `encode.quant_matrices` true (new fields, defaults 0 and false), set in `cleanup-4k` and `film-restoration`. Whole draft, v7 against v6: dark-pixel plateaus 83.6% to 33.2% (source 76.9%), fine-band RMS 0.89 to 0.96, file 99.6 MB to 171 MB (+72%; a very dark film, about 17 Mb/s on average). That size is the price: the owner can trade texture for bits with `shadow_weight` or `ac_bias`. His call after watching v7.

## SVT-AV1 4.2 parameters (checked 2026-10-31)

Valid: `ac-bias`, `enable-qm`, `qm-min`, `variance-boost-strength`, `luminance-qp-bias`, `sharpness`, `tf-strength`, `enable-restoration`. Invalid: `variance-boost-octile`, `noise-norm-strength`, `psy-rd`, `spy-rd`. Gotcha: ffmpeg accepts unknown `-svtav1-params` names SILENTLY unless you run with `-v warning`, so a typo looks like a working encode. Always check the log.

## Known limit, not changed (IDEA-096)

The pipeline decodes the source to 8-bit RGB (rgb24) and the model outputs 8-bit, so the 10-bit shadow precision of a 10-bit source is lost at the model stage, before any finishing. Banding is handled downstream (float, deband where it is on, grain); a 10-bit path through the model is a research item (INQUIRY-050).
