# Restore stage: what was built and measured at 2160p (2026-10-30)

Everything below was MEASURED on 2026-10-30 on the owner's server (RTX 5080, 16 GB each), with the tiled ReCaVSR engine in `restore_worker/recavsr_tiled.py`, unless it says estimate. Earlier numbers (SparkVSR, the VAE, ReCaVSR at 1.62 Mpx) stay in `m3-benchmark.md` and `recavsr-evaluation.md`. This file feeds INQUIRY-017 (ETA gate) and FEATURE-006.

## The tiled engine

The reference script needs 27.5 GB for a full 4K frame, so the engine cuts each 2160p frame into six overlapping tiles of 1344x1152 (overlap 128x96, `restore_core/tiling.py`), keeps ONE compiled session alive and resets the recycled state per tile. That is also why the roughly 120 s of `torch.compile` is paid once per process and not once per segment.

- One RTX 5080, warm: 0.573 s/frame, peak 13.2 GiB. Of the engine time the DiT is 64% and decode plus composite 35%. The CPU side (prepare and composite) is about 23% of the wall time, a candidate to move to the GPU (IDEA-047).
- Determinism: two consecutive runs on the same engine are bit-identical (max difference 0), so the per-tile reset leaks no state between tiles or segments.
- Fidelity: one full-frame tile reproduces the reference CLI, 43.2 dB average between two lossy encodes. No visible seam where four tiles meet.

## Real footage, two GPUs, hardened containers

The owner's draft (79 s, native 3840x2160 10-bit AV1 SDR BT.709, 1.1 Mb/s, very dark) ran whole: 10 segments, 1,896 frames, two GPUs, hardened containers with no network and a read-only root filesystem. Wall time 15.5 min including the one-time compile.

| Per segment, warm, per GPU | s/frame |
|---|---|
| engine | 0.53 |
| decode | 0.05 |
| finish and encode | 0.22 |
| end to end (not overlapped) | 0.82 |

- Projection (ESTIMATE from those numbers) for a 172,800-frame film on two GPUs: about 19.7 h today; about 14 h if decode and encode overlap the GPU work (FEATURE-044, expected -30%, bounded by segment length in RAM). The earlier 12 to 14 h estimate assumed the engine alone.
- Output about 7.4 Mb/s with baked grain at CRF 24 (before the `av1_fgs` default, `restore-finish-grain-hdr.md`).
- Probe of the draft: class `uhd-damaged` (blockiness 1.17, detail 0.001 very soft, noise 0.12, 0.006 bits per pixel), preset `cleanup-4k`. First restored segment at 10x shadow amplification looked faithful at normal brightness, with slightly deeper blacks (the owner accepts that if it stays slight, with real contrast and the original untouched).

## Segment length is a memory limit

A segment lives in RAM at source size and restored size at once, so the recipe bounds it (`advanced.restore.segment_max_seconds`, 2 to 30; `cleanup-4k` uses 6 since 2026-10-31) and the API refuses what does not fit, using the envelope of `restore_core/budget.py`. Measured on the real GPU worker (cgroup anon, 2026-10-31): 2160p with recavsr 161 frames 16.5 GiB and 241 frames 24.3 GiB (0.0975 GiB per frame), and a 241-frame segment OOM-killed a 24g worker in a live run. CPU classical 640x360 to 2160p: 25/50/100 frames 5.7/7.4/10.2 GiB (ffmpeg 4.4 to 5.8 of it). Engine `none` at 2160p with the heavy chain: 16/40 frames 3.8/5.7 GiB (QC, laptop VM). The encoder alone takes 7 to 8 GiB. Envelope (an upper bound over these measurements, not a model): recavsr 4.5 output frames per frame + 1.5 GiB; classical 3.5 frames + 1 GiB + 0.55 GiB per output Mpx; `none` 5.0 frames + the same; outputs with a side above 16384 are refused; the GPU worker limit is 22g. QC run 6 (2026-10-31, late night) re-checked the envelope and it held within 3%. Overlapping decode and encode with the GPU work will need a bounded queue of segments, not a bigger one.

## FP8: two rounds (INQUIRY-038 closed, INQUIRY-061 adopted)

Round 1 (2026-10-30): torchao 0.16.0 per-tensor FP8 on the middle 26 blocks was transparent (48.4 dB against bf16, two bf16 runs differ by 51 dB) and freed 2.8 GiB of VRAM (13.2 to 10.4), but not faster: DiT 22.0 s against 21.1 s, 0.648 s per frame eager against 0.573 s compiled bf16. Rowwise FP8 fails on this Blackwell (`CUBLAS_STATUS_NOT_SUPPORTED`) and `torch.compile` hung on the quantized model (18 min and more).

Round 2 (2026-10-31, the owner verified the numbers): our own `fp8` mode in `restore_worker/quantize.py`, `Fp8Linear` with per-channel weights times per-token activations and a tensor-wise `_scaled_mm`; it needs `torch.compile`. The hang was torchao setting a global Inductor config, which the own mode avoids. Result against bf16 on the same clips: DiT 18.21 to 12.77 s (1.43x), 0.578 to 0.475 s per frame, VRAM 13.2 to 9.7 GiB, 46.83 dB (worst frame 45.9). The error grows along a segment and resets at each cut, so short segments help. Hardware ceiling is about 3x, so there is room. Bits: no single FP8 matmul exceeds about 5.3 effective bits (bf16 9.2), and three FP8 matmuls together reach 9.1 bits, which is break-even (the answer to the owner's 9-bit question). Gate (>= 1.25x, >= 45 dB) passed.

Recipe: `advanced.restore.precision` is now Optional (unset means whatever the worker runs; worker env `RESTORE_PRECISION`, default bf16), values `bf16 | fp8 | fp8_fast`; a worker running another precision fails the job. bf16 stays the default. NVFP4 is not offered (owner: overkill) and MXFP8 kernels are not built for this part. The end-to-end s/frame and the ETA of INQUIRY-017 were NOT re-measured with fp8. The kernel spike of INQUIRY-029 stays in `m3-benchmark.md`.

## Finishing stage costs added 2026-10-31 (night, GPU worker)

- Face detection about 0.08 s per frame (YuNet on the source, every 4th frame); `face_guard: zoom` about 0.7 s per frame once compiled, and the first compile about 190 s per worker process and per crop size (cached on disk after). Details: `restore-face-guard.md`.
- Grain from the source, measured on real grainy clips: the finished picture keeps about 60% of the source grain amplitude and the default AV1 encode removes about a third of that. Adaptive softening is luma only; `/v1/docs` puts it at a few percent of a second per 2160p frame on a GPU (the code description, not re-measured here). Look-and-feel table of the draft stretch: `restore-finishing-features.md`.
- Shadow texture (2026-10-31, late night): the AV1 encoder, not the model, flattened the dark parts (0.9% of dark pixels in flat plateaus before the encode, 34.1% after). The new defaults in `cleanup-4k` (deband off, `shadow_weight` 0.35, `ac_bias` 1.0, quant matrices) bring the whole draft from 83.6% to 33.2% (source 76.9%) and cost +72% file size (99.6 to 171 MB, about 17 Mb/s on a very dark film). Variants, SVT-AV1 parameter check: `restore-shadow-texture.md`.
- The end-to-end s/frame and the film ETA (INQUIRY-017) were NOT re-measured with fp8, the new finishing stages, the zoom guard (about 0.7 s per frame on the faces) or the larger bitrate; the 19.7 h projection above is the old one and is probably optimistic with zoom on (estimate, not measured).

## Known gaps

- Forced cuts in the middle of a shot have no pre-roll: the new stream restarts without history (ISSUE-048).
- Open-GOP sources (HEVC, x265 default) now fall back to a closed-GOP transcode cut in the client (BUG-068, MIN-049); MPEG-TS with an offset fails closed (MIN-071).
- Decode, restore and encode do not overlap yet (FEATURE-044).
- The model path is 8-bit: the source is decoded to rgb24 and the model outputs 8-bit, so the 10-bit shadow precision of a source is lost before the finishing stage (IDEA-096).
