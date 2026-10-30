# M3 benchmark gate: what was actually measured (2026-10-30)

First real SparkVSR numbers on the server, the reason why the stock upstream script cannot be the production path, and the quantization spike. Everything marked "measured" was observed on 2026-10-30; the extrapolations are labelled as estimates, and the quality side has NOT been assessed yet. The LXC is only ever called "the LXC" here: no IPs, no key material.

## Setup

One RTX 5080 per run, torch 2.8.0+cu128, bf16, SparkVSR S2 weights, `ref_mode=no_ref`. The upstream CLI script was patched only to skip T5 and to add timers (`tools/scripts/ops/bench/patch_sparkvsr.py`). Clip: 49 frames at 960x540, upscaled x4 to 3840x2160, 512x512 tiles with overlap 32, a single temporal chunk, 28 tiles per clip. The benchmark containers run with `--network none` and the weights come from a read-only host directory in the LXC (28 files, 42.2 GB / 39.3 GiB, SHA-256 of all 14 LFS files checked against the Hugging Face listing, 0 mismatches: ISSUE-030).

## Measured ETA (INQUIRY-017, first figure)

- Warm time per 49-frame 2160p clip: 457 s on GPU 0 and 436 s on GPU 1. Two clips including model load took 942 s and 935 s, so the two cards agree within about 1% on wall time.
- That is about 9.1 s/frame with a naive per-tile transformer swap.
- Breakdown per clip (GPU 0): transformer 44 s (28 calls, 1.56 s each, ONE denoise step per tile), VAE decode 203 s (7.3 s per tile), the naive transformer-to-CPU swap 114 s, remainder about 96 s (mostly VAE encode and I/O, not timed separately).
- Without the swap: about 340 s per clip, about 6.9 s/frame. The VAE (encode + decode) is about 87% of that swap-free time and the transformer only about 13%, which is the single most important finding: the bottleneck is the VAE, not the diffusion step.
- Peak VRAM: 13.0 GiB allocated, 15.5 GiB reserved on the 16 GiB card, with the swap hack.
- Quality: NOT assessed. There is no PiSA-SR reference yet, and the authors document `no_ref` as not their recommended setting. These are speed figures only.

Estimate, not a measurement: a 2 h film at 24 fps is about 172,800 frames, so 6.9 s/frame gives about 13.8 days on one GPU, about 7 days on two, and about 8 days with 8-frame chunk overlap. That is roughly half of the earlier upper bound (about 15 days on 2 GPUs, extrapolated from a 3090 community report), though still days and not "hours". Cost scales with TARGET pixels, so 1080p to 2160p costs the same per frame as 540p to 2160p. A restore at a 1080p target followed by a Lanczos resize to 2160p would cost about 4x less (about 1.7 days per film), but that is a quality trade-off nobody has tested (IDEA-034).

INQUIRY-017 stays in progress on purpose: its definition is a hard gate at the END of M3, and these figures come from a patched upstream script with a naive swap, not from the stage-major streamer that will ship. The gate closes with the number measured on that streamer.

## Hard constraints found

1. The model does NOT fit in 16 GiB with the stock script: the transformer (about 11 GB bf16) plus T5 (about 9.5 GB) OOM at load (`pipe.to("cuda")`). The script accepts a cached empty-prompt embedding (`pretrained_models/prompt_embeddings/<sha256 of empty string>.safetensors`, 1x226x4096 bf16, generated once by `make_empty_prompt_embedding.py`), so T5 is never loaded and the pipeline loads with `text_encoder=None`.
2. Even without T5, the resident 11 GB transformer leaves too little room for the VAE: tiled or untiled decode OOMs unless the transformer is parked. The design answer is stage-major scheduling (the owner suggested serial load/offload loops): run the transformer on all tiles of a segment while resident, offload it ONCE, then run the VAE over all stored latents. Pinned host memory should make an 11 GB move about a second; the 4-5 s measured was pageable memory. VAE tiling/slicing cannot be switched off while the transformer is resident (VAE encode OOM, verified), so testing it off belongs to the streamer.
3. Host RAM: one 49-frame 2160p upstream process held about 34 GB (whole clip, output and counter in fp32/int32). The LXC cap is 50 GB, so two GPU workers do not fit. The M3 windowed frame streamer with bounded uint8 windows is therefore REQUIRED, not optional.
4. Upstream `ref_utils.py` imports `fal_client` (the fal.ai cloud API client) unconditionally. It is not installed; a stub module that raises on any use satisfies the import, and the production worker must do the same, since it runs with no egress. Upstream also imports `pyiqa` without listing it in `requirements.txt`.
5. Tile coverage: 28 tiles x 512^2 is 7.3 Mpx, less than the 8.3 Mpx of a 2160p frame, so a coverage gap was suspected. Checked by PSNR against a bilinear upscale in regions near the right and bottom edges: all regions differ equally from bilinear (31-37 dB), so no pass-through region was found. It is not a bug; keep a per-region coverage check in the harness anyway.

## Quantization spike (INQUIRY-029)

Synthetic 3072 to 12288 linear layer, 16384 tokens, no real weights, torchao 0.13.0 pinned because the latest torchao needs torch >= 2.11 and the proven base is 2.8 (script: `quant_kernel_spike.py`).

| Variant | Runs on sm_120 | Relative error | Time | Versus bf16 |
|---|---|---|---|---|
| bf16 | yes | - | 10.54 ms | 1.00x |
| FP8 weight-only | yes | 2.6% | 11.75 ms | no speedup |
| FP8 dynamic W8A8 | yes | 3.7% | 7.16 ms | 1.47x |
| NVFP4 (torchao `NVFP4InferenceConfig`) | yes | 22.8% (random data) | 12.41 ms | 0.85x, slower (not compiled, unfused) |

Reported weight bytes were identical for all variants (tensor subclasses), so the memory saving is NOT measured. Since the transformer is only about 13% of the runtime, NVFP4 or FP8 gives at most a few percent end to end. Its real value would be memory (it could avoid the swap), which stage-major scheduling already achieves with no quality risk. INQUIRY-029 stays open at lower priority (P3): revisit it after the VAE is optimised, when the transformer's share rises. The real-weight quality gate is unchanged.

## Next steps (roadmap)

- Stage-major windowed streamer with pinned-memory offload: the M3 core, sub-tasks of FEATURE-006.
- VAE optimisation spike (larger tiles, tiling off in stage-major, channels_last_3d, torch.compile): INQUIRY-032.
- PiSA-SR reference quality run; the SD 2.1 base and the `pisa_sr.pkl` weights are still not located: INQUIRY-033.
- Optional "restore at 1080p then Lanczos" budget recipe field: IDEA-034.
- The five scripts under `tools/scripts/ops/bench/` are new and uncommitted; indexed in `tools/CLAUDE.md`.
