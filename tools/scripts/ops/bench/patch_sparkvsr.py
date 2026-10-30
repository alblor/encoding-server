"""Make a benchmark copy of SparkVSR's inference script. Upstream is never modified.

usage: python3 patch_sparkvsr.py UPSTREAM_SCRIPT OUTPUT_SCRIPT [--swap-transformer]

Changes, each asserted to match exactly once so a drifted upstream fails loudly instead of
producing numbers from an unpatched script:
  1. load the pipeline without T5 (the empty-prompt embedding file replaces it)
  2. print wall time of the transformer call and of the VAE decode, per tile, with a [bench] prefix
  3. print the peak CUDA memory allocated so far
  4. with --swap-transformer: park the transformer on the CPU during VAE decode, because the 11 GB
     transformer plus the decoder do not fit in 16 GB. Transfer time is printed separately.
"""
import sys

REPLACEMENTS = [
    (
        "low_cpu_mem_usage=True)",
        "low_cpu_mem_usage=True, text_encoder=None)",
    ),
    (
        "    # Predict\n",
        "    torch.cuda.synchronize(); _bench_t0 = time.perf_counter()\n    # Predict\n",
    ),
    (
        "    # Denoise\n",
        "    torch.cuda.synchronize()\n"
        "    print(f\"[bench] transformer {time.perf_counter() - _bench_t0:.3f}s\", flush=True)\n"
        "    # Denoise\n",
    ),
]

DECODE_LINE = (
    "    video_generate = pipe.vae.decode(latent_generate / pipe.vae.config.scaling_factor).sample\n"
)
DECODE_TIMED = (
    "    torch.cuda.synchronize(); _bench_t1 = time.perf_counter()\n"
    + DECODE_LINE
    + "    torch.cuda.synchronize()\n"
    "    print(f\"[bench] vae_decode {time.perf_counter() - _bench_t1:.3f}s \"\n"
    "          f\"peak_alloc {torch.cuda.max_memory_allocated() / 2**30:.2f}GiB\", flush=True)\n"
)
DECODE_SWAPPED = (
    "    torch.cuda.synchronize(); _bench_t2 = time.perf_counter()\n"
    "    pipe.transformer.to('cpu'); torch.cuda.empty_cache()\n"
    "    torch.cuda.synchronize(); _bench_t1 = time.perf_counter()\n"
    + DECODE_LINE
    + "    torch.cuda.synchronize()\n"
    "    _bench_dec = time.perf_counter() - _bench_t1\n"
    "    pipe.transformer.to('cuda'); torch.cuda.synchronize()\n"
    "    print(f\"[bench] vae_decode {_bench_dec:.3f}s swap_overhead \"\n"
    "          f\"{time.perf_counter() - _bench_t2 - _bench_dec:.3f}s \"\n"
    "          f\"peak_alloc {torch.cuda.max_memory_allocated() / 2**30:.2f}GiB\", flush=True)\n"
)


def main() -> None:
    src_path, out_path = sys.argv[1], sys.argv[2]
    swap = "--swap-transformer" in sys.argv[3:]
    text = open(src_path).read()
    pairs = REPLACEMENTS + [(DECODE_LINE, DECODE_SWAPPED if swap else DECODE_TIMED)]
    for old, new in pairs:
        found = text.count(old)
        assert found == 1, f"expected exactly one match, found {found} for: {old.strip()[:70]!r}"
        text = text.replace(old, new)
    text = "import time\n" + text
    open(out_path, "w").write(text)
    print(f"wrote {out_path} (swap_transformer={swap})")


if __name__ == "__main__":
    main()
