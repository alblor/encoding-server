"""VAE speed spike (INQUIRY-032): encode/decode time and peak memory of the CogVideoX VAE alone.

The VAE is about 87% of SparkVSR's swap-free runtime, so this isolates it: no transformer, no T5, the
whole 16 GB is free. Input is random data of the right shape (timing does not depend on content).
Each variant is warmed up once, then timed twice. OOM is caught and reported, not fatal.

usage (bench image, one GPU visible): python vae_speed_spike.py MODEL_DIR [FRAMES]
"""
import sys
import time

import torch
from diffusers import AutoencoderKLCogVideoX

MODEL = sys.argv[1]
FRAMES = int(sys.argv[2]) if len(sys.argv) > 2 else 49
global_dtype = {"d": torch.bfloat16}


def run_variant(vae, label: str, size: int) -> None:
    x = torch.randn(1, 3, FRAMES, size, size, dtype=global_dtype["d"], device="cuda").clamp(-1, 1)
    try:
        torch.cuda.empty_cache()
        torch.cuda.reset_peak_memory_stats()
        with torch.no_grad():
            z = vae.encode(x).latent_dist.sample()          # warm-up
            vae.decode(z).sample
            torch.cuda.synchronize()
            t0 = time.perf_counter()
            for _ in range(2):
                z = vae.encode(x).latent_dist.sample()
            torch.cuda.synchronize()
            enc = (time.perf_counter() - t0) / 2
            t0 = time.perf_counter()
            for _ in range(2):
                vae.decode(z).sample
            torch.cuda.synchronize()
            dec = (time.perf_counter() - t0) / 2
        mpx = size * size * FRAMES / 1e6
        peak = torch.cuda.max_memory_allocated() / 2**30
        print(f"{label:34s} tile {size:4d}  enc {enc:6.2f}s  dec {dec:6.2f}s  total {enc + dec:6.2f}s  "
              f"= {(enc + dec) / mpx * 1000:6.1f} ms/Mpx-frame  peak {peak:5.2f} GiB", flush=True)
    except torch.OutOfMemoryError:
        print(f"{label:34s} tile {size:4d}  OOM", flush=True)
    finally:
        del x
        torch.cuda.empty_cache()


def main() -> None:
    torch.backends.cudnn.benchmark = True
    vae = AutoencoderKLCogVideoX.from_pretrained(MODEL, subfolder="vae", torch_dtype=torch.bfloat16).to("cuda").eval()
    print(f"torch {torch.__version__}, {torch.cuda.get_device_name(0)}, frames {FRAMES}", flush=True)

    vae.enable_tiling(); vae.enable_slicing()
    run_variant(vae, "baseline bf16, tiling ON", 512)
    vae16 = AutoencoderKLCogVideoX.from_pretrained(MODEL, subfolder="vae", torch_dtype=torch.float16).to("cuda").eval()
    vae16.enable_tiling(); vae16.enable_slicing()
    global_dtype["d"] = torch.float16
    run_variant(vae16, "fp16, tiling ON", 512)
    global_dtype["d"] = torch.bfloat16
    try:
        vae.decoder = torch.compile(vae.decoder)
        vae.encoder = torch.compile(vae.encoder)
        run_variant(vae, "bf16 + torch.compile, tiling ON", 512)
    except Exception as exc:
        print(f"torch.compile variant failed: {type(exc).__name__}: {str(exc)[:120]}", flush=True)


if __name__ == "__main__":
    main()
