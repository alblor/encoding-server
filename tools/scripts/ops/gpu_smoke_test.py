"""Blackwell (sm_120) smoke test for the restoration worker image.

Run inside a CUDA-enabled PyTorch container, for example:
    docker run --rm -i --runtime=nvidia -e NVIDIA_VISIBLE_DEVICES=all IMAGE python - < gpu_smoke_test.py

Checks, per visible GPU: the compute capability, that this torch build ships sm_120 kernels,
a bf16 matmul throughput figure, and which low-precision dtypes this torch exposes (input for
the NVFP4/BF16 spike). It reads nothing from disk and writes nothing.
"""
import time

import torch


def bf16_tflops(device: int, n: int = 8192, iters: int = 30) -> float:
    a = torch.randn(n, n, device=f"cuda:{device}", dtype=torch.bfloat16)
    b = torch.randn(n, n, device=f"cuda:{device}", dtype=torch.bfloat16)
    for _ in range(5):
        a @ b
    torch.cuda.synchronize(device)
    start = time.perf_counter()
    for _ in range(iters):
        a @ b
    torch.cuda.synchronize(device)
    elapsed = time.perf_counter() - start
    return 2 * n**3 * iters / elapsed / 1e12


def main() -> None:
    print(f"torch {torch.__version__}, cuda {torch.version.cuda}, cudnn {torch.backends.cudnn.version()}")
    arches = torch.cuda.get_arch_list()
    print(f"arch list: {arches}")
    print(f"ships sm_120: {'sm_120' in arches}")
    print(f"visible GPUs: {torch.cuda.device_count()}")
    for i in range(torch.cuda.device_count()):
        props = torch.cuda.get_device_properties(i)
        print(f"GPU {i}: {props.name}, capability {props.major}.{props.minor}, "
              f"{props.total_memory / 2**30:.1f} GiB")
        print(f"GPU {i}: bf16 matmul {bf16_tflops(i):.0f} TFLOPS")
    for name in ("float8_e4m3fn", "float8_e5m2", "float4_e2m1fn_x2"):
        print(f"dtype torch.{name}: {hasattr(torch, name)}")
    print(f"torch._scaled_mm present: {hasattr(torch, '_scaled_mm')}")


if __name__ == "__main__":
    main()
