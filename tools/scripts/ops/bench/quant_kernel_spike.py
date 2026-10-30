"""Do FP8 and NVFP4 linear layers run on this GPU, how accurate are they, and are they faster than bf16?

Uses a synthetic layer with the shape of a CogVideoX1.5-5B feed-forward projection (3072 -> 12288),
no model weights. It answers the tooling question of INQUIRY-029 before any real model is touched.
Quality on the real model is a separate gate (output deltas versus bf16, flicker metric, TV A/B).

usage (inside an image with torch + torchao, one GPU visible): python quant_kernel_spike.py
"""
import copy
import time
import traceback

import torch


def timed(fn, iters: int = 20) -> float:
    for _ in range(3):
        fn()
    torch.cuda.synchronize()
    start = time.perf_counter()
    for _ in range(iters):
        fn()
    torch.cuda.synchronize()
    return (time.perf_counter() - start) / iters * 1000


def rel_error(a: torch.Tensor, b: torch.Tensor) -> float:
    return ((a.float() - b.float()).norm() / b.float().norm()).item()


def try_config(name: str, make_config, base: torch.nn.Module, x: torch.Tensor, ref: torch.Tensor, t_bf16: float):
    try:
        from torchao.quantization import quantize_

        layer = copy.deepcopy(base)
        quantize_(layer, make_config())
        with torch.no_grad():
            out = layer(x)
            ms = timed(lambda: layer(x))
        weight_bytes = sum(p.numel() * p.element_size() for p in layer.parameters())
        print(f"{name:28s} OK   rel_err={rel_error(out, ref):.4f}  {ms:7.2f} ms "
              f"(bf16 {t_bf16:.2f} ms, x{t_bf16 / ms:.2f})  weight_bytes={weight_bytes / 2**20:.1f} MiB")
    except Exception as exc:  # the point of the spike is to learn what fails and why
        print(f"{name:28s} FAIL {type(exc).__name__}: {str(exc)[:160]}")
        traceback.print_exc(limit=2)


def main() -> None:
    import torchao

    print(f"torch {torch.__version__}  torchao {torchao.__version__}  "
          f"device {torch.cuda.get_device_name(0)} capability {torch.cuda.get_device_capability(0)}")
    torch.manual_seed(0)
    base = torch.nn.Linear(3072, 12288, bias=True, dtype=torch.bfloat16, device="cuda")
    x = torch.randn(16384, 3072, dtype=torch.bfloat16, device="cuda")
    with torch.no_grad():
        ref = base(x)
        t_bf16 = timed(lambda: base(x))
    print(f"bf16 baseline: {t_bf16:.2f} ms, weight {base.weight.numel() * 2 / 2**20:.1f} MiB")

    import torchao.quantization as q

    print("available configs:", sorted(n for n in dir(q) if "Float8" in n or "NVFP4" in n or "MX" in n or "Fp8" in n))
    candidates = {
        "fp8 weight-only": lambda: q.Float8WeightOnlyConfig(),
        "fp8 dynamic (W8A8)": lambda: q.Float8DynamicActivationFloat8WeightConfig(),
    }
    try:
        from torchao.prototype.mx_formats.inference_workflow import NVFP4InferenceConfig
        candidates["nvfp4 (W4A4, torchao)"] = lambda: NVFP4InferenceConfig()
    except Exception as exc:
        print(f"NVFP4InferenceConfig import failed: {type(exc).__name__}: {str(exc)[:160]}")
    for name, make in candidates.items():
        try_config(name, make, base, x, ref, t_bf16)


if __name__ == "__main__":
    main()
