"""What is the real matmul speed-up of FP8 (and INT8, FP16-accumulate) over bf16 on this GPU, for ReCaVSR's shapes?

Inputs are already in the low-precision dtype, so no quantisation cost is counted: this is the hardware and
library ceiling. Every variant is captured in a CUDA graph (several calls per graph, replayed many times) so
launch overhead is hidden, and each runs for about a second so clocks settle as they do in a long DiT run.

Shapes come from the ReCaVSR S checkpoint at 1344x1152 tiles: 1512 tokens per latent frame, blocks of 2 latent
frames (M = 3024) after a 6-frame prefix (M = 9072); dim 3072, feed-forward 14336, q/k/v not fused.

Author: Lorenzo Albanese (alblor)
usage (inside the recavsr-fp8 image, one GPU visible): python fp8_ceiling_bench.py [--seconds 1.0] [--accum-only | --kernels-only]
"""
import argparse
import json

import torch

SHAPES = {  # name: (K, N); M is the token count
    "attn_proj 3072x3072": (3072, 3072),
    "qkv_fused 3072x9216": (3072, 9216),
    "ffn_up 3072x14336": (3072, 14336),
    "ffn_down 14336x3072": (14336, 3072),
}
TOKENS = (3024, 9072)


def graph_time(fn, seconds: float, calls_per_graph: int = 10) -> float:
    """Milliseconds per call, measured on CUDA-graph replays."""
    stream = torch.cuda.Stream()
    stream.wait_stream(torch.cuda.current_stream())
    with torch.cuda.stream(stream):
        for _ in range(3):
            fn()
    torch.cuda.current_stream().wait_stream(stream)
    graph = torch.cuda.CUDAGraph()
    with torch.cuda.graph(graph):
        for _ in range(calls_per_graph):
            fn()
    # calibrate the replay count to the wanted duration, then measure
    start, end = torch.cuda.Event(enable_timing=True), torch.cuda.Event(enable_timing=True)
    start.record(); graph.replay(); end.record(); torch.cuda.synchronize()
    one = start.elapsed_time(end) / 1000
    replays = max(5, int(seconds / max(one, 1e-6)))
    for _ in range(max(2, replays // 4)):          # warm the clocks
        graph.replay()
    start.record()
    for _ in range(replays):
        graph.replay()
    end.record()
    torch.cuda.synchronize()
    return start.elapsed_time(end) / (replays * calls_per_graph)


def accumulator_check() -> None:
    """Does the FP8 kernel accumulate in full FP32? Same FP8 values through the kernel and through FP64.

    All-positive inputs, so rounding errors cannot cancel: about 1e-7 relative error means an FP32
    accumulator, 1e-4 or more means a reduced one (which would cap accuracy on long-K layers whatever the scales).
    """
    torch.manual_seed(1)
    for k in (3072, 14336):
        x8 = (torch.rand(512, k, device="cuda") * 4 + 0.5).to(torch.float8_e4m3fn)
        w8 = (torch.rand(512, k, device="cuda") * 4 + 0.5).to(torch.float8_e4m3fn)
        one = torch.ones((), device="cuda")
        exact = x8.double() @ w8.double().t()
        for out_dtype in (torch.float32, torch.bfloat16):
            try:
                got = torch._scaled_mm(x8, w8.t(), scale_a=one, scale_b=one, out_dtype=out_dtype)
                err = ((got.double() - exact).abs() / exact).max().item()
                print(f"accumulator check K={k} fp8 out={out_dtype}: max rel err {err:.2e}", flush=True)
            except Exception as exc:
                print(f"accumulator check K={k} fp8 out={out_dtype}: FAIL {type(exc).__name__}", flush=True)
        xh, wh = x8.half(), w8.half()
        exact16 = xh.double() @ wh.double().t()
        for flag in (False, True):
            if hasattr(torch.backends.cuda.matmul, "allow_fp16_accumulation"):
                torch.backends.cuda.matmul.allow_fp16_accumulation = flag
                # scaled down by 64 per side so a K=14336 sum of products up to 20 stays inside the fp16 range
                got = torch.mm(xh / 64, wh.t() / 64).double() * 4096
                err = ((got - exact16).abs() / exact16).max().item()
                print(f"accumulator check K={k} fp16 mm, fp16 accumulation={flag}: max rel err {err:.2e}", flush=True)
        torch.backends.cuda.matmul.allow_fp16_accumulation = False


def kernel_selection_check(seconds: float) -> None:
    """Which cuBLAS kernel does each torch._scaled_mm call style get on this GPU, and how fast is it?

    torchao's per-tensor FP8 ran an Ada (sm89_xmma) kernel inside the model, while plain calls ran the native
    Blackwell one (nvjet_sm120): this isolates the call argument responsible.
    """
    from torch.profiler import ProfilerActivity, profile

    m, k, n = 9072, 3072, 14336
    x8 = (torch.randn(m, k, device="cuda") * 16).to(torch.float8_e4m3fn)
    w8 = (torch.randn(n, k, device="cuda") * 16).to(torch.float8_e4m3fn)
    s = torch.tensor(0.01, device="cuda")
    s11 = torch.full((1, 1), 0.01, device="cuda")
    bias = torch.randn(n, device="cuda", dtype=torch.bfloat16)
    bf16 = graph_time(lambda: torch.mm(x8.bfloat16(), w8.bfloat16().t()), seconds)
    styles = {
        "plain (scalar scales)": dict(scale_a=s, scale_b=s),
        "use_fast_accum=True": dict(scale_a=s, scale_b=s, use_fast_accum=True),
        "bias=bf16": dict(scale_a=s, scale_b=s, bias=bias),
        "(1,1) scales": dict(scale_a=s11, scale_b=s11),
        "fast_accum + bias": dict(scale_a=s, scale_b=s, use_fast_accum=True, bias=bias),
    }
    print(f"kernel selection, M={m} K={k} N={n}: bf16 mm {bf16:.3f} ms", flush=True)
    for name, kw in styles.items():
        fn = lambda kw=kw: torch._scaled_mm(x8, w8.t(), out_dtype=torch.bfloat16, **kw)
        try:
            ms = graph_time(fn, seconds)
            with profile(activities=[ProfilerActivity.CUDA]) as prof:
                fn(); torch.cuda.synchronize()
            kernels = [e.key for e in prof.key_averages() if "gemm" in e.key or "nvjet" in e.key or "xmma" in e.key]
            print(f"  {name:24s} {ms:6.3f} ms x{bf16 / ms:4.2f}  {kernels[0][:90] if kernels else '?'}", flush=True)
        except Exception as exc:
            print(f"  {name:24s} FAIL {type(exc).__name__}: {str(exc)[:100]}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=1.0)
    ap.add_argument("--accum-only", action="store_true", help="only run the accumulator precision check")
    ap.add_argument("--kernels-only", action="store_true", help="only run the cuBLAS kernel selection check")
    args = ap.parse_args()
    torch.manual_seed(0)
    dev = "cuda"
    print(f"torch {torch.__version__} {torch.cuda.get_device_name(0)} cap {torch.cuda.get_device_capability(0)}",
          flush=True)
    if args.kernels_only:
        kernel_selection_check(args.seconds)
        return
    accumulator_check()
    if args.accum_only:
        return
    has_fp16_acc = hasattr(torch.backends.cuda.matmul, "allow_fp16_accumulation")
    rows = []
    for name, (k, n) in SHAPES.items():
        w = torch.randn(n, k, device=dev, dtype=torch.bfloat16) / k ** 0.5
        for m in TOKENS:
            x = torch.randn(m, k, device=dev, dtype=torch.bfloat16)
            flops = 2 * m * n * k
            res = {"shape": name, "M": m}
            res["bf16"] = graph_time(lambda: torch.mm(x, w.t()), args.seconds)
            xh, wh = x.half(), w.half()
            res["fp16_acc32"] = graph_time(lambda: torch.mm(xh, wh.t()), args.seconds)
            if has_fp16_acc:
                torch.backends.cuda.matmul.allow_fp16_accumulation = True
                res["fp16_acc16"] = graph_time(lambda: torch.mm(xh, wh.t()), args.seconds)
                torch.backends.cuda.matmul.allow_fp16_accumulation = False
            x8 = (x * 16).to(torch.float8_e4m3fn)
            w8 = (w * 16 * k ** 0.5).to(torch.float8_e4m3fn)
            one = torch.ones((), device=dev, dtype=torch.float32)
            res["fp8_bf16out"] = graph_time(
                lambda: torch._scaled_mm(x8, w8.t(), scale_a=one, scale_b=one, out_dtype=torch.bfloat16), args.seconds)
            try:
                res["fp8_fp16out"] = graph_time(
                    lambda: torch._scaled_mm(x8, w8.t(), scale_a=one, scale_b=one, out_dtype=torch.float16),
                    args.seconds)
            except Exception as exc:  # report and continue: the point is to learn what this part supports
                res["fp8_fp16out"] = f"FAIL {type(exc).__name__}"
            xi = torch.randint(-127, 128, (m, k), device=dev, dtype=torch.int8)
            wi = torch.randint(-127, 128, (n, k), device=dev, dtype=torch.int8)
            try:
                res["int8_int32out"] = graph_time(lambda: torch._int_mm(xi, wi.t()), args.seconds)
            except Exception as exc:
                res["int8_int32out"] = f"FAIL {type(exc).__name__}: {str(exc)[:80]}"
            line = f"{name:22s} M={m:5d}"
            for key, ms in res.items():
                if key in ("shape", "M"):
                    continue
                if isinstance(ms, float):
                    line += f" | {key} {ms:6.3f} ms {flops / ms / 1e9:6.1f} TF x{res['bf16'] / ms:4.2f}"
                else:
                    line += f" | {key} {ms}"
            print(line, flush=True)
            rows.append(res)
    # a whole block's linears, as the DiT runs them (6 attention projections + up + down per block)
    for m in TOKENS:
        total = {}
        for key in rows[0]:
            if key in ("shape", "M"):
                continue
            vals = {r["shape"]: r[key] for r in rows if r["M"] == m}
            if all(isinstance(v, float) for v in vals.values()):
                total[key] = (6 * vals["attn_proj 3072x3072"] + vals["ffn_up 3072x14336"]
                              + vals["ffn_down 14336x3072"])
        print(f"one block's linears at M={m}: " + ", ".join(
            f"{k} {v:.3f} ms (x{total['bf16'] / v:.2f})" for k, v in total.items()), flush=True)
    print("json " + json.dumps(rows))


if __name__ == "__main__":
    main()
