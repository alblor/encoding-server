"""FP8 lab for the ReCaVSR transformer: accuracy ladder on real activations, block speed, block sensitivity.

Parts (choose with --parts, default all):
  ladder       hooks on every hot linear of all 30 blocks while one tile of a real clip runs (prefix + first body
               step); calibration statistics come from a different tile. For each layer the output of every
               scheme below is compared with an FP32 matmul of the same bf16 inputs (bias left out, so it cannot
               hide the error). Errors are relative L2, also shown as SNR in dB and as effective bits.
  speed        one middle block (default 10) with the exact arguments it receives in a body step (M=3024) and in
               the prefix (M=9072): bf16, own fp8, torchao fp8, experimental int8 (W8A8 through torch._int_mm) and
               fp16 with fp16 accumulation, eager and compiled with the session's options, plus a profiler kernel
               table grouped by kind (matmul, attention, quantise/scale/other). --speed-variants picks a subset.
  sensitivity  the DiT output (the latents of the prefix and first body step) when only block i is quantised
               with the own scheme, for every i, then whole sets of blocks, against bf16.

Schemes in the ladder (x = activation, w = weight):
  bf16                 the model as it runs today (noise floor of the measurement)
  fp16_acc16           fp16 inputs, fp16 accumulation (no quantisation, 1.7x on this card)
  fp8 x:tensor w:tensor   torchao fp8_fast equivalent
  fp8 x:tensor w:chan
  fp8 x:token w:chan      the shipped `fp8` mode
  fp8 x:static w:chan     one calibrated scale per layer for x (no reduction at run time)
  fp8 x:token w:chan +smooth  SmoothQuant-style per-input-channel rebalancing (alpha 0.5, calibrated)
  fp8 w hi+lo             two-term weight, FP8 residual (2 matmuls)
  fp8 x,w hi+lo           two-term weight and activation, 3 matmuls (hi*hi + hi*lo + lo*hi)
  int8 x:token w:chan     (+smooth) W8A8 through torch._int_mm

Author: Lorenzo Albanese (alblor)
usage (recavsr-fp8 image, repo on PYTHONPATH, one GPU visible):
  python fp8_linear_lab.py --clip /cmp/synth_2160p_blocky.mp4 [--parts ladder,speed,sensitivity] [--block 10]
"""
from __future__ import annotations

import argparse
import copy
import gc
import json
import math
import subprocess
import time
from collections import defaultdict

import numpy as np
import torch
import torch.nn.functional as F
from safetensors.torch import load_file

from recavsr_infer.runtime.cache import FixedKVCache
from recavsr_infer.runtime.transformer import PreparedBlock, TransformerSession
from recavsr_infer.weights import load_model
from restore_worker.quantize import (FP8_MAX, _fp8_own, _fp8_torchao, fp8_matmul, fp8_scale, quantize_rows,
                                     to_fp8)

TILE_H, TILE_W = 1152, 1344
SEED = 42


# ---------------------------------------------------------------------------------------------------- input

def read_frames(path: str, count: int) -> np.ndarray:
    probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width,height",
                            "-of", "csv=p=0", path], capture_output=True, text=True, check=True).stdout.split(",")
    w, h = int(probe[0]), int(probe[1])
    raw = subprocess.run(["ffmpeg", "-v", "error", "-i", path, "-an", "-pix_fmt", "rgb24", "-frames:v", str(count),
                          "-f", "rawvideo", "-"], capture_output=True, check=True).stdout
    return np.frombuffer(raw, np.uint8).reshape(-1, h, w, 3)


def lq_block(frames: np.ndarray, start: int, count: int, y0: int, x0: int, dev) -> torch.Tensor:
    crop = frames[start:start + count, y0:y0 + TILE_H, x0:x0 + TILE_W]
    if crop.shape[1:3] != (TILE_H, TILE_W):                     # small sources: pad like the engine does
        crop = np.pad(crop, ((0, 0), (0, TILE_H - crop.shape[1]), (0, TILE_W - crop.shape[2]), (0, 0)), mode="edge")
    x = torch.from_numpy(np.ascontiguousarray(crop)).to(dev)
    return x.permute(3, 0, 1, 2).unsqueeze(0).float() / 127.5 - 1.0


def reset(session: TransformerSession) -> None:
    """Same as RecavsrTiledEngine._reset, transformer half."""
    router = session.model._static_kv_router
    session.caches = [FixedKVCache(a, initial=router.anchor_initial_index, stride=router.anchor_stride_latents,
                                   anchors=router.anchor_capacity_latents) for a in router.layer_actions]
    session.lq_state = session.model.lq_proj.create_streaming_state()
    session.generator = torch.Generator(device=session.device).manual_seed(SEED)
    session.latent_offset, session.previous_latents = 0, None


def run_tile(session, frames, y0, x0, body_steps=1) -> list[torch.Tensor]:
    reset(session)
    outs = [session.step(lq_block(frames, 0, 21, y0, x0, session.device))]
    for i in range(body_steps):
        outs.append(session.step(lq_block(frames, 21 + 8 * i, 8, y0, x0, session.device)))
    return outs


# ---------------------------------------------------------------------------------------------------- schemes

def rel(y: torch.Tensor, ref: torch.Tensor) -> float:
    return ((y.float() - ref).norm() / ref.norm().clamp(min=1e-30)).item()


def split_hi_lo(t: torch.Tensor):
    """Two-term FP8 per row: t ~ hi*s_hi + lo*s_lo, the residual quantised with its own per-row scale."""
    hi, s_hi = quantize_rows(t)
    res = t.float() - hi.float() * s_hi
    lo, s_lo = quantize_rows(res)
    return hi, s_hi, lo, s_lo


def int8_rows(t: torch.Tensor):
    scale = t.abs().amax(dim=-1, keepdim=True).float().clamp(min=1e-12) / 127
    return (t.float() / scale).round().clamp(-127, 127).to(torch.int8), scale


def schemes(x: torch.Tensor, w: torch.Tensor, stats: dict | None) -> dict[str, torch.Tensor]:
    """Every scheme's output (no bias) for one layer. x (M, K) bf16 rows to evaluate, w (N, K) bf16."""
    out = {"bf16": x @ w.t()}
    with _fp16acc():
        out["fp16_acc16"] = (x.half() @ w.half().t())
    xt_scale = fp8_scale(stats["x_amax_full"])                   # dynamic per-tensor (amax of the whole tensor)
    w_q, w_s = quantize_rows(w)                                   # per output channel
    wt_s = fp8_scale(w.abs().amax())
    wt_q = to_fp8(w, wt_s)
    x_tq = to_fp8(x, xt_scale)
    out["fp8 x:tensor w:tensor"] = fp8_matmul(x_tq, wt_q).float() * (xt_scale * wt_s)
    out["fp8 x:tensor w:chan"] = fp8_matmul(x_tq, w_q).float() * xt_scale * w_s.reshape(1, -1)
    x_q, x_s = quantize_rows(x)
    out["fp8 x:token w:chan"] = fp8_matmul(x_q, w_q).float() * x_s * w_s.reshape(1, -1)
    if stats.get("calib_amax") is not None:
        st = fp8_scale(stats["calib_amax"])
        out["fp8 x:static w:chan"] = fp8_matmul(to_fp8(x, st), w_q).float() * st * w_s.reshape(1, -1)
        # SmoothQuant: x_j / s_j and w_j * s_j, s_j = amax_x_j^a / amax_w_j^(1-a), a = 0.5
        s = (stats["calib_chan"].clamp(min=1e-5) ** 0.5 / w.abs().amax(0).float().clamp(min=1e-5) ** 0.5)
        xs, ws = x.float() / s, w.float() * s
        xsq, xss = quantize_rows(xs)
        wsq, wss = quantize_rows(ws)
        out["fp8 x:token w:chan +smooth"] = fp8_matmul(xsq, wsq).float() * xss * wss.reshape(1, -1)
        xi, xis = int8_rows(xs)
        wi, wis = int8_rows(ws)
        out["int8 x:token w:chan +smooth"] = torch._int_mm(xi, wi.t()).float() * xis * wis.reshape(1, -1)
    hi, s_hi, lo, s_lo = split_hi_lo(w)
    out["fp8 w hi+lo (2 mm)"] = (fp8_matmul(x_q, hi).float() * s_hi.reshape(1, -1)
                                 + fp8_matmul(x_q, lo).float() * s_lo.reshape(1, -1)) * x_s
    xhi, xs_hi, xlo, xs_lo = split_hi_lo(x)
    out["fp8 x,w hi+lo (3 mm)"] = (fp8_matmul(xhi, hi).float() * xs_hi * s_hi.reshape(1, -1)
                                   + fp8_matmul(xhi, lo).float() * xs_hi * s_lo.reshape(1, -1)
                                   + fp8_matmul(xlo, hi).float() * xs_lo * s_hi.reshape(1, -1))
    xi, xis = int8_rows(x)
    wi, wis = int8_rows(w)
    out["int8 x:token w:chan"] = torch._int_mm(xi, wi.t()).float() * xis * wis.reshape(1, -1)
    return out


class _fp16acc:
    def __enter__(self):
        torch.backends.cuda.matmul.allow_fp16_accumulation = True

    def __exit__(self, *exc):
        torch.backends.cuda.matmul.allow_fp16_accumulation = False


# ---------------------------------------------------------------------------------------------------- hooks

def hot_layers(block):
    """(kind, module whose input is hooked, weight getter) for the 6 matmuls a block runs per token."""
    a1, a2 = block.attn1, block.attn2
    return [
        ("qkv", a1.to_q, lambda: torch.cat([a1.to_q.weight, a1.to_k.weight, a1.to_v.weight])),
        ("attn_out", a1.to_out[0], lambda: a1.to_out[0].weight),
        ("cross_q", a2.to_q, lambda: a2.to_q.weight),
        ("cross_out", a2.to_out[0], lambda: a2.to_out[0].weight),
        ("ffn_up", block.ffn.net[0].proj, lambda: block.ffn.net[0].proj.weight),
        ("ffn_down", block.ffn.net[2], lambda: block.ffn.net[2].weight),
    ]


def part_ladder(session, model, frames, rows: int, report: dict) -> None:
    calib: dict = defaultdict(dict)
    results: dict = defaultdict(lambda: defaultdict(list))      # kind -> scheme -> [(block, step, err)]
    extra: dict = defaultdict(list)
    state = {"mode": "calib", "step": 0}
    gen = torch.Generator(device=session.device).manual_seed(0)

    def make_hook(bi, kind, get_w):
        def hook(module, args):
            x = args[0].reshape(-1, args[0].shape[-1])
            key = (bi, kind)
            if state["mode"] == "calib":
                c = calib[key]
                c["amax"] = max(c.get("amax", 0.0), x.abs().amax().item())
                ch = x.abs().amax(0).float()
                c["chan"] = ch if "chan" not in c else torch.maximum(c["chan"], ch)
                return
            w = get_w()
            idx = torch.randperm(x.shape[0], generator=gen, device=x.device)[:rows]
            xs = x[idx].contiguous()
            stats = {"x_amax_full": x.abs().amax(), "calib_amax": torch.tensor(calib[key]["amax"], device=x.device),
                     "calib_chan": calib[key]["chan"]}
            ref = xs.float() @ w.float().t()
            for name, y in schemes(xs, w, stats).items():
                results[kind][name].append((bi, state["step"], rel(y, ref)))
            # how often a calibrated static scale would clip, and the fp16 overflow margin
            extra["static_clip_frac"].append((x.abs() > calib[key]["amax"]).float().mean().item())
            extra["x_amax_over_calib"].append(x.abs().amax().item() / calib[key]["amax"])
            extra["fp16_max_abs_out"].append(ref.abs().amax().item())
            extra[f"x_amax_{kind}"].append(x.abs().amax().item())
            tok = x.abs().amax(-1).float()
            extra[f"token_amax_ratio_{kind}"].append((tok.max() / tok.median()).item())
        return hook

    handles = []
    for bi, block in enumerate(model.blocks):
        for kind, module, get_w in hot_layers(block):
            handles.append(module.register_forward_pre_hook(make_hook(bi, kind, get_w)))
    with torch.inference_mode():
        run_tile(session, frames, 0, 0)                            # calibration: top-left tile
        state["mode"] = "eval"
        reset(session)
        y0, x0 = max(0, frames.shape[1] - TILE_H), max(0, (frames.shape[2] - TILE_W) // 2)
        state["step"] = 0
        session.step(lq_block(frames, 0, 21, y0, x0, session.device))
        state["step"] = 1
        session.step(lq_block(frames, 21, 8, y0, x0, session.device))
    for h in handles:
        h.remove()

    print("\n== ladder: relative L2 error vs FP32 (median over 30 blocks x 2 steps; worst in brackets), "
          "SNR dB, effective bits ==", flush=True)
    table = {}
    names = list(next(iter(results.values())).keys())
    kinds = list(results.keys())
    print(f"{'scheme':30s} " + " ".join(f"{k:>18s}" for k in kinds) + "   all-median  SNRdB  bits", flush=True)
    for name in names:
        cells, allv = [], []
        for k in kinds:
            v = [e for _, _, e in results[k][name]]
            allv += v
            cells.append(f"{np.median(v):8.2e} [{max(v):7.1e}]")
            table.setdefault(name, {})[k] = {"median": float(np.median(v)), "max": float(max(v))}
        med = float(np.median(allv))
        table[name]["all_median"] = med
        print(f"{name:30s} " + " ".join(f"{c:>18s}" for c in cells)
              + f"   {med:8.2e}  {-20 * math.log10(med):5.1f}  {-math.log2(med):4.1f}", flush=True)
    # per-block worst for the shipped scheme, to see which blocks are sensitive at the layer level
    per_block = defaultdict(float)
    for k in kinds:
        for bi, _, e in results[k]["fp8 x:token w:chan"]:
            per_block[bi] = max(per_block[bi], e)
    print("per-block worst layer error, fp8 x:token w:chan: "
          + " ".join(f"{bi}:{e:.3f}" for bi, e in sorted(per_block.items())), flush=True)
    summary = {k: (float(np.max(v)) if "amax" in k or "max" in k or "ratio" in k else float(np.mean(v)))
               for k, v in extra.items()}
    print("activation facts: " + json.dumps({k: round(v, 4) for k, v in summary.items()}), flush=True)
    report["ladder"] = {"table": table, "per_block_worst": dict(per_block), "facts": summary}


# ---------------------------------------------------------------------------------------------------- speed

def capture_block_args(session, frames, index: int) -> dict:
    """The exact positional arguments block `index` receives in the prefix and in the first body step."""
    got = {}

    def hook(module, args):
        tag = "prefix" if args[0].shape[1] > 4000 else "body"
        got.setdefault(tag, tuple(a.clone() if torch.is_tensor(a) else a for a in args))

    core = session.cores[index]
    h = core.register_forward_pre_hook(hook)
    with torch.inference_mode():
        run_tile(session, frames, 0, 0)
    h.remove()
    return got


def time_call(fn, iters=20) -> float:
    for _ in range(3):
        fn()
    torch.cuda.synchronize()
    s, e = torch.cuda.Event(enable_timing=True), torch.cuda.Event(enable_timing=True)
    s.record()
    for _ in range(iters):
        fn()
    e.record()
    torch.cuda.synchronize()
    return s.elapsed_time(e) / iters


KINDS = (("matmul", ("gemm", "cutlass", "sm120", "sm90", "nvjet", "cublas", "xmma", "s16816", "s1688", "_mm_")),
         ("attention", ("paired_local", "flash", "fmha", "attention", "efficient")),)


def kernel_table(fn, label: str) -> dict:
    from torch.profiler import ProfilerActivity, profile
    fn(); torch.cuda.synchronize()
    with profile(activities=[ProfilerActivity.CUDA]) as prof:
        for _ in range(3):
            fn()
        torch.cuda.synchronize()
    per = defaultdict(float)
    count = defaultdict(int)
    for ev in prof.key_averages():
        if ev.device_type.name != "CUDA" and getattr(ev, "self_device_time_total", 0) == 0:
            continue
        t = getattr(ev, "self_device_time_total", None) or getattr(ev, "self_cuda_time_total", 0)
        if t:
            per[ev.key] += t / 3 / 1000
            count[ev.key] += ev.count // 3
    kinds = defaultdict(float)
    for name, ms in per.items():
        low = name.lower()
        kind = next((k for k, keys in KINDS if any(s in low for s in keys)), "other")
        kinds[kind] += ms
    print(f"  kernels {label}: total {sum(per.values()):.2f} ms = "
          + ", ".join(f"{k} {v:.2f}" for k, v in sorted(kinds.items())), flush=True)
    for name, ms in sorted(per.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    {ms:7.3f} ms x{count[name]:3d}  {name[:110]}", flush=True)
    return {"total": sum(per.values()), **kinds}


class Int8Linear(torch.nn.Module):
    """Experimental W8A8: int8 weight per output channel, int8 activation per token, torch._int_mm (int32 out)."""

    def __init__(self, linear):
        super().__init__()
        w_q, w_s = int8_rows(linear.weight.detach())
        self.register_buffer("weight_i8", w_q.contiguous())
        self.register_buffer("w_scale", w_s.reshape(-1))
        self.register_buffer("bias", None if linear.bias is None else linear.bias.detach().float())
        self.n, self.k = linear.weight.shape

    def forward(self, x):
        lead = x.shape[:-1]
        x2 = x.reshape(-1, self.k)
        x_q, x_s = int8_rows(x2)
        y = torch._int_mm(x_q, self.weight_i8.t()).float() * x_s * self.w_scale
        if self.bias is not None:
            y = y + self.bias
        return y.to(torch.bfloat16).reshape(*lead, self.n)


class Fp16AccLinear(torch.nn.Module):
    """fp16 weight and input, cuBLAS fp16 accumulation (needs allow_fp16_accumulation set while it runs)."""

    def __init__(self, linear):
        super().__init__()
        self.register_buffer("weight16", linear.weight.detach().half())
        self.register_buffer("bias16", None if linear.bias is None else linear.bias.detach().half())

    def forward(self, x):
        return F.linear(x.half(), self.weight16, self.bias16).to(torch.bfloat16)


def swap_hot_linears(blocks, cls) -> None:
    """Same layer selection as restore_worker.quantize._fp8_own, with any replacement class."""
    for block in blocks:
        a1 = block.attn1
        a1.fuse_projections()
        for name in ("to_q", "to_k", "to_v"):
            delattr(a1, name)
        a1.to_qkv = cls(a1.to_qkv)
        a1.to_out[0] = cls(a1.to_out[0])
        block.attn2.to_q = cls(block.attn2.to_q)
        block.attn2.to_out[0] = cls(block.attn2.to_out[0])
        block.ffn.net[0].proj = cls(block.ffn.net[0].proj)
        block.ffn.net[2] = cls(block.ffn.net[2])


def part_speed(session, model, frames, index: int, report: dict, compile_torchao: bool, only: str = "") -> None:
    args = capture_block_args(session, frames, index)
    options = {**torch._inductor.list_mode_options("default"),
               "emulate_precision_casts": True, "force_same_precision": True}
    torch._dynamo.config.recompile_limit = 64
    variants = {"bf16": session.cores[index]}
    makers = (("fp8 own", _fp8_own), ("fp8 torchao", _fp8_torchao),
              ("int8 own", lambda b: swap_hot_linears(b, Int8Linear)),
              ("fp16 acc16", lambda b: swap_hot_linears(b, Fp16AccLinear)))
    for name, fn in makers:
        if only and name not in only.split("+"):
            continue
        with torch.inference_mode():
            blk = copy.deepcopy(model.blocks[index])
            fn([blk])
            variants[name] = PreparedBlock(blk, session.conditioning, session.rope, window=session_window(session)).eval()
    out = {}
    for name, core in variants.items():
        torch.backends.cuda.matmul.allow_fp16_accumulation = name == "fp16 acc16"
        for tag, a in args.items():
            with torch.inference_mode():
                ms = time_call(lambda: core(*a))
                ktab = kernel_table(lambda: core(*a), f"{name} eager {tag}")
            out[f"{name} eager {tag}"] = {"ms": ms, "kernels": ktab}
            print(f"{name:12s} eager    {tag:6s} {ms:7.2f} ms", flush=True)
        if name == "fp8 torchao" and not compile_torchao:
            continue
        compiled = torch.compile(core, fullgraph=True, dynamic=False, options=options)
        for tag, a in args.items():
            t0 = time.perf_counter()
            with torch.inference_mode():
                compiled(*a)
            torch.cuda.synchronize()
            ct = time.perf_counter() - t0
            with torch.inference_mode():
                ms = time_call(lambda: compiled(*a))
                ktab = kernel_table(lambda: compiled(*a), f"{name} compiled {tag}")
            out[f"{name} compiled {tag}"] = {"ms": ms, "compile_s": ct, "kernels": ktab}
            print(f"{name:12s} compiled {tag:6s} {ms:7.2f} ms (first call incl. compile {ct:.1f} s)", flush=True)
        with torch.inference_mode():                         # accuracy of the block output, same inputs
            if name != "bf16":
                for tag, a in args.items():
                    ref = variants["bf16"](*a)[0].float()
                    got = compiled(*a)[0].float()
                    print(f"  block output rel err {name} {tag}: {rel(got, ref):.2e}", flush=True)
    torch.backends.cuda.matmul.allow_fp16_accumulation = False
    report["speed"] = out


def session_window(session):
    return session.cores[0].window if hasattr(session.cores[0], "window") else (22, 40)


# ---------------------------------------------------------------------------------------------------- sensitivity

def part_sensitivity(session, model, frames, report: dict) -> None:
    y0, x0 = max(0, frames.shape[1] - TILE_H), max(0, (frames.shape[2] - TILE_W) // 2)
    with torch.inference_mode():
        base = [o.clone() for o in run_tile(session, frames, y0, x0)]
    originals = list(session.cores)
    window = session_window(session)

    def quantised_core(i):
        with torch.inference_mode():
            blk = copy.deepcopy(model.blocks[i])
            _fp8_own([blk])
            return PreparedBlock(blk, session.conditioning, session.rope, window=window).eval()

    def measure(indices, offload: bool) -> list[float]:
        for i in indices:
            session.cores[i] = quantised_core(i)
            if offload:                                       # keep VRAM bounded while many blocks are swapped
                with torch.inference_mode():
                    model.blocks[i].to("cpu")
        gc.collect()
        torch.cuda.empty_cache()
        with torch.inference_mode():
            outs = run_tile(session, frames, y0, x0)
        errs = [rel(o, b.float()) for o, b in zip(outs, base)]
        del outs
        for i in indices:                                     # drop the FP8 copies before the bf16 blocks return
            session.cores[i] = originals[i]
        gc.collect()
        torch.cuda.empty_cache()
        if offload:
            with torch.inference_mode():
                for i in indices:
                    model.blocks[i].to(session.device)
        return errs

    # control first: with nothing swapped the error must be 0 (eager runs are deterministic), otherwise every
    # number below carries that floor
    control = measure([], offload=False)
    print(f"sensitivity control (nothing quantised): prefix {control[0]:.2e} body {control[1]:.2e}", flush=True)
    single = {}
    for i in range(len(model.blocks)):
        single[i] = measure([i], offload=False)
        print(f"sensitivity block {i:2d} alone: prefix {single[i][0]:.2e} body {single[i][1]:.2e}  "
              f"(allocated {torch.cuda.memory_allocated() / 2**30:.2f} GiB)", flush=True)
    sets = {"middle 2..27 (shipped)": range(2, 28), "all 30": range(30)}
    multi = {}
    for label, idx in sets.items():
        multi[label] = measure(list(idx), offload=True)
        print(f"sensitivity {label}: prefix {multi[label][0]:.2e} body {multi[label][1]:.2e}", flush=True)
    after = measure([], offload=False)
    print(f"sensitivity control after the swaps: prefix {after[0]:.2e} body {after[1]:.2e}", flush=True)
    multi["control"], multi["control_after"] = control, after
    report["sensitivity"] = {"single": single, "sets": multi}


# ---------------------------------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--clip", default="/cmp/synth_2160p_blocky.mp4")
    ap.add_argument("--parts", default="ladder,speed,sensitivity")
    ap.add_argument("--block", type=int, default=10)
    ap.add_argument("--rows", type=int, default=2048, help="token rows per layer evaluated in the ladder")
    ap.add_argument("--compile-torchao", action="store_true")
    ap.add_argument("--speed-variants", default="", help="e.g. 'int8 own+fp16 acc16' (default: all)")
    ap.add_argument("--model-dir", default="/m")
    ap.add_argument("--json", default="/out/lab.json")
    args = ap.parse_args()
    parts = args.parts.split(",")
    dev = torch.device("cuda:0")
    frames = read_frames(args.clip, 29)
    print(f"clip {args.clip}: {frames.shape}", flush=True)
    with torch.inference_mode():
        model = load_model(args.model_dir, device=dev)
        prompt = load_file(f"{args.model_dir}/prompt.safetensors")["positive"]
        session = TransformerSession(model, prompt, TILE_H, TILE_W, seed=SEED, compile_blocks=False)
    report: dict = {"clip": args.clip}
    if "ladder" in parts:
        part_ladder(session, model, frames, args.rows, report)
    if "speed" in parts:
        part_speed(session, model, frames, args.block, report, args.compile_torchao, args.speed_variants)
    if "sensitivity" in parts:
        part_sensitivity(session, model, frames, report)
    with open(args.json, "w") as fh:
        json.dump(report, fh, default=str)
    print(f"peak allocated {torch.cuda.max_memory_allocated() / 2**30:.1f} GiB", flush=True)


if __name__ == "__main__":
    main()
