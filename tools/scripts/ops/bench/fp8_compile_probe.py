"""Why does torch.compile "hang" on the FP8 ReCaVSR transformer? Time the compile of ONE block, per signature.

Builds a 1152x1344 TransformerSession without compile, then compiles only the chosen middle block(s) with the
exact options TransformerSession uses (fullgraph, dynamic=False, emulate_precision_casts, force_same_precision)
and runs one prefix step plus body steps on random input. Every step is timed, so the compile cost per KV-cache
signature is visible; faulthandler dumps all stacks every --dump-every seconds, which shows where a long compile
spends its time. Run with TORCH_LOGS=recompiles to see each recompilation and its guard failure.

Author: Lorenzo Albanese (alblor)
usage (recavsr-fp8 image, repo on PYTHONPATH, one GPU visible):
  python fp8_compile_probe.py --precision fp8_fast --blocks 10 [--steps 5] [--dump-every 120]
"""
import argparse
import faulthandler
import os
import sys
import threading
import time

import torch
from safetensors.torch import load_file

from recavsr_infer.runtime.transformer import TransformerSession
from recavsr_infer.weights import load_model
from restore_worker.quantize import MODES, quantize_transformer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--precision", default="fp8_fast", choices=MODES)
    ap.add_argument("--blocks", default="10", help="comma-separated block indices to compile, or 'all'")
    ap.add_argument("--steps", type=int, default=5, help="1 prefix step then body steps")
    ap.add_argument("--dump-every", type=int, default=120)
    ap.add_argument("--model-dir", default="/m")
    ap.add_argument("--give-up", type=int, default=0, help="dump all stacks and exit after this many seconds")
    ap.add_argument("--torchao-inductor-config", action="store_true",
                    help="apply torchao's recommended_inductor_config_setter() (what quantize_ did by default)")
    args = ap.parse_args()
    faulthandler.dump_traceback_later(args.dump_every, repeat=True, file=sys.stderr)
    if args.give_up:
        def give_up():
            print(f"GAVE UP after {args.give_up} s", flush=True)
            faulthandler.dump_traceback(file=sys.stderr)
            os._exit(3)
        threading.Timer(args.give_up, give_up).start()
    if args.torchao_inductor_config:
        from torchao.quantization.utils import recommended_inductor_config_setter
        recommended_inductor_config_setter()

    dev = torch.device("cuda:0")
    with torch.inference_mode():
        model = load_model(args.model_dir, device=dev)
        prompt = load_file(f"{args.model_dir}/prompt.safetensors")["positive"]
        print("quantization", quantize_transformer(model, args.precision), flush=True)
        session = TransformerSession(model, prompt, 1152, 1344, compile_blocks=False)
    torch._dynamo.config.recompile_limit = 64
    indices = range(len(session.cores)) if args.blocks == "all" else [int(i) for i in args.blocks.split(",")]
    options = {**torch._inductor.list_mode_options("default"),
               "emulate_precision_casts": True, "force_same_precision": True}
    for i in indices:
        session.cores[i] = torch.compile(session.cores[i], fullgraph=True, dynamic=False, options=options)
    cfg = torch._inductor.config
    print(f"compiling blocks {list(indices)}; inductor coordinate_descent_tuning={cfg.coordinate_descent_tuning} "
          f"check_all_directions={cfg.coordinate_descent_check_all_directions}", flush=True)

    gen = torch.Generator(device=dev).manual_seed(0)
    for step in range(args.steps):
        frames = 21 if step == 0 else 8
        lq = torch.rand((1, 3, frames, 1152, 1344), generator=gen, device=dev) * 2 - 1
        torch.cuda.synchronize()
        t0 = time.perf_counter()
        with torch.inference_mode():
            session.step(lq)
        torch.cuda.synchronize()
        print(f"step {step} ({'prefix' if step == 0 else 'body'}): {time.perf_counter() - t0:.1f} s", flush=True)
    faulthandler.cancel_dump_traceback_later()
    os._exit(0)                     # the give-up timer thread must not keep the process alive


if __name__ == "__main__":
    main()
