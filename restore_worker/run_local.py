"""Run a directory of segments through the restoration pipeline on one device, with one resident engine.

This is the worker's inner loop without the queue: it is how a batch is run by hand, on the server, and
how the pipeline is tested on real footage. Segments are processed in name order; the absolute index
of each segment's first frame (which seeds the grain) is the running total of the frames before it.

usage: python -m restore_worker.run_local --recipe recipe.json --segments DIR --out DIR
                                          [--device cuda:0] [--model-dir /m] [--only 0,2,4]
Prints one JSON line per segment (frames, size, seconds, per-stage times) and a summary at the end.
The recipe file is a RecipeRequest: {"preset": "...", "basic": {...}, "advanced": {...}}.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from restore_core.recipe import resolve
from restore_worker.pipeline import SegmentJob, probe, run_segment


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipe", type=Path, required=True)
    ap.add_argument("--segments", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--device", default="cuda:0")
    ap.add_argument("--model-dir", type=Path, default=Path("/m"))
    ap.add_argument("--only", help="comma-separated segment positions to process, for splitting work across GPUs")
    args = ap.parse_args(argv)

    recipe = resolve(json.loads(args.recipe.read_text()))
    segments = sorted(args.segments.glob("*.mkv")) + sorted(args.segments.glob("*.mp4"))
    if not segments:
        print("no segments found", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)

    # Absolute frame offsets come from the whole list, even when this process only handles some of it.
    offsets, total = [], 0
    for seg in segments:
        offsets.append(total)
        total += probe(seg).frames or 0
    wanted = {int(i) for i in args.only.split(",")} if args.only else set(range(len(segments)))

    engine = None
    if recipe.basic.engine == "recavsr":
        from restore_worker.recavsr_tiled import RecavsrTiledEngine
        t = time.perf_counter()
        engine = RecavsrTiledEngine(args.model_dir, args.device, precision=recipe.advanced.restore.precision or "bf16",
                                    decoder=recipe.advanced.restore.decoder, seed=recipe.advanced.restore.seed)
        print(json.dumps({"event": "engine_loaded", "seconds": round(time.perf_counter() - t, 1)}), flush=True)

    device = args.device if engine is not None else "cpu"
    done_frames, started = 0, time.perf_counter()
    for index, seg in enumerate(segments):
        if index not in wanted:
            continue
        job = SegmentJob(seg, args.out / (seg.stem + ".mkv"), recipe, first_frame_index=offsets[index])
        result = run_segment(job, engine, device=device)
        done_frames += result.frames
        print(json.dumps({"event": "segment", "segment": seg.name, "index": index, "first_frame": offsets[index],
                          "frames": result.frames, "size": f"{result.width}x{result.height}",
                          "seconds": round(result.seconds, 1),
                          "stages": {k: (round(v, 1) if isinstance(v, float) else v) for k, v in result.stages.items()}}), flush=True)
    elapsed = time.perf_counter() - started
    print(json.dumps({"event": "done", "frames": done_frames, "seconds": round(elapsed, 1),
                      "seconds_per_frame": round(elapsed / max(done_frames, 1), 3)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
