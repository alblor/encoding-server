"""Sustained-load thermal and PCIe comparison of every visible GPU.

Runs a bf16 matmul loop on all visible GPUs at the same time (the worst case for a box where the
cards sit next to each other), samples nvidia-smi every few seconds, then reports per GPU: temperature,
fan, power, SM clock, throttle reasons and the PCIe link measured under load. It also measures
pinned host-to-device bandwidth per GPU, which is what an 11 GB model offload costs.

usage (inside a CUDA torch container with the utility capability):
    python gpu_thermal_check.py [SECONDS]        # default 120
Throttle bits: 0x1 idle, 0x2 app clocks, 0x4 sw power cap, 0x8 hw slowdown, 0x20 sw thermal, 0x40 hw thermal,
0x80 hw power brake (see nvidia-smi -q -d PERFORMANCE).
"""
import statistics
import subprocess
import sys
import threading
import time

import torch

FIELDS = ("index,temperature.gpu,fan.speed,power.draw,clocks.sm,clocks_throttle_reasons.active,"
          "pcie.link.gen.current,pcie.link.width.current,utilization.gpu")
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 120


def burn(device: int, stop: threading.Event) -> None:
    a = torch.randn(8192, 8192, device=f"cuda:{device}", dtype=torch.bfloat16)
    b = torch.randn(8192, 8192, device=f"cuda:{device}", dtype=torch.bfloat16)
    while not stop.is_set():
        for _ in range(20):
            a @ b
        torch.cuda.synchronize(device)


def sample() -> list[list[str]]:
    out = subprocess.run(["nvidia-smi", f"--query-gpu={FIELDS}", "--format=csv,noheader,nounits"],
                         capture_output=True, text=True, check=True).stdout
    return [[c.strip() for c in line.split(",")] for line in out.strip().splitlines()]


def h2d_bandwidth(device: int, gib: int = 4) -> tuple[float, float]:
    """(pinned GB/s, pageable GB/s) host to device for a gib-sized buffer."""
    results = []
    for pinned in (True, False):
        host = torch.empty(gib * 2**30, dtype=torch.uint8, pin_memory=pinned)
        dev = torch.empty_like(host, device=f"cuda:{device}")
        dev.copy_(host)
        torch.cuda.synchronize(device)
        t0 = time.perf_counter()
        for _ in range(3):
            dev.copy_(host)
        torch.cuda.synchronize(device)
        results.append(3 * gib * 2**30 / (time.perf_counter() - t0) / 1e9)
        del host, dev
    return results[0], results[1]


def main() -> None:
    count = torch.cuda.device_count()
    print(f"{count} GPUs, sustained load for {DURATION}s on all of them")
    idle = sample()
    stop = threading.Event()
    threads = [threading.Thread(target=burn, args=(i, stop), daemon=True) for i in range(count)]
    for t in threads:
        t.start()
    rows: list[list[list[str]]] = []
    end = time.time() + DURATION
    while time.time() < end:
        time.sleep(3)
        rows.append(sample())
    stop.set()
    for t in threads:
        t.join()

    for i in range(count):
        series = [r[i] for r in rows]
        temp = [float(s[1]) for s in series]
        fan = [float(s[2]) for s in series if s[2].replace(".", "").isdigit()]
        power = [float(s[3]) for s in series]
        clock = [float(s[4]) for s in series]
        reasons = 0
        for s in series:
            reasons |= int(s[5], 16)
        half = len(temp) // 2
        print(f"GPU {i}: idle {idle[i][1]} C | load temp start {temp[0]:.0f} max {max(temp):.0f} "
              f"avg {statistics.mean(temp):.1f} last-half avg {statistics.mean(temp[half:]):.1f} C | "
              f"fan avg {statistics.mean(fan) if fan else float('nan'):.0f}% max {max(fan) if fan else float('nan'):.0f}% | "
              f"power avg {statistics.mean(power):.0f} W max {max(power):.0f} W | "
              f"SM clock avg {statistics.mean(clock):.0f} MHz min {min(clock):.0f} max {max(clock):.0f} | "
              f"throttle bits seen 0x{reasons:x} | PCIe under load gen{series[-1][6]} x{series[-1][7]}")
    for i in range(count):
        pinned, pageable = h2d_bandwidth(i)
        print(f"GPU {i}: host->device pinned {pinned:.1f} GB/s, pageable {pageable:.1f} GB/s "
              f"(11 GB model offload: {11 / pinned:.1f}s pinned, {11 / pageable:.1f}s pageable)")


if __name__ == "__main__":
    main()
