# M0.4 server spikes: what was actually measured (2026-10-30)

These are the verified results of the first session on the real Proxmox server, run over SSH with a throwaway key that is torn down afterwards (MIN-018). Everything below was observed, nothing is extrapolated, and the unproven parts are said out loud. The LXC is only ever called "the LXC" in tracked files: no IPs, no key material.

## Host and LXC

- Proxmox VE 8.4.14, kernel 6.8.12-15-pve. It is NOT 9.x, so native OCI app containers are not available on this server: IDEA-019 is closed as moot, and Docker-in-LXC is the only path.
- Host NVIDIA driver 580.76.05, two RTX 5080 with 16,303 MiB each.
- The LXC is CT 901, Ubuntu 22.04.5, unprivileged, features `nesting` + `keyctl`, 32 cores, 50,000 MB RAM cap, rootfs 22 GB (ZFS subvol) at the start of the session, resized later the same day (ISSUE-030, below).
- The five device nodes (`nvidia0`, `nvidia1`, `nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools`) were handed to the LXC with `dev0` to `dev4` lines. They are `crw-rw-rw-` on the host, so no idmap work was needed at all (INQUIRY-003 answered: not needed for these nodes). Host RAM was not recorded in this session.

## Inside the LXC

- NVIDIA userspace 580.76.05 from the official `.run` installer with `--no-kernel-modules`, same version as the host module. NVIDIA publishes no checksum file for this release (the URL returned 404), so the only integrity checks available were the installer's embedded md5/crc and TLS to `download.nvidia.com`. The functional proof is `nvidia-smi` matching the host module.
- `nvidia-container-toolkit` 1.20.1 with `no-cgroups=true`, Docker runtime `nvidia` registered. Docker is 28.4.0.
- `nvidia-smi` inside a plain container lists both GPUs.

## Blackwell spike (INQUIRY-002, torch part PASSED)

`pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime` ships sm_120, both GPUs report capability 12.0, and a bf16 matmul runs at about 119-120 TFLOPS per card. torch exposes `float8_e4m3fn`, `float8_e5m2`, `float4_e2m1fn_x2` and `torch._scaled_mm`, which keeps the NVFP4 idea (INQUIRY-029) open. FP4 kernels on sm_120 and CogVideoX quality under NVFP4 are still UNPROVEN. The SparkVSR smoke test ran later the same day on both GPUs and INQUIRY-002 is complete; the numbers are in `m3-benchmark.md`. Script: `tools/scripts/ops/gpu_smoke_test.py` (new, uncommitted at the time of writing).

## Licences (INQUIRY-011, partly answered)

- `JiongzeYu/SparkVSR` on Hugging Face is a full diffusers-format pipeline (transformer, text_encoder, vae; 39.3 GiB, 28 files), tagged `apache-2.0`, not gated.
- `zai-org/CogVideoX1.5-5B-I2V` (28.9 GiB) is tagged `license:other`, the CogVideoX licence. Read the card before M3 for the personal-use terms.
- The SD 2.1 base and the PiSA-SR weights needed for `ref_mode=pisasr` were NOT located (the API call for `stabilityai/stable-diffusion-2-1-base` failed). Still open.

## Storage blocker (ISSUE-030, resolved)

The LXC rootfs was 22 GB and the torch image alone took it to 13 GB used, while the SparkVSR weights are 39.3 GiB. RAM was not an option, since the LXC cap is 50 GB and weights in tmpfs would eat 39 GB of it. The owner picked the resize: rootfs +70G, so 92 GB in total with 85 GB free. The SparkVSR weights now sit in a host directory in the LXC: 28 files, 42.2 GB (39.3 GiB), with the SHA-256 of all 14 LFS files verified against the Hugging Face listing and 0 mismatches. Weights are public artifacts, not user media, so they may live on normal disk: the RAM-only rule covers media only.

## TrueNAS storage idea (INQUIRY-031)

The owner wants to move the LXC storage to a TrueNAS dataset (TrueNAS runs as a Proxmox VM with the storage controller passed through), isolated and encrypted. Recorded constraints:

- Docker `overlay2` does not work on NFS, so the Docker data root must stay on block storage (local ZFS or an iSCSI zvol).
- ZFS native encryption protects data at rest only, and the unlock key has to be available at boot.
- The TrueNAS VM must boot before the LXC.
- Suggested use for now: read-only weights on an encrypted dataset, mounted into the LXC from the host.

## Thermal and PCIe check (2026-10-30, `tools/scripts/ops/gpu_thermal_check.py`)

Both cards loaded for 120 s with a bf16 matmul loop, sampled with `nvidia-smi`:

| | GPU 0 | GPU 1 |
|---|---|---|
| Max temperature | 69 C | 87 C |
| Fan | 44% | 100% |
| Power | 308 W | 319 to 332 W |
| SM clock | 2814 MHz, steady | 2707 to 2797 MHz |
| Throttle | none | software thermal slowdown bit seen |
| PCIe under load | gen4 x8 | gen4 x16 |
| Host-to-device bandwidth | 14.5 GB/s | 28.8 GB/s |

An 11 GB offload takes about 0.8 s on GPU 0 against 0.4 s on GPU 1. GPU 1 ALONE for 240 s with GPU 0 idle still reached 85 C max (average 81.9, last half 83.2), fan 93%, 326 W, clock 2789 MHz, no throttle, so the heat does not come from the neighbour's load. The owner's diagnosis is that the card next to it blocks the airflow. The undervolt or power-cap phase is planned at the END of the project (MIN-037); candidate: a power cap of about 300 W on GPU 1, set on the Proxmox host with `nvidia-smi -pl`, which resets on reboot. Not applied, not tested.

## Teardown facts (MIN-018)

- `sshd` in the LXC is socket-activated, so teardown must disable BOTH `ssh.socket` and `ssh.service`, otherwise the socket brings it back.
- The Mac reaches the LXC over a different interface than the Wi-Fi one. The key was locked with the correct source IP after a first failed login, where the `from=` lock rejected the wrong IP exactly as designed.
