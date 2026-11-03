# GPU undervolt and fan policy on the Proxmox host (MIN-037, complete 2026-11-03)

Read this before touching the power limit, the V/F curve or the fans of the two RTX 5080 Founders Editions, and before you update the NVIDIA driver on the host. The follow-ups are MIN-108, MIN-109 and INQUIRY-110 (`roadmap-v8.md`).

## Why it exists

GPU 1 sits right above GPU 0's exhaust and on 2026-10-30 it was at 87 °C with 100% fan under dual load. The goal was never the silicon lottery for +10-15% speed, but a very stable configuration with less power and less thermal stress. The campaign ran from 2026-11-01 to 2026-11-03 (driver 580.76.05, VBIOS 98.03.3B.00.01 on both cards, both GPUs loaded at the same time like in production), and its end result is what runs on the host today.

## What runs on the host

| Part | Where | What it does |
|---|---|---|
| `gpu-profile.service` | `/etc/systemd/system`, oneshot, `Before=pve-guests.service` | at boot: power limit 300 W and the V/F curve flat at 2850 MHz with +450 MHz below it, on both cards, then reads every point back |
| `gpu-fan-policy.service` | `/etc/systemd/system`, `Type=notify` | the fan loop: reads each card's temperature every 3 s and writes the fan speed |
| scripts | `/opt/gpu-profile` | `gpu_profile.py` (apply / verify / fans / fans-auto / reset), `gpu_ctl.py`, `vf_curve.py`, `vf_read.py`, vendored `pynvml.py` (nvidia-ml-py 13.580.126) |
| settings | `/etc/default/gpu-profile` | see below |

Installed on 2026-11-03 at 20:33 with `install.sh`, enabled, profile verified, 0 Xid. Persistence mode is left Enabled, because the unit owns it now. Nothing here survives a reboot by itself, hence the units: PL, curve and manual fan speeds are all volatile.

The restore kit (the exact installed files + `SHA256SUMS` + a README, with the restore steps) is on the owner's Mac in the owner's HomeLab folder for the Proxmox host (`~/Desktop/HomeLab/`, subfolder `gpu-undervolt-min037`; the literal path is in the gitignored root `CLAUDE.md`). Its source is `tools/sandbox/gpu-tuning/deploy/`.

Settings in `/etc/default/gpu-profile`:

- **GPU_PROFILE_CURVE / OFFSET / PL (2850 / 450 / 300)**: the certified profile, change them only to another certified one.
- **GPU_PROFILE_DRIVER (580.76.05)**: the pin, see below.
- **GPU_PROFILE_FAN_OFFSET (15)**: points added to the stock fan curve, 0 gives back the stock curve (still software-driven).
- **GPU_PROFILE_HOT_C / HOT_PCT (82 / 85)**: the hot floor, `HOT_C=200` disables it. `TAKE_C`, `RELEASE_C` and `COOL_S` are constants at the top of `gpu_profile.py`.

After an edit: `systemctl restart gpu-profile gpu-fan-policy`.

## The driver pin

The curve is written through undocumented NvAPI calls (function IDs from nvcurve 0.5.0, re-verified on these cards), so the unit applies it only on driver 580.76.05, reads every point back, and leaves the cards at stock if the driver is different or anything does not match, saying so in the journal. After a driver update the profile therefore stays at stock on purpose: re-validate first (MIN-109), then change `GPU_PROFILE_DRIVER`. NVML does not see the curve deltas (`nvidia-smi` shows offset 0 while the curve is edited), so checks must read the curve itself (`vf_curve.py show` or `gpu_profile.py verify`), and setting the NVML offset to 0 wipes the curve, so the two can never be stacked.

## Results (measured 2026-11-01 to 2026-11-03)

Against stock, on both cards: 22-25% less energy per frame on ReCaVSR (25.4% on GPU 0, 22.3% on GPU 1) with the output bit-identical to stock, 110-122 mV less core voltage on the real workload (977 / 996 to 867 / 874 mV), 2-5% faster matmul and 0.3-1.7% faster ReCaVSR. Certification of 4 h 15 min, every test PASS and 0 Xid: 30 min matmul, 130 load/idle bursts, 30 min gpu-burn, memtest_vulkan, 2 h ReCaVSR with 206 of 206 rounds identical to stock. It sits 40 MHz under +490, the highest offset passed on both cards. GPU 1's heat is the stacking and not the card: with GPU 0's fans at 100%, GPU 1 at the same 300 W went from 84 °C to 74 °C.

The clock lock was a dead end on GPU 1 (2 corrupted load/idle transitions out of 66 even at +0), and on GPU 0 a lock with +420 or more throws Xid 62 at idle. The curve flatten has 496 clean transitions on GPU 1, none bad, hence the profile uses the curve on both cards. Below about 250 W you only lose speed, because GPU 1's stock curve has a voltage floor around 840-850 mV.

If production ever shows a fault: back off by 60 MHz of offset (2850 +390, round `b2`), or use 2700 +360 (`v2`, the most efficient fallback measured). Both are screening results of about 12 minutes, not certified for hours.

## Fan policy (owner's choice, 2026-11-03)

The driver has no fan curve offset, so the +15 is a software curve, like LACT and MSI Afterburner do it.

- **Curve**: the stock curve measured in the campaign (about 110k samples with the fans on auto) + 15 points, 30-100%: 53% at 50-62 °C, 60% at 69, 71% at 83, 100% from 86.
- **Zero-RPM**: the firmware keeps control until 50 °C, and gets it back at 39 °C or less once the ramp is over. Taking over earlier would make the fans cycle at idle (an idle card parks at ~40 °C).
- **Cool-down**: speed goes up at once, comes down with a quadratic ease-in over 30 s under 50 °C, 1 min in the 50s, 2 min in the 60s, 4 min in the 70s, 10 min from 80 °C.
- **Hot floor**: every card at 85% or more while any card is above 82 °C, off at 80 °C, then the 10 min ramp.
- **Safety**: a manual fan speed outlives the process that set it, so the unit has a 30 s watchdog, `Restart=always` (15 s) and an `ExecStopPost` that gives both cards back to the firmware however the loop ended.

Be precise about what was tested: the 4 h 15 min certification ran with GPU 0's fans forced to 80% (85% from the moment GPU 1 reached 85 °C), not with this policy. The policy itself has the screening round f01 (PASS on both cards, GPU 1 peaked at 84 °C), the live fan tests f02 and f03, and the crash tests on the host (`kill -9`, `SIGSTOP` with the watchdog, `SIGTERM`, manual fans left at startup: all end with the cards on auto).

The installed build, with the QC fixes, was also verified live on 2026-11-03 at 20:39-20:47 with a 3.5 min bf16 load on both GPUs from the LXC: the loop took over from zero-RPM, tracked stock + 15 (GPU 0 58 °C at 53%, GPU 1 79 °C at 68%) and ramped down after the load.

## Verify, and go back to stock

Root login over SSH is disabled on the host by design, and the campaign's temporary access is revoked (below), so these run in the Proxmox web shell as root:

```bash
systemctl status gpu-profile gpu-fan-policy
python3 /opt/gpu-profile/gpu_profile.py verify && echo OK      # PL and every curve point as applied
journalctl -u gpu-profile -u gpu-fan-policy -b
nvidia-smi --query-gpu=index,power.limit,temperature.gpu,fan.speed --format=csv
# stock right now (PL 360 W, curve zero, fans auto), until the next boot or restart
systemctl stop gpu-fan-policy gpu-profile
# remove everything: resets the cards, deletes the files, persistence mode off
sh install.sh uninstall        # from the folder of the restore kit
```

The boot ordering has never been tested with a real reboot (MIN-108). The 300 W power limit is the floor of the Founders Edition, other 5080 models go lower.

## Evidence and tooling

Everything is in the gitignored `tools/sandbox/gpu-tuning/`: `REPORT.md` (every round, the airflow test, the instability island), `results/` (one JSON per round, `telemetry/<round>/` per-second, `host-actions/` with the host's `actions.log` and curve snapshots, `stock-ref/` gzipped with checksums, `cert1*.json`), and the tools `run_config.sh`, `campaign.py`, `analyze.py`, `summarize.py` (`--map 0|1`). Since they are gitignored, a clean checkout does not have them (INQUIRY-110).

## Teardown (done 2026-11-03)

The sshd `Match` block and the key line on the host are reverted (root SSH from the Mac refused again), the key is shredded and `known_hosts` cleared. `/etc/sudoers.d` was checked and untouched. The temp folders on the host and in the LXC are removed (the actions log, curve snapshots and telemetry were copied first), the `gpubench` image is gone, and `/dev/shm/media` was not touched. This is the campaign's host access only: the LXC session key and its teardown stay with MIN-018.
