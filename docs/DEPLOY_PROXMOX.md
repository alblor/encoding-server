# 🎞️ Deploying the restoration feature on Proxmox (Docker-in-LXC, NVIDIA GPUs)

**The optional GPU side of the encoding server, set up on a Proxmox LXC with two RTX 5080, step by step.**

## Why this guide exists

I wanted my movies restored and re-encoded to AV1 without them ever touching a disk outside my own server, so the restoration feature lives inside the encoding server I already had: same API, same Redis, same encryption, plus one worker container per GPU. This guide is the exact path that worked on my machine (Proxmox VE 8.4.14, host driver 580.76.05, two RTX 5080 with 16 GiB each, an unprivileged Ubuntu 22.04 LXC), written after doing it, not before. If your hardware differs, the reasoning behind each step should still hold, though the versions will not.

The default stack does not change at all if you skip all of this: the GPU workers are a compose profile (`gpu`) that nobody starts by accident.

## What you end up with

- The API (`secure-encoding-api`) and Redis exactly as before, plus `restore-worker-gpu0` and `restore-worker-gpu1`, each pinned to one card.
- Workers on an internal-only network: they reach Redis and nothing else, no internet. Media passes between the API and the workers through a RAM-backed volume (`restore-work`), never a disk.
- Weights on disk, read-only inside the workers. They are public files, not your media, so the "RAM only" promise covers media and not these.

## Before you start

- A Proxmox VE host with the NVIDIA driver already installed and working (`nvidia-smi` on the host lists your cards).
- An LXC with `nesting` and `keyctl` enabled. Mine is unprivileged, 32 cores, 50,000 MB of RAM and a 92 GB root disk. The disk is not a detail: the worker image is 6.35 GB and the weights are 10.8 GB, so do not start from a 22 GB rootfs like I did.
- RAM: a worker may use up to 22 GB of it per GPU (a 2160p segment of 161 frames peaked at 16.5 GiB when I measured it: two frame arrays, the AV1 encoder and the engine), plus the RAM volume (8 GB by default). Both cards busy at the same time can take 44 GB between them, and the API, Redis and the rest of the container need a few more, so my 50,000 MB is about the least that is safe. The 8 GB of the RAM volume is a cap and not a reservation (it only holds compressed segments, a few hundred MB at a time), but do not size the LXC below the workers' total.

- If an older version is already running in the same LXC, do not delete or overwrite its folder: move it aside (`mv ~/encoding-server ~/encoding-server.old`) and keep its `.secrets.backup` untouched, it can hold the only copy of your previous secrets. The new folder starts from fresh secrets (Step 5), so anything encrypted with the old ones needs the old stack to be read.

## Steps

**Step 1: Hand the GPU device nodes to the LXC**

On the Proxmox host, one `dev` line per node. I needed five (`/dev/nvidia0`, `/dev/nvidia1`, `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`), as `dev0` to `dev4` in the container config:

```bash
pct set <CTID> -dev0 /dev/nvidia0 -dev1 /dev/nvidia1 -dev2 /dev/nvidiactl -dev3 /dev/nvidia-uvm -dev4 /dev/nvidia-uvm-tools
```

On my host these nodes are world-readable and writable (`crw-rw-rw-`), so I needed no idmap work for the unprivileged LXC. Check yours with `ls -l /dev/nvidia*` before assuming the same. Restart the container afterwards.

**Step 2: Install the NVIDIA userspace inside the LXC, same version as the host**

Use the official `.run` installer for the SAME version the host module has, with `--no-kernel-modules` (the LXC shares the host kernel, it must not try to build one):

```bash
sh NVIDIA-Linux-x86_64-580.76.05.run --no-kernel-modules
nvidia-smi
```

`nvidia-smi` inside the LXC has to show your cards and the same driver version as the host. A mismatch is the most likely thing to go wrong here. Note that NVIDIA publishes no checksum file for this release (the URL answered 404 when I looked), so the integrity checks you get are the installer's own and TLS to `download.nvidia.com`.

**Step 3: Docker and the NVIDIA container toolkit**

Install Docker (I run 28.4.0) and `nvidia-container-toolkit` (1.20.1). Two settings matter in an LXC: the `nvidia` runtime has to be registered with Docker, and the toolkit needs `no-cgroups = true`, because an unprivileged container cannot manage device cgroups itself. Then prove it from inside a plain container:

```bash
docker info | grep -i runtimes
docker run --rm --runtime=nvidia -e NVIDIA_VISIBLE_DEVICES=all ubuntu:22.04 nvidia-smi
```

Both cards should be listed. If they are not, stop here: nothing later will fix it.

**Step 4: Get the code and configure it**

```bash
git clone https://github.com/alblor/encoding-server.git && cd encoding-server
cp .env.example .env
```

Edit `.env`. Two values are not optional on a server:

- `COMPOSE_PROJECT_NAME=encoding-server`: the secret lifecycle script derives the container name from it.
- `API_BIND_ADDR`: the address of the LXC interface your other machines reach. The default is loopback, which means nothing outside the LXC can connect. Never use `0.0.0.0` without a firewall in front.

The rest of `.env.example` is documented inline (`RESTORE_WORK_SIZE`, `RESTORE_PRECISION`, the worker memory numbers). `.env` is gitignored, keep it that way.

**Step 5: Secrets**

```bash
./scripts/generate_secrets.sh
```

This writes five secrets into `./secrets` (gitignored): the JWT secret, the master key, the Redis password, the API master key and a separate Redis password for the workers. The workers do not use the main Redis password: they log in as a restricted Redis user that sees only the restore queues and job records, so a compromised ffmpeg inside a worker cannot read an encryption key.

When `make gpu-up` shreds the host copies it can keep an encrypted backup of them, but only if you point `SECRET_BACKUP_PASSPHRASE_FILE` at a file holding a passphrase you keep somewhere else. Without it no backup is made, which is the safer default: the secrets stay recoverable from the running containers (`make gpu-down` restores them), and an archive whose passphrase nobody kept is of no use to anyone.

**Step 6: Build and stage the weights**

```bash
make gpu-build
make gpu-weights
```

`make gpu-weights` fetches the ReCaVSR weights in a throwaway container (the workers themselves have no network), checks the three files against pinned SHA-256 values and leaves them in `/srv/models/recavsr` (change it with `RESTORE_MODELS_DIR`). It also stages the two small detectors the face and head guard of the `cleanup-4k` preset needs, `yunet.onnx` and `yolox.onnx`, with the host's `curl` and checks them against pinned SHA-256 values too, so the host needs `curl` and internet for this step. Run it again any time: if everything is already there and verified it just says so.

**Step 7: Start it**

```bash
make gpu-up
make gpu-status
```

`gpu-up` first creates the compile cache folder (`RESTORE_CACHE_DIR`, `/srv/cache/restore` by default) and hands it to uid 10001, because the workers run as that user and Docker would otherwise create the folder as root and the first job would fail on a permission error, so run it as root as in the LXC. It then starts the stack, waits a few seconds and shreds the host copies of the secrets (they live in the containers' RAM from then on). `gpu-status` lists the containers and asks the API which engines it can reach: `gpu0` and `gpu1` should both show `recavsr`. Warning: after the shred, never restart a single container by hand, they would find no secret to read. Use `make gpu-down` and `make gpu-up`, that restores and re-shreds them for you.

**Step 8: Check the hardening did what it says**

```bash
docker exec -u 1000 encoding-server-secure-encoding-api-1 id   # the app user: groups 1000 and 10001
docker exec encoding-server-restore-worker-gpu0-1 grep -E 'Uid|CapEff|CapBnd' /proc/1/status
```

The API process has to be in group 10001 (that is how it writes into the shared job folders), and the worker has to run as uid 10001 with `CapEff` and `CapBnd` all zeros.

**Step 9: Run a film**

From any machine that reaches the API, with the client tools:

```bash
python client-tools/probe_media.py MOVIE                    # what the film is and which recipe it gets
python client-tools/restore_film.py MOVIE --preset cleanup-4k --api-url https://HOST:8443 --limit-segments 3
```

Do the three-segment trial first, look at the result on your own screen, and only then drop `--limit-segments`. A full film is many hours of GPU time (measured in bf16: about 0.82 s per 2160p frame end to end on one card, so around 20 hours for a two hour film on two cards; `fp8` is faster in the transformer, I have not timed a whole film with it), and the run is resumable: run the same command again and it picks up where it stopped.

## Choices you will want to look at

**RESTORE_PRECISION (Default: bf16)**: the transformer precision of the workers. `fp8` is about 1.4x faster in the transformer and saves 3.5 GiB of VRAM, at 46.8 dB against bf16 on detailed 49-frame test clips. The error grows along a segment and resets at every cut, so keep segments short with it. It applies to every worker started afterwards.

**RESTORE_WORK_SIZE (Default: 8g)**: the RAM volume that carries compressed segments between API and workers. It lives in host RAM, so do not set it past what the machine can spare.

**RESTORE_GPU_WORKER_MEMORY_MB and RESTORE_CPU_WORKER_MEMORY_MB**: what the API assumes a worker has, to refuse a segment that cannot fit (422 with the number of frames that would) instead of letting a worker be killed for running out of memory. Keep them equal to the `mem_limit` of the worker services.

**No NVIDIA card, still want to try it**: the `cpu` profile starts a worker for the `classical` and `none` engines, which is how the whole feature gets tested on a laptop.

## Heat

My two cards do not run the same. The second one sits right under the first and runs about 16 degrees hotter under the same load (87 C against 69 C after two minutes of matmuls, with the fan at 100%). A power cap on the host (`nvidia-smi -pl <watts>`) is the thing I plan to try, and it resets on reboot. I have not applied or tested it yet, so treat it as an idea and not as a recommendation.

## Taking it down, and SSH

`make gpu-down` restores the secrets from the containers and stops everything. If you used SSH for the setup and want to close it afterwards: in an LXC, `sshd` is socket-activated, so disabling only `ssh.service` is not enough, the socket brings it back. Disable both (`systemctl disable --now ssh.socket ssh.service`), and only after you are sure you can still reach the container from the Proxmox console or web UI.

## Author Information and Licensing

Lorenzo Albanese (alblor). The restoration engine is ReCaVSR (kopper/ReCaVSR, pinned to a commit in `restore-worker/Dockerfile.gpu`, weights pinned by revision in `scripts/stage_restore_weights.sh`), used with its own licences; they are not redistributed by this repository. The encoder is a pinned static ffmpeg build with SVT-AV1 4.2.0, checked against its published SHA-256.

DISCLAIMER: this is a home setup written down after it worked, not a hardened product. Restore only media you have the right to process, and read the licences of the weights you download.
