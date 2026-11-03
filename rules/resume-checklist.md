# Resume checklist: what to do next, in order

For the working agent after a context compaction. Read `polishing-log.md` and `polishing-log-2.md` (why things are the way they are, the second one has v8 and the open blur question), `roadmap-v8.md` (IDs 100 on), `restore-qc.md` (what failed, what was fixed, which re-check is open), `restore-finishing-features.md`, `restore-face-guard.md` and `restore-shadow-texture.md` (the newest stages) and `HISTORY.md` (first entry) before acting. Written 2026-10-31, updated 2026-11-03 (v9, QC gate passed, deploy started).

## State

- Branch `feature/restoration-pipeline` has 4 pushed commits since main: `7c25bde` (compose bind), `d6e552f` (tools), `82a880b` (docs) and the earlier `c54cd40`, `f323d95`, `9ac067f`. `main` is untouched (`32b5058`).
- A LARGE uncommitted tree sat on top until the commits of 2026-11-03 (check `git status --short`): `restore_core`, `restore_worker`, `restore-worker`, `api/app/restore`, `client-tools`, tests, compose, Makefile, `.env.example`, scripts, `rules/`, `docs/DEPLOY_PROXMOX.md`. The version bump to 2.1.0-secure is already in the tree (`api/main.py`, `api/app/documentation.py`; the docs test accepts 2.x.y-secure); the release will be v1.1.0.
- Built and measured since the last checklist: softness match, brightness anchor, FP8 mode, memory-budget envelope, restricted Redis user, upload limits, open-GOP handling in the client, and (night) adaptive softening, the tone block, the colour anchor, grain from the source, the face guard (on and zoom) and the new `cleanup-4k` preset. Late night: shadow texture (deband off, `shadow_weight`, `ac_bias`, quant matrices), the face tracker (shot cuts, wide gate), `face_zoom_mix`, the client probe window. 2026-11-01: head tracks (FEATURE-100), the opt-in glow (MIN-102) and plateau purge (MIN-103). Host suite `make test-restore` expects 215 tests, `make test-restore-worker` (CPU worker image) 138, all passing (session, 2026-11-03).
- QC: runs 1 to 3 FAIL, run 4 PASS WITH CONCERNS, run 5 FAIL (1 critical, fixed), run 6 PASS WITH CONCERNS, **run 7, the numeric merge gate, PASS 4.80** (rounds 3.56, 4.66, 4.80; zero margin). ISSUE-059 is complete. Two areas stay UNVERIFIED for the deploy trial: the AppArmor profile (INQUIRY-116) and the GPU image on the real host (INQUIRY-117). I did NOT promote the `review` rows (BUG-064 to 068 and the rest, list in `restore-qc.md`) to `complete`: confirm that run 7 covered them, then promote and write their outcomes. Scope: `restore-qc.md`, `roadmap-gate.md`.
- The owner's standing authorization (2026-10-30): proceed unattended, interrupt only if results look bad or something is infeasible, up to merge and live deploy of v1.1.0. His go was conditional on QC >= 4.8/5, and 4.80 satisfied it on 2026-11-03: v9 (`cleanup-4k` with `glow` 1.0, MIN-119) is the approved render, and the merge, tag `v1.1.0` and deploy started right after (FEATURE-060, progress). The blur question (INQUIRY-106) is answered: bloom only.
- Standing rules: security first; SSH teardown at the end; never print or write secrets; NO Claude attribution anywhere in git; commits go through the `git-scm-master` agent in the voice of `~/.claude/skills/lory-engineering-voice/SKILL.md`, titles under 72 characters; CLAUDE.md files stay gitignored.

## To do, in order

1. **Re-check gate** (ISSUE-059): done, 4.80. Open from it: promote the `review` rows after confirming coverage (see State), and BUG-113 to BUG-115 are complete (`roadmap-outcomes-2.md`).
2. **The owner's go**: given by the 4.80. He may still change recipe defaults in `restore_core/recipe.py` (`shadow_weight`, `ac_bias`, `face_zoom_mix`, `anchor_amount`, tone, `soften_amount`, `glow`). Still open for him: the original grain (INQUIRY-058, blocks MIN-057), the YubiKey go or no-go (INQUIRY-111, `yubikey-auth-inquiry.md`), the SparkVSR-dependent INQUIRY-010/033 and IDEA-034/039 to close. MiniMax-H3 only if he asks (INQUIRY-099).
3. **Commits** via `git-scm-master` (logical, atomic, Lory's voice, no attribution), push the branch, merge to main (no force), tag `v1.1.0` (FEATURE-060, in progress: check `git log` for how far it got).
4. **Deploy** to the LXC (plan below), then `make gpu-status` must list gpu0 and gpu1; this is where INQUIRY-116 and INQUIRY-117 get checked.
5. **3-segment trial** through the real client from the Mac (`restore_film.py --limit-segments 3`), plus the second-host reachability check of ISSUE-028 (the API is reachable from the Mac only because `API_BIND_ADDR` is set in a `.env` ON THE SERVER; the default is loopback).
6. **SSH teardown** (below) and the final report.

The first `face_guard: zoom` job on a fresh worker compiles about 190 s per crop size, so the 3-segment trial is slower than the following ones, and `cleanup-4k` now uses zoom. Re-measure the film ETA (INQUIRY-017) on the trial. Smaller things still open: MIN-118 (budget omits the zoom arrays), MIN-112 (auth docs), README drift (MIN-021), the "automated vs off" wording (identical on the wire), `make -n` on the gpu targets, MIN-071 (MPEG-TS with an offset), MIN-072 (worker memory against LXC RAM).

## Infra facts

- Proxmox 8.4.14, host driver 580.76.05, two RTX 5080 (16 GiB): GPU 0 links gen4 x8, GPU 1 gen4 x16 and ran about 16 C hotter until the MIN-037 undervolt and fan policy (installed 2026-11-03, `gpu-undervolt.md`; follow-ups MIN-108, MIN-109, INQUIRY-110). GPU 0 is the owner's own benchmark: sessions use GPU 1 ONLY.
- LXC: Ubuntu 22.04, unprivileged, 32 cores, 50,000 MB RAM, 92 GB rootfs with about 35 GB free. Docker 28.4.0, compose v2.39.2, nvidia runtime registered, `no-cgroups = true` in the nvidia container runtime config (all verified 2026-10-31), NVIDIA userspace 580.76.05. The LXC address is known to the working agent only: never write it in a tracked file.
- Memory: the GPU worker has `mem_limit` and `memswap_limit` 22g, `RESTORE_GPU_WORKER_MEMORY_MB` 22528 (`restore-qc.md`). Two workers at 22g plus the 8g RAM volume are more than the 50,000 MB of the LXC if both peak together; the budget guard refuses what cannot fit, the sum is not enforced.
- Server access ONLY through the wrapper script `ssh.sh` in the session scratchpad folder: its path is NOT stored in any file, take it from the session system prompt (restricted throwaway key locked to the Mac's current interface address, `known_hosts` in the same folder). Server scripts: `/srv/src/code/ops/{worker_run.sh, tiled_run.sh, exp_run2.sh}`.
- Weights at `/srv/models/recavsr` (ReCaVSR, SHA-256 verified, revision `b9bc1851e81188848de783203f8cdb0596520828`); the same folder holds `yunet.onnx` and `yolox.onnx`. The SparkVSR weights, code, image and scratch were DELETED on 2026-11-01 with the owner's approval (MIN-107), so the optional SparkVSR engine needs them staged again. Media only in `/dev/shm/media` (RAM).
- The live v1.0.0 install is at `/root/encoding-server`: an OLDER checkout (commit `7c885b7`), not running, no secrets on disk. Its `.secrets.backup` folder holds the owner's previous secrets: NEVER delete it.

## Deploy plan (non-destructive, written up in `docs/DEPLOY_PROXMOX.md`)

1. `mv /root/encoding-server /root/encoding-server.v1.0.0.bak`, keep `.secrets.backup`, then put the merged main in a fresh `/root/encoding-server` (git archive or clone of main).
2. Create `.env` there with `COMPOSE_PROJECT_NAME=encoding-server` and `API_BIND_ADDR` set to the LXC address (never committed). Worker precision comes from `RESTORE_PRECISION` (default bf16).
3. `scripts/generate_secrets.sh` (FIVE secrets now, the fifth is `restore_worker_redis_password`; it prints lengths only), `make gpu-build`, `make gpu-weights` (already staged: verify only; it now also stages the YuNet face model and the YOLOX person model `yolox.onnx` next to the weights, and `.env` may set `RESTORE_MODELS_DIR` and `RESTORE_CACHE_DIR`), `make gpu-up` (runs `gpu-cache` first: bind directory owned by 10001:10001, mode 0750), `make gpu-status`. A secrets backup is opt-in: point `SECRET_BACKUP_PASSPHRASE_FILE` at a file the owner keeps, otherwise none is made.
4. Verify: the API process has groups 1000 and 10001 (`docker exec ... id`); the worker is uid 10001 with CapEff 0 and an empty CapBnd; `secret-status` counts five secrets.

## Teardown (last)

- Remove the throwaway key line from `authorized_keys`; shred the local private key and `known_hosts` in the scratchpad.
- `systemctl disable --now ssh.socket ssh.service` in the LXC, ONLY AFTER confirming the owner has Proxmox console or web access. Verify and report.
- Server cleanup state (2026-11-01): kept are the `encoding-restore-worker` image, `/srv/models/recavsr`, `/srv/src/code` and RAM scratch under `/dev/shm/media`. At the end remove what is still left of the test artefacts (bench images such as `recavsr-bench`, `recavsr-fp8` and dangling ones, `/srv/src/code`, `/dev/shm/media`; the 2026-11-01 report did not say whether the bench images are still there, so check). Keep the weights and the production images.

## Files on the Mac

Comparison material in `~/Downloads/restoration-comparison/` (`short/`, `long/`, `draft_213f/`, `uhd_cleanup/`, `draft_movie/` with `restored_draft_v2` to `v7.mkv` (v8, the approved draft, came later), `variants/` and `abrupt/`); the owner's draft source `~/Downloads/encoding-server/output_av1.mkv` (gitignored).
