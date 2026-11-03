# Restoration QC, early runs: run 1 and run 2 (FAIL, fixed)

Moved out of `restore-qc.md` on 2026-10-31 (late night) to keep both files under 10,000 bytes; nothing was changed. Run 1 (2026-10-30/31) said FAIL with 4 critical and 3 high findings (BUG-064, BUG-065, BUG-066); run 2 (2026-10-31) said FAIL again with 2 critical, 2 high and 3 medium (BUG-067, BUG-068). Runs 3 to 6 and the open gate are in `restore-qc.md`.

## Run 1: critical (BUG-064)

1. The API entrypoint dropped privileges with `su-exec 1000:1000`, which loads no supplementary groups, so the API never had gid 10001 and every submit failed. Fix: `su-exec 1000`; check `docker exec ... id` after the deploy (MIN-055).
2. The worker entrypoint chowned the 0700 directory before the file, so root (no DAC_OVERRIDE) lost access and the worker exited 1. Fix: chmod file, chown file, then chown directory, plus SETPCAP so the bounding set is emptied (CapEff 0, empty CapBnd).
3. The client keyframe cut was not frame-exact on Matroska with B-frames and hid it by adopting the server's frame count (1260 frames for 960). Fix: seek 0.25 s past the keyframe, `-frames:v` from an EXACT count out of the packet list, check the count and the MD5 of the first decoded frame, never adopt the server's count. Tests compare every piece frame by frame (framemd5) for mkv and mp4.
4. Client assembly crashed on relative paths, Matroska `stream=duration` N/A and mp4 `mov_text`. Fix: absolute paths, a strict total frame check, format durations, subtitles copy, then srt, then drop with a warning.

## Run 1: high, medium, low (BUG-065, BUG-066)

- High: a dead worker left jobs running forever (keepalive 15 s, API reaper `RESTORE_STALE_SECONDS` 900 and `RESTORE_QUEUE_MAX_SECONDS` 86400, client stale timeout 900 s; contract in `restore-job-protocol.md`); the `budget` preset ran the CPU worker out of memory.
- Medium: the `RESTORE_MAX_JOBS` race (atomic reservation), the worker seeing the whole secrets folder, a CPU worker popping GPU jobs (per-engine queues), jobs that cannot succeed accepted (`hdr: preserve` removed, 422).
- Low: nested JSON 500 (now 422), body cap on resolve, `fullmatch` on ids, consistent error shapes, `Dockerfile.cpu` follows `TARGETARCH`, friendly `probe_media` errors, no recipe for HDR sources.

## Run 2: findings and fixes (BUG-067, BUG-068)

Which finding was critical, high or medium was not recorded per item; the fixes are grouped by area.

- **Memory budget** (`restore_core/budget.py`). The first version underestimated. Measured on the real GPU worker (cgroup anon): 161 frames of 2160p with recavsr 16.5 GiB, 241 frames 24.3 GiB (0.0975 GiB per frame); classical CPU 640x360 to 2160p at 25/50/100 frames 5.7/7.4/10.2 GiB (ffmpeg 4.4 to 5.8 of it); engine `none` at 2160p with the heavy chain at 16/40 frames 3.8/5.7 GiB (QC, laptop VM); the encoder alone 7 to 8 GiB. Now an envelope: recavsr 4.5 output frames per frame + 1.5 GiB; classical 3.5 frames + 1 GiB + 0.55 GiB per output Mpx; `none` 5.0 frames + the same. Outputs with a side above 16384 are refused, and the worker re-checks its own cgroup. GPU worker `mem_limit` and `memswap_limit` 20g to 22g, `RESTORE_GPU_WORKER_MEMORY_MB` 22528, `cleanup-4k` `segment_max_seconds` 6 (a 241-frame 2160p segment OOM-killed a 24g worker in a live run, the guard now refuses it). The encoder OOM-kill gets its own message.
- **Secrets**. A fifth secret, `restore_worker_redis_password`, for a restricted Redis ACL user `restore-worker`: only the `restore:queue/job/cancel/worker` keys and `brpop hset hgetall get expire ping client|setinfo`, tested against a real Redis. The lifecycle script compares with the real secret count, the API entrypoint copies the fifth secret, compose mounts it in the API container so `secret-restore` round-trips, and the Redis and worker entrypoints refuse a `SHREDDED_FOR_SECURITY` marker as a password.
- **Upload DoS**. `_bound_upload_time`: 30 s idle timeout plus a minimum average of 64 KiB/s after a 30 s grace, on bytes received.
- **Client** (`restore_film.py`). Last-frame check on copy cuts; `preflight()` of the first, middle and last segment; open-GOP sources (x265 default) fall back automatically to a `--cut` transcode (decode, near-lossless SVT-AV1 CRF 8 10-bit closed-GOP piece, checked by frame count and first/last-frame PSNR >= 42 dB on a timestamp-selected source frame); `plan_segments(force_cuts)` splits a GOP longer than `segment_max_seconds` into equal forced pieces (needs transcode); `plan_film()` handles sources that do not start at 0 and fails closed if the plan does not cover the source; stale timer only for running jobs; apostrophe-safe concat; `--cut auto|copy|transcode`. Owner decision: re-encode open-GOP films to a closed GOP without considerable quality loss. Known limit: MPEG-TS with an offset fails closed (MIN-071).
- **Smaller**: grain seeded per ABSOLUTE frame, hdr peak must be at least the reference, minimum frame side 64, `/recipe/resolve` 422 for sparkvsr, `quick_links`, the docs test accepts 2.x.y-secure.
