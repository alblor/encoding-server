# Restoration job protocol (API and worker)

The contract between the API container (Alpine, keeps the keys, owns encryption) and the restore worker (glibc, GPU, never sees a key).
A job is one segment of a film: a few seconds of picture cut by the client on a scene change. Everything about a job lives in Redis
(state) and in a shared RAM-backed volume (the two media files). Nothing is written to a disk.

## Redis keys (the existing password-protected `redis-secure`)

| Key | Type | Written by | Meaning |
|---|---|---|---|
| `restore:queue:recavsr`, `restore:queue:classical`, `restore:queue:none` | lists | API `LPUSH`, worker `BRPOP` | job ids waiting for that engine, oldest popped first |
| `restore:job:{id}` | hash | both | job state, fields below |
| `restore:cancel:{id}` | string `"1"` | API | the worker polls it between chunks and stops |

One queue per engine, on purpose: the API pushes a job to the queue of its effective recipe `basic.engine`, and a worker `BRPOP`s only the queues of the engines it can run, so a CPU worker never pops a `recavsr` job and fails it. `sparkvsr` has no queue: it is rejected at submit with 422.

The worker does not use the main Redis password: it authenticates as the ACL user `restore-worker`, who can only touch the keys above (`stack.md`). Uploads are bounded in time as well as in size: a 30 s idle timeout and a minimum average of 64 KiB/s after a 30 s grace, counted on bytes received (`_bound_upload_time` in `api/app/restore/router.py`). The worker re-checks its own cgroup memory against the budget (`restore_core/budget.py`) before it starts.

`{id}` is a 32-character lowercase hex id made by the API (matched with `fullmatch`). Hash fields, all strings:

| Field | Values | Written by |
|---|---|---|
| `status` | `queued`, `running`, `done`, `failed`, `cancelled` | API sets `queued`; worker sets the rest |
| `stage` | `""`, `decode`, `restore`, `encode` | worker |
| `progress` | `0.0` to `1.0` of the whole job | worker |
| `error` | short text, empty unless `failed` | worker |
| `recipe` | the EffectiveRecipe as JSON (`restore_core.recipe`) | API, after `resolve()` |
| `first_frame` | integer: absolute index of the segment's first frame in the film, seeds the grain | API, from the client |
| `segment_index` | integer, informational | API |
| `frames`, `width`, `height` | integers of the result | worker, on `done` |
| `seconds` | float, wall time of the job | worker, on `done` |
| `worker` | worker name, for example `gpu0` | worker |
| `created_at`, `updated_at` | ISO 8601 UTC; while a job runs the worker refreshes `updated_at` every 15 s (keepalive) | API, worker |

A finished hash (`done`, `failed`, `cancelled`) is given a 24 h expiry by whoever wrote the terminal status.

## Shared volume

A tmpfs volume mounted at `/restore-work` in both containers. Per job a directory `/restore-work/{id}/`, mode 0770, group `restore`
(gid 10001, the worker's group; the API user is a member). The API entrypoint must drop to `su-exec 1000`, NOT `1000:1000`: the second form does not load supplementary groups, the API then misses gid 10001 and every submit fails (BUG-064). The API writes `in.mkv` (already decrypted) before it pushes the job. The
worker writes `out.mkv` and then sets `done`. The API deletes the whole directory (overwrite, then unlink, as the existing secure delete
does) when the client deletes the job, when a job is cancelled, and on expiry. The worker never deletes `in.mkv` of a job it did not finish.

## Lifecycle

1. API validates the request (recipe through `restore_core.recipe.resolve`, size limit, content), decrypts the upload into
   `in.mkv`, creates the hash with `status=queued`, then `LPUSH restore:queue {id}`.
2. Worker pops an id, sets `status=running`, runs the pipeline, updates `stage` and `progress`, polls `restore:cancel:{id}`.
3. On success the worker writes `out.mkv`, sets `done` with `frames`, `width`, `height`, `seconds`. On failure it sets `failed` with `error`
   and removes `out.mkv`. On cancel it sets `cancelled` and removes `out.mkv`.
4. The client polls status, then downloads. The API encrypts `out.mkv` for the client the same way the existing jobs do, and serves it.
5. The client deletes the job; the API wipes the directory and the Redis keys.

Dead workers and old jobs (reaper in the API). A running job whose `updated_at` is older than `RESTORE_STALE_SECONDS` (default 900) is failed with "the worker stopped responding", and a queued job older than `RESTORE_QUEUE_MAX_SECONDS` (default 86400) is failed with "expired in the queue". Cancel and delete of a stale job complete normally. The client has its own stale timeout of 900 s. Other API limits: `RESTORE_MAX_SEGMENT_MB` default 2048, `RESTORE_MAX_JOBS` default 64 (reserved atomically, so parallel submits cannot overshoot).

## Encryption

Handled entirely by the API, with the existing `EncryptionManager` and the same `automated` and `manual` meanings as `/v1/jobs`. A third mode
`off` skips the crypto layer only: the media still lives only in RAM, the network stays internal, cleanup is unchanged. On the wire `automated` and `off` are identical (plaintext over TLS, as for `/v1/jobs`). The worker always sees plaintext
and never a key. That is the one change to the security model and it is documented in `rules/restoration-design.md`.

## Endpoints (API side, all under `/v1/restore`, same authentication as `/v1/jobs`)

| Method and path | Purpose |
|---|---|
| `GET /v1/restore/presets` | preset names with their descriptions and the resolved recipe of each |
| `POST /v1/restore/recipe/resolve` | validate a recipe request and return the EffectiveRecipe, nothing is queued |
| `POST /v1/restore/jobs` | multipart: `file` (the segment), `recipe` (JSON, a RecipeRequest), `first_frame` (int), `segment_index` (int), `decryption_password` (manual mode only); returns the job id, the effective recipe and the status |
| `GET /v1/restore/jobs/{id}` | status, stage, progress, error, result size when done |
| `GET /v1/restore/jobs/{id}/download` | the result, encrypted as the job's mode says |
| `POST /v1/restore/jobs/{id}/cancel` | stop a queued or running job |
| `DELETE /v1/restore/jobs/{id}` | wipe the job's files and keys |
| `GET /v1/restore/capabilities` | engines the attached workers can run (`none`, `classical`, `recavsr`), `queue_length` plus a per-engine `queues` breakdown, workers seen in the last minute |

Values the pipeline cannot honour are refused at submit with 422, not accepted and failed later: `sparkvsr` as engine, and `hdr: preserve`, which was removed from the schema. Nested JSON mistakes answer 422 too, never 500.

Errors use the same shape as the existing API. Every field of the recipe is documented in `/v1/docs` (the three tiers) the way the existing
endpoints are.
