# Environment setup, run and test commands

All commands come from the root `Makefile` and run from the repo root. The Makefile is the control panel, prefer it over raw `docker compose`. Compose file: `docker-compose.secure.yml`.

## Desktop (macOS or Linux with Docker)

Prerequisites: Docker + Docker Compose, Python 3.11+ (host side, for the integration tests and `client-tools/`), `jq` and `openssl` (used by `cert-*` targets). The README recommends 48 GB RAM and 8+ cores for real workloads; the compose file reserves 16g and limits 32g for the API.

```bash
bash scripts/generate_secrets.sh     # creates ./secrets/ (4 Docker secrets, gitignored); asks before overwriting
make secure-build                    # docker compose build
make secure-up                       # builds, starts, then shreds secrets from the host (memory-only mode)
make secure-down                     # restores secrets from the container, then stops
make secure-logs | make secure-shell
make secret-status | secret-shred | secret-restore
make cert-status                     # CERT=... KEY=... make cert-upload for an enterprise certificate
make docs                            # prints the /v1/docs access points
make cleanup                         # down -v, prune, delete test results (destructive)
```

API: `https://localhost:8443` (self-signed certificate, use `curl -k`). Health: `/health`.

## Tests

The server must be up (`make secure-up`) before the integration targets, they call the live HTTPS API.

```bash
make test-all          # test-prepare (generate stubs) + test
make test              # unit + encryption + manual + automated + api + docs + progress + cancellation + apparmor
make test-quick        # unit only, runs inside the container (pytest /app/tests/unit/)
make test-docs         # tests/integration/test_documentation_api.py (asserts on /v1/docs content)
make test-apparmor     # tests/test_apparmor_detection.py
```

### Baseline (M0.3, 2026-10-29, pristine v1.0.0)

Run on the Mac in a Colima VM (4 CPU, 8 GiB) from a disposable copy where the `security_opt` AppArmor line was removed, since the VM has no `ffmpeg-isolated` profile loaded. Results: unit 17/17, encryption_stubs 8/8, manual 9/9, automated 12/12, documentation 100%, progress 6/6, cancellation 6/6, api_endpoints 8/11. `test-apparmor` was NOT run: it needs real AppArmor, so it can only be verified on Proxmox. The 3 api_endpoints failures exist on v1.0.0 and are not ours (MIN-024): the test submits manual mode without `decryption_password`, and two error-handling checks expect a top-level `error` field while FastAPI nests it under `detail`.

The suite must stay at least this green. Do not trust the README's 96.2% figure, it is upstream's.

### Quirks found running the suite off the Proxmox target

- Encode tests fail with "moov atom not found" until valid clips exist: `tests/scripts/generate_test_data.py` writes random bytes named `test-media-N.mp4`, and the real samples lived in the gitignored `tests/data/media/`. Valid fixtures should be generated with ffmpeg lavfi under `tools/fixtures` (MIN-025).
- Integration scripts spawn the client tools as subprocesses, so `requests` and `cryptography` must be in the interpreter on PATH. Working invocation: `uv run --with requests --with cryptography python tests/integration/<test>.py`. The Makefile test targets call host-side `python` and assume those deps; macOS also has no `timeout` command (MIN-026).
- `scripts/secure_secret_lifecycle.sh` hard-codes a container name derived from the compose project name `encoding-server`. From another folder name, export `COMPOSE_PROJECT_NAME=encoding-server`.
- Colima shares only `$HOME` with its VM, so the bind-mounted `./secrets` must live under `$HOME` (MIN-027).

## Proxmox / Docker-in-LXC (production target)

Same `make secure-*` flow inside the LXC. AppArmor may be better managed by the outer LXC. GPU passthrough (device nodes, idmap, nvidia-container-toolkit with `no-cgroups = true`) is not set up yet, it is the M0 spike (INQUIRY-003), and the deploy guide `docs/DEPLOY_PROXMOX.md` is written at M6 from what actually worked (FEATURE-009).

## Upgrades and CVE hygiene

- Re-check pins in `api/requirements.txt` and the `alpine:3.19` / `redis:7-alpine` bases at every milestone; Alpine 3.19 is aging, plan a base bump.
- Run `pip list --outdated` inside the build context and review security advisories before bumping `fastapi`, `cryptography`, `pyjwt`, `python-multipart`, `pyOpenSSL`.
- After any bump: `make secure-build && make secure-up && make test-all`.
- The new worker image will pin torch (cu128+) and SVT-AV1 explicitly (MIN-016); record each pin in this file when it lands.
