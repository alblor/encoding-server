# Roadmap task details: the final QC gate, deploy caveats, API authentication (ID 111 onwards)

Companion of `roadmap-v8.md` (IDs 100 to 110); the table is in `CLAUDE.md`, the outcomes of closed IDs are in `roadmap-outcomes-2.md`. Created 2026-11-03. Gate numbers are from the quality-control engineer's report; I did not re-run them.

### FEATURE-060 — Release v1.1.0 and live deploy (progress, P0)
The owner's conditional go was "deploy only if QC is 4.8/5 or better, otherwise fix first". The final gate scored 4.80 (`restore-qc.md`, run 7), so on 2026-11-03 the merge, the tag `v1.1.0` (internal version 2.1.0-secure) and the non-destructive deploy of `docs/DEPLOY_PROXMOX.md` started. This row stays `progress` until the outcome is reported; the final entry follows.
- [x] Gate met (4.80, zero margin); [ ] commits, merge, tag; [ ] deploy; [ ] INQUIRY-116 and INQUIRY-117 checked on the real host; [ ] 3-segment trial; [ ] SSH teardown

### INQUIRY-111 — YubiKey (FIDO2) as the API authentication (planned, P1, waiting for the owner's go)
Research done, nothing built. The owner does not want to create credentials and asked whether each API call can be authorized by a manual press on his YubiKey. Verdict: feasible, no blocker; one touch yields a short-lived token, not a touch per call. Design, rejected alternatives, estimate and the unverified points: `yubikey-auth-inquiry.md`. It would answer ISSUE-054 if he goes ahead.
- [ ] Owner: go or no-go; [ ] run `tools/sandbox/yubikey/probe.py` with the key inserted; [ ] pick the token lifetime; [ ] if go: build, test on hardware, new QC pass

### MIN-112 — `/v1/docs/auth` describes auth that does not exist (planned, P2)
The `/v1/docs/auth` guide (`api/app/documentation.py`, synopsis "JWT tokens and API key authentication system") and the "None required (Note: Will require API key in production)" strings promise infrastructure that is not there. Today `X-API-Key` only scopes jobs (ISSUE-054). Fix the text to say what is true, and change it again when INQUIRY-111 is decided. Per the docs rule in `CLAUDE.md`, the README, the docs test and the endpoint strings move together.
- [ ] Rewrite the strings; [ ] update `tests/integration/test_documentation_api.py` and the README in the same change

### INQUIRY-116 — AppArmor profile on a real AppArmor host (planned, P1, gate caveat)
The QC sandbox (Colima) has no AppArmor, so the `security_opt` profile was never loaded. It needs the deploy host. Check that the containers start with the profile and that nothing legitimate is denied.
- [ ] Load the profile on the server; [ ] start the API and a worker; [ ] read the kernel log for denials

### INQUIRY-117 — GPU image on the real host (planned, P1, gate caveat)
Four things the sandbox cannot show: the entrypoint `setpriv --bounding-set=-all` under `no-cgroups`, the worker's Redis ACL login, `worker.py` end to end, and `make gpu-build` of the current `Dockerfile.gpu`, which is newer than the image the GPU evidence came from.
- [ ] `make gpu-build`; [ ] CapEff 0 and an empty CapBnd in the worker; [ ] worker logs in as the ACL user; [ ] one segment end to end (the 3-segment trial)

### MIN-118 — The memory budget does not charge the zoom arrays (planned, P2)
`restore_core/budget.py` does not count the zoom arrays: about 1.3 GB for a 180-frame track at side 384 (QC verdict: PLAUSIBLE, not measured). The estimate for `cleanup-4k` at 161 frames was 18.3 of 22 GiB, so the uncharged part matters on a long track.
- [ ] Measure the real peak on a long track; [ ] charge the arrays in the budget; [ ] test

### Notes from the gate with no points (info)
- `tone.pivot` falls back to the restored frames when no source is kept.
- `bitdepth.anchor_source` is accepted and unused (MIN-051 stays as written).
- `Dockerfile.cpu` does not copy `run_local.py` or `quantize.py`; fine for the worker.

### Leftover housekeeping, recorded not decided
- The SparkVSR-dependent INQUIRY-010, INQUIRY-033, IDEA-034 and IDEA-039 stay open for the owner to close (their weights are gone, MIN-107).
- MIN-021 (README recipe docs) is still open.
- The undervolt and thermal follow-ups (MIN-108, MIN-109, INQUIRY-110) wait for the end phase.
