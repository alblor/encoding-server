# YubiKey (FIDO2) as the API authentication: research, not built (INQUIRY-111)

Written 2026-11-03. This is a research note. Nothing here is implemented, and nothing runs until the owner says go. It is the candidate answer to ISSUE-054 (the API has no authentication) and sits next to MIN-112 (the docs claim an auth system that does not exist).

## Why this came up

Today the API has no request authentication. `X-API-Key` only scopes jobs by its SHA-256 (`stack.md`); the only gates are TLS and `API_BIND_ADDR`. The `/v1/docs/auth` text talks about JWT tokens and an API-key system, which is aspirational (MIN-112). The owner does not want to create and store credentials, and asked whether every API call can instead be authorized by his YubiKey with a manual press, so that when he asks the agent to re-encode a movie, the call first waits on the key.

## Verdict: feasible, no blocker

The doc-scraper agent opened python-fido2 2.2.1 (docs and code), py_webauthn 3.0.1, the PyPI wheel lists, the Yubico FIDO technical manual, WebAuthn L3, CTAP 2.2 and the OpenSSH security-key docs. I did not run anything on hardware.

## Recommended design

- python-fido2 on both sides (server verifies, CLI talks to the key).
- A non-resident ES256 credential: no key slot is used, and the server stores only the credential ID and the public key, which is not a secret.
- `user_verification="discouraged"` on BOTH begin calls. This is a trap: with `preferred` or unset and no PIN on the key, the client raises `CONFIGURATION_UNSUPPORTED`.
- RP ID: the LAN address of the API, or a fixed string with a custom origin verifier. python-fido2 accepts an https origin whose host equals the RP ID; a browser would refuse an IP, a CLI does not.
- Endpoints `POST /auth/challenge` and `POST /auth/assert`. The second returns a short-lived token (claims: action, film, exp). A FastAPI `Depends` checks it on every route.
- The principal becomes the credential ID, so the per-key job scoping of `stack.md` carries over.
- Single-use nonce in Redis with a 60 s TTL.
- Check `signCount` ourselves: `Fido2Server` does not, and a decrease is an alarm.
- Register two keys, so losing one is not a lockout.
- The CLI must print WHAT is being authorized before it blocks on the touch, because the key shows nothing.

A film is hundreds of API calls, so a touch per HTTP call is unworkable. The shape is one touch, one token (15 to 60 min, or per film), a new touch on expiry. The lifetime is the owner's decision.

## Alternatives, rejected or costlier

- `ssh-keygen -Y sign` with sk keys: Apple's `/usr/bin/ssh-keygen` lacks sk support (needs Homebrew OpenSSH), and whether `-Y verify` enforces user presence is unverified.
- PIV with mTLS and touch-always: high effort, PKCS#11 plumbing for Python on macOS.
- Yubico OTP: needs a validation service, and the workers and API have no egress.
- HMAC-SHA1 challenge-response: the shared secret would live on the server.
- A browser WebAuthn approval page: needs a hostname.

## Estimate

About 120 to 180 lines on the server, 80 to 120 in the client, three new files plus tests, and about a day of hardware testing. Anything that changes authentication after the deploy needs a new QC pass.

## Unverified and open

- No YubiKey was plugged into the Mac, so nothing ran on hardware.
- The model and firmware must be checked. YubiKey 5 series and Security Keys do touch-only; Bio, 5 Enhanced PIN and FIPS require user verification and block touch-only by default.
- macOS permission behaviour of python-fido2 from the agent's terminal: no Input Monitoring requirement was found for the FIDO interface, but it was not tested.
- libfido2 issue 983 reports intermittent open errors on macOS 26 for some keys, so plan a retry on open.

## What the owner can run now

A read-only probe, with the key inserted: `tools/sandbox/yubikey/probe.py` (gitignored). It lists keys and reads their capabilities. No touch, and it creates nothing on the key.

## Decisions waiting for the owner

- [ ] Go or no-go on building it
- [ ] Token lifetime: 15 to 60 min, or one per film
- [ ] The key model and firmware (probe output)
