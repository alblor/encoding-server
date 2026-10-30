# Conventions and working rules

## Code

- Python formatted with Black at 88 columns, Google-style docstrings. `black`, `isort`, `flake8`, `mypy` are pinned in `api/requirements.txt`. Some existing files predate this and are not Black-clean; do not reformat files you are not otherwise touching.
- Every new module opens with a docstring stating its purpose and `Author: Lorenzo Albanese (alblor)`, as the existing modules do.
- Handle errors explicitly. No bare `except`, no silent fallbacks around security checks.
- New behaviour comes with a test. Integration tests live in `tests/integration/`, unit tests in `tests/unit/`; the Makefile has one target per integration file, add a target when you add a file.

## Git

- Atomic, descriptive Conventional Commits (`type(scope): summary`), written in Lory's voice (see `~/.claude/skills/lory-engineering-voice`).
- Author is Lorenzo Albanese (alblor). No Claude attribution, co-author trailer or "generated with" line in any git artifact (commits, PRs, tags). This overrides tool defaults.
- Read `HISTORY.md` before committing, and log the session in it in the same change.
- Branch: `feature/restoration-pipeline`. Nothing is pushed until the owner asks.
- `CLAUDE.md` and `.claude/` are in `.gitignore` (private). `HISTORY.md`, `rules/` and `README.md` are not ignored.

## Support files and secrets

- Utility scripts, fixtures, seeds and scratch work go under `tools/` (`tools/scripts/{dev,data,ops}`, `tools/fixtures/{inputs,expected}`, `tools/seeds/{dev,test}`, `tools/sandbox/` ephemeral and gitignored, `tools/other/` is the owner's). Never in the root, `api/`, or ad-hoc folders. The `tools/` folder does not exist yet.
- Secrets only through Docker secrets (`./secrets/`) and, for local helper scripts, `.secrets/` (gitignored by convention). Never in tracked files, never in `tools/`. Scripts read `os.environ["KEY"]`; placeholders go in `.env.example`, which the repo does not have because no env var carries a secret today.
- Note: `.gitignore` covers `secrets/` and `.env` but not `.secrets/` or `tools/sandbox/` yet (MIN-020).

## Documentation

- New API endpoint: update `api/app/documentation.py` (endpoint list, ids), the README, and `tests/integration/test_documentation_api.py` expectations together. The test asserts exactly 8 documented endpoints, 5 quick-start steps in overview, version starting `2.0.0` and author containing "Lorenzo Albanese".
- README and docs prose follows Lory's voice: no marketing adjectives, facts only from the repo or the thread, `Lorenzo Albanese (alblor)` in the author block.
- Roadmap changes go through the `claude-roadmap` conventions in `CLAUDE.md`; completed items are logged in `HISTORY.md` in the same session.
- Every source folder has a short folder-level `CLAUDE.md` (synopsis, dependencies, file index). Update it when you add or remove a file.
