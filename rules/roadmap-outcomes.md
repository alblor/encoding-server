# Roadmap outcomes (completed IDs)

What each completed roadmap item turned out to be, one entry per ID, in the order they closed. The open items with sub-tasks are in `roadmap-details.md`; the table of record is `CLAUDE.md`. IDs are never reused. Last updated 2026-10-30.

- INQUIRY-003: no idmap needed. IDEA-019: moot (Proxmox 8.4.14). ISSUE-030: rootfs +70G, weights SHA-256 verified. INQUIRY-002: SparkVSR runs on both GPUs (torch 2.8 cu128). See `m0-server-spikes.md`, `m3-benchmark.md`.
- INQUIRY-032: the CogVideoX VAE costs about 626 ms per megapixel-frame, tile size and fp16 do not help, tiling off OOMs; `torch.compile` untested (IDEA-039). SparkVSR demoted to optional engine.
- INQUIRY-029: kernel spike done (FP8 W8A8 1.47x, NVFP4 0.85x); transformer only about 13% of SparkVSR runtime, work continues as INQUIRY-038.
- MIN-041: `rules/conventions.md` no longer points clones at the gitignored `tools/CLAUDE.md`.
- INQUIRY-035 (2026-10-30): the owner chose ReCaVSR as PRIMARY after seeing the draft videos, stills and metrics ("quality looks very similar among the two") and skipped the real-film A/B on his TV. Residual risk: every comparison used ReCaVSR's own modern, AI-looking demo clip, never film, and "very similar" is a visual judgement on that one clip. The first live rung of the M6 ladder (FEATURE-009) gives the first real-film look. The evaluation record stays in `recavsr-evaluation.md`. Left open from its list: pin commit and weights (MIN-043), SparkVSR with the PiSA-SR reference (INQUIRY-033).
- MIN-040: `Dockerfile.recavsr-bench`, `run_recavsr_bench.sh` and `vae_speed_spike.py` are in `tools/scripts/ops/bench/` (commit d6e552f) and indexed in `tools/CLAUDE.md`.
