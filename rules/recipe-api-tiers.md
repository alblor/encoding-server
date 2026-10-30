# Job endpoint: presets, basic block, advanced block (FEATURE-036)

Owner decision of 2026-10-30. Nothing here is built; the field lists are drafts to settle when FEATURE-036 starts.

The recipe is also the public contract of the final job endpoint, and the owner wants it small on the surface and deep underneath. It is built in three layers, and each layer is documented in `/v1/docs` the way the existing encoding endpoints are (every field with type, default, allowed values, what it changes and what it costs):

- Presets: a named starting point (for example a film-restoration preset and a budget one) that fills the whole recipe. Preset names are what a normal user picks.
- Basic block: a LIMITED set of parameters most users may touch (engine choice, target resolution, HDR mode, quality level, encryption mode and similar). The exact list is part of FEATURE-036, but it has to stay short on purpose.
- Advanced block: the troubleshooting and optimisation tier (precision, tile size and overlap, window and chunk sizes, shot-boundary behaviour, encoder tuning, per-stage toggles). It is optional, every field has a safe default, and the docs say plainly which fields can cost quality or speed.

Proposed rules for the tier (my draft, to be settled in FEATURE-036): a request with only a preset or only the basic block must be valid; advanced fields are validated and bounded, never passed through as strings (same principle as the typed FFmpeg command builder in `restoration-design.md`); the effective recipe (preset plus overrides) is returned so a run can be reproduced. Changing the documented endpoints means updating `api/app/documentation.py`, the README and `tests/integration/test_documentation_api.py` together.
