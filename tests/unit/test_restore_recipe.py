"""Recipe schema: presets, tiers, validation, and the effective recipe that makes a run reproducible."""
import pytest
from pydantic import ValidationError

from restore_core.recipe import PRESETS, RecipeRequest, effective_scale, resolve


def test_empty_request_is_valid_and_fully_filled():
    recipe = resolve({})
    assert recipe.basic.engine == "recavsr" and recipe.basic.target_height == 2160
    assert recipe.advanced.restore.tile_width == 1344 and recipe.advanced.grain.mode == "auto"
    assert recipe.encoder_preset == 4 and recipe.encoder_crf == 24      # "high"


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_every_preset_resolves(name):
    assert resolve({"preset": name}).preset == name


def test_preset_then_basic_then_advanced_precedence():
    recipe = resolve({
        "preset": "cleanup-4k",
        "basic": {"quality": "maximum"},
        "advanced": {"restore": {"scale": 1.5}, "prefilter": {"mode": "medium"}},
    })
    assert recipe.basic.quality == "maximum" and recipe.encoder_crf == 20
    assert recipe.advanced.restore.scale == 1.5          # advanced override beats the preset's 1.0
    assert recipe.advanced.prefilter.mode == "medium"    # and the preset's other keys are kept where untouched
    assert recipe.advanced.prefilter.deblock is False


def test_explicit_encoder_values_beat_the_quality_table():
    recipe = resolve({"basic": {"quality": "draft"}, "advanced": {"encode": {"crf": 18, "preset": 3}}})
    assert (recipe.encoder_preset, recipe.encoder_crf) == (3, 18)


@pytest.mark.parametrize("bad", [
    {"basic": {"quality": "ultra"}},
    {"basic": {"hdr": "preserve"}},                              # not implemented yet: refused at the schema, not in a worker
    {"basic": {"colour": "x"}},                                 # typo in a basic key
    {"advanced": {"restore": {"tile_width": 1000}}},            # not a multiple of 32
    {"advanced": {"restore": {"precision": "nvfp4"}}},
    {"advanced": {"restore": {"min_overlap": 2048, "tile_width": 1344}}},
    {"advanced": {"grain": {"strength": 1.5}}},
    {"advanced": {"nonsense": {}}},
    {"preset": "does-not-exist"},
    {"recipe_version": 2},
    {"extra": 1},
])
def test_bad_requests_are_rejected_not_defaulted(bad):
    with pytest.raises((ValidationError, ValueError)):
        resolve(bad)


def test_engine_none_cannot_rescale():
    with pytest.raises(ValidationError):
        resolve({"basic": {"engine": "none"}, "advanced": {"restore": {"scale": 2}}})


def test_effective_recipe_round_trips_so_a_run_can_be_reproduced():
    first = resolve({"preset": "film-restoration", "advanced": {"restore": {"seed": 7}}})
    again = resolve(first.model_dump())                     # an effective recipe is itself a valid request shape
    assert again.model_dump() == first.model_dump()


def test_effective_scale_rules():
    assert effective_scale(resolve({}), 540) == 4.0
    assert effective_scale(resolve({}), 2160) == 1.0
    assert effective_scale(resolve({}), 4320) == 1.0        # never shrinks
    assert effective_scale(resolve({"advanced": {"restore": {"scale": 2}}}), 540) == 2.0


def test_request_model_rejects_unknown_top_level_keys():
    with pytest.raises(ValidationError):
        RecipeRequest.model_validate({"preset": "draft", "colour": 1})


def test_the_budget_preset_uses_half_length_segments_to_fit_the_cpu_worker():
    assert resolve({"preset": "budget"}).advanced.restore.segment_max_seconds == 4.0
    assert resolve({"preset": "film-restoration"}).advanced.restore.segment_max_seconds == 8.0


def test_cleanup_preset_is_the_combination_chosen_on_the_draft_and_other_presets_leave_it_off():
    cleanup = resolve({"preset": "cleanup-4k"}).advanced
    assert (cleanup.fidelity.soften, cleanup.fidelity.anchor, cleanup.fidelity.face_guard) == ("adaptive", "source", "zoom")
    assert (cleanup.tone.contrast, cleanup.tone.saturation, cleanup.tone.pivot) == (0.2, 1.06, None)
    assert resolve({"preset": "film-restoration"}).advanced.fidelity.soften == "off"
    assert resolve({}).advanced.fidelity.soften_amount == 0.8


@pytest.mark.parametrize("bad", [{"advanced": {"fidelity": {"soften_amount": 1.5}}}, {"advanced": {"fidelity": {"soften": "blur"}}},
                                 {"advanced": {"fidelity": {"typo": 1}}}])
def test_fidelity_fields_are_validated(bad):
    with pytest.raises((ValidationError, ValueError)):
        resolve(bad)


def test_hdr_reference_white_cannot_be_above_the_peak():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        resolve({"basic": {"hdr": "synthesize"}, "advanced": {"hdr": {"peak_nits": 203, "reference_white_nits": 400}}})
    assert resolve({"basic": {"hdr": "synthesize"}, "advanced": {"hdr": {"peak_nits": 400, "reference_white_nits": 400}}})


def test_the_restoring_presets_keep_the_textures_of_dark_areas_through_the_encode():
    for name in ("cleanup-4k", "film-restoration"):
        adv = resolve({"preset": name}).advanced
        assert adv.bitdepth.deband == "off" and adv.grain.shadow_weight == 0.35
        assert adv.encode.ac_bias == 1.0 and adv.encode.quant_matrices is True
    assert resolve({"preset": "cleanup-4k"}).advanced.fidelity.face_guard == "zoom"
    assert resolve({"preset": "cleanup-4k"}).advanced.fidelity.face_zoom_mix == 0.8
    assert resolve({}).advanced.encode.ac_bias == 0.0 and resolve({}).advanced.grain.shadow_weight == 0.12      # the plain defaults are unchanged
