"""The memory budget that keeps one big request from getting a worker OOM-killed."""
from restore_core import budget
from restore_core.recipe import resolve

GIB = 1024 ** 3


def test_the_default_2160p_cleanup_segment_at_30_fps_fits_a_22_gib_gpu_worker():
    recipe = resolve({"preset": "cleanup-4k"})
    frames = int(recipe.advanced.restore.segment_max_seconds * 30)             # the longest segment the client cuts
    assert budget.refusal(recipe, 3840, 2160, frames, 22 * GIB) is None


def test_241_frames_of_2160p_do_not_fit_because_they_really_peaked_at_24_gib():
    recipe = resolve({"preset": "cleanup-4k"})
    assert budget.refusal(recipe, 3840, 2160, 241, 22 * GIB)


def test_the_estimate_is_never_below_what_the_real_workers_measured():
    cleanup = resolve({"preset": "cleanup-4k"})
    classical = resolve({"basic": {"engine": "classical", "target_height": 2160}})
    none_4k = resolve({"preset": "clean-4k"})
    measured = [                                            # (recipe, source size, frames, peak GiB on a real worker)
        (cleanup, (3840, 2160), 161, 16.5), (cleanup, (3840, 2160), 241, 24.3),
        (classical, (640, 360), 25, 5.7), (classical, (640, 360), 50, 7.4), (classical, (640, 360), 100, 10.2),
        (none_4k, (3840, 2160), 16, 3.8), (none_4k, (3840, 2160), 40, 5.7), (none_4k, (3840, 2160), 241, 14.2),
    ]
    for recipe, (w, h), frames, peak in measured:
        assert budget.estimate_bytes(recipe, w, h, frames) >= peak * GIB, (recipe.basic.engine, frames)


def test_an_output_the_encoder_cannot_produce_is_refused_whatever_the_frame_count():
    recipe = resolve({"basic": {"engine": "classical", "target_height": 2160}})
    reason = budget.refusal(recipe, 640, 64, 1, 64 * GIB)                     # 640x64 would become 21600x2160
    assert reason and "16384" in reason


def test_the_estimate_counts_the_output_size_not_the_input_size():
    recipe = resolve({"basic": {"engine": "classical", "target_height": 2160}})
    assert budget.estimate_bytes(recipe, 640, 360, 200) > 200 * 3 * 3840 * 2160 * 3          # more than three output frames each


def test_the_request_that_killed_the_cpu_worker_is_now_refused():
    # 100 frames of 640x360 classically upscaled to 2160p peaked above a 6 GiB cgroup on a real worker
    recipe = resolve({"basic": {"engine": "classical", "target_height": 2160}})
    assert budget.refusal(recipe, 640, 360, 100, 6 * GIB) is not None


def test_cgroup_limit_reads_a_number_and_ignores_max(tmp_path):
    f = tmp_path / "memory.max"
    f.write_text("12884901888\n")
    assert budget.cgroup_limit_bytes(str(f)) == 12 * GIB
    f.write_text("max\n")
    assert budget.cgroup_limit_bytes(str(f)) is None
    assert budget.cgroup_limit_bytes(str(tmp_path / "missing")) is None
