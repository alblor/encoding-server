"""probe_media: the measurements read known images correctly, and the classes follow from them."""
import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

spec = importlib.util.spec_from_file_location("probe_media", Path(__file__).resolve().parents[2] / "client-tools" / "probe_media.py")
probe = importlib.util.module_from_spec(spec)
sys.modules["probe_media"] = probe          # dataclasses look their module up here
spec.loader.exec_module(probe)

RNG = np.random.default_rng(7)


def _smooth(h=512, w=512):
    """A low-contrast gradient with no detail and no noise."""
    return (np.linspace(60, 180, w)[None, :] + np.linspace(0, 20, h)[:, None]).astype(np.float32)


def test_noise_estimate_recovers_the_injected_sigma():
    for sigma in (2.0, 5.0, 9.0):
        image = _smooth() + RNG.normal(0, sigma, (512, 512)).astype(np.float32)
        assert probe.measure(image).noise == pytest.approx(sigma, rel=0.15)


def test_a_clean_gradient_has_no_noise_no_blocking_and_little_detail():
    m = probe.measure(_smooth())
    assert m.noise < 0.2 and m.detail < 0.001 and m.blockiness < 1.1


def test_forced_8_pixel_blocks_raise_blockiness_well_above_one():
    levels = RNG.integers(60, 200, (64, 64)).astype(np.float32)
    blocky = np.kron(levels, np.ones((8, 8), np.float32))
    assert probe.measure(blocky).blockiness > 3.0
    natural = _smooth() + RNG.normal(0, 4, (512, 512)).astype(np.float32)
    assert 0.9 < probe.measure(natural).blockiness < 1.1


def test_a_sharp_noisy_picture_has_far_more_high_frequency_detail_than_a_soft_one():
    sharp = RNG.normal(128, 30, (512, 512)).astype(np.float32)
    soft = _smooth() + RNG.normal(0, 1, (512, 512)).astype(np.float32)
    assert probe.measure(sharp).detail > 20 * probe.measure(soft).detail


@pytest.mark.parametrize("height,metrics,klass,preset", [
    (480, probe.Metrics(0.05, 1.0, 1.0), "low-res", "film-restoration"),
    (1080, probe.Metrics(0.05, 1.0, 1.0), "hd", "film-restoration"),
    (2160, probe.Metrics(0.05, 1.3, 1.0), "uhd-damaged", "cleanup-4k"),          # blocking
    (2160, probe.Metrics(0.05, 1.0, 4.5), "uhd-damaged", "cleanup-4k"),          # noise
    (2160, probe.Metrics(0.005, 1.0, 1.0), "uhd-damaged", "cleanup-4k"),         # soft: upscaled
    (2160, probe.Metrics(0.05, 1.02, 1.5), "uhd-clean", "clean-4k"),
])
def test_classes_and_presets(height, metrics, klass, preset):
    got_class, got_preset, reasons = probe.classify(height, metrics)
    assert (got_class, got_preset) == (klass, preset) and reasons


def test_estimate_scales_with_pixels_and_gpus_and_skips_the_none_engine():
    full = probe.estimate_hours(172_800, 2160, 3840, 2, "recavsr")
    assert full["gpu_hours_engine_only"] == pytest.approx(172_800 * 0.58 / 2 / 3600, abs=0.1)
    half = probe.estimate_hours(172_800, 1080, 1920, 2, "recavsr")
    assert half["gpu_hours_engine_only"] == pytest.approx(full["gpu_hours_engine_only"] / 4, rel=0.05)
    assert "note" in probe.estimate_hours(100, 2160, 3840, 2, "none")


def _run_cli(*argv):
    import subprocess as sp
    return sp.run([sys.executable, str(Path(probe.__file__)), *argv], capture_output=True, text=True)


def test_missing_empty_and_non_video_files_get_a_clear_message_not_a_traceback(tmp_path):
    missing = _run_cli(str(tmp_path / "nope.mkv"))
    assert missing.returncode == 2 and "no such file" in missing.stderr and "Traceback" not in missing.stderr
    empty = tmp_path / "empty.mkv"
    empty.write_bytes(b"")
    r = _run_cli(str(empty))
    assert r.returncode == 2 and "is empty" in r.stderr and "Traceback" not in r.stderr
    text = tmp_path / "notes.mkv"
    text.write_text("this is not a video")
    r = _run_cli(str(text))
    assert r.returncode == 2 and "could not be read as a video" in r.stderr and "Traceback" not in r.stderr


def test_an_hdr_source_gets_a_warning_and_no_recipe(tmp_path):
    import shutil, subprocess as sp
    if not shutil.which("ffmpeg"):
        pytest.skip("needs ffmpeg")
    clip = tmp_path / "hdr.mkv"
    sp.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=24:duration=2",
            "-vf", "setparams=colorspace=bt2020nc:color_primaries=bt2020:color_trc=smpte2084",    # frames carry the tags in ffmpeg 8
            "-c:v", "libx265", "-pix_fmt", "yuv420p10le", str(clip)], check=True)
    report = probe.build_report(str(clip), 2, 2, 2160)
    assert report["recipe"] is None and any("HDR source" in w for w in report["warnings"])
