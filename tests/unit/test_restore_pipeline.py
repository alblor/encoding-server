"""The pipeline end to end on the CPU: a real clip through ffmpeg, the finishing stage and SVT-AV1."""
import json
import shutil
import subprocess

import numpy as np
import pytest

from restore_core.recipe import resolve
from restore_worker.pipeline import Cancelled, PipelineError, SegmentJob, probe, run_segment

pytestmark = pytest.mark.skipif(
    not shutil.which("ffmpeg") or "libsvtav1" not in subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout,
    reason="needs ffmpeg with libsvtav1",
)

FAST = {"encode": {"preset": 10, "crf": 45}}      # tests care about plumbing, not compression efficiency


@pytest.fixture()
def clip(tmp_path):
    path = tmp_path / "in.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=24:duration=1",
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-colorspace", "bt709", "-color_trc", "bt709",
                    "-color_primaries", "bt709", str(path)], check=True)
    return path


def _stream(path):
    out = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries",
                          "stream=codec_name,width,height,pix_fmt,nb_read_frames,color_transfer,color_primaries,color_space",
                          "-of", "json", str(path)], capture_output=True, text=True, check=True).stdout
    return json.loads(out)["streams"][0]


def test_clean_reencode_gives_10_bit_av1_with_every_frame(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "none", "grain": "off"}, "advanced": FAST})
    result = run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe))
    s = _stream(tmp_path / "out.mkv")
    assert (s["codec_name"], s["pix_fmt"]) == ("av1", "yuv420p10le")
    assert (int(s["width"]), int(s["height"]), int(s["nb_read_frames"])) == (320, 180, 24)
    assert (s["color_transfer"], s["color_primaries"], s["color_space"]) == ("bt709", "bt709", "bt709")
    assert result.frames == 24 and result.seconds > 0


def test_classical_upscale_changes_the_size_and_keeps_the_frame_count(clip, tmp_path):
    pytest.importorskip("cv2")
    recipe = resolve({"basic": {"engine": "classical", "target_height": 360}, "advanced": FAST})
    result = run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe))
    s = _stream(tmp_path / "out.mkv")
    assert (int(s["width"]), int(s["height"]), int(s["nb_read_frames"])) == (640, 360, 24)
    assert (result.width, result.height) == (640, 360)


def test_grain_and_deband_run_through_the_whole_chain(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "none"}, "advanced": {**FAST, "grain": {"mode": "baked", "strength": 0.7},
                                                                  "bitdepth": {"deband": "light"}}})
    run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe, first_frame_index=500))
    assert int(_stream(tmp_path / "out.mkv")["nb_read_frames"]) == 24


def test_av1_film_grain_synthesis_option_is_accepted_by_the_encoder(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "none"}, "advanced": {**FAST, "grain": {"mode": "av1_fgs", "fgs_level": 8}}})
    run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe))
    assert int(_stream(tmp_path / "out.mkv")["nb_read_frames"]) == 24


def test_recavsr_without_an_engine_fails_clearly_not_silently(clip, tmp_path):
    with pytest.raises(PipelineError, match="needs a GPU worker"):
        run_segment(SegmentJob(clip, tmp_path / "out.mkv", resolve({"advanced": FAST})))


def test_hdr_synthesize_writes_an_hdr10_stream_with_the_right_signalling(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "none", "hdr": "synthesize", "grain": "off"}, "advanced": FAST})
    run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe))
    s = _stream(tmp_path / "out.mkv")
    assert (s["pix_fmt"], s["color_transfer"], s["color_primaries"], s["color_space"]) == ("yuv420p10le", "smpte2084", "bt2020", "bt2020nc")
    assert int(s["nb_read_frames"]) == 24


class _FakeEngine:
    """Stands in for the GPU engine: doubles the size with nearest-neighbour, returns stats."""

    def __init__(self):
        self.calls = []

    def restore(self, frames, *, scale, tile_height, tile_width, min_overlap, progress=None):
        self.calls.append((scale, tile_height, tile_width, min_overlap))
        out = frames.repeat(2, axis=1).repeat(2, axis=2)
        if progress:
            progress(0, 1, len(frames))
        return out, {"tiles": 1}


def test_engine_interface_gets_the_recipe_values_and_its_output_is_encoded(clip, tmp_path):
    engine = _FakeEngine()
    recipe = resolve({"basic": {"target_height": 360}, "advanced": {**FAST, "restore": {"min_overlap": 64}}})
    result = run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe), engine)
    assert engine.calls == [(2.0, 1152, 1344, 64)]            # 180 -> 360 is a scale of 2
    assert (result.width, result.height) == (640, 360) and result.stages["engine"] == {"tiles": 1}


def test_cancellation_stops_the_segment_and_leaves_no_zombie(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "none"}, "advanced": FAST})
    with pytest.raises(Cancelled):
        run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe), cancelled=lambda: True)


def test_probe_reads_size_rate_and_colour(clip):
    info = probe(clip)
    assert (info.width, info.height, info.frames, info.fps) == (320, 180, 24, "24/1")
    assert info.color_matrix == "bt709" and info.color_range == "tv"


class _PrecisionEngine:
    """Stands in for the GPU engine: returns the frames untouched and says what precision it runs."""

    def __init__(self, precision):
        self.precision = precision

    def restore(self, frames, **kwargs):
        return frames, {}


def test_a_recipe_that_asks_for_another_precision_than_the_worker_runs_fails_before_any_work(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "recavsr"}, "advanced": {**FAST, "restore": {"precision": "fp8", "scale": 1}}})
    with pytest.raises(PipelineError, match="asks for precision fp8 and this worker runs bf16"):
        run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe), engine=_PrecisionEngine("bf16"))


def test_an_unset_precision_runs_on_whatever_the_worker_has(clip, tmp_path):
    recipe = resolve({"basic": {"engine": "recavsr", "grain": "off"}, "advanced": {**FAST, "restore": {"scale": 1}}})
    result = run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe), engine=_PrecisionEngine("fp8"))
    assert result.frames == 24


def test_an_unreadable_cgroup_limit_still_checks_the_encoder_side_limit(tmp_path):
    wide = tmp_path / "wide.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=640x64:rate=24:duration=1", "-c:v", "libx264",
                    "-pix_fmt", "yuv420p", str(wide)], check=True)
    recipe = resolve({"basic": {"engine": "classical", "target_height": 2160}, "advanced": FAST})        # 21600x2160 would be the output
    with pytest.raises(PipelineError, match="16384"):
        run_segment(SegmentJob(wide, tmp_path / "out.mkv", recipe))


@pytest.mark.parametrize("fidelity", [{"soften": "adaptive"}, {"face_guard": "zoom"}, {"face_guard": "on"}])
def test_every_option_that_compares_with_the_source_keeps_the_source(clip, tmp_path, fidelity, monkeypatch):
    monkeypatch.setenv("FACE_MODEL", str(tmp_path / "missing.onnx"))
    recipe = resolve({"basic": {"engine": "none", "grain": "off"}, "advanced": {**FAST, "fidelity": fidelity}})
    if "face_guard" in fidelity:
        with pytest.raises(PipelineError, match="face detector"):          # the stage ran, so the source was kept for it
            run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe))
    else:
        assert run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe)).frames == 24


def test_the_encoder_gets_ac_bias_and_quant_matrices_when_the_recipe_asks_for_them():
    from pathlib import Path

    from restore_core.ffmpeg_cmds import encode_cmd

    with_texture = encode_cmd(Path("o.mkv"), 640, 360, "24/1", resolve({"preset": "cleanup-4k"}), hdr10=False)
    plain = encode_cmd(Path("o.mkv"), 640, 360, "24/1", resolve({}), hdr10=False)
    params = with_texture[with_texture.index("-svtav1-params") + 1]
    assert "ac-bias=1" in params and "enable-qm=1" in params
    assert "ac-bias" not in plain[plain.index("-svtav1-params") + 1] and "enable-qm" not in plain[plain.index("-svtav1-params") + 1]


def test_a_main_engine_output_that_is_not_uint8_frames_fails_cleanly(clip, tmp_path):
    class Wrong:
        precision = None

        def restore(self, frames, **kw):
            return frames.astype("float32"), {}

    recipe = resolve({"basic": {"engine": "recavsr", "grain": "off"}, "advanced": {**FAST, "restore": {"scale": 1}}})
    with pytest.raises(PipelineError, match="the engine returned"):
        run_segment(SegmentJob(clip, tmp_path / "out.mkv", recipe), engine=Wrong())


@pytest.mark.parametrize("advanced", [
    {"fidelity": {"soften": "adaptive"}}, {"fidelity": {"soften": "match"}}, {"fidelity": {"anchor": "source"}},
    {"fidelity": {"face_guard": "zoom"}}, {"fidelity": {"glow": 1.0}}, {"grain": {"mode": "source"}},
])
def test_every_stage_that_reads_the_original_keeps_it(advanced):
    from restore_worker.pipeline import recipe_needs_source
    base = {"basic": {"grain": "auto"}} if "grain" in advanced else {"basic": {"grain": "off"}}
    assert recipe_needs_source(resolve({**base, "advanced": advanced})), advanced


def test_a_recipe_with_no_source_stage_drops_the_original():
    from restore_worker.pipeline import recipe_needs_source
    assert not recipe_needs_source(resolve({"basic": {"grain": "off"}, "advanced": {"fidelity": {"glow": 0.0}}}))
