"""restore_film client: cut planning is contiguous, complete and bounded; the manifest resumes and refuses strangers."""
import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("restore_film", Path(__file__).resolve().parents[2] / "client-tools" / "restore_film.py")
rf = importlib.util.module_from_spec(spec)
sys.modules["restore_film"] = rf
spec.loader.exec_module(rf)

FPS = Fraction(24000, 1001)


def _plan(keys, duration, **kw):
    kw.setdefault("target_seconds", 4.8)
    kw.setdefault("max_frames", 192)
    return rf.plan_segments(keys, duration, FPS, **kw)


def _check_cover(segments, duration):
    assert segments[0].start == 0.0 and segments[-1].end == pytest.approx(duration)
    for a, b in zip(segments, segments[1:]):
        assert a.end == b.start                                           # contiguous: nothing dropped, nothing repeated
    assert [s.first_frame for s in segments] == [sum(x.frames for x in segments[:i]) for i in range(len(segments))]


def test_regular_keyframes_give_segments_at_the_target_length():
    seg = _plan([i * 2.0 for i in range(0, 11)], 20.0)
    _check_cover(seg, 20.0)
    assert [round(s.end - s.start, 1) for s in seg[:-1]] == [6.0, 6.0, 6.0] and seg[-1].end == 20.0


def test_no_segment_exceeds_the_frame_limit():
    seg = _plan([i * 3.0 for i in range(0, 40)], 118.0, max_frames=100)    # 3 s GOPs, limit 4.17 s
    _check_cover(seg, 118.0)
    assert max(s.frames for s in seg) <= 100


def test_a_gap_longer_than_the_limit_is_an_error_not_a_silent_long_segment():
    with pytest.raises(ValueError, match="without a keyframe"):
        _plan([0.0, 12.0, 24.0], 36.0, max_frames=100)


def test_a_tiny_tail_is_folded_into_the_previous_segment():
    seg = _plan([0.0, 6.0, 12.0], 12.05)                                  # 1 frame left over
    _check_cover(seg, 12.05)
    assert len(seg) == 2 and seg[-1].end == pytest.approx(12.05)


def test_a_film_with_a_single_keyframe_that_fits_is_one_segment():
    seg = _plan([0.0], 5.0)
    assert len(seg) == 1 and seg[0].frames == round(5.0 * float(FPS))


def test_a_missing_first_keyframe_still_starts_at_zero():
    seg = _plan([2.5, 7.5], 10.0)
    _check_cover(seg, 10.0)


def test_total_frames_match_the_duration_within_rounding():
    seg = _plan([i * 2.0 for i in range(0, 50)], 98.3)
    assert abs(sum(s.frames for s in seg) - round(98.3 * float(FPS))) <= len(seg)


def test_manifest_persists_updates_and_resumes(tmp_path):
    header = {"source_size": 123, "recipe": {"preset": "x"}}
    m = rf.Manifest(tmp_path / "m.json", header)
    m.update(3, state="done", sha256="abc")
    again = rf.Manifest(tmp_path / "m.json", header)
    assert again.get(3)["state"] == "done" and again.get(9) == {"state": "pending"}


def test_manifest_refuses_a_work_folder_from_another_film_or_recipe(tmp_path):
    rf.Manifest(tmp_path / "m.json", {"source_size": 1, "recipe": {"a": 1}})
    with pytest.raises(SystemExit, match="another film or another recipe"):
        rf.Manifest(tmp_path / "m.json", {"source_size": 2, "recipe": {"a": 1}})
    with pytest.raises(SystemExit):
        rf.Manifest(tmp_path / "m.json", {"source_size": 1, "recipe": {"a": 2}})


def test_sha256_file(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    assert rf.sha256_file(f) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- the cut must be frame-exact: content checked frame by frame, not just counted --------------------------------------

import json
import shutil
import subprocess

needs_ffmpeg = pytest.mark.skipif(not shutil.which("ffmpeg"), reason="needs ffmpeg")


def _make_film(path: Path, container: str, seconds: int = 24, gop: int = 48, bframes: int = 3, with_av=True):
    """A synthetic film whose every frame is different (testsrc2 shows a counter), with B-frames, audio and subtitles."""
    srt = path.with_suffix(".srt")
    srt.write_text("1\n00:00:01,000 --> 00:00:03,000\nhello\n\n2\n00:00:10,000 --> 00:00:12,000\nworld\n")
    cmd = ["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", f"testsrc2=size=320x180:rate=24:duration={seconds}"]
    if with_av:
        cmd += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}", "-i", str(srt)]
    cmd += ["-map", "0:v"] + (["-map", "1:a", "-map", "2:s"] if with_av else [])
    cmd += ["-c:v", "libx264", "-g", str(gop), "-bf", str(bframes), "-keyint_min", str(gop), "-sc_threshold", "0", "-pix_fmt", "yuv420p"]
    if with_av:
        cmd += ["-c:a", "aac", "-c:s", "srt" if container == "mkv" else "mov_text"]
    subprocess.run(cmd + [str(path)], check=True)
    return path


def _framemd5(path: Path, start=None, frames=None) -> list[str]:
    cmd = ["ffmpeg", "-v", "error", "-nostdin"] + (["-ss", f"{start:.6f}"] if start else []) + ["-i", str(path), "-map", "0:v:0", "-an", "-sn"]
    if frames:
        cmd += ["-frames:v", str(frames)]
    out = subprocess.run(cmd + ["-f", "framemd5", "-"], capture_output=True, text=True, check=True).stdout
    return [line.rsplit(",", 1)[-1].strip() for line in out.splitlines() if line and not line.startswith("#")]


@needs_ffmpeg
@pytest.mark.parametrize("container", ["mkv", "mp4"])
@pytest.mark.parametrize("bframes", [0, 3])
def test_every_cut_piece_matches_the_source_frame_for_frame(tmp_path, container, bframes):
    film = _make_film(tmp_path / f"film.{container}", container, bframes=bframes)
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    assert len(segs) >= 3 and sum(x.frames for x in segs) == info["frames"]
    source = _framemd5(film)
    assert len(source) == info["frames"]
    position = 0
    for seg in segs:
        piece = tmp_path / f"p{seg.index}.mkv"
        n = rf.cut_segment(film, seg, piece)                       # raises if the cut is wrong: that is the point
        assert _framemd5(piece) == source[position:position + n], f"segment {seg.index} is not the source's frames {position}..{position + n}"
        position += n
    assert position == info["frames"]                              # contiguous, nothing dropped, nothing repeated


@needs_ffmpeg
def test_cut_segment_refuses_a_cut_that_starts_at_the_wrong_frame(tmp_path, monkeypatch):
    film = _make_film(tmp_path / "film.mkv", "mkv")
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    # Starting mid-GOP is something a stream copy cannot honour: it starts at the keyframe before, a second early.
    wrong = rf.Segment(9, segs[1].start + 1.0, segs[1].end, segs[1].frames, 0)
    with pytest.raises(RuntimeError, match="not frame-exact|wrong frame"):
        rf.cut_segment(film, wrong, tmp_path / "bad.mkv")


def _stream_counts(path: Path) -> dict:
    out = json.loads(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "stream=codec_type", "-of", "json", str(path)],
                                    capture_output=True, text=True, check=True).stdout)
    counts = {}
    for st in out["streams"]:
        counts[st["codec_type"]] = counts.get(st["codec_type"], 0) + 1
    return counts


def _assemble_roundtrip(film: Path, work: Path, out: Path):
    """Cut every segment, treat the pieces as restored results, and run the client's own assembly."""
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    (work / "results").mkdir(parents=True)
    for seg in segs:
        rf.cut_segment(film, seg, work / "results" / f"seg_{seg.index:05d}.mkv")
    rf.assemble(film, work, segs, out, info)
    return info


@needs_ffmpeg
def test_assembly_works_with_relative_paths_and_keeps_audio_and_subtitles(tmp_path, monkeypatch):
    film = _make_film(tmp_path / "film.mkv", "mkv")
    monkeypatch.chdir(tmp_path)                                  # relative names, the default way to use the client
    info = _assemble_roundtrip(Path("film.mkv"), Path("work"), Path("out.mkv"))
    out = tmp_path / "out.mkv"
    assert rf.count_frames(out) == info["frames"]
    assert _stream_counts(out) == {"video": 1, "audio": 1, "subtitle": 1}


@needs_ffmpeg
def test_assembly_converts_mp4_text_subtitles_instead_of_failing(tmp_path):
    film = _make_film(tmp_path / "film.mp4", "mp4")               # mov_text subtitles cannot be copied into Matroska
    _assemble_roundtrip(film, tmp_path / "work", tmp_path / "out.mkv")
    assert _stream_counts(tmp_path / "out.mkv") == {"video": 1, "audio": 1, "subtitle": 1}


@needs_ffmpeg
def test_assembly_refuses_when_the_segments_do_not_add_up_to_the_source(tmp_path):
    film = _make_film(tmp_path / "film.mkv", "mkv")
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    (tmp_path / "work" / "results").mkdir(parents=True)
    for seg in segs[:-1]:                                          # one segment never came back
        rf.cut_segment(film, seg, tmp_path / "work" / "results" / f"seg_{seg.index:05d}.mkv")
    with pytest.raises(SystemExit, match="assembly check failed"):
        rf.assemble(film, tmp_path / "work", segs[:-1], tmp_path / "out.mkv", info)
    assert not (tmp_path / "out.mkv").exists()                     # nothing half-built is left to be trusted


def test_stale_job_is_dropped_by_the_client_and_ctrl_c_leaves_nothing_submitted(tmp_path):
    class Resp:
        def __init__(self, status, body=None, code=200):
            self._b, self.status_code, self.text = body or {}, code, ""
        def json(self):
            return self._b
    calls = []
    class FakeClient:
        def call(self, method, path, **kw):
            calls.append((method, path))
            if method == "GET":
                return Resp(200, {"status": "running", "updated_at": "same"})   # a dead worker: never changes
            return Resp(200, {})
    manifest = rf.Manifest(tmp_path / "m.json", {"source_size": 1, "recipe": {}})
    manifest.update(0, state="submitted", job_id="a" * 32, frames=10)
    seg = rf.Segment(0, 0, 1, 10, 0)
    (tmp_path / "results").mkdir()
    with pytest.raises(RuntimeError, match="no sign of life"):
        rf.process_segment(FakeClient(), tmp_path / "x", seg, "{}", tmp_path, manifest, "automated", None, threading_event(), print, stale_seconds=0.2)
    assert manifest.get(0)["state"] == "pending" and ("DELETE", "/jobs/" + "a" * 32) in calls


def threading_event():
    import threading
    return threading.Event()


def _open_gop_film(path: Path) -> Path:
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25:duration=24",
                    "-c:v", "libx265", "-x265-params", "bframes=6:open-gop=1:keyint=100:min-keyint=25:log-level=error", str(path)], check=True)
    return path


needs_x265 = pytest.mark.skipif(
    not shutil.which("ffmpeg") or "libx265" not in subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout
    or "libsvtav1" not in subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout,
    reason="needs ffmpeg with libx265 and libsvtav1",
)


@needs_x265
def test_an_open_gop_source_is_refused_by_the_copy_cut_and_cut_exactly_by_the_transcode(tmp_path):
    film = _open_gop_film(tmp_path / "open.mkv")
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    with pytest.raises(RuntimeError, match="wrong frame"):
        rf.preflight(film, segs, tmp_path, "copy")                           # the stream copy drops a frame at a boundary
    assert rf.preflight(film, segs, tmp_path, "auto") == "transcode"         # and auto notices and switches
    total = sum(rf.transcode_segment(film, s, tmp_path / f"t{s.index}.mkv") for s in segs)
    assert total == info["frames"]


@needs_x265
def test_the_transcode_check_catches_a_piece_that_is_one_frame_off(tmp_path):
    film = _open_gop_film(tmp_path / "open.mkv")
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, 24.0, Fraction(25), target_seconds=4.0, max_frames=200, pts=every)
    seg = segs[1]
    piece = tmp_path / "p.mkv"
    rf.transcode_segment(film, seg, piece)
    right = rf._psnr((["-i", str(piece)], None), rf.frame_at(film, seg.start))
    one_off = rf._psnr((["-i", str(piece)], None), rf.frame_at(film, seg.start + 0.04))
    assert right > rf.TRANSCODE_MIN_PSNR > one_off


@needs_ffmpeg
def test_an_apostrophe_in_the_work_folder_does_not_break_the_final_concat(tmp_path):
    film = _make_film(tmp_path / "Schindler's List.mkv", "mkv")
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments(keys, info["duration"], info["fps"], target_seconds=4.0, max_frames=200, pts=every)
    work = tmp_path / "Schindler's List.restore-work"
    (work / "results").mkdir(parents=True)
    for s in segs:
        rf.cut_segment(film, s, work / "results" / f"seg_{s.index:05d}.mkv")
    out = tmp_path / "Schindler's List.restored.mkv"
    rf.assemble(film, work, segs, out, info)
    assert rf.count_frames(out) == info["frames"]


def test_a_long_gop_is_refused_by_default_and_cut_into_equal_forced_pieces_when_allowed():
    keys = [0.0] + [6.7 * i for i in range(1, 6)]                      # a keyframe only every 6.7 s (161 frames)
    with pytest.raises(ValueError, match="without a keyframe"):
        _plan(keys, 33.5, max_frames=143)
    segments = _plan(keys, 33.5, max_frames=143, force_cuts=True)
    _check_cover(segments, 33.5)
    assert all(s.frames <= 143 for s in segments)
    assert [s.forced for s in segments[:4]] == [False, True, False, True]    # every piece after the first of a GOP starts mid-GOP
    assert abs(segments[0].frames - segments[1].frames) <= 1                 # equal halves, not 143 plus a sliver of 18


def test_forced_cuts_follow_the_real_frame_times_when_the_packet_list_is_known():
    pts = [i / float(FPS) for i in range(1000)]
    keys = [pts[0], pts[400], pts[800]]
    segments = rf.plan_segments(keys, 1000 / float(FPS), FPS, target_seconds=3.0, max_frames=150, pts=pts, force_cuts=True)
    assert sum(s.frames for s in segments) == 1000 and all(s.frames <= 150 for s in segments)
    assert [s.first_frame for s in segments] == [sum(x.frames for x in segments[:i]) for i in range(len(segments))]


def _offset_film(path: Path, offset: float) -> Path:
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25:duration=14",
                    "-f", "lavfi", "-i", "sine=frequency=440:duration=14", "-c:v", "libx264", "-bf", "3", "-g", "50",
                    "-c:a", "aac", "-output_ts_offset", str(offset), str(path)], check=True)
    return path


@needs_ffmpeg
@pytest.mark.parametrize("suffix,offset", [("mkv", 1.4), ("mkv", 10.0), ("mp4", 1.0)])
def test_a_source_that_does_not_start_at_zero_is_planned_cut_and_assembled(tmp_path, suffix, offset):
    film = _offset_film(tmp_path / f"film.{suffix}", offset)
    info = rf.probe_source(film)
    segs = rf.plan_film(film, info, 6.0, True)
    assert sum(s.frames for s in segs) == info["frames"]
    assert info["span"] == pytest.approx(14.0, abs=0.1)
    work = tmp_path / "work"
    (work / "results").mkdir(parents=True)
    for s in segs:                                                          # the pieces stand in for restored results
        rf.transcode_segment(film, s, work / "results" / f"seg_{s.index:05d}.mkv")
    out = tmp_path / "out.mkv"
    rf.assemble(film, work, segs, out, info)                                # raises if the frames or the duration are off
    assert rf.count_frames(out) == info["frames"]


@needs_ffmpeg
def test_a_stretch_of_exactly_max_frames_with_an_audio_tail_plans_without_an_error(tmp_path):
    film = tmp_path / "longgop.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25", "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000",
                    "-t", "12", "-c:v", "libx264", "-g", "300", "-keyint_min", "300", "-sc_threshold", "0", "-c:a", "aac", str(film)], check=True)
    info = rf.probe_source(film)
    segs = rf.plan_film(film, info, 3.0, True)                         # 75 frames per segment, 300 frames: an exact multiple
    assert sum(s.frames for s in segs) == info["frames"] and all(s.frames <= 75 for s in segs)


@needs_ffmpeg
def test_video_that_starts_after_the_audio_stays_late_against_it_in_the_assembled_film(tmp_path):
    film = tmp_path / "skew.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-itsoffset", "1.4", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25", "-itsoffset", "1.0",
                    "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000", "-t", "8", "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-g", "50",
                    "-c:a", "aac", str(film)], check=True)
    assert rf.video_start_delay(film) == pytest.approx(0.4, abs=0.02)
    info = rf.probe_source(film)
    segs = rf.plan_film(film, info, 3.0, True)
    work = tmp_path / "work"
    (work / "results").mkdir(parents=True)
    for s in segs:
        rf.transcode_segment(film, s, work / "results" / f"seg_{s.index:05d}.mkv")
    out = tmp_path / "out.mkv"
    rf.assemble(film, work, segs, out, info)

    def start(kind):
        return float(subprocess.run(["ffprobe", "-v", "error", "-select_streams", f"{kind}:0", "-show_entries", "stream=start_time", "-of", "csv=p=0", str(out)],
                                    capture_output=True, text=True).stdout.strip())

    assert start("v") - start("a") == pytest.approx(0.4, abs=0.05)


@needs_ffmpeg
@pytest.mark.parametrize("lead_in", [0.6, 2.0, 9.0])
def test_a_long_video_lead_in_is_kept_and_does_not_fail_the_final_check(tmp_path, lead_in):
    film = tmp_path / "lead.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-itsoffset", str(lead_in), "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25:duration=6",
                    "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000:duration=6", "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-g", "50",
                    "-c:a", "aac", str(film)], check=True)
    info = rf.probe_source(film)
    segs = rf.plan_film(film, info, 3.0, True)
    assert rf.video_start_delay(film, info["video_start"]) == pytest.approx(lead_in, abs=0.05)
    work = tmp_path / "work"
    (work / "results").mkdir(parents=True)
    for s in segs:
        rf.transcode_segment(film, s, work / "results" / f"seg_{s.index:05d}.mkv")
    out = tmp_path / "out.mkv"
    rf.assemble(film, work, segs, out, info)                       # must not raise "do not trust the file"

    def first_pts(kind):
        raw = subprocess.run(["ffprobe", "-v", "error", "-select_streams", f"{kind}:0", "-show_entries", "packet=pts_time", "-read_intervals", "%+#1", "-of", "csv=p=0", str(out)],
                             capture_output=True, text=True).stdout.split()
        return min(float(v.rstrip(",")) for v in raw)

    assert first_pts("v") - first_pts("a") == pytest.approx(lead_in, abs=0.1)


@needs_ffmpeg
def test_a_copy_cut_is_frame_exact_when_the_video_starts_long_after_the_audio(tmp_path):
    film = tmp_path / "late.mkv"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-itsoffset", "10", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=25:duration=8", "-f", "lavfi",
                    "-i", "sine=frequency=440:sample_rate=48000:duration=18", "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-g", "50", "-bf", "2",
                    "-c:a", "aac", str(film)], check=True)
    info = rf.probe_source(film)
    every, keys = rf.packet_times(film)
    segs = rf.plan_segments([k - every[0] for k in keys], every[-1] + 1 / 25 - every[0], info["fps"], target_seconds=2.0, max_frames=100, pts=[t - every[0] for t in every])
    for s in segs:
        s.start, s.end = s.start + every[0], s.end + every[0]
        s.last_pts = None if s.last_pts is None else s.last_pts + every[0]
    source = _framemd5(film)
    position = 0
    for seg in segs:
        piece = tmp_path / f"p{seg.index}.mkv"
        n = rf.cut_segment(film, seg, piece)
        assert _framemd5(piece) == source[position:position + n]
        position += n
    assert position == info["frames"]
