"""Worker side of the job protocol, against a fake Redis and the CPU engines."""
import shutil
import subprocess

import pytest

from restore_core.recipe import resolve
import time

from restore_worker.worker import Worker, queue_keys

pytestmark = pytest.mark.skipif(
    not shutil.which("ffmpeg") or "libsvtav1" not in subprocess.run(["ffmpeg", "-hide_banner", "-encoders"], capture_output=True, text=True).stdout,
    reason="needs ffmpeg with libsvtav1",
)

FAST = {"encode": {"preset": 10, "crf": 45}}


class FakeRedis:
    """The few Redis commands the worker uses, with the same return shapes as redis-py (decode_responses=True)."""

    def __init__(self):
        self.hashes, self.strings, self.lists, self.ttls = {}, {}, {}, {}

    def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update({k: str(v) for k, v in mapping.items()})

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def expire(self, key, seconds):
        self.ttls[key] = seconds

    def get(self, key):
        return self.strings.get(key)

    def set(self, key, value):
        self.strings[key] = value

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def brpop(self, keys, timeout=0):
        for key in ([keys] if isinstance(keys, str) else keys):          # served in the order given, like Redis
            items = self.lists.get(key, [])
            if items:
                return (key, items.pop())
        return None


@pytest.fixture()
def env(tmp_path):
    """A shared work dir holding one decodable 1 s clip, and a worker for the CPU engines."""
    redis_ = FakeRedis()
    work = tmp_path / "work"
    work.mkdir()
    worker = Worker(redis_, "test-cpu", "cpu", ["classical", "none"], work)

    def submit(recipe_request, *, clip=True, first_frame=0):
        job_id = "a" * 32
        (work / job_id).mkdir(exist_ok=True)
        if clip:
            subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=24:duration=1",
                            "-c:v", "libx264", "-pix_fmt", "yuv420p", str(work / job_id / "in.mkv")], check=True)
        else:
            (work / job_id / "in.mkv").write_bytes(b"this is not a video")
        recipe = resolve(recipe_request)
        redis_.hset(f"restore:job:{job_id}", {"status": "queued", "recipe": recipe.model_dump_json(), "first_frame": first_frame})
        return job_id

    return redis_, worker, work, submit


def test_a_queued_job_runs_to_done_and_leaves_the_result(env):
    redis_, worker, work, submit = env
    job_id = submit({"basic": {"engine": "none", "grain": "off"}, "advanced": FAST})
    worker.handle(job_id)
    job = redis_.hgetall(f"restore:job:{job_id}")
    assert job["status"] == "done" and job["progress"] == "1.0" and job["error"] == ""
    assert (job["frames"], job["width"], job["height"], job["worker"]) == ("24", "320", "180", "test-cpu")
    assert (work / job_id / "out.mkv").stat().st_size > 0
    assert redis_.ttls[f"restore:job:{job_id}"] == 24 * 3600


def test_classical_upscale_reports_the_new_size(env):
    pytest.importorskip("cv2")
    redis_, worker, work, submit = env
    job_id = submit({"basic": {"engine": "classical", "target_height": 360}, "advanced": FAST})
    worker.handle(job_id)
    assert redis_.hgetall(f"restore:job:{job_id}")["width"] == "640"


def test_an_engine_this_worker_does_not_offer_fails_the_job_not_the_worker(env):
    redis_, worker, work, submit = env
    job_id = submit({"advanced": FAST})                                   # default engine is recavsr
    worker.handle(job_id)
    job = redis_.hgetall(f"restore:job:{job_id}")
    assert job["status"] == "failed" and "does not offer engine 'recavsr'" in job["error"]
    assert not (work / job_id / "out.mkv").exists()


def test_a_cancel_flag_set_before_the_start_ends_the_job_as_cancelled(env):
    redis_, worker, work, submit = env
    job_id = submit({"basic": {"engine": "none"}, "advanced": FAST})
    redis_.set(f"restore:cancel:{job_id}", "1")
    worker.handle(job_id)
    assert redis_.hgetall(f"restore:job:{job_id}")["status"] == "cancelled"
    assert not (work / job_id / "out.mkv").exists()


def test_a_corrupt_input_fails_with_a_message_and_cleans_up(env):
    redis_, worker, work, submit = env
    job_id = submit({"basic": {"engine": "none"}, "advanced": FAST}, clip=False)
    worker.handle(job_id)
    job = redis_.hgetall(f"restore:job:{job_id}")
    assert job["status"] == "failed" and job["error"].startswith("PipelineError")
    assert not (work / job_id / "out.mkv").exists()


def test_a_job_that_is_not_queued_is_left_alone(env):
    redis_, worker, work, submit = env
    job_id = submit({"basic": {"engine": "none"}, "advanced": FAST})
    redis_.hset(f"restore:job:{job_id}", {"status": "cancelled"})
    worker.handle(job_id)
    assert redis_.hgetall(f"restore:job:{job_id}")["status"] == "cancelled"
    assert not (work / job_id / "out.mkv").exists()


def test_a_missing_job_record_is_skipped(env):
    redis_, worker, work, submit = env
    worker.handle("b" * 32)                                              # popped id whose hash already expired
    assert redis_.hgetall("restore:job:" + "b" * 32) == {}


def test_the_heartbeat_registers_engines_with_a_short_expiry(env):
    redis_, worker, work, submit = env
    worker.heartbeat()
    record = redis_.hgetall("restore:worker:test-cpu")
    assert record["engines"] == "classical,none" and record["device"] == "cpu"
    assert redis_.ttls["restore:worker:test-cpu"] == 60


def test_a_worker_pops_only_the_queues_of_its_engines_most_capable_first():
    assert queue_keys(["classical", "none"]) == ["restore:queue:classical", "restore:queue:none"]
    assert queue_keys(["none", "recavsr", "classical"]) == ["restore:queue:recavsr", "restore:queue:classical", "restore:queue:none"]
    assert queue_keys(["sparkvsr"]) == []                                  # unknown engines get no queue


def test_a_cpu_worker_never_sees_a_recavsr_job(env):
    redis_, worker, work, submit = env
    redis_.lpush("restore:queue:recavsr", "r" * 32)
    redis_.lpush("restore:queue:none", "n" * 32)
    assert redis_.brpop(queue_keys(worker.engines), timeout=0) == ("restore:queue:none", "n" * 32)
    assert redis_.brpop(queue_keys(worker.engines), timeout=0) is None     # the recavsr job stays queued for a GPU worker


def test_the_keepalive_refreshes_updated_at_while_a_job_runs(env):
    redis_, worker, work, submit = env
    import threading
    job_id = submit({"basic": {"engine": "none"}})
    redis_.hset(f"restore:job:{job_id}", {"updated_at": "old"})
    worker.keepalive_every = 0.05
    done = threading.Event()
    t = threading.Thread(target=worker._keepalive, args=(job_id, done), daemon=True)
    t.start()
    time.sleep(0.3)
    done.set()
    t.join(1)
    assert redis_.hgetall(f"restore:job:{job_id}")["updated_at"] != "old"


def test_the_cpu_image_copies_every_module_the_worker_imports():
    from pathlib import Path

    dockerfile = (Path(__file__).resolve().parents[2] / "restore-worker" / "Dockerfile.cpu").read_text()
    for module in ("finish", "hdr", "pipeline", "worker", "faces", "face_zoom", "heads"):          # faces is imported lazily by the pipeline
        assert f"restore_worker/{module}.py" in dockerfile, module
