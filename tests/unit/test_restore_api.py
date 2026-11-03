"""Unit tests for the restoration API (/v1/restore).

They run the real router and service on a FastAPI TestClient, with an in-memory Redis stand-in and
a temporary directory as the shared volume. ffprobe and ffmpeg must be on PATH (the API image has
both); the test videos are generated with ffmpeg's lavfi sources, nothing is downloaded.

Author: Lorenzo Albanese (alblor)
"""

import asyncio
import fnmatch
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# main.py exits at import time without Docker secrets; give it throwaway ones if none are set.
if "SECURE_SECRETS_PATH" not in os.environ:
    _secrets = Path(tempfile.mkdtemp(prefix="restore-test-secrets-"))
    for _name, _value in {
        "jwt_secret": "j" * 40,
        "encryption_master_key": "dGVzdC1tYXN0ZXIta2V5LWZvci11bml0LXRlc3Rpbmc=",
        "api_master_key": "a" * 32,
        "redis_password": "r" * 24,
    }.items():
        (_secrets / _name).write_text(_value)
    os.environ["SECURE_SECRETS_PATH"] = str(_secrets)

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from starlette.datastructures import UploadFile

from app.documentation import DocumentationManager
from app.encryption import EncryptionManager
from app.restore.config import RestoreConfig
from app.restore.files import decrypt_password_file, wipe_dir, wipe_file
from app.restore.models import now_iso
from app.restore.models import is_job_id
from app.restore.router import restore_validation_handler, router
from app.restore.service import RestoreService
from app.restore.store import RestoreStore
from restore_core.recipe import PRESETS

pytestmark = pytest.mark.skipif(
    shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None,
    reason="ffmpeg and ffprobe are required",
)

MASTER_KEY = "dGVzdC1tYXN0ZXIta2V5LWZvci11bml0LXRlc3Rpbmc="
PASSWORD = "correct horse battery staple"


# --- in-memory Redis ------------------------------------------------------------------------------


class FakeRedis:
    """The few Redis commands the restoration API uses, with expiry on a clock the tests control."""

    def __init__(self) -> None:
        self.data: dict = {}
        self.expires: dict = {}
        self.offset = 0.0

    def _now(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def _purge(self) -> None:
        for key in [k for k, t in self.expires.items() if t <= self._now()]:
            self.data.pop(key, None)
            del self.expires[key]

    def hset(self, key, mapping=None, **kw):
        self._purge()
        self.data.setdefault(key, {}).update(
            {str(k): str(v) for k, v in (mapping or {}).items()}
        )
        return len(mapping or {})

    def hgetall(self, key):
        self._purge()
        value = self.data.get(key)
        return dict(value) if isinstance(value, dict) else {}

    def expire(self, key, seconds):
        self._purge()
        if key in self.data:
            self.expires[key] = self._now() + seconds
            return True
        return False

    def ttl(self, key):
        self._purge()
        if key not in self.data:
            return -2
        return int(self.expires[key] - self._now()) if key in self.expires else -1

    def set(self, key, value, ex=None):
        self._purge()
        self.data[key] = str(value)
        self.expires.pop(key, None)
        if ex:
            self.expires[key] = self._now() + ex
        return True

    def setex(self, key, seconds, value):
        return self.set(key, value, ex=seconds)

    def get(self, key):
        self._purge()
        value = self.data.get(key)
        return value if isinstance(value, str) else None

    def delete(self, *keys):
        self._purge()
        return sum(1 for k in keys if self.data.pop(k, None) is not None)

    def lpush(self, key, *values):
        self._purge()
        self.data.setdefault(key, [])
        for v in values:
            self.data[key].insert(0, str(v))
        return len(self.data[key])

    def lrem(self, key, count, value):
        self._purge()
        items = self.data.get(key, [])
        self.data[key] = [i for i in items if i != value]
        return len(items) - len(self.data[key])

    def llen(self, key):
        self._purge()
        return len(self.data.get(key, []))

    def scan_iter(self, match="*", count=None):
        self._purge()
        yield from [k for k in list(self.data) if fnmatch.fnmatch(k, match)]


# --- media fixtures ---------------------------------------------------------------------------------


def _ffmpeg(*args: str) -> None:
    subprocess.run(
        ["ffmpeg", "-v", "error", "-y", *args], check=True, stdin=subprocess.DEVNULL
    )


@pytest.fixture(scope="session")
def media(tmp_path_factory):
    """Small generated clips: a valid mkv and mp4 (10 frames, 64x64), a two-video-stream mkv, a bigger-frame mkv."""
    folder = tmp_path_factory.mktemp("media")
    src = ["-f", "lavfi", "-i", "testsrc=size=64x64:rate=10", "-t", "1"]
    paths = {
        "mkv": folder / "good.mkv",
        "mp4": folder / "good.mp4",
        "two_video": folder / "two.mkv",
        "big_frame": folder / "big.mkv",
    }
    _ffmpeg(*src, "-c:v", "mpeg4", str(paths["mkv"]))
    _ffmpeg(*src, "-c:v", "mpeg4", str(paths["mp4"]))
    _ffmpeg(
        *src, *src, "-map", "0", "-map", "1", "-c:v", "mpeg4", str(paths["two_video"])
    )
    _ffmpeg(
        "-f",
        "lavfi",
        "-i",
        "testsrc=size=320x240:rate=10",
        "-t",
        "1",
        "-c:v",
        "mpeg4",
        str(paths["big_frame"]),
    )
    return {name: path.read_bytes() for name, path in paths.items()}


# --- app fixtures -----------------------------------------------------------------------------------


@pytest.fixture
def redis_fake():
    return FakeRedis()


@pytest.fixture
def config(tmp_path):
    work = tmp_path / "restore-work"
    work.mkdir()
    return RestoreConfig(
        work_dir=work,
        worker_gid=os.getgid(),
        max_segment_bytes=5 * 1024 * 1024,
        max_frames=50,
        max_pixels=128 * 128,
        max_jobs=10,
        wipe_passes=1,
        free_space_margin_bytes=0,
    )


@pytest.fixture
def manager(redis_fake):
    return EncryptionManager(master_key=MASTER_KEY, redis_client=redis_fake)


@pytest.fixture
def service(redis_fake, config, manager):
    return RestoreService(RestoreStore(redis_fake), config, manager)


@pytest.fixture
def client(service):
    app = FastAPI()
    app.include_router(router)
    app.add_exception_handler(RequestValidationError, restore_validation_handler)
    app.state.restore_service = service
    return TestClient(app)


ALICE = {"X-API-Key": "alice-key"}
BOB = {"X-API-Key": "bob-key"}


def submit(
    client,
    data: bytes,
    recipe=None,
    headers=ALICE,
    password=None,
    extra=None,
    filename="clip.mkv",
):
    fields = {
        "recipe": json.dumps(recipe if recipe is not None else {"preset": "draft"})
    }
    if password is not None:
        fields["decryption_password"] = password
    fields.update(extra or {})
    return client.post(
        "/v1/restore/jobs",
        files={"file": (filename, data, "video/x-matroska")},
        data=fields,
        headers=headers,
    )


def encrypted(manager, tmp_path, data: bytes, password=PASSWORD) -> bytes:
    plain, enc = tmp_path / "plain.bin", tmp_path / "enc.bin"
    plain.write_bytes(data)
    manager.encrypt_password_based_file(str(plain), str(enc), password)
    return enc.read_bytes()


def worker_finishes(
    redis_fake,
    config,
    job_id: str,
    payload: bytes = b"RESTORED-RESULT" * 100,
    status: str = "done",
) -> None:
    """Do what the GPU worker does on the shared volume and in Redis."""
    if status == "done":
        (config.work_dir / job_id / "out.mkv").write_bytes(payload)
    redis_fake.hset(
        f"restore:job:{job_id}",
        mapping={
            "status": status,
            "stage": "",
            "progress": "1.0",
            "frames": "10",
            "width": "128",
            "height": "128",
            "seconds": "3.5",
            "updated_at": now_iso(),
        },
    )
    redis_fake.expire(f"restore:job:{job_id}", 24 * 3600)


def queue_total(redis_fake) -> int:
    return sum(
        redis_fake.llen(f"restore:queue:{e}") for e in ("recavsr", "classical", "none")
    )


def register_worker(redis_fake, name="gpu0", engines="recavsr,classical,none"):
    redis_fake.hset(
        f"restore:worker:{name}",
        mapping={"engines": engines, "device": "cuda:0", "updated_at": now_iso()},
    )
    redis_fake.expire(f"restore:worker:{name}", 60)


# --- presets and resolve ----------------------------------------------------------------------------


def test_presets_lists_every_preset_with_its_resolved_recipe(client):
    body = client.get("/v1/restore/presets").json()["presets"]
    assert set(body) == set(PRESETS)
    assert body["draft"]["description"] == PRESETS["draft"]["description"]
    assert body["draft"]["recipe"]["basic"]["target_height"] == 1080
    assert body["draft"]["recipe"]["advanced"]["encode"]["tune"] == 0


def test_resolve_returns_effective_recipe_and_queues_nothing(client, redis_fake):
    response = client.post(
        "/v1/restore/recipe/resolve",
        json={"preset": "budget", "basic": {"quality": "maximum"}},
    )
    assert response.status_code == 200
    recipe = response.json()["effective_recipe"]
    assert (
        recipe["basic"]["engine"] == "classical"
        and recipe["basic"]["quality"] == "maximum"
    )
    assert recipe["advanced"]["restore"]["tile_height"] == 1152
    assert queue_total(redis_fake) == 0


@pytest.mark.parametrize(
    "body, needle",
    [
        ({"preset": "nope"}, "unknown preset"),
        ({"basic": {"target_height": 99999}}, "target_height"),
        ({"basic": {"engine": "magic"}}, "engine"),
        ({"advanced": {"restore": {"tile_height": 1000}}}, "tile_height"),
        (
            {"advanced": {"restore": {"min_overlap": 4096, "tile_height": 512}}},
            "min_overlap",
        ),
        ({"surprise": 1}, "surprise"),
        ({"advanced": {"encode": {"tune": 3}}}, "tune"),
    ],
)
def test_resolve_rejects_bad_recipes_with_422(client, body, needle):
    response = client.post("/v1/restore/recipe/resolve", json=body)
    assert response.status_code == 422
    error = response.json()["detail"]["error"]
    assert error["type"] == "validation_error"
    assert needle in error["message"]


def test_resolve_rejects_non_object_body(client):
    assert client.post("/v1/restore/recipe/resolve", json=[1, 2]).status_code == 422


# --- submit: the three encryption modes ---------------------------------------------------------------


@pytest.mark.parametrize("mode", ["automated", "manual", "off"])
def test_submit_each_encryption_mode(
    client, redis_fake, config, manager, media, tmp_path, mode
):
    recipe = {"preset": "draft", "basic": {"encryption": mode}}
    if mode == "manual":
        response = submit(
            client,
            encrypted(manager, tmp_path, media["mkv"]),
            recipe,
            password=PASSWORD,
        )
    else:
        response = submit(client, media["mkv"], recipe)
    assert response.status_code == 200, response.text
    body = response.json()
    job_id = body["job_id"]
    assert len(job_id) == 32 and job_id == job_id.lower() and int(job_id, 16) >= 0
    assert body["status"] == "queued" and body["encryption"] == mode
    assert (
        body["recipe"]["basic"]["encryption"] == mode
        and body["recipe"]["preset"] == "draft"
    )
    assert body["input"] == {
        "bytes": len(media["mkv"]),
        "width": 64,
        "height": 64,
        "frames": 10,
    }

    directory = config.work_dir / job_id
    assert sorted(p.name for p in directory.iterdir()) == [
        "in.mkv"
    ]  # manual: the encrypted upload is gone
    assert (directory / "in.mkv").read_bytes() == media["mkv"]
    assert stat.S_IMODE(directory.stat().st_mode) == 0o770
    assert stat.S_IMODE((directory / "in.mkv").stat().st_mode) == 0o660
    assert directory.stat().st_gid == config.worker_gid

    record = redis_fake.hgetall(f"restore:job:{job_id}")
    assert (
        record["status"] == "queued"
        and record["progress"] == "0.0"
        and record["error"] == ""
    )
    assert json.loads(record["recipe"]) == body["recipe"]
    assert (
        record["encryption"] == mode
        and record["first_frame"] == "0"
        and record["segment_index"] == "0"
    )
    assert redis_fake.ttl(f"restore:job:{job_id}") > 0
    assert redis_fake.data["restore:queue:recavsr"] == [job_id]  # draft wants recavsr
    assert ("restore:pw:" + job_id in redis_fake.data) == (mode == "manual")
    assert PASSWORD not in json.dumps(
        redis_fake.data
    )  # the password never sits in Redis in the clear


def test_submit_keeps_first_frame_and_segment_index(client, redis_fake, media):
    body = submit(
        client, media["mkv"], extra={"first_frame": "1234", "segment_index": "7"}
    ).json()
    record = redis_fake.hgetall(f"restore:job:{body['job_id']}")
    assert record["first_frame"] == "1234" and record["segment_index"] == "7"


@pytest.mark.parametrize(
    "extra",
    [{"first_frame": "-1"}, {"segment_index": "x"}, {"first_frame": str(2**41)}],
)
def test_submit_rejects_bad_counters(client, media, config, extra):
    assert submit(client, media["mkv"], extra=extra).status_code == 422
    assert list(config.work_dir.iterdir()) == []


def test_submit_default_encryption_is_automated(client, media):
    assert (
        submit(client, media["mkv"], {"preset": "draft"}).json()["encryption"]
        == "automated"
    )


def test_submit_accepts_mp4(client, media):
    response = submit(client, media["mp4"], filename="clip.mp4")
    assert response.status_code == 200 and response.json()["input"]["frames"] == 10


def test_manual_mode_requires_password(client, media, config, manager, tmp_path):
    recipe = {"preset": "draft", "basic": {"encryption": "manual"}}
    response = submit(client, encrypted(manager, tmp_path, media["mkv"]), recipe)
    assert response.status_code == 400
    assert "decryption_password" in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == []


def test_manual_mode_wrong_password_is_rejected_and_wiped(
    client, redis_fake, media, config, manager, tmp_path
):
    recipe = {"preset": "draft", "basic": {"encryption": "manual"}}
    response = submit(
        client, encrypted(manager, tmp_path, media["mkv"]), recipe, password="wrong"
    )
    assert response.status_code == 422
    assert "decrypted" in response.json()["detail"]["error"]["message"]
    assert "wrong" not in response.text
    assert list(config.work_dir.iterdir()) == []
    assert not [
        k
        for k in redis_fake.data
        if k.startswith("restore:job:") or k.startswith("restore:pw:")
    ]
    assert queue_total(redis_fake) == 0


def test_password_is_ignored_outside_manual_mode(client, redis_fake, media):
    body = submit(client, media["mkv"], password="unused").json()
    assert ("restore:pw:" + body["job_id"]) not in redis_fake.data


# --- submit: validation ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "recipe_text, needle",
    [
        ("{not json", "JSON"),
        (json.dumps({"preset": "nope"}), "unknown preset"),
        (json.dumps({"basic": {"quality": "ultra"}}), "quality"),
        (json.dumps({"basic": {"encryption": "plain"}}), "encryption"),
    ],
)
def test_submit_rejects_bad_recipe_before_touching_disk(
    client, media, config, recipe_text, needle
):
    response = client.post(
        "/v1/restore/jobs",
        files={"file": ("c.mkv", media["mkv"])},
        data={"recipe": recipe_text},
    )
    assert response.status_code == 422
    assert needle in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == []


def test_submit_without_recipe_is_422_in_the_project_error_shape(client, media):
    response = client.post("/v1/restore/jobs", files={"file": ("c.mkv", media["mkv"])})
    assert response.status_code == 422
    error = response.json()["detail"]["error"]
    assert error["type"] == "validation_error" and "recipe" in error["message"]
    assert error["problems"][0]["field"] == "recipe"


def test_not_a_video_is_rejected_and_wiped(client, redis_fake, config):
    response = submit(client, b"this is not a video at all" * 100)
    assert response.status_code == 422
    assert "Matroska or MP4" in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == []
    assert queue_total(redis_fake) == 0


def test_playlist_text_is_not_followed(client, config):
    playlist = (
        b"#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:1,\nfile:///etc/hostname\n#EXT-X-ENDLIST\n"
    )
    assert submit(client, playlist).status_code == 422
    assert list(config.work_dir.iterdir()) == []


def test_empty_upload_is_rejected(client, config):
    assert submit(client, b"").status_code == 422
    assert list(config.work_dir.iterdir()) == []


def test_two_video_streams_are_rejected(client, media, config):
    response = submit(client, media["two_video"])
    assert response.status_code == 422
    assert "exactly one video stream" in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == []


def test_frame_limit(client, media, config, service):
    service.config = replace(config, max_frames=5)
    response = submit(client, media["mkv"])
    assert (
        response.status_code == 422
        and "frames" in response.json()["detail"]["error"]["message"]
    )
    assert list(config.work_dir.iterdir()) == []


def test_pixel_limit(client, media, config, service):
    service.config = replace(config, max_pixels=64 * 64)
    assert submit(client, media["mkv"]).status_code == 200  # exactly at the limit
    response = submit(client, media["big_frame"])  # 320x240
    assert (
        response.status_code == 422
        and "pixels" in response.json()["detail"]["error"]["message"]
    )


def test_client_file_name_is_ignored(client, config, media):
    body = submit(
        client, media["mkv"], filename="../../../etc/passwd; rm -rf x.mkv"
    ).json()
    assert sorted(p.name for p in (config.work_dir / body["job_id"]).iterdir()) == [
        "in.mkv"
    ]
    assert sorted(p.name for p in config.work_dir.iterdir()) == [body["job_id"]]


# --- size cap -----------------------------------------------------------------------------------------------


def test_content_length_over_cap_is_refused_before_reading(
    client, service, config, media
):
    service.config = replace(config, max_segment_bytes=1024, form_overhead_bytes=1024)
    response = submit(client, b"\0" * 4096)
    assert response.status_code == 413
    assert response.json()["detail"]["error"]["type"] == "payload_too_large"
    assert list(config.work_dir.iterdir()) == []


def test_chunked_upload_without_length_is_refused(client):
    response = client.post(
        "/v1/restore/jobs",
        content=iter([b"abc"]),
        headers={"content-type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 411


def test_stream_cap_stops_a_body_that_outgrows_the_header(service, config, redis_fake):
    """The streaming loop enforces the cap on its own, whatever the header said."""
    service.config = replace(config, max_segment_bytes=1000, upload_chunk_bytes=100)
    upload = UploadFile(file=io.BytesIO(b"\0" * 5000), filename="x.mkv")
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        asyncio.run(
            service.submit_job(
                "anonymous", upload, json.dumps({"preset": "draft"}), 0, 0, None
            )
        )
    assert caught.value.status_code == 413
    assert list(config.work_dir.iterdir()) == []


def test_job_count_limit(client, media, service, config):
    service.config = replace(config, max_jobs=2)
    assert submit(client, media["mkv"]).status_code == 200
    assert submit(client, media["mkv"]).status_code == 200
    assert submit(client, media["mkv"]).status_code == 429


def test_missing_volume_is_503(client, media, config):
    shutil.rmtree(config.work_dir)
    assert submit(client, media["mkv"]).status_code == 503


# --- status, ownership -----------------------------------------------------------------------------------------


def test_status_follows_the_worker(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    assert (
        client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()["status"]
        == "queued"
    )
    redis_fake.hset(
        f"restore:job:{job_id}",
        mapping={"status": "running", "stage": "restore", "progress": "0.42"},
    )
    running = client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()
    assert (
        running["status"] == "running"
        and running["stage"] == "restore"
        and running["progress"] == 0.42
    )
    worker_finishes(redis_fake, config, job_id, payload=b"x" * 321)
    done = client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()
    assert done["status"] == "done" and done["result"] == {
        "frames": 10,
        "width": 128,
        "height": 128,
        "seconds": 3.5,
        "bytes": 321,
    }
    assert done["recipe"]["preset"] == "draft"


def test_failed_job_shows_the_error(client, redis_fake, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.hset(
        f"restore:job:{job_id}",
        mapping={"status": "failed", "error": "CUDA out of memory"},
    )
    body = client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()
    assert body["status"] == "failed" and body["error"] == "CUDA out of memory"


def test_owner_isolation_everything_is_404_for_others(
    client, redis_fake, config, media
):
    job_id = submit(client, media["mkv"], headers=ALICE).json()["job_id"]
    worker_finishes(redis_fake, config, job_id)
    for other in (BOB, {}):
        assert (
            client.get(f"/v1/restore/jobs/{job_id}", headers=other).status_code == 404
        )
        assert (
            client.get(f"/v1/restore/jobs/{job_id}/download", headers=other).status_code
            == 404
        )
        assert (
            client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=other).status_code
            == 404
        )
        assert (
            client.delete(f"/v1/restore/jobs/{job_id}", headers=other).status_code
            == 404
        )
    assert (
        config.work_dir / job_id / "out.mkv"
    ).exists()  # the owner's job is untouched
    assert client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 200


@pytest.mark.parametrize(
    "job_id", ["0" * 32, "../etc", "A" * 32, "x" * 31, "..%2f..%2f", "g" * 32]
)
def test_unknown_or_malformed_ids_are_404(client, job_id):
    assert client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 404
    assert client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 404


# --- download ---------------------------------------------------------------------------------------------------


def test_download_only_when_done(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    for status in ("queued", "running", "failed", "cancelled"):
        redis_fake.hset(f"restore:job:{job_id}", mapping={"status": status})
        response = client.get(f"/v1/restore/jobs/{job_id}/download", headers=ALICE)
        assert response.status_code == 409, status
        assert status in response.json()["detail"]["error"]["message"]


@pytest.mark.parametrize("mode", ["automated", "off"])
def test_download_plain_modes(client, redis_fake, config, media, mode):
    job_id = submit(
        client, media["mkv"], {"preset": "draft", "basic": {"encryption": mode}}
    ).json()["job_id"]
    worker_finishes(redis_fake, config, job_id, payload=b"RESULT-BYTES" * 5000)
    response = client.get(f"/v1/restore/jobs/{job_id}/download", headers=ALICE)
    assert response.status_code == 200
    assert response.content == b"RESULT-BYTES" * 5000
    assert (
        response.headers["content-disposition"] == 'attachment; filename="restored.mkv"'
    )
    assert response.headers["content-length"] == str(len(response.content))
    assert response.headers["content-type"] == "video/x-matroska"


def test_download_manual_mode_is_encrypted_with_the_job_password(
    client, redis_fake, config, media, manager, tmp_path
):
    recipe = {"preset": "draft", "basic": {"encryption": "manual"}}
    job_id = submit(
        client, encrypted(manager, tmp_path, media["mkv"]), recipe, password=PASSWORD
    ).json()["job_id"]
    result = os.urandom(3 * 1024 * 1024 + 17)
    worker_finishes(redis_fake, config, job_id, payload=result)
    response = client.get(f"/v1/restore/jobs/{job_id}/download", headers=ALICE)
    assert response.status_code == 200
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="restored.mkv.enc"'
    )
    assert response.content != result and len(response.content) == len(result) + 64
    assert response.headers["content-length"] == str(len(response.content))
    (tmp_path / "dl.enc").write_bytes(response.content)
    # The client-side format: the project's own decrypt routine reads it back.
    manager.decrypt_password_based_file(
        str(tmp_path / "dl.enc"), str(tmp_path / "dl.mkv"), PASSWORD
    )
    assert (tmp_path / "dl.mkv").read_bytes() == result
    assert not [
        p for p in (config.work_dir / job_id).iterdir() if p.name.startswith("dl-")
    ]  # temp copy wiped


def test_download_missing_result_file_is_404(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.hset(f"restore:job:{job_id}", mapping={"status": "done"})
    assert (
        client.get(f"/v1/restore/jobs/{job_id}/download", headers=ALICE).status_code
        == 404
    )


# --- cancel and delete --------------------------------------------------------------------------------------------


def test_cancel_queued_job(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    response = client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE)
    assert response.status_code == 200 and response.json()["status"] == "cancelled"
    assert redis_fake.get(f"restore:cancel:{job_id}") == "1"
    assert queue_total(redis_fake) == 0
    assert not (config.work_dir / job_id).exists()
    assert redis_fake.ttl(f"restore:job:{job_id}") > 0
    again = client.post(
        f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE
    )  # idempotent
    assert again.status_code == 200 and again.json()["status"] == "cancelled"


def test_cancel_running_job_waits_for_the_worker_then_cleanup_wipes(
    client, redis_fake, config, media, service
):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.hset(
        f"restore:job:{job_id}", mapping={"status": "running", "stage": "restore"}
    )
    body = client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE).json()
    assert body["status"] == "running" and body["cancelling"] is True
    assert redis_fake.get(f"restore:cancel:{job_id}") == "1"
    assert (
        config.work_dir / job_id / "in.mkv"
    ).exists()  # the worker is still reading it
    assert service.cleanup_once() == {"wiped": 0, "failed": 0, "reaped": 0}
    worker_finishes(
        redis_fake, config, job_id, status="cancelled"
    )  # the worker saw the flag
    assert (
        client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()["status"]
        == "cancelled"
    )
    assert service.cleanup_once() == {"wiped": 1, "failed": 0, "reaped": 0}
    assert not (config.work_dir / job_id).exists()
    assert (
        client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()["status"]
        == "cancelled"
    )


def test_cancel_finished_job_changes_nothing(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    worker_finishes(redis_fake, config, job_id)
    body = client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE).json()
    assert body["status"] == "done"
    assert redis_fake.get(f"restore:cancel:{job_id}") is None


def test_delete_wipes_files_and_keys(
    client, redis_fake, config, manager, media, tmp_path
):
    recipe = {"preset": "draft", "basic": {"encryption": "manual"}}
    job_id = submit(
        client, encrypted(manager, tmp_path, media["mkv"]), recipe, password=PASSWORD
    ).json()["job_id"]
    worker_finishes(redis_fake, config, job_id)
    key_keys = [k for k in redis_fake.data if k.startswith("key:")]
    assert len(key_keys) == 1
    response = client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE)
    assert response.status_code == 200 and response.json() == {
        "job_id": job_id,
        "deleted": True,
    }
    assert not (config.work_dir / job_id).exists()
    leftovers = [
        k
        for k in redis_fake.data
        if job_id in k and not k.startswith("restore:cancel:")
    ]
    assert leftovers == [] and not [k for k in redis_fake.data if k.startswith("key:")]
    assert client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 404
    assert (
        client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 404
    )  # already gone


def test_delete_queued_job_takes_it_off_the_queue(client, redis_fake, config, media):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    assert client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 200
    assert queue_total(redis_fake) == 0
    assert (
        redis_fake.get(f"restore:cancel:{job_id}") == "1"
    )  # a worker that just popped it still stops


def test_delete_running_job_is_deferred_until_it_stops(
    client, redis_fake, config, media, service
):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.hset(f"restore:job:{job_id}", mapping={"status": "running"})
    response = client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE)
    assert response.status_code == 202 and response.json()["deleted"] is False
    assert (config.work_dir / job_id).exists()
    worker_finishes(redis_fake, config, job_id, status="cancelled")
    assert service.cleanup_once() == {"wiped": 1, "failed": 0, "reaped": 0}
    assert not (config.work_dir / job_id).exists()
    assert client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 404


def test_wipe_overwrites_before_unlinking(tmp_path):
    victim = tmp_path / "secret.bin"
    victim.write_bytes(b"PLAINTEXT-FRAME-DATA" * 1000)
    survivor = tmp_path / "hardlink.bin"
    os.link(
        victim, survivor
    )  # same inode: shows what is left in the blocks after the wipe
    assert wipe_file(victim, passes=2) is True
    assert not victim.exists()
    assert (
        survivor.stat().st_size == 20000 and b"PLAINTEXT" not in survivor.read_bytes()
    )


def test_wipe_dir_removes_nested_files_and_never_follows_symlinks(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep me")
    target = tmp_path / "job"
    (target / "sub").mkdir(parents=True)
    (target / "a.bin").write_bytes(b"a" * 10)
    (target / "sub" / "b.bin").write_bytes(b"b" * 10)
    (target / "link").symlink_to(outside)
    assert wipe_dir(target, passes=1) is True
    assert not target.exists() and outside.read_text() == "keep me"


# --- capabilities -----------------------------------------------------------------------------------------------------


def test_capabilities_without_a_worker_says_so(client, redis_fake, media):
    body = client.get("/v1/restore/capabilities").json()
    assert (
        body["available"] is False and body["engines"] == [] and body["workers"] == []
    )
    assert "No restoration worker is running" in body["message"]
    assert body["queue_length"] == 0
    submitted = submit(client, media["mkv"]).json()
    assert "No restoration worker" in submitted["warning"]
    assert client.get("/v1/restore/capabilities").json()["queue_length"] == 1


def test_capabilities_with_live_workers(client, redis_fake, media):
    register_worker(redis_fake, "gpu0", "recavsr,classical,none")
    register_worker(redis_fake, "gpu1", "classical,none,bogus")
    body = client.get("/v1/restore/capabilities").json()
    assert body["available"] is True and body["engines"] == [
        "classical",
        "none",
        "recavsr",
    ]
    assert [w["name"] for w in body["workers"]] == ["gpu0", "gpu1"]
    assert body["workers"][1]["engines"] == [
        "classical",
        "none",
    ]  # unknown names are dropped
    assert "warning" not in submit(client, media["mkv"]).json()


def test_capabilities_forgets_a_worker_after_its_ttl(client, redis_fake):
    register_worker(redis_fake)
    assert client.get("/v1/restore/capabilities").json()["available"] is True
    redis_fake.advance(61)
    assert client.get("/v1/restore/capabilities").json()["available"] is False


def test_submit_warns_when_no_worker_offers_the_engine(client, redis_fake, media):
    register_worker(redis_fake, "cpu0", "classical,none")
    body = submit(
        client, media["mkv"], {"preset": "draft"}
    ).json()  # draft wants recavsr
    assert "recavsr" in body["warning"]


# --- cleanup ------------------------------------------------------------------------------------------------------------


def test_cleanup_wipes_directories_whose_hash_expired(
    client, redis_fake, config, media, service
):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.advance(config.job_ttl_seconds + 1)
    assert service.cleanup_once() == {"wiped": 1, "failed": 0, "reaped": 0}
    assert not (config.work_dir / job_id).exists()


def test_cleanup_keeps_running_and_recent_finished_jobs(
    client, redis_fake, config, media, service
):
    running = submit(client, media["mkv"]).json()["job_id"]
    redis_fake.hset(f"restore:job:{running}", mapping={"status": "running"})
    done = submit(client, media["mkv"]).json()["job_id"]
    worker_finishes(redis_fake, config, done)
    assert service.cleanup_once() == {"wiped": 0, "failed": 0, "reaped": 0}
    assert (config.work_dir / running).exists() and (config.work_dir / done).exists()


def test_cleanup_wipes_terminal_jobs_older_than_24_hours(
    client, redis_fake, config, media, service
):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    worker_finishes(redis_fake, config, job_id)
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(
        timespec="seconds"
    )
    redis_fake.hset(f"restore:job:{job_id}", mapping={"updated_at": old})
    redis_fake.expire(
        f"restore:job:{job_id}", 10**6
    )  # the hash outlives its directory
    assert service.cleanup_once() == {"wiped": 1, "failed": 0, "reaped": 0}
    assert not (config.work_dir / job_id).exists()
    assert redis_fake.hgetall(f"restore:job:{job_id}") == {}


def test_cleanup_skips_uploads_in_progress_and_foreign_directories(
    redis_fake, config, service
):
    receiving = "a" * 32
    (config.work_dir / receiving).mkdir()
    (config.work_dir / receiving / "in.mkv").write_bytes(b"half an upload")
    foreign = config.work_dir / "lost+found"
    foreign.mkdir()
    service._inflight.add(receiving)
    assert service.cleanup_once() == {"wiped": 0, "failed": 0, "reaped": 0}
    assert (config.work_dir / receiving).exists() and foreign.exists()
    service._inflight.discard(receiving)
    assert service.cleanup_once() == {
        "wiped": 1,
        "failed": 0,
        "reaped": 0,
    }  # no hash, nobody receiving: stale
    assert foreign.exists()


def test_cleanup_gives_an_expiry_to_hashes_a_worker_recreated(redis_fake, service):
    stray = "b" * 32
    redis_fake.hset(
        f"restore:job:{stray}", mapping={"status": "failed"}
    )  # no owner, no ttl
    assert redis_fake.ttl(f"restore:job:{stray}") == -1
    service.cleanup_once()
    assert 0 < redis_fake.ttl(f"restore:job:{stray}") <= 3600


# --- manual-mode crypto compatibility ----------------------------------------------------------------------------------------


def test_streaming_decrypt_matches_the_project_format_across_chunks(manager, tmp_path):
    data = os.urandom(300_001)
    source = tmp_path / "enc"
    source.write_bytes(encrypted(manager, tmp_path, data))
    out = tmp_path / "plain"
    size = decrypt_password_file(
        source, out, PASSWORD, os.getgid(), chunk_size=4096, max_plain_bytes=10**9
    )
    assert size == len(data) and out.read_bytes() == data


def test_streaming_decrypt_detects_tampering(manager, tmp_path):
    blob = bytearray(encrypted(manager, tmp_path, b"x" * 5000))
    blob[100] ^= 1
    source = tmp_path / "enc"
    source.write_bytes(bytes(blob))
    with pytest.raises(ValueError):
        decrypt_password_file(
            source, tmp_path / "plain", PASSWORD, os.getgid(), 4096, 10**9
        )


def test_streaming_decrypt_rejects_short_files(tmp_path):
    source = tmp_path / "enc"
    source.write_bytes(b"tiny")
    with pytest.raises(ValueError):
        decrypt_password_file(
            source, tmp_path / "plain", PASSWORD, os.getgid(), 4096, 10**9
        )


# --- logging, errors, wiring ---------------------------------------------------------------------------------------------------------


def test_password_never_reaches_the_logs_or_errors(
    client, media, manager, tmp_path, caplog
):
    recipe = {"preset": "draft", "basic": {"encryption": "manual"}}
    with caplog.at_level("DEBUG"):
        bad = submit(
            client,
            encrypted(manager, tmp_path, media["mkv"]),
            recipe,
            password="s3cret-wrong-pw",
        )
        good = submit(
            client,
            encrypted(manager, tmp_path, media["mkv"]),
            recipe,
            password=PASSWORD,
        )
    assert bad.status_code == 422 and good.status_code == 200
    assert (
        "s3cret-wrong-pw" not in bad.text + caplog.text
        and PASSWORD not in good.text + caplog.text
    )


def test_service_missing_is_503():
    app = FastAPI()
    app.include_router(router)
    assert TestClient(app).get("/v1/restore/capabilities").status_code == 503


def test_main_app_includes_the_restore_routes():
    from main import app as main_app

    paths = {
        (route.path, tuple(sorted(route.methods)))
        for route in main_app.routes
        if hasattr(route, "methods")
    }
    for path, method in [
        ("/v1/restore/presets", "GET"),
        ("/v1/restore/recipe/resolve", "POST"),
        ("/v1/restore/jobs", "POST"),
        ("/v1/restore/jobs/{job_id}", "GET"),
        ("/v1/restore/jobs/{job_id}/download", "GET"),
        ("/v1/restore/jobs/{job_id}/cancel", "POST"),
        ("/v1/restore/jobs/{job_id}", "DELETE"),
        ("/v1/restore/capabilities", "GET"),
    ]:
        assert any(p == path and method in m for p, m in paths), (method, path)


# --- documentation ---------------------------------------------------------------------------------------------------------------------

RESTORE_DOC_IDS = [
    "restore_presets",
    "restore_resolve",
    "restore_submit",
    "restore_status",
    "restore_download",
    "restore_cancel",
    "restore_delete",
    "restore_capabilities",
]


def test_every_restore_endpoint_is_documented():
    docs = DocumentationManager()
    listed = {e["id"]: e for e in docs.get_endpoints_list()["manpage"]["endpoints"]}
    for doc_id in RESTORE_DOC_IDS:
        assert doc_id in listed, doc_id
        page = docs.get_endpoint_documentation(doc_id)
        assert page is not None and page["manpage"]["path"] == listed[doc_id]["path"]
        assert page["manpage"]["method"] == listed[doc_id]["method"]


def test_recipe_tiers_are_documented_field_by_field():
    from restore_core.recipe import Advanced, Basic

    tiers = DocumentationManager().get_endpoint_documentation("restore_resolve")[
        "manpage"
    ]["recipe_tiers"]
    assert {"presets", "basic", "advanced"} <= set(tiers)
    assert {f["name"] for f in tiers["basic"]["fields"]} == set(Basic.model_fields)
    assert set(tiers["advanced"]["sections"]) == set(Advanced.model_fields)
    tile = next(
        f
        for f in tiers["advanced"]["sections"]["restore"]["fields"]
        if f["name"] == "tile_height"
    )
    assert (
        tile["default"] == 1152
        and "multiple_of=32" in tile["constraints"]
        and tile["description"]
    )
    assert set(tiers["presets"]) == set(PRESETS)
    json.dumps(
        DocumentationManager().get_endpoint_documentation("restore_resolve")
    )  # must be serialisable


# --- per-engine queues -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "preset, engine",
    [("draft", "recavsr"), ("budget", "classical"), ("clean-4k", "none")],
)
def test_job_goes_to_the_queue_of_its_engine(client, redis_fake, media, preset, engine):
    job_id = submit(client, media["mkv"], {"preset": preset}).json()["job_id"]
    for name in ("recavsr", "classical", "none"):
        assert redis_fake.data.get(f"restore:queue:{name}", []) == (
            [job_id] if name == engine else []
        )
    assert "restore:queue" not in redis_fake.data  # the old single queue is gone
    caps = client.get("/v1/restore/capabilities").json()
    assert caps["queues"] == {
        "recavsr": int(engine == "recavsr"),
        "classical": int(engine == "classical"),
        "none": int(engine == "none"),
    }
    assert caps["queue_length"] == 1


def test_queue_length_is_the_sum_of_the_three_queues(client, redis_fake, media):
    for preset in ("draft", "draft", "budget", "clean-4k"):
        assert submit(client, media["mkv"], {"preset": preset}).status_code == 200
    caps = client.get("/v1/restore/capabilities").json()
    assert caps["queues"] == {"recavsr": 2, "classical": 1, "none": 1}
    assert caps["queue_length"] == 4


def test_sparkvsr_is_refused_at_submit(client, media, config, redis_fake):
    recipe = {"preset": "draft", "basic": {"engine": "sparkvsr"}}
    response = submit(client, media["mkv"], recipe)
    assert response.status_code == 422
    assert "not available" in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == [] and queue_total(redis_fake) == 0


def test_cancel_takes_the_id_off_whichever_queue_holds_it(client, redis_fake, media):
    job_id = submit(client, media["mkv"], {"preset": "budget"}).json()["job_id"]
    assert redis_fake.llen("restore:queue:classical") == 1
    client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE)
    assert queue_total(redis_fake) == 0


# --- stale jobs --------------------------------------------------------------------------------------------


def running_job(client, redis_fake, media, **kw):
    job_id = submit(client, media["mkv"], **kw).json()["job_id"]
    redis_fake.hset(
        f"restore:job:{job_id}", mapping={"status": "running", "stage": "restore"}
    )
    return job_id


def test_silent_running_job_is_failed_by_cleanup(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    start = datetime.now(timezone.utc)
    service._clock = lambda: start + timedelta(seconds=config.stale_seconds - 10)
    assert service.cleanup_once()["reaped"] == 0  # still inside the window
    service._clock = lambda: start + timedelta(seconds=config.stale_seconds + 60)
    assert service.cleanup_once()["reaped"] == 1
    record = redis_fake.hgetall(f"restore:job:{job_id}")
    assert (
        record["status"] == "failed"
        and record["error"] == "the worker stopped responding"
    )
    assert 0 < redis_fake.ttl(f"restore:job:{job_id}") <= config.terminal_ttl_seconds
    assert (
        redis_fake.get(f"restore:cancel:{job_id}") == "1"
    )  # a worker that comes back stops
    assert service.cleanup_once()["reaped"] == 0  # settled once


def test_worker_heartbeat_keeps_a_long_job_alive(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    start = datetime.now(timezone.utc)
    for minutes in (10, 20, 30):  # the worker refreshes updated_at while it runs
        moment = start + timedelta(minutes=minutes)
        redis_fake.hset(
            f"restore:job:{job_id}",
            mapping={"updated_at": moment.isoformat(timespec="seconds")},
        )
        service._clock = lambda m=moment: m + timedelta(minutes=1)
        assert service.cleanup_once()["reaped"] == 0
    assert redis_fake.hgetall(f"restore:job:{job_id}")["status"] == "running"


def test_stale_running_job_can_be_cancelled_and_deleted(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    service._clock = lambda: datetime.now(timezone.utc) + timedelta(
        seconds=config.stale_seconds + 1
    )
    body = client.post(f"/v1/restore/jobs/{job_id}/cancel", headers=ALICE).json()
    assert (
        body["status"] == "failed" and body["error"] == "the worker stopped responding"
    )
    response = client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE)
    assert response.status_code == 200 and response.json()["deleted"] is True
    assert not (config.work_dir / job_id).exists()


def test_delete_of_a_stale_running_job_completes_at_once(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    service._clock = lambda: datetime.now(timezone.utc) + timedelta(
        seconds=config.stale_seconds + 1
    )
    assert client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 200
    assert not (config.work_dir / job_id).exists()
    assert redis_fake.hgetall(f"restore:job:{job_id}") == {}


def test_status_of_a_stale_running_job_says_failed(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    service._clock = lambda: datetime.now(timezone.utc) + timedelta(
        seconds=config.stale_seconds + 1
    )
    assert (
        client.get(f"/v1/restore/jobs/{job_id}", headers=ALICE).json()["status"]
        == "failed"
    )


def test_cleanup_wipes_a_stale_job_that_had_a_delete_pending(
    client, redis_fake, config, media, service
):
    job_id = running_job(client, redis_fake, media)
    assert client.delete(f"/v1/restore/jobs/{job_id}", headers=ALICE).status_code == 202
    service._clock = lambda: datetime.now(timezone.utc) + timedelta(
        seconds=config.stale_seconds + 1
    )
    assert service.cleanup_once()["reaped"] == 1
    assert not (config.work_dir / job_id).exists()
    assert redis_fake.hgetall(f"restore:job:{job_id}") == {}


def test_job_waiting_too_long_in_the_queue_expires(
    client, redis_fake, config, media, service
):
    job_id = submit(client, media["mkv"]).json()["job_id"]
    start = datetime.now(timezone.utc)
    service._clock = lambda: start + timedelta(seconds=config.queue_max_seconds - 60)
    assert service.cleanup_once()["reaped"] == 0
    service._clock = lambda: start + timedelta(seconds=config.queue_max_seconds + 60)
    assert service.cleanup_once()["reaped"] == 1
    record = redis_fake.hgetall(f"restore:job:{job_id}")
    assert record["status"] == "failed" and record["error"] == "expired in the queue"
    assert queue_total(redis_fake) == 0
    assert 0 < redis_fake.ttl(f"restore:job:{job_id}") <= config.terminal_ttl_seconds


def test_stale_and_queue_windows_are_configurable_and_default_sanely():
    default = RestoreConfig()
    assert default.stale_seconds == 900 and default.queue_max_seconds == 86400
    assert default.max_segment_bytes == 2048 * 1024 * 1024
    from types import SimpleNamespace

    settings = SimpleNamespace(
        RESTORE_WORK_DIR="/x",
        RESTORE_WORKER_GID=5,
        RESTORE_MAX_SEGMENT_MB=7,
        RESTORE_MAX_SEGMENT_FRAMES=8,
        RESTORE_MAX_PIXELS=9,
        RESTORE_MAX_JOBS=10,
        RESTORE_GPU_WORKER_MEMORY_MB=22528,
        RESTORE_CPU_WORKER_MEMORY_MB=12288,
        RESTORE_STALE_SECONDS=11,
        RESTORE_QUEUE_MAX_SECONDS=12,
        RESTORE_CLEANUP_INTERVAL_SECONDS=13,
        RESTORE_WIPE_PASSES=14,
        RESTORE_FFPROBE_PATH="p",
    )
    built = RestoreConfig.from_settings(settings)
    assert (built.stale_seconds, built.queue_max_seconds, built.max_segment_bytes) == (
        11,
        12,
        7 * 1024 * 1024,
    )


# --- limits under concurrency ---------------------------------------------------------------------------------


def test_concurrent_submits_cannot_exceed_the_job_limit(client, media, service, config):
    from concurrent.futures import ThreadPoolExecutor

    service.config = replace(config, max_jobs=12)

    def one(_):
        return submit(TestClient(client.app), media["mkv"]).status_code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(one, range(20)))
    assert codes.count(200) == 12 and codes.count(429) == 8, codes
    assert len(list(config.work_dir.iterdir())) == 12
    assert service._pending_slots == set() and service._reserved_bytes == {}


def test_reservations_are_released_when_a_request_fails(client, media, service):
    submit(client, b"not a video")
    submit(client, media["mkv"], {"preset": "nope"})
    client.post(
        "/v1/restore/jobs", files={"file": ("c.mkv", media["mkv"])}
    )  # no recipe
    assert service._pending_slots == set() and service._reserved_bytes == {}


def test_free_space_reservations_add_up(service, config, monkeypatch):
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _: usage(0, 0, 2500))
    service.config = replace(config, free_space_margin_bytes=100)
    first = service.reserve_upload(1000)  # needs 2000 + 100
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as caught:
        service.reserve_upload(1000)  # 2000 already promised
    assert caught.value.status_code == 507
    service.release_upload(first)
    service.release_upload(first)  # releasing twice is harmless
    assert service.reserve_upload(1000)


# --- hostile input ---------------------------------------------------------------------------------------------


def test_deeply_nested_recipe_field_is_422_not_500(client, media, config):
    for nested in (
        "[" * 5000,
        "[" * 5000 + "]" * 5000,
        '{"advanced":' * 3000 + "{}" + "}" * 3000,
    ):
        response = submit(client, media["mkv"], extra={})  # control: a valid one works
        assert response.status_code == 200
        bad = client.post(
            "/v1/restore/jobs",
            files={"file": ("c.mkv", media["mkv"])},
            data={"recipe": nested},
        )
        assert bad.status_code == 422, nested[:10]
        assert bad.json()["detail"]["error"]["type"] == "validation_error"


def test_resolve_survives_nested_json(client):
    for nested in ("[" * 5000, "[" * 5000 + "]" * 5000):
        response = client.post(
            "/v1/restore/recipe/resolve",
            content=nested,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400, nested[:5]


def test_resolve_refuses_a_big_body(client):
    big = json.dumps({"preset": "draft", "advanced": {"pad": "x" * 70000}})
    response = client.post(
        "/v1/restore/recipe/resolve",
        content=big,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["detail"]["error"]["type"] == "payload_too_large"


def test_resolve_refuses_a_big_chunked_body(client):
    chunks = iter(
        [b"[" * 40000, b" " * 40000]
    )  # no Content-Length: the streamed limit applies
    response = client.post(
        "/v1/restore/recipe/resolve",
        content=chunks,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413


def test_resolve_bad_json_is_400(client):
    response = client.post(
        "/v1/restore/recipe/resolve",
        content=b"{nope",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400


def test_invalid_hdr_value_is_422(client):
    # The allowed hdr values are restore_core's business; anything outside them must be a 422.
    response = client.post(
        "/v1/restore/recipe/resolve", json={"basic": {"hdr": "bogus"}}
    )
    assert (
        response.status_code == 422
        and "hdr" in response.json()["detail"]["error"]["message"]
    )


def test_job_id_check_is_a_full_match():
    assert is_job_id("a" * 32) and is_job_id("0123456789abcdef" * 2)
    assert not is_job_id("a" * 32 + "\n")
    assert not is_job_id("\n" + "a" * 31)
    assert (
        not is_job_id("a" * 31) and not is_job_id("A" * 32) and not is_job_id("a" * 33)
    )


def test_trailing_newline_in_a_job_id_is_404(client):
    assert (
        client.get("/v1/restore/jobs/" + "a" * 32 + "%0A", headers=ALICE).status_code
        == 404
    )


# --- job directory failures -----------------------------------------------------------------------------------


def test_group_failure_removes_the_directory_and_says_what_is_wrong(
    client, media, config, redis_fake, monkeypatch
):
    def refuse(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chown", refuse)
    response = submit(client, media["mkv"])
    assert response.status_code == 500
    message = response.json()["detail"]["error"]["message"]
    assert "not set up correctly" in message and "worker group" in message
    assert (
        "Traceback" not in response.text and str(config.work_dir) not in response.text
    )
    assert list(config.work_dir.iterdir()) == []
    assert queue_total(redis_fake) == 0
    assert not [k for k in redis_fake.data if k.startswith("restore:job:")]


def test_mkdir_failure_is_a_clean_500(client, media, config, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(os, "mkdir", refuse)
    response = submit(client, media["mkv"])
    assert response.status_code == 500 and "not set up correctly" in response.text
    assert list(config.work_dir.iterdir()) == []


def test_entrypoint_keeps_the_supplementary_groups():
    """su-exec with uid:gid drops supplementary groups, so the API would lose gid 10001."""
    path = Path(__file__).resolve().parents[2] / "api" / "docker-entrypoint.sh"
    if not path.exists():
        pytest.skip("the entrypoint is not inside the API image, run this test from the repository")
    script = path.read_text()
    assert "su-exec 1000:1000" not in script
    assert 'exec su-exec 1000 "$0"' in script


def test_a_segment_that_cannot_fit_the_worker_memory_is_refused_at_submit(media, config, redis_fake, manager):
    from dataclasses import replace

    tight = replace(config, cpu_worker_memory_bytes=1)
    app = FastAPI()
    app.include_router(router)
    app.add_exception_handler(RequestValidationError, restore_validation_handler)
    app.state.restore_service = RestoreService(RestoreStore(redis_fake), tight, manager)
    response = submit(TestClient(app), media["mkv"], {"preset": "budget"})
    assert response.status_code == 422
    assert "worker memory" in response.json()["detail"]["error"]["message"]
    assert list(config.work_dir.iterdir()) == [] and queue_total(redis_fake) == 0


def test_a_stalled_upload_is_dropped_and_gives_its_slot_back(config, redis_fake, manager):
    import asyncio
    from dataclasses import replace

    quick = replace(config, upload_idle_seconds=0.2)
    service = RestoreService(RestoreStore(redis_fake), quick, manager)
    app = FastAPI()
    app.include_router(router)
    app.state.restore_service = service
    boundary = "x"
    head = f'--{boundary}\r\nContent-Disposition: form-data; name="recipe"\r\n\r\n{{"preset": "draft"}}\r\n'.encode()
    scope = {
        "type": "http", "method": "POST", "path": "/v1/restore/jobs", "raw_path": b"/v1/restore/jobs", "query_string": b"",
        "headers": [(b"content-type", f"multipart/form-data; boundary={boundary}".encode()), (b"content-length", b"100000"),
                    (b"x-api-key", b"k")],
        "http_version": "1.1", "scheme": "http", "server": ("test", 80), "client": ("c", 1),
    }
    sent, calls = [], iter([{"type": "http.request", "body": head, "more_body": True}])

    async def receive():
        try:
            return next(calls)
        except StopIteration:
            await asyncio.sleep(30)                                   # the client stops sending and never closes

    async def send(message):
        sent.append(message)

    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=5))
    assert sent[0]["status"] == 408
    assert service._pending_slots == set() and service._reserved_bytes == {}


def test_the_resolve_endpoint_refuses_an_engine_the_queue_cannot_take(client):
    response = client.post("/v1/restore/recipe/resolve", json={"preset": "draft", "basic": {"engine": "sparkvsr"}}, headers=ALICE)
    assert response.status_code == 422 and "not available" in response.json()["detail"]["error"]["message"]


def test_a_slow_drip_upload_is_cut_once_past_the_grace_period(config, redis_fake, manager):
    import asyncio
    from dataclasses import replace

    cfg = replace(config, upload_idle_seconds=5.0, upload_grace_seconds=0.3, upload_min_bytes_per_second=1000)
    service = RestoreService(RestoreStore(redis_fake), cfg, manager)
    app = FastAPI()
    app.include_router(router)
    app.state.restore_service = service
    head = b'--x\r\nContent-Disposition: form-data; name="decryption_password"\r\n\r\n'
    scope = {
        "type": "http", "method": "POST", "path": "/v1/restore/jobs", "raw_path": b"/v1/restore/jobs", "query_string": b"",
        "headers": [(b"content-type", b"multipart/form-data; boundary=x"), (b"content-length", b"3000000"), (b"x-api-key", b"k")],
        "http_version": "1.1", "scheme": "http", "server": ("test", 80), "client": ("c", 1),
    }
    sent, state = [], {"opened": False}

    async def receive():                                              # one byte every 0.2 s, declared as three megabytes, at a minimum rate of 1000 B/s
        await asyncio.sleep(0.2)
        first = not state["opened"]
        state["opened"] = True
        return {"type": "http.request", "body": head if first else b"a", "more_body": True}

    async def send(message):
        sent.append(message)

    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=5))
    assert sent[0]["status"] == 408
    assert service._pending_slots == set() and service._reserved_bytes == {}
