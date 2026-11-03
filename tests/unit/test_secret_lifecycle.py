"""secure_secret_lifecycle.sh with a stubbed docker: the shred must reach all five secrets, on Linux (shred) and on macOS (dd)."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "secure_secret_lifecycle.sh"
SECRETS = ["jwt_secret", "encryption_master_key", "redis_password", "api_master_key", "restore_worker_redis_password"]


def _env(tmp_path: Path, *, with_shred: bool) -> dict:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    docker = stubs / "docker"
    docker.write_text("#!/bin/sh\necho container-id\n")              # `docker ps ... --quiet | grep -q .` finds a running container
    docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
    if not with_shred:                                              # macOS ships no shred: hide it so the dd fallback runs
        (stubs / "shred").write_text("#!/bin/sh\nexit 127\n")
        (stubs / "shred").chmod(0o755)
    return {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}


def _run(tmp_path: Path, command: str, env: dict, **extra) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), command], cwd=tmp_path, env={**env, **extra}, capture_output=True, text=True)


@pytest.mark.parametrize("with_shred", [True, False], ids=["shred", "dd-fallback"])
def test_shred_marks_every_secret_including_the_restore_worker_one(tmp_path, with_shred):
    (tmp_path / "secrets").mkdir()
    for name in SECRETS:
        (tmp_path / "secrets" / name).write_text(f"value-of-{name}")
    result = _run(tmp_path, "shred", _env(tmp_path, with_shred=with_shred))
    assert result.returncode == 0, result.stdout + result.stderr
    for name in SECRETS:
        text = (tmp_path / "secrets" / name).read_text()
        assert text.startswith("SHREDDED_FOR_SECURITY"), name
        assert f"value-of-{name}" not in text
    assert "shredded 5 secrets" in result.stdout


def test_without_a_passphrase_file_no_unreadable_backup_is_written(tmp_path):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "jwt_secret").write_text("x")
    result = _run(tmp_path, "shred", _env(tmp_path, with_shred=True))
    assert result.returncode == 0
    assert not (tmp_path / ".secrets.backup").exists()
    assert "no backup made" in result.stdout


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_backup_opens_with_the_passphrase_file_and_not_a_command_line_one(tmp_path):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "jwt_secret").write_text("kept")
    phrase = tmp_path / "phrase"
    phrase.write_text("owner-passphrase")
    result = _run(tmp_path, "shred", _env(tmp_path, with_shred=True), SECRET_BACKUP_PASSPHRASE_FILE=str(phrase))
    assert result.returncode == 0, result.stdout + result.stderr
    archive = next((tmp_path / ".secrets.backup").glob("secrets-*.tar.gz"))
    opened = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-pass", f"file:{phrase}", "-in", str(archive)],
                            capture_output=True)
    assert opened.returncode == 0 and b"kept" in subprocess.run(["tar", "xzO"], input=opened.stdout, capture_output=True).stdout
