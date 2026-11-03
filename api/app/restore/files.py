"""File handling for restoration jobs: job directories, capped copies, manual-mode decryption, wiping.

Everything here works on the shared RAM volume. Names are never taken from the client, the
stored input is always <work_dir>/<id>/in.mkv.

Author: Lorenzo Albanese (alblor)
"""

import logging
import os
import stat
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import is_job_id

logger = logging.getLogger(__name__)

INPUT_NAME = "in.mkv"
OUTPUT_NAME = "out.mkv"
UPLOAD_NAME = "upload.enc"

# Client-compatible password file layout, the same as EncryptionManager.encrypt_password_based_file:
# [32-byte salt][16-byte IV][ciphertext][16-byte GCM tag], key = PBKDF2-HMAC-SHA256, 100000 rounds.
_SALT_LEN, _IV_LEN, _TAG_LEN, _KDF_ROUNDS = 32, 16, 16, 100000


class UploadTooLarge(Exception):
    """The stream went over the byte cap."""


class JobDirError(Exception):
    """The job directory could not be created with the right mode and group."""


def job_dir(work_dir: Path, job_id: str) -> Path:
    """Directory of a job. The id is validated, so this can never leave work_dir."""
    if not is_job_id(job_id):
        raise ValueError("invalid job id")
    return work_dir / job_id


def create_job_dir(work_dir: Path, job_id: str, gid: int) -> Path:
    """Create <work_dir>/<id> with mode 0770 and group gid.

    If any step fails after the directory exists it is removed again, so a misconfigured volume
    or group never leaves an empty directory behind. Raises JobDirError, which carries no path.
    """
    path = job_dir(work_dir, job_id)
    try:
        os.mkdir(path, 0o770)
    except OSError as exc:
        logger.error("cannot create a job directory: %s", exc.strerror)
        raise JobDirError() from None
    try:
        os.chmod(
            path, 0o770
        )  # mkdir is filtered by the umask, the protocol wants exactly 0770
        os.chown(path, -1, gid)
    except OSError as exc:
        logger.error(
            "cannot set group %d on a job directory (is the API user in that group?): %s",
            gid,
            exc.strerror,
        )
        try:
            os.rmdir(path)
        except OSError:
            logger.error("could not remove the half-made job directory")
        raise JobDirError() from None
    return path


def open_private_output(path: Path, gid: int):
    """Create a new file (never follow a symlink, never overwrite) with mode 0660 and group gid."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660)
    try:
        os.fchmod(fd, 0o660)
        os.fchown(fd, -1, gid)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, "wb")


def decrypt_password_file(
    src: Path, dst: Path, password: str, gid: int, chunk_size: int, max_plain_bytes: int
) -> int:
    """Stream-decrypt a client password file into dst and return the plaintext size.

    Same format and key derivation as EncryptionManager.decrypt_password_based_file, but in
    chunks: that method reads the whole ciphertext into memory, which is not acceptable for
    segments of several GiB. The tag is checked at the end, so a wrong password or a modified
    file raises ValueError and the caller wipes dst.
    """
    total = src.stat().st_size
    header = _SALT_LEN + _IV_LEN
    if total < header + _TAG_LEN + 1:
        raise ValueError("not a valid encrypted file")
    cipher_len = total - header - _TAG_LEN
    if cipher_len > max_plain_bytes:
        raise UploadTooLarge()
    with open(src, "rb") as inp:
        salt = inp.read(_SALT_LEN)
        iv = inp.read(_IV_LEN)
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=_KDF_ROUNDS
        ).derive(password.encode("utf-8"))
        inp.seek(total - _TAG_LEN)
        tag = inp.read(_TAG_LEN)
        inp.seek(header)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        remaining = cipher_len
        with open_private_output(dst, gid) as out:
            while remaining > 0:
                block = inp.read(min(chunk_size, remaining))
                if not block:
                    raise ValueError("not a valid encrypted file")
                remaining -= len(block)
                out.write(decryptor.update(block))
            try:
                out.write(decryptor.finalize())
            except InvalidTag:
                raise ValueError(
                    "decryption failed: wrong password or modified file"
                ) from None
    return cipher_len


def _overwrite(path: Path, size: int, passes: int) -> None:
    """Overwrite a regular file in place with random blocks, fsync after each pass."""
    block = os.urandom(1024 * 1024)
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        for _ in range(passes):
            os.lseek(fd, 0, os.SEEK_SET)
            written = 0
            while written < size:
                written += os.write(fd, block[: min(len(block), size - written)])
            os.fsync(fd)
            block = os.urandom(1024 * 1024)
    finally:
        os.close(fd)


def wipe_file(path: Path, passes: int) -> bool:
    """Overwrite then unlink one file. Always unlinks. Returns True when the file is gone.

    A file the API user may not open for writing (for example one the worker made with a
    stricter mode) cannot be overwritten, so it is only unlinked and a warning is logged.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    if stat.S_ISREG(info.st_mode):
        try:
            _overwrite(path, info.st_size, passes)
        except OSError as exc:
            logger.warning(
                "could not overwrite %s before unlink (%s), unlinking only",
                path.name,
                exc.strerror,
            )
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.error("could not unlink %s: %s", path.name, exc.strerror)
        return False
    return True


def wipe_dir(path: Path, passes: int) -> bool:
    """Wipe a job directory: overwrite then unlink every file, then remove the directory.

    Symlinks are unlinked and never followed. Returns True when the directory no longer exists.
    """
    try:
        entries = list(os.scandir(path))
    except FileNotFoundError:
        return True
    ok = True
    for entry in entries:
        child = Path(entry.path)
        if entry.is_dir(follow_symlinks=False):
            ok = wipe_dir(child, passes) and ok
        else:
            ok = wipe_file(child, passes) and ok
    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.error("could not remove job directory: %s", exc.strerror)
        return False
    return ok


def read_chunks(
    path: Path, chunk_size: int, on_close: Callable[[], None] = lambda: None
):
    """Generator over a file in chunks. The file is opened up front, so a concurrent unlink cannot break it."""
    handle = open(path, "rb")

    def generate():
        try:
            while True:
                block = handle.read(chunk_size)
                if not block:
                    break
                yield block
        finally:
            handle.close()
            on_close()

    return generate()
