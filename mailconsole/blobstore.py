"""Content-addressed storage for archived messages, optionally encrypted at rest.

Layout: ``<root>/<aa>/<bb>/<sha256>`` (plain) or ``...<sha256>.enc`` (encrypted).
Writes go to a temporary file, are fsynced and then renamed, so a stored blob
is either complete or absent. Identical messages share one blob.

Encryption (when a key file is configured) uses AES-256-GCM over 64 KiB
chunks. A random per-file salt derives a per-file key from the master key
(HMAC-SHA256), so chunk counters can serve as nonces. Each chunk's
associated data binds the file header, its index and whether it is the last
chunk, so reordering, truncation and tampering are all detected. Chunks make
random access cheap: reading an attachment decrypts only the chunks it spans.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import secrets
import struct
from pathlib import Path

MAGIC = b"MCA1"
CHUNK = 64 * 1024
TAG = 16
HEADER = struct.Struct(">4s16sIQ")     # magic, salt, chunk size, plaintext size
KEY_LABEL = b"mail-console archive v1"


class IntegrityError(Exception):
    pass


def load_key(path: Path | None) -> bytes | None:
    if path is None or not path.exists():
        return None
    text = path.read_text().strip()
    key = bytes.fromhex(text)
    if len(key) != 32:
        raise ValueError(f"{path}: expected 64 hex characters (256-bit key)")
    return key


def new_key_hex() -> str:
    return secrets.token_hex(32)


def _aesgcm(master: bytes, salt: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(hmac.new(master, KEY_LABEL + salt, hashlib.sha256).digest())


def _nonce(index: int) -> bytes:
    return index.to_bytes(12, "big")


def _aad(header: bytes, index: int, final: bool) -> bytes:
    return header + struct.pack(">Q?", index, final)


class Store:
    def __init__(self, root: Path, key: bytes | None):
        self.root = Path(root)
        self.key = key

    @property
    def encrypted(self) -> bool:
        return self.key is not None

    def rel_path(self, sha256: str, encrypted: bool) -> str:
        return f"{sha256[:2]}/{sha256[2:4]}/{sha256}{'.enc' if encrypted else ''}"

    def put(self, src: Path, expected_sha256: str) -> tuple[str, int, bool]:
        """Store ``src`` under its SHA-256. Returns (relative path, stored size, encrypted).

        The content hash is verified while copying; a mismatch raises
        IntegrityError and stores nothing.
        """
        rel = self.rel_path(expected_sha256, self.encrypted)
        final = self.root / rel
        if final.exists():
            return rel, final.stat().st_size, self.encrypted
        final.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        tmp = final.with_name(f".tmp-{final.name}-{secrets.token_hex(4)}")
        digest = hashlib.sha256()
        size = src.stat().st_size
        try:
            with open(src, "rb") as fin, open(tmp, "xb") as fout:
                if self.key is None:
                    while True:
                        data = fin.read(CHUNK)
                        if not data:
                            break
                        digest.update(data)
                        fout.write(data)
                else:
                    salt = secrets.token_bytes(16)
                    header = HEADER.pack(MAGIC, salt, CHUNK, size)
                    fout.write(header)
                    aead = _aesgcm(self.key, salt)
                    count = max(1, -(-size // CHUNK))
                    for index in range(count):
                        data = fin.read(CHUNK)
                        digest.update(data)
                        fout.write(aead.encrypt(_nonce(index), data, _aad(header, index, index == count - 1)))
                fout.flush()
                os.fsync(fout.fileno())
            if digest.hexdigest() != expected_sha256:
                raise IntegrityError(f"content hash mismatch for {src.name}")
            os.chmod(tmp, 0o640)
            os.rename(tmp, final)
            dfd = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return rel, final.stat().st_size, self.encrypted

    def open(self, rel: str) -> io.BufferedReader:
        """Open a stored blob for reading plaintext (seekable, supports readline)."""
        path = self.root / rel
        if rel.endswith(".enc"):
            if self.key is None:
                raise IntegrityError("archive is encrypted but no archive key is configured")
            return io.BufferedReader(_EncryptedReader(path, self.key), buffer_size=CHUNK)
        return open(path, "rb")

    def delete(self, rel: str) -> None:
        (self.root / rel).unlink(missing_ok=True)

    def verify(self, rel: str, sha256: str) -> bool:
        digest = hashlib.sha256()
        try:
            with self.open(rel) as fh:
                for data in iter(lambda: fh.read(CHUNK), b""):
                    digest.update(data)
        except (IntegrityError, OSError, ValueError):
            return False
        return digest.hexdigest() == sha256


class _EncryptedReader(io.RawIOBase):
    def __init__(self, path: Path, key: bytes):
        self._fh = open(path, "rb")
        header = self._fh.read(HEADER.size)
        try:
            magic, salt, chunk, size = HEADER.unpack(header)
        except struct.error:
            raise IntegrityError(f"{path.name}: truncated header") from None
        if magic != MAGIC:
            raise IntegrityError(f"{path.name}: not an archive blob")
        self._header, self._chunk, self._size = header, chunk, size
        self._count = max(1, -(-size // chunk))
        self._aead = _aesgcm(key, salt)
        self._pos = 0
        self._cache: tuple[int, bytes] | None = None

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = self._size + offset
        self._pos = max(0, self._pos)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def _chunk_plain(self, index: int) -> bytes:
        if self._cache and self._cache[0] == index:
            return self._cache[1]
        self._fh.seek(HEADER.size + index * (self._chunk + TAG))
        expected = min(self._chunk, self._size - index * self._chunk) + TAG
        blob = self._fh.read(expected)
        if len(blob) != expected:
            raise IntegrityError("archive blob is truncated")
        try:
            plain = self._aead.decrypt(_nonce(index), blob, _aad(self._header, index, index == self._count - 1))
        except Exception as exc:  # cryptography.exceptions.InvalidTag
            raise IntegrityError("archive blob failed authentication (tampered or wrong key)") from exc
        self._cache = (index, plain)
        return plain

    def readinto(self, buffer) -> int:
        if self._pos >= self._size:
            return 0
        index, within = divmod(self._pos, self._chunk)
        plain = self._chunk_plain(index)[within:]
        n = min(len(buffer), len(plain))
        buffer[:n] = plain[:n]
        self._pos += n
        return n

    def close(self) -> None:
        self._fh.close()
        super().close()
