from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.parse import urlparse


@dataclass(frozen=True)
class ManifestFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ReferenceManifest:
    schema_version: int
    repository: str
    commit: str
    license: str
    files: tuple[ManifestFile, ...]


@dataclass(frozen=True)
class FileVerification:
    path: str
    status: str
    expected_sha256: str
    actual_sha256: str | None


@dataclass(frozen=True)
class VerificationReport:
    repository: str
    expected_commit: str
    actual_commit: str | None
    commit_status: str
    files: tuple[FileVerification, ...]

    @property
    def ok(self) -> bool:
        return self.commit_status == "match" and all(
            item.status == "match" for item in self.files
        )


def load_manifest(path: Path) -> ReferenceManifest:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("unsupported reference manifest schema")

    files = tuple(_load_file(item) for item in document.get("files", []))
    if not files:
        raise ValueError("reference manifest contains no files")
    repository = _load_repository(str(document["repository"]))
    commit = _load_commit(str(document["commit"]))
    license_name = str(document["license"]).strip()
    if not license_name:
        raise ValueError("reference manifest license is empty")
    return ReferenceManifest(
        schema_version=1,
        repository=repository,
        commit=commit,
        license=license_name,
        files=files,
    )


def _load_repository(repository: str) -> str:
    parsed = urlparse(repository)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"unsafe reference repository: {repository}")
    return repository


def _load_commit(commit: str) -> str:
    normalized = commit.strip().lower()
    if len(normalized) != 40:
        raise ValueError("reference manifest commit must be a full SHA-1")
    if any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("reference manifest commit is not hexadecimal")
    return normalized


def _load_file(item: dict[str, object]) -> ManifestFile:
    relative_path = str(item["path"])
    pure_path = PurePosixPath(relative_path)
    if pure_path.is_absolute() or ".." in pure_path.parts:
        raise ValueError(f"unsafe reference path: {relative_path}")

    digest = str(item["sha256"]).lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"invalid SHA-256 for {relative_path}")
    size = int(item["size"])
    if size < 0:
        raise ValueError(f"invalid size for {relative_path}")
    return ManifestFile(relative_path, digest, size)


def verify_reference(
    checkout: Path,
    manifest: ReferenceManifest,
    commit_reader: Callable[[Path], str | None] | None = None,
) -> VerificationReport:
    resolved_checkout = checkout.resolve()
    reader = commit_reader or read_git_commit
    actual_commit = reader(resolved_checkout)
    commit_status = "match" if actual_commit == manifest.commit else "mismatch"

    files = tuple(
        _verify_file(resolved_checkout, expected) for expected in manifest.files
    )
    return VerificationReport(
        repository=manifest.repository,
        expected_commit=manifest.commit,
        actual_commit=actual_commit,
        commit_status=commit_status,
        files=files,
    )


def _verify_file(checkout: Path, expected: ManifestFile) -> FileVerification:
    candidate = (checkout / Path(expected.path)).resolve()
    try:
        candidate.relative_to(checkout)
    except ValueError as error:
        raise ValueError(f"reference path escaped checkout: {expected.path}") from error

    if not candidate.is_file():
        return FileVerification(expected.path, "missing", expected.sha256, None)

    size_matches = candidate.stat().st_size == expected.size
    if not size_matches:
        return FileVerification(expected.path, "mismatch", expected.sha256, None)

    digest = _sha256_file(candidate)
    status = "match" if digest == expected.sha256 and size_matches else "mismatch"
    return FileVerification(expected.path, status, expected.sha256, digest)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_git_commit(checkout: Path) -> str | None:
    try:
        process = subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={checkout.as_posix()}",
                "-C",
                str(checkout),
                "rev-parse",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return process.stdout.strip() or None
