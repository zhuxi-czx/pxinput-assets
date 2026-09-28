#!/usr/bin/env python3
"""Build the signed, immutable offline grammar release asset inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


SWIFT = "/usr/bin/swift"
CRYPTO_HELPER = Path(__file__).with_name("offline_grammar_crypto.swift")
SWIFT_MODULE_CACHE = Path(tempfile.gettempdir()) / "pxinput-offline-grammar-swift-module-cache"
REPOSITORY = "zhuxi-czx/pxinput-assets"
RELEASE_TAG = "offline-grammar-v1"
SIGNING_KEY_ID = "pxinput-offline-grammar-release-v1"
MODEL_ID = "wanxiang-lts-zh-hans"
MODEL_FILENAME = "wanxiang-lts-zh-hans.gram"
MODEL_VERSION = 1
MODEL_BYTE_LENGTH = 420_340_780
MODEL_SHA256 = "b91d525f118b24871cfc82b47b32921cdbc92a43cea42419a88afe4f780b278c"
RIME_VERSION = "1.16.1"
ATTRIBUTION_URL = "https://creativecommons.org/licenses/by/4.0/legalcode"
VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class ReleaseBuildError(ValueError):
    """Raised when an input cannot produce the reviewed release inventory."""


def build_manifest(
    *,
    model_byte_length: int,
    model_sha256: str,
    repository: str,
    tag: str,
    minimum_app_version: str,
    maximum_app_version: str,
) -> bytes:
    """Return the exact UTF-8 bytes covered by the detached Ed25519 signature."""
    _validate_release_identity(repository, tag)
    if model_byte_length != MODEL_BYTE_LENGTH or model_sha256 != MODEL_SHA256:
        raise ReleaseBuildError("model identity does not match the reviewed release")
    _validate_version_range(minimum_app_version, maximum_app_version)
    release_base = f"https://github.com/{repository}/releases/download/{tag}"
    manifest = {
        "schemaVersion": 1,
        "signingKeyID": SIGNING_KEY_ID,
        "model": {
            "id": MODEL_ID,
            "version": MODEL_VERSION,
            "filename": MODEL_FILENAME,
            "byteLength": model_byte_length,
            "sha256": model_sha256,
            "downloadURL": f"{release_base}/{MODEL_FILENAME}",
            "minimumAppVersion": minimum_app_version,
            "maximumAppVersion": maximum_app_version,
            "rimeVersion": RIME_VERSION,
            "attributionURL": ATTRIBUTION_URL,
        },
    }
    return (json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def build_release(
    *,
    model_path: Path,
    output_path: Path,
    repository: str,
    tag: str,
    private_key_path: Path,
    minimum_app_version: str,
    maximum_app_version: str,
) -> None:
    """Validate, sign, verify, and atomically write the three release assets."""
    output_path = Path(output_path)
    _validate_empty_output(output_path)
    _validate_release_identity(repository, tag)
    _validate_version_range(minimum_app_version, maximum_app_version)
    model_path = _validate_model(Path(model_path))
    private_key_path = Path(private_key_path)

    stage = Path(tempfile.mkdtemp(prefix=".offline-grammar-release-", dir=output_path.parent))
    try:
        staged_model_path = stage / MODEL_FILENAME
        shutil.copyfile(model_path, staged_model_path)
        _validate_model(staged_model_path)
        manifest = build_manifest(
            model_byte_length=MODEL_BYTE_LENGTH,
            model_sha256=MODEL_SHA256,
            repository=repository,
            tag=tag,
            minimum_app_version=minimum_app_version,
            maximum_app_version=maximum_app_version,
        )
        manifest_path = stage / "manifest.json"
        signature_path = stage / "manifest.sig"
        public_key_path = stage / "verification-public.base64"
        manifest_path.write_bytes(manifest)
        _cryptokit(
            "sign", "--private-key-file", str(private_key_path),
            "--input", str(manifest_path), "--signature-output", str(signature_path),
            "--public-key-output", str(public_key_path),
        )
        if signature_path.stat().st_size != 64:
            raise ReleaseBuildError("Ed25519 signature must be exactly 64 bytes")
        public_key_path.unlink()
        if {path.name for path in stage.iterdir()} != {"manifest.json", "manifest.sig", MODEL_FILENAME}:
            raise ReleaseBuildError("release inventory is not exact")
        if output_path.exists():
            output_path.rmdir()
        os.replace(stage, output_path)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _validate_release_identity(repository: str, tag: str) -> None:
    if repository != REPOSITORY:
        raise ReleaseBuildError("repository does not match the reviewed release")
    if tag != RELEASE_TAG:
        raise ReleaseBuildError("tag does not match the reviewed release")


def _validate_version_range(minimum: str, maximum: str) -> None:
    if not VERSION_PATTERN.fullmatch(minimum) or not VERSION_PATTERN.fullmatch(maximum):
        raise ReleaseBuildError("app compatibility versions must be semantic versions")
    if tuple(map(int, maximum.split("."))) < tuple(map(int, minimum.split("."))):
        raise ReleaseBuildError("maximum app compatibility version precedes minimum")


def _validate_model(path: Path) -> Path:
    if not path.is_file() or path.is_symlink() or path.name != MODEL_FILENAME:
        raise ReleaseBuildError("model must be the reviewed regular grammar file")
    if path.stat().st_size != MODEL_BYTE_LENGTH:
        raise ReleaseBuildError("model byte length does not match the reviewed release")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    if digest.hexdigest() != MODEL_SHA256:
        raise ReleaseBuildError("model SHA-256 does not match the reviewed release")
    return path


def _validate_empty_output(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise ReleaseBuildError("output path must be a new or empty directory")
    elif not path.parent.is_dir() or path.parent.is_symlink():
        raise ReleaseBuildError("output parent must be an existing directory")


def _cryptokit(*arguments: str) -> None:
    try:
        SWIFT_MODULE_CACHE.mkdir(exist_ok=True)
        subprocess.run(
            [SWIFT, "-module-cache-path", str(SWIFT_MODULE_CACHE), str(CRYPTO_HELPER), *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseBuildError("CryptoKit signing or verification failed") from error


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--minimum-app-version", required=True)
    parser.add_argument("--maximum-app-version", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        build_release(
            model_path=arguments.model,
            output_path=arguments.output,
            repository=arguments.repository,
            tag=arguments.tag,
            private_key_path=arguments.private_key,
            minimum_app_version=arguments.minimum_app_version,
            maximum_app_version=arguments.maximum_app_version,
        )
    except ReleaseBuildError as error:
        print(f"build_offline_grammar_release: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
