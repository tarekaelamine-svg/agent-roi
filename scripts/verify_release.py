#!/usr/bin/env python3
"""Validate an Agent-ROI source tree and its built release artifacts."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
from email.policy import default as email_policy
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def project_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def runtime_version() -> str:
    init_file = ROOT / "src" / "agent_roi" / "__init__.py"
    match = re.search(
        r'^\s*__version__\s*=\s*["\']([^"\']+)["\']',
        init_file.read_text(encoding="utf-8"),
        re.M,
    )
    if not match:
        raise RuntimeError("Unable to find agent_roi.__version__")
    return match.group(1)


def verify_source(expected_tag: str = "") -> str:
    version = project_version()
    assert runtime_version() == version, "Runtime and project versions differ"

    chart = (ROOT / "deployment" / "helm" / "agent-roi" / "Chart.yaml").read_text(
        encoding="utf-8"
    )
    assert f"version: {version}" in chart, "Helm chart version does not match package"
    assert f'appVersion: "{version}"' in chart, "Helm appVersion does not match package"

    if expected_tag:
        assert expected_tag.removeprefix("v") == version, (
            f"Git tag {expected_tag!r} does not match package version {version!r}"
        )

    private_key_markers = (
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN DSA PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
    )
    private_key_suffixes = {".pem", ".key", ".p8"}
    excluded_parts = {
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        "release-output",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
    }

    private_keys: list[Path] = []
    for candidate in ROOT.rglob("*"):
        if not candidate.is_file() or candidate.suffix.lower() not in private_key_suffixes:
            continue
        relative = candidate.relative_to(ROOT)
        if any(part in excluded_parts for part in relative.parts):
            continue
        try:
            payload = candidate.read_bytes()
        except OSError:
            continue
        if any(marker in payload for marker in private_key_markers):
            private_keys.append(relative)

    assert not private_keys, (
        "Private key material found in release source: "
        + ", ".join(str(path) for path in private_keys)
    )

    for name in (".env", "agent-roi-data"):
        candidate = ROOT / name
        if candidate.exists():
            raise AssertionError(f"Local runtime artifact must not be released: {candidate}")

    return version


def verify_wheel(path: Path, version: str) -> None:
    expected_name = f"agent_roi-{version}-py3-none-any.whl"
    assert path.name == expected_name, f"Unexpected wheel filename: {path.name!r}"

    with zipfile.ZipFile(path) as archive:
        corrupt_member = archive.testzip()
        assert corrupt_member is None, f"Corrupt wheel member: {corrupt_member}"

        metadata_name = next(
            (name for name in archive.namelist() if name.endswith(".dist-info/METADATA")),
            None,
        )
        assert metadata_name is not None, "Wheel has no dist-info/METADATA file"

        # Parse metadata structurally instead of relying on LF versus CRLF line endings.
        metadata = BytesParser(policy=email_policy).parsebytes(archive.read(metadata_name))
        assert metadata.get("Name") == "agent-roi", (
            f"Wheel project name is {metadata.get('Name')!r}, expected 'agent-roi'"
        )
        assert metadata.get("Version") == version, (
            f"Wheel version is {metadata.get('Version')!r}, expected {version!r}"
        )

        wheel_name = next(
            (name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")),
            None,
        )
        assert wheel_name is not None, "Wheel has no dist-info/WHEEL file"

        record_name = next(
            (name for name in archive.namelist() if name.endswith(".dist-info/RECORD")),
            None,
        )
        assert record_name is not None, "Wheel has no dist-info/RECORD file"
        assert archive.read(record_name).strip(), "Wheel RECORD is empty"


def verify_sdist(path: Path, version: str) -> None:
    assert path.name == f"agent_roi-{version}.tar.gz", f"Unexpected sdist filename: {path.name}"
    prefix = f"agent_roi-{version}/"
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        assert any(name.startswith(prefix) for name in names), "Invalid sdist root directory"
        assert f"{prefix}pyproject.toml" in names, "sdist is missing pyproject.toml"


def verify_dist(dist_dir: Path, version: str) -> list[Path]:
    wheel = dist_dir / f"agent_roi-{version}-py3-none-any.whl"
    sdist = dist_dir / f"agent_roi-{version}.tar.gz"
    assert wheel.is_file(), f"Missing wheel: {wheel}"
    assert sdist.is_file(), f"Missing source distribution: {sdist}"
    verify_wheel(wheel, version)
    verify_sdist(sdist, version)
    return [wheel, sdist]


def write_checksums(files: list[Path]) -> Path:
    output = ROOT / "release-output"
    output.mkdir(exist_ok=True)
    checksum_file = output / "SHA256SUMS.txt"
    lines = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    checksum_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return checksum_file


def build_distributions() -> None:
    if importlib.util.find_spec("build") is not None:
        run(sys.executable, "-m", "build")
        return
    print("The optional build frontend is unavailable; using the declared setuptools PEP 517 backend.")
    run(
        sys.executable,
        "-c",
        "from setuptools.build_meta import build_wheel, build_sdist; "
        "build_wheel('dist'); build_sdist('dist')",
    )


def check_distributions() -> None:
    if importlib.util.find_spec("twine") is not None:
        # Avoid shell glob behavior differences by passsing the actual files.
        files = sorted(str(path) for path in (ROOT / "dist").iterdir() if path.is_file())
        run(sys.executable, "-m", "twine", "check", *files)
    else:
        print("Twine is unavailable; internal wheel/sdist metadata validation will be used.")


def require_clean_git() -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    if result.stdout.strip():
        raise RuntimeError("Git working tree is not clean:\n" + result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", default="")
    parser.add_argument("--expected-tag", default="")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    args = parser.parse_args()

    version = verify_source(args.expected_tag)
    if args.require_clean:
        require_clean_git()

    dist_dir = Path(args.dist_dir).resolve() if args.dist_dir else ROOT / "dist"
    if args.full:
        run(sys.executable, "-m", "compileall", "-q", "src")
        run(
            sys.executable,
            "-m",
            "pytest",
            "--cov=agent_roi",
            "--cov-branch",
            "--cov-report=term-missing",
            "--cov-fail-under=98",
        )
        shutil.rmtree(dist_dir, ignore_errors=True)
        build_distributions()
        check_distributions()

    files: list[Path] = []
    if dist_dir.exists():
        files = verify_dist(dist_dir, version)
        checksum = write_checksums(files)
        print(f"Checksums: {checksum.relative_to(ROOT)}")

    print(f"Agent-ROI {version} release validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
