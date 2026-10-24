"""Record and verify the exact release distributions tested by the live gate."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

TAG = re.compile(r"v?\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?")


def resolve_tag(source: Path, tag: str) -> str:
    """Resolve an existing version tag and require reviewed main ancestry."""
    if not TAG.fullmatch(tag):
        raise ValueError("An existing version tag is required")
    sha = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], cwd=source, text=True
    ).strip()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    version = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if sha != head or tag.removeprefix("v") != version:
        raise ValueError("Tag, commit and package version must agree")
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "origin/main"], cwd=source, check=False
    )
    if result.returncode:
        raise ValueError("Release commit must belong to main history")
    return sha


def inspect_wheel(wheel: Path) -> tuple[str, list[str]]:
    """Validate the complete archive before pip or any interpreter can execute it."""
    with zipfile.ZipFile(wheel) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("Invalid wheel members")
        if sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
            raise ValueError("Oversized wheel")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in entry.filename
                or entry.file_size > 16 * 1024 * 1024
                or (entry.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise ValueError("Unsafe wheel member")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("Invalid wheel metadata")
        metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
        version = metadata["Version"]
        if metadata["Name"] != "ksef-client" or not version or not TAG.fullmatch(version):
            raise ValueError("Unexpected release package")
        parts = wheel.name.removesuffix(".whl").split("-")
        prefix = f"ksef_client-{version}.dist-info/"
        if (
            len(parts) != 5
            or parts[:2] != ["ksef_client", version]
            or any(re.fullmatch(r"[A-Za-z0-9_.]+", part) is None for part in parts[2:])
            or metadata_names[0] != prefix + "METADATA"
        ):
            raise ValueError("Wheel filename or dist-info disagrees with metadata")
        if "ksef_client/__init__.py" not in names or any(
            not name.startswith(("ksef_client/", prefix)) or name.endswith(".pth") for name in names
        ):
            raise ValueError("Unexpected executable content outside SDK package")
        return version, names


def distributions(directory: Path) -> list[Path]:
    files = sorted(p for p in directory.iterdir() if p.name != "release-manifest.json")
    if (
        len(files) != 2
        or sum(p.suffix == ".whl" for p in files) != 1
        or sum(p.name.endswith(".tar.gz") for p in files) != 1
        or any(
            not p.is_file() or p.is_symlink() or not re.fullmatch(r"[A-Za-z0-9_.+-]+", p.name)
            for p in files
        )
    ):
        raise ValueError("Require exactly one wheel and one sdist")
    return files


def describe(directory: Path, sha: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Require exact commit SHA")
    files = distributions(directory)
    wheel = next(p for p in files if p.suffix == ".whl")
    version, _ = inspect_wheel(wheel)
    sdist = next(p for p in files if p.name.endswith(".tar.gz"))
    roots = {f"ksef_client-{version}", f"ksef-client-{version}"}
    if sdist.name.removesuffix(".tar.gz") not in roots:
        raise ValueError("Sdist filename disagrees with metadata")
    with tarfile.open(sdist, "r:gz") as archive:
        candidates = [
            entry
            for entry in archive
            if len(PurePosixPath(entry.name).parts) == 2
            and PurePosixPath(entry.name).name == "PKG-INFO"
        ]
        if (
            len(candidates) != 1
            or not candidates[0].isfile()
            or candidates[0].size > 1024 * 1024
            or PurePosixPath(candidates[0].name).parts[0] not in roots
        ):
            raise ValueError("Invalid sdist metadata")
        stream = archive.extractfile(candidates[0])
        if stream is None:
            raise ValueError("Missing sdist metadata")
        source_metadata = BytesParser().parsebytes(stream.read(1024 * 1024 + 1))
    if source_metadata["Name"] != "ksef-client" or source_metadata["Version"] != version:
        raise ValueError("Wheel and sdist metadata disagree")
    return {
        "version": version,
        "commit": sha,
        "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
    }


def record(directory: Path, sha: str, *, tag: str | None = None) -> None:
    if (directory / "release-manifest.json").is_symlink():
        raise ValueError("Release manifest must not be a symlink")
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if current != sha:
        raise ValueError("Checkout differs from release commit")
    manifest = describe(directory, sha)
    version = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    if manifest["version"] != version:
        raise ValueError("Wheel version differs from source")
    if tag is not None:
        if not TAG.fullmatch(tag) or tag.removeprefix("v") != version:
            raise ValueError("Release tag differs from version")
        target = subprocess.check_output(
            ["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
            text=True,
        ).strip()
        if target != sha:
            raise ValueError("Tag differs from release commit")
    (directory / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def verify(directory: Path, sha: str) -> None:
    if (directory / "release-manifest.json").is_symlink():
        raise ValueError("Release manifest must not be a symlink")
    saved = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    if saved != describe(directory, sha):
        raise ValueError("Release artifact checksum, version or commit mismatch")


def verify_installed_wheel(wheel: Path) -> None:
    """Prove that imported SDK files match the exact wheel, not an editable checkout."""
    _, members = inspect_wheel(wheel)
    import ksef_client

    distribution = importlib.metadata.distribution("ksef-client")
    root = Path(str(distribution.locate_file(""))).resolve()
    expected_init = root / "ksef_client" / "__init__.py"
    if Path(ksef_client.__file__).resolve() != expected_init.resolve():
        raise ValueError("SDK import does not come from the installed wheel distribution")
    found = set()
    with zipfile.ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if entry.filename not in members or entry.filename.endswith(".dist-info/RECORD"):
                continue
            relative = PurePosixPath(entry.filename)
            if (
                ".." in relative.parts
                or "\\" in entry.filename
                or entry.filename in found
                or entry.file_size > 16 * 1024 * 1024
            ):
                raise ValueError("Unsafe installed wheel member")
            found.add(entry.filename)
            installed = root.joinpath(*relative.parts)
            if (
                installed.is_symlink()
                or not installed.resolve().is_relative_to(root)
                or not installed.is_file()
            ):
                raise ValueError("Missing or unsafe installed wheel file")
            if (
                hashlib.sha256(installed.read_bytes()).digest()
                != hashlib.sha256(archive.read(entry)).digest()
            ):
                raise ValueError("Installed SDK differs from the tested wheel")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["record", "verify", "verify-installed"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--tag")
    args = parser.parse_args(argv)
    if args.mode == "record":
        record(args.directory, args.sha, tag=args.tag)
    else:
        verify(args.directory, args.sha)
        if args.mode == "verify-installed":
            wheel = next(p for p in distributions(args.directory) if p.suffix == ".whl")
            verify_installed_wheel(wheel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
