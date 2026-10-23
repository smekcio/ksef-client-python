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
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("Invalid wheel metadata")
        metadata = BytesParser().parsebytes(archive.read(names[0]))
    if metadata["Name"] != "ksef-client" or not metadata["Version"]:
        raise ValueError("Unexpected release package")
    sdist = next(p for p in files if p.name.endswith(".tar.gz"))
    with tarfile.open(sdist, "r:gz") as archive:
        candidates = [
            entry
            for entry in archive
            if len(PurePosixPath(entry.name).parts) == 2
            and PurePosixPath(entry.name).name == "PKG-INFO"
        ]
        if len(candidates) != 1 or not candidates[0].isfile() or candidates[0].size > 1024 * 1024:
            raise ValueError("Invalid sdist metadata")
        stream = archive.extractfile(candidates[0])
        if stream is None:
            raise ValueError("Missing sdist metadata")
        source_metadata = BytesParser().parsebytes(stream.read(1024 * 1024 + 1))
    if any(source_metadata[key] != metadata[key] for key in ("Name", "Version")):
        raise ValueError("Wheel and sdist metadata disagree")
    return {
        "version": metadata["Version"],
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
    import ksef_client

    distribution = importlib.metadata.distribution("ksef-client")
    root = Path(str(distribution.locate_file(""))).resolve()
    expected_init = root / "ksef_client" / "__init__.py"
    if Path(ksef_client.__file__).resolve() != expected_init.resolve():
        raise ValueError("SDK import does not come from the installed wheel distribution")
    found = set()
    with zipfile.ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if not entry.filename.startswith("ksef_client/") or entry.is_dir():
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
    if "ksef_client/__init__.py" not in found:
        raise ValueError("Wheel does not contain the SDK package")


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
