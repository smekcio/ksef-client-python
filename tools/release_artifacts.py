"""Record and verify the exact release distributions tested by the live gate."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from pathlib import Path

tomllib = importlib.import_module("tomllib" if sys.version_info >= (3, 11) else "tomli")

TAG = re.compile(r"v?\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?(?:\.post\d+)?")


def distributions(directory: Path) -> list[Path]:
    files = sorted(p for p in directory.iterdir() if p.name != "release-manifest.json")
    if (
        len(files) != 2
        or sum(p.suffix == ".whl" for p in files) != 1
        or sum(p.name.endswith(".tar.gz") for p in files) != 1
        or any(not p.is_file() or p.is_symlink() for p in files)
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
    return {
        "version": metadata["Version"],
        "commit": sha,
        "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
    }


def record(directory: Path, sha: str, *, tag: str | None = None) -> None:
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
    saved = json.loads((directory / "release-manifest.json").read_text(encoding="utf-8"))
    if saved != describe(directory, sha):
        raise ValueError("Release artifact checksum, version or commit mismatch")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["record", "verify"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--tag")
    args = parser.parse_args(argv)
    if args.mode == "record":
        record(args.directory, args.sha, tag=args.tag)
    else:
        verify(args.directory, args.sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
