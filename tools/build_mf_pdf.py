"""Rebuild the pinned upstream PDF module. Requires the manifest's Node/npm versions."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    assets = Path(__file__).resolve().parents[1] / "src/ksef_client/_mf_pdf"
    pin = json.loads((assets / "upstream.json").read_text())
    npm = shutil.which("npm.cmd" if sys.platform == "win32" else "npm")
    if not npm:
        raise RuntimeError("npm is required to rebuild the generator")
    for executable, expected in [("node", pin["node"]), (npm, pin["npm"])]:
        actual = subprocess.check_output([executable, "--version"], text=True).strip()
        if actual != expected:
            raise RuntimeError(f"Expected {executable} {expected}, found {actual}")
    with tempfile.TemporaryDirectory(prefix="ksef-mf-build-") as directory:
        source = Path(directory)
        subprocess.run(
            ["git", "clone", "--quiet", f"https://github.com/{pin['repository']}.git", str(source)],
            check=True,
        )
        subprocess.run(["git", "checkout", "--detach", pin["commit"]], cwd=source, check=True)
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=source, text=True
        ).strip()
        package = json.loads((source / "package.json").read_text())
        if commit != pin["commit"] or package["version"] != pin["version"]:
            raise RuntimeError("Upstream commit or version mismatch")
        subprocess.run(
            [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=source, check=True
        )
        subprocess.run([npm, "run", "build"], cwd=source, check=True)
        data = (source / "dist/ksef-fe-invoice-converter.js").read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if args.check:
            if digest != pin["sha256"] or data != (assets / "generator.mjs").read_bytes():
                raise RuntimeError("Pinned PDF generator differs from rebuilt output")
        else:
            (assets / "generator.mjs").write_bytes(data)
            shutil.copyfile(source / "LICENSE", assets / "LICENSE-MF.txt")
            notices = []
            for package_path in sorted((source / "node_modules").rglob("package.json")):
                try:
                    metadata = json.loads(package_path.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    continue
                for name in (
                    "LICENSE",
                    "LICENSE.txt",
                    "LICENSE.md",
                    "license",
                    "license.txt",
                    "OFL.txt",
                ):
                    license_path = package_path.parent / name
                    if license_path.is_file():
                        notices.append(
                            metadata.get("name", str(package_path.parent))
                            + " "
                            + metadata.get("version", "")
                            + "\n"
                            + license_path.read_text(encoding="utf-8", errors="replace")
                        )
                        break
            (assets / "THIRD-PARTY-LICENSES.txt").write_text("\n\n".join(notices), encoding="utf-8")
            pin["sha256"] = digest
            (assets / "upstream.json").write_text(json.dumps(pin, indent=2) + "\n")


if __name__ == "__main__":
    main()
