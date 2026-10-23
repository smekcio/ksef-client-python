from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from tools import release_artifacts as release
from tools import verify_e2e_results as gate


def write_report(path, outcomes):
    import xml.etree.ElementTree as ET

    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite")
    for name, outcome in outcomes:
        file, function = name.split("::")
        case = ET.SubElement(
            suite, "testcase", classname=file[:-3].replace("/", "."), name=function
        )
        if outcome:
            ET.SubElement(case, outcome)
    ET.ElementTree(root).write(path)


@pytest.mark.parametrize("outcome", ["skipped", "failure", "error"])
def test_gate_rejects_nonpassed_required_test(tmp_path, outcome):
    path = tmp_path / "junit.xml"
    name = "tests/test_a.py::test_required"
    write_report(path, [(name, outcome)])
    with pytest.raises(ValueError):
        gate.verify(path, [name])


def test_gate_requires_exactly_one_occurrence_and_complete_manifest(tmp_path):
    path = tmp_path / "junit.xml"
    names = gate.required_tests()
    write_report(path, [(name, None) for name in names])
    gate.verify(path, names)
    write_report(path, [(name, None) for name in names[:-1]])
    with pytest.raises(ValueError):
        gate.verify(path, names)
    write_report(path, [(name, None) for name in names] + [(names[0], None)])
    with pytest.raises(ValueError):
        gate.verify(path, names)


@pytest.mark.parametrize("data", [[], {}, ["invalid"], ["tests/test_a.py::test_a"] * 2])
def test_gate_rejects_invalid_manifest(tmp_path, data):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        gate.required_tests(path)


def test_gate_cli_and_runner_fail_closed(tmp_path, monkeypatch):
    report = tmp_path / "junit.xml"
    assert gate.main([str(report)]) == 1
    report.write_text("broken")
    assert gate.main([str(report)]) == 1
    write_report(report, [(name, None) for name in gate.required_tests()])
    assert gate.main([str(report)]) == 0
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert not report.exists(), "a stale success must be removed before pytest"
        write_report(report, [(name, None) for name in gate.required_tests()])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main([str(report), "--run"]) == 0
    assert "xfail_strict=true" in calls[0]
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=5))
    assert gate.main([str(report), "--run"]) == 5


def fake_dist(tmp_path, version="0.20.0"):
    directory = tmp_path / "dist"
    directory.mkdir()
    with zipfile.ZipFile(directory / "ksef_client.whl", "w") as wheel:
        wheel.writestr(
            "ksef_client.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: ksef-client\nVersion: {version}\n",
        )
    (directory / "ksef_client.tar.gz").write_bytes(b"sdist")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="0.20.0"\n')
    return directory


def test_release_provenance_and_checksum(tmp_path, monkeypatch):
    directory = fake_dist(tmp_path)
    monkeypatch.chdir(tmp_path)
    sha = "a" * 40
    monkeypatch.setattr(release.subprocess, "check_output", lambda *a, **k: sha)
    release.record(directory, sha, tag="v0.20.0")
    release.verify(directory, sha)
    assert release.main(["verify", str(directory), "--sha", sha]) == 0
    assert release.main(["record", str(directory), "--sha", sha, "--tag", "v0.20.0"]) == 0
    (directory / "ksef_client.tar.gz").write_bytes(b"changed")
    with pytest.raises(ValueError, match="mismatch"):
        release.verify(directory, sha)
    with pytest.raises(ValueError):
        release.record(directory, sha, tag="main")
    with pytest.raises(ValueError):
        release.record(directory, sha, tag="v0.21.0")
    with pytest.raises(ValueError):
        release.describe(directory, "branch")
    monkeypatch.setattr(release.subprocess, "check_output", lambda *a, **k: "b" * 40)
    with pytest.raises(ValueError, match="Checkout"):
        release.record(directory, sha)
    values = iter([sha, "b" * 40])
    monkeypatch.setattr(release.subprocess, "check_output", lambda *a, **k: next(values))
    with pytest.raises(ValueError, match="Tag"):
        release.record(directory, sha, tag="v0.20.0")


def test_release_wrong_version_and_unexpected_distributions(tmp_path, monkeypatch):
    directory = fake_dist(tmp_path, "0.21.0")
    monkeypatch.chdir(tmp_path)
    sha = "a" * 40
    monkeypatch.setattr(release.subprocess, "check_output", lambda *a, **k: sha)
    with pytest.raises(ValueError, match="Wheel version"):
        release.record(directory, sha)
    (directory / "unexpected.txt").write_text("unexpected")
    with pytest.raises(ValueError, match="exactly"):
        release.distributions(directory)


def test_wheel_metadata_validation(tmp_path):
    directory = fake_dist(tmp_path)
    wheel = directory / "ksef_client.whl"
    for contents in [{}, {"a.dist-info/METADATA": "Name: other\nVersion: 1\n"}]:
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, value in contents.items():
                archive.writestr(name, value)
        with pytest.raises(ValueError):
            release.describe(directory, "a" * 40)


def test_installed_mode_rejects_source_import():
    result = subprocess.run(
        [__import__("sys").executable, "-c", "import tests.conftest"],
        env={
            **__import__("os").environ,
            "KSEF_TEST_INSTALLED": "1",
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "installed wheel" in result.stderr


def test_workflow_gate_dependencies():
    # These invariants prevent a future workflow edit from bypassing live verification.
    root = Path(__file__).parents[1]
    publish = (root / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    reusable = (root / ".github/workflows/required-test-e2e.yml").read_text(encoding="utf-8")
    daily = (root / ".github/workflows/python-e2e.yml").read_text(encoding="utf-8")
    assert "needs: [resolve, checks, build, e2e]" in publish
    assert "artifact-name: release-dist" in publish
    assert "packages-dir: publish-dist/" in publish
    assert "tools.release_artifacts verify" in publish
    assert "KSEF_TEST_INSTALLED:" in reusable
    assert "tools.verify_e2e_results output/required-test.xml --run" in reusable
    assert "group: ksef-test-live" in reusable
    assert "cancel-in-progress: false" in reusable
    assert "uses: ./.github/workflows/required-test-e2e.yml" in daily
    assert "for attempt in" not in reusable
