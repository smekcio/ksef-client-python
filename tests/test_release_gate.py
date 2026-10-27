from __future__ import annotations

import io
import json
import subprocess
import tarfile
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
    calls: list = []

    def run(command, **kwargs):
        calls.append(command)
        assert not report.exists(), "a stale success must be removed before pytest"
        write_report(report, [(name, None) for name in gate.required_tests()])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(gate, "validate_live_install", lambda required: None)
    monkeypatch.setattr(gate.subprocess, "run", run)
    assert gate.main([str(report), "--run"]) == 0
    assert "xfail_strict=true" in calls[0]
    monkeypatch.setattr(gate.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=5))
    assert gate.main([str(report), "--run"]) == 5


def fake_dist(tmp_path, version="0.20.0"):
    directory = tmp_path / "dist"
    directory.mkdir()
    with zipfile.ZipFile(directory / f"ksef_client-{version}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(
            f"ksef_client-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: ksef-client\nVersion: {version}\n",
        )
        wheel.writestr("ksef_client/__init__.py", b"original")
    with tarfile.open(directory / f"ksef_client-{version}.tar.gz", "w:gz") as archive:
        data = f"Metadata-Version: 2.1\nName: ksef-client\nVersion: {version}\n".encode()
        entry = tarfile.TarInfo(f"ksef-client-{version}/PKG-INFO")
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
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
    with (directory / "ksef_client-0.20.0.tar.gz").open("ab") as output:
        output.write(b"changed")
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
    wheel = directory / "ksef_client-0.20.0-py3-none-any.whl"
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


def test_test_gate_forwards_only_named_secrets_and_keeps_environment_protection():
    root = Path(__file__).parents[1] / ".github/workflows"
    reusable = (root / "required-test-e2e.yml").read_text(encoding="utf-8")
    callers = [
        (root / name).read_text(encoding="utf-8") for name in ("python-e2e.yml", "publish-pypi.yml")
    ]
    names = [
        "KSEF_TEST_TOKEN",
        "KSEF_TEST_CONTEXT_TYPE",
        "KSEF_TEST_CONTEXT_VALUE",
        "KSEF_TEST_XADES_CERT_CRT",
        "KSEF_TEST_XADES_CERT_CRT_B64",
        "KSEF_TEST_XADES_PRIVATE_KEY_PEM",
        "KSEF_TEST_XADES_PRIVATE_KEY_PEM_B64",
        "KSEF_TEST_XADES_PRIVATE_KEY_PASSWORD",
    ]
    assert "environment: ksef-test" in reusable
    for name in names:
        assert f"      {name}:\n        required:" in reusable
        for caller in callers:
            assert f"      {name}: ${{{{ secrets.{name} }}}}" in caller
            assert "secrets: inherit" not in caller


def test_review_sdist_metadata_must_match_wheel(tmp_path):
    directory = fake_dist(tmp_path)
    with tarfile.open(directory / "ksef_client-0.20.0.tar.gz", "w:gz") as archive:
        data = b"Name: ksef-client\nVersion: 0.19.0\n"
        entry = tarfile.TarInfo("ksef-client-0.20.0/PKG-INFO")
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
    with pytest.raises(ValueError, match="disagree"):
        release.describe(directory, "a" * 40)


def test_review_installed_sdk_content_must_match_exact_wheel(tmp_path, monkeypatch):
    import importlib.metadata

    import ksef_client

    root = tmp_path / "installed"
    package = root / "ksef_client"
    package.mkdir(parents=True)
    init = package / "__init__.py"
    init.write_bytes(b"original")
    wheel = tmp_path / "ksef_client-0.20.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("ksef_client/__init__.py", b"original")
        metadata = b"Name: ksef-client\nVersion: 0.20.0\n"
        archive.writestr("ksef_client-0.20.0.dist-info/METADATA", metadata)
    info = root / "ksef_client-0.20.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_bytes(metadata)
    fake = SimpleNamespace(locate_file=lambda name: root)
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: fake)
    monkeypatch.setattr(ksef_client, "__file__", str(init))
    release.verify_installed_wheel(wheel)
    init.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="differs"):
        release.verify_installed_wheel(wheel)
    init.unlink()
    with pytest.raises(ValueError, match="Missing"):
        release.verify_installed_wheel(wheel)
    monkeypatch.setattr(ksef_client, "__file__", str(tmp_path / "shadowed.py"))
    with pytest.raises(ValueError, match="import"):
        release.verify_installed_wheel(wheel)


def test_review_release_workflow_scopes_secrets_and_pins_actions():
    import re

    root = Path(__file__).parents[1]
    text = (root / ".github/workflows/required-test-e2e.yml").read_text(encoding="utf-8")
    job_env = text.split("    env:\n", 1)[1].split("    steps:", 1)[0]
    assert "secrets." not in job_env
    assert "verify-installed dist" in text
    assert "KSEF_TEST_WHEEL=" in text
    for name in ["required-test-e2e.yml", "publish-pypi.yml", "python-e2e.yml"]:
        workflow = (root / ".github/workflows" / name).read_text(encoding="utf-8")
        for action in re.findall(r"uses: ([^\s]+)", workflow):
            assert action.startswith("./") or re.search(r"@[0-9a-f]{40}$", action)


def test_review_junit_suite_failures_cannot_be_hidden_by_passing_case_nodes(tmp_path):
    path = tmp_path / "junit.xml"
    names = gate.required_tests()
    write_report(path, [(name, None) for name in names])
    text = path.read_text(encoding="utf-8")
    for changed in [
        text.replace("<testsuite>", '<testsuite errors="1">'),
        text.replace("testsuites", "not-junit"),
    ]:
        path.write_text(changed)
        with pytest.raises(ValueError):
            gate.verify(path, names)


@pytest.mark.parametrize("outcome", ["rerunFailure", "rerunError", "flakyFailure", "flakyError"])
def test_gate_rejects_scenario_retries(tmp_path, outcome):
    path = tmp_path / "junit.xml"
    names = gate.required_tests()
    write_report(path, [(name, outcome if i == 0 else None) for i, name in enumerate(names)])
    with pytest.raises(ValueError, match="reruns"):
        gate.verify(path, names)


def test_live_runner_requires_real_install_and_fixed_manifest(monkeypatch, tmp_path):
    monkeypatch.setenv("KSEF_E2E", "1")
    monkeypatch.setenv("KSEF_TEST_INSTALLED", "1")
    monkeypatch.delenv("KSEF_TEST_WHEEL", raising=False)
    with pytest.raises(ValueError, match="exact wheel"):
        gate.validate_live_install(gate.REQUIRED)
    monkeypatch.setenv("KSEF_TEST_WHEEL", str(tmp_path / "wheel.whl"))
    calls: list = []
    monkeypatch.setattr(release, "verify_installed_wheel", calls.append)
    gate.validate_live_install(gate.REQUIRED)
    assert calls == [tmp_path / "wheel.whl"]
    with pytest.raises(ValueError, match="approved TEST"):
        gate.validate_live_install(["tests/test_unit.py::test_unit"])
    monkeypatch.setenv("KSEF_TEST_INSTALLED", "0")
    with pytest.raises(ValueError, match="installed wheel mode"):
        gate.validate_live_install(gate.REQUIRED)


@pytest.mark.parametrize(
    "member", ["evil.pth", "ksef_client/evil.pth", "../evil", "/evil", "other.py"]
)
def test_wheel_is_rejected_before_install_for_unexpected_content(tmp_path, member):
    directory = fake_dist(tmp_path)
    wheel = next(directory.glob("*.whl"))
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(member, b"DUMMY_PAYLOAD")
    with pytest.raises(ValueError):
        release.inspect_wheel(wheel)


def test_distribution_filename_is_bound_to_metadata(tmp_path):
    directory = fake_dist(tmp_path)
    wheel = next(directory.glob("*.whl"))
    wrong = wheel.with_name("ksef_client-9.0.0-py3-none-any.whl")
    wheel.rename(wrong)
    with pytest.raises(ValueError, match="filename"):
        release.describe(directory, "a" * 40)
    wrong.rename(wheel)
    source = next(directory.glob("*.tar.gz"))
    source.rename(source.with_name("ksef_client-9.0.0.tar.gz"))
    with pytest.raises(ValueError, match="filename"):
        release.describe(directory, "a" * 40)


def test_publish_job_never_runs_tag_code_with_oidc():
    root = Path(__file__).parents[1]
    workflow = (root / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    publish = workflow.split("\n  publish:\n", 1)[1]
    assert "environment: pypi" in publish
    assert "id-token: write" in publish
    assert "run:" not in publish and "checkout@" not in publish
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "resolve_tag(Path" in workflow
    assert "github.workflow_sha" in workflow
    e2e = (root / ".github/workflows/python-e2e.yml").read_text(encoding="utf-8")
    assert "secrets: inherit" not in workflow + e2e
    assert e2e.count("if: github.event_name != 'pull_request'") == 3
    reusable = (root / ".github/workflows/required-test-e2e.yml").read_text(encoding="utf-8")
    live = reusable.split("\n  required-test:\n", 1)[1]
    assert "environment: ksef-test" in live
    assert "release-source" not in live
    assert "--require-hashes" in live and '"--no-deps"' in live


def test_release_tag_must_be_merged_into_main(tmp_path):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=tmp_path, text=True).strip()

    git("init", "-b", "main")
    git("config", "user.name", "Mateusz SmektaĹ‚a")
    git("config", "user.email", "mateuszsmekcio@gmail.com")
    project = tmp_path / "pyproject.toml"
    project.write_text('[project]\nversion="0.20.0"\n')
    git("add", ".")
    git("commit", "-m", "test fixture: main")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    git("tag", "v0.20.0")
    assert release.resolve_tag(tmp_path, "v0.20.0") == git("rev-parse", "HEAD")
    git("checkout", "-b", "candidate")
    project.write_text('[project]\nversion="0.20.1"\n')
    git("commit", "-am", "test fixture: unmerged candidate")
    git("tag", "v0.20.1")
    with pytest.raises(ValueError, match="main history"):
        release.resolve_tag(tmp_path, "v0.20.1")
    with pytest.raises(ValueError, match="existing version"):
        release.resolve_tag(tmp_path, "candidate")
    with pytest.raises(ValueError, match="must agree"):
        release.resolve_tag(tmp_path, "v0.20.0")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    assert release.resolve_tag(tmp_path, "v0.20.1") == git("rev-parse", "HEAD")
