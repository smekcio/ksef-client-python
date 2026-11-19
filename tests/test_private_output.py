import ctypes
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ksef_client import _private_files as files


def test_private_output_replacement_and_no_clobber(tmp_path):
    target = tmp_path / "receipt.xml"
    files.write_private_file(target, b"first")
    with pytest.raises(FileExistsError):
        files.write_private_file(target, b"second")
    assert target.read_bytes() == b"first"
    with pytest.raises(RuntimeError), files.private_output(target, overwrite=True) as stream:
        stream.write(b"partial")
        raise RuntimeError
    assert target.read_bytes() == b"first"
    files.write_private_file(target, b"second", overwrite=True)
    assert target.read_bytes() == b"second"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(os.name == "nt", reason="Windows pins the output directory against renames")
def test_moved_output_directory_cleans_original_staging(tmp_path):
    parent = tmp_path / "outputs"
    moved = tmp_path / "old"
    parent.mkdir()
    with (
        pytest.raises(OSError, match="Output directory changed"),
        files.private_output(parent / "invoice.zip") as stream,
    ):
        stream.write(b"invoice")
        parent.rename(moved)
        parent.mkdir()
    assert list(parent.iterdir()) == []
    assert list(moved.iterdir()) == []


@pytest.mark.skipif(
    not (hasattr(os, "O_PATH") or hasattr(os, "O_SEARCH")), reason="Traverse-only descriptors"
)
def test_traverse_only_ancestor_allows_publication(tmp_path):
    ancestor = tmp_path / "shared"
    output = ancestor / "private"
    output.mkdir(parents=True)
    ancestor.chmod(0o111)
    try:
        target = output / "bundle.zip"
        files.write_private_file(target, b"bundle")
        assert target.read_bytes() == b"bundle"
    finally:
        ancestor.chmod(0o700)


@pytest.mark.skipif(os.name == "nt", reason="Exercise the Windows handle protocol on POSIX")
def test_windows_pins_all_components_and_uses_rename(tmp_path, monkeypatch):
    windows = SimpleNamespace(**vars(os))
    windows.name = "nt"
    kernel = Mock()
    monkeypatch.setattr(files, "os", windows)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
    held = []

    def acquire(path, *, directory):
        assert directory
        held.append(path)
        return len(held)

    monkeypatch.setattr(files, "_windows_handle", acquire)
    rename = Mock(wraps=os.rename)
    monkeypatch.setattr(windows, "rename", rename)
    files.write_private_file(tmp_path / "bundle.zip", b"bundle")
    assert held == [*reversed(tmp_path.parents), tmp_path]
    assert [args.args[0] for args in kernel.CloseHandle.call_args_list] == list(
        range(len(held), 0, -1)
    )
    assert Path(rename.call_args.args[0]).parent == tmp_path
    assert (tmp_path / "bundle.zip").read_bytes() == b"bundle"
