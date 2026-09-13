from io import BytesIO
from pathlib import Path
import tarfile

import pytest

from gaia_secure_agent.archive_inspect import inspect_source_archive


def _add_file(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(content)
    archive.addfile(info, BytesIO(content))


def test_valid_single_root_archive_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        _add_file(archive, "project-root/README.md", b"hello")
        _add_file(archive, "project-root/src/app.py", b"print('ok')\n")

    result = inspect_source_archive(path)

    assert result.accepted is True
    assert result.top_level_root == "project-root"
    assert result.regular_file_count == 2
    assert result.total_uncompressed_bytes > 0


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        _add_file(archive, "project-root/../escape.txt", b"no")

    with pytest.raises(RuntimeError, match="traversal"):
        inspect_source_archive(path)


def test_symlink_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        link = tarfile.TarInfo(name="project-root/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
        _add_file(archive, "project-root/README.md", b"hello")

    with pytest.raises(RuntimeError, match="link"):
        inspect_source_archive(path)


def test_multiple_top_level_roots_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        _add_file(archive, "root-one/a.txt", b"a")
        _add_file(archive, "root-two/b.txt", b"b")

    with pytest.raises(RuntimeError, match="one top-level"):
        inspect_source_archive(path)


def test_oversized_file_metadata_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "source.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        _add_file(archive, "project-root/big.bin", b"123456")

    with pytest.raises(RuntimeError, match="oversized"):
        inspect_source_archive(path, max_file_bytes=5)
