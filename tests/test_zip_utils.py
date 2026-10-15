import binascii
import struct
import tarfile
import tracemalloc
import unittest
import zipfile
from io import BytesIO
from typing import Any
from unittest.mock import patch

from ksef_client.utils.zip_utils import (
    build_tar_gz,
    build_zip,
    split_bytes,
    untar_gz_bytes,
    untar_gz_bytes_safe,
    unzip_bytes,
    unzip_bytes_safe,
)


def _zip_with_entry_name(name: str, payload: bytes) -> bytes:
    """Zip z nazwą wpisu zapisaną dosłownie.

    Nagłówki składamy ręcznie, bo ``zipfile.writestr("")`` wywraca się na Pythonie
    3.10/3.11 na ``IndexError: string index out of range`` (błąd standardowej
    biblioteki, naprawiony w 3.12) — test walidacji nazw nie miałby szansy
    wykonać się na tych interpreterach, a to właśnie one pilnują zgodności
    z najniższą wspieraną wersją.
    """
    encoded = name.encode("utf-8")
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    local_header = (
        b"PK\x03\x04"
        + struct.pack(
            "<HHHHHIIIHH",
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(encoded),
            0,
        )
        + encoded
        + payload
    )
    central_header = (
        b"PK\x01\x02"
        + struct.pack(
            "<HHHHHHIIIHHHHHII",
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(encoded),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + encoded
    )
    end_of_directory = b"PK\x05\x06" + struct.pack(
        "<HHHHIIH", 0, 0, 1, 1, len(central_header), len(local_header), 0
    )
    return local_header + central_header + end_of_directory


def _tar_with_entry_name(name: str) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        payload = b"x"
        info.size = len(payload)
        archive.addfile(info, BytesIO(payload))
    return buffer.getvalue()


class _EndlessEntryStream:
    """Strumień wpisu tar oddający więcej bajtów, niż deklaruje nagłówek.

    `tarfile` sam ogranicza odczyt do `size` z nagłówka tar, więc kłamiący
    nagłówek (scenariusz z audytu: deklaracja 1 KiB przy payloadzie 128 MiB)
    odtwarzamy podmieniając strumień wpisu.
    """

    def __init__(self, total: int) -> None:
        self._left = total

    def read(self, size: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        chunk = min(size if size and size > 0 else self._left, self._left, 64 * 1024)
        self._left -= chunk
        return b"a" * chunk


class ZipUtilsTests(unittest.TestCase):
    def test_zip_roundtrip(self):
        files = {"a.txt": b"hello", "b.txt": b"world"}
        zip_bytes = build_zip(files)
        unzipped = unzip_bytes(zip_bytes)
        self.assertEqual(unzipped["a.txt"], b"hello")
        self.assertEqual(unzipped["b.txt"], b"world")

    def test_build_zip_is_deterministic(self):
        files = {"a.txt": b"hello", "b.txt": b"world"}

        first = build_zip(files)
        second = build_zip(files)

        self.assertEqual(first, second)
        with zipfile.ZipFile(BytesIO(first), "r") as zf:
            self.assertEqual(zf.getinfo("a.txt").date_time, (1980, 1, 1, 0, 0, 0))

    def test_tar_gz_roundtrip(self):
        archive = build_tar_gz({"a.txt": b"hello", "dir/b.txt": b"world"})
        unpacked = untar_gz_bytes(archive)
        self.assertEqual(unpacked["a.txt"], b"hello")
        self.assertEqual(unpacked["dir/b.txt"], b"world")

    def test_build_tar_gz_is_deterministic(self):
        files = {"a.txt": b"hello", "b.txt": b"world"}

        first = build_tar_gz(files)
        second = build_tar_gz(files)

        self.assertEqual(first, second)
        with tarfile.open(fileobj=BytesIO(first), mode="r:gz") as tf:
            self.assertEqual(tf.getmember("a.txt").mtime, 0)

    def test_untar_gz_safe_rejects_invalid_limits(self):
        archive = build_tar_gz({"a.txt": b"hello"})
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_files=0)
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_total_uncompressed_size=0)
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_file_uncompressed_size=0)
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_compression_ratio=0)

    def test_untar_gz_safe_skips_directories_and_limits_files(self):
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
            dir_info = tarfile.TarInfo("dir")
            dir_info.type = tarfile.DIRTYPE
            tf.addfile(dir_info)
            for name in ("dir/a.txt", "dir/b.txt"):
                payload = b"hello"
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tf.addfile(info, BytesIO(payload))

        archive = buffer.getvalue()
        self.assertEqual(untar_gz_bytes_safe(archive)["dir/a.txt"], b"hello")
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_files=1)

    def test_untar_gz_safe_limits_content(self):
        archive = build_tar_gz({"a.txt": b"a" * 10})
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_total_uncompressed_size=5)
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_file_uncompressed_size=5)

    def test_untar_gz_safe_limits_compression_ratio(self):
        archive = build_tar_gz({"a.txt": b"a" * 1024})
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(archive, max_compression_ratio=0.1)

    def test_untar_gz_safe_rejects_unreadable_file_entry(self):
        archive = build_tar_gz({"a.txt": b"hello"})
        with (
            patch.object(tarfile.TarFile, "extractfile", return_value=None),
            self.assertRaises(ValueError),
        ):
            untar_gz_bytes_safe(archive)

    def test_untar_gz_safe_rejects_unsafe_paths(self):
        for name in ("/abs/a.txt", "../a.txt", "C:/temp/a.txt"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build_tar_gz({name: b"hello"})

    def test_untar_gz_safe_rejects_links(self):
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            tf.addfile(info)
        with self.assertRaises(ValueError):
            untar_gz_bytes_safe(buffer.getvalue())

    def test_unzip_limits_max_files(self):
        files = {"a.txt": b"hello", "b.txt": b"world"}
        zip_bytes = build_zip(files)
        with self.assertRaises(ValueError):
            unzip_bytes(zip_bytes, max_files=1)

    def test_unzip_limits_max_total_uncompressed_size(self):
        zip_bytes = build_zip({"a.txt": b"a" * 10})
        with self.assertRaises(ValueError):
            unzip_bytes(zip_bytes, max_total_uncompressed_size=5)

    def test_unzip_limits_max_compression_ratio(self):
        payload = b"a" * (256 * 1024)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", payload)
        zip_bytes = buffer.getvalue()
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            info = zf.getinfo("a.txt")
            ratio = info.file_size / max(info.compress_size, 1)
        with self.assertRaises(ValueError):
            unzip_bytes(zip_bytes, max_compression_ratio=ratio - 0.001)

    def test_unzip_safe_allows_disabling_compression_ratio_check(self):
        payload = b"a" * (256 * 1024)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", payload)
        unzipped = unzip_bytes_safe(buffer.getvalue(), max_compression_ratio=None)
        self.assertEqual(unzipped["a.txt"], payload)

    def test_unzip_safe_rejects_invalid_limits(self):
        zip_bytes = build_zip({"a.txt": b"hello"})
        with self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes, max_files=0)
        with self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes, max_total_uncompressed_size=0)
        with self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes, max_file_uncompressed_size=0)
        with self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes, max_compression_ratio=0)

    def test_unzip_safe_skips_directories(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("dir/", b"")
            zf.writestr("dir/a.txt", b"hello")
        unzipped = unzip_bytes_safe(buffer.getvalue())
        self.assertEqual(unzipped["dir/a.txt"], b"hello")

    def test_unzip_safe_limits_max_file_uncompressed_size(self):
        zip_bytes = build_zip({"a.txt": b"a" * 10})
        with self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes, max_file_uncompressed_size=5)

    def test_unzip_safe_suspicious_zero_compressed_size(self):
        zip_bytes = build_zip({"a.txt": b"a"})
        original_infolist = zipfile.ZipFile.infolist

        def infolist_with_bad_metadata(self):
            infos = original_infolist(self)
            infos[0].compress_size = 0
            infos[0].file_size = 1
            return infos

        with patch.object(
            zipfile.ZipFile, "infolist", infolist_with_bad_metadata
        ), self.assertRaises(ValueError):
            unzip_bytes_safe(zip_bytes)

    def test_unzip_safe_accepts_empty_file_entry(self):
        zip_bytes = build_zip({"empty.txt": b""})
        unzipped = unzip_bytes_safe(zip_bytes)
        self.assertEqual(unzipped["empty.txt"], b"")

    def test_unzip_safe_rejects_absolute_entry_path(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("/abs/a.txt", b"hello")
        with self.assertRaises(ValueError):
            unzip_bytes_safe(buffer.getvalue())

    def test_unzip_safe_rejects_dotdot_entry_path(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("../a.txt", b"hello")
        with self.assertRaises(ValueError):
            unzip_bytes_safe(buffer.getvalue())

    def test_unzip_safe_rejects_drive_separator_in_entry_path(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("C:/temp/a.txt", b"hello")
        with self.assertRaises(ValueError):
            unzip_bytes_safe(buffer.getvalue())

    def test_split_bytes(self):
        data = b"a" * 10
        parts = split_bytes(data, max_part_size=4)
        self.assertEqual(len(parts), 3)
        self.assertEqual(b"".join(parts), data)

    def test_split_bytes_invalid_size(self):
        with self.assertRaises(ValueError):
            split_bytes(b"data", max_part_size=0)

    def test_split_bytes_single_part(self):
        data = b"a" * 3
        parts = split_bytes(data, max_part_size=10)
        self.assertEqual(parts, [data])


class ArchiveMemoryLimitTests(unittest.TestCase):
    """Limity muszą ograniczać PAMIĘĆ, nie tylko metadane wpisu.

    Regresja: `entry.read()` bez rozmiaru materializował całą treść wpisu, więc
    metadane mogły deklarować 1 KiB, gdy DEFLATE produkował 128 MiB (peak
    `tracemalloc` 269,5 MiB dla archiwum 130 KiB przy limitach 2048/4096/200).
    """

    LIMITS: dict[str, Any] = {
        "max_files": 2048,
        "max_total_uncompressed_size": 4096,
        "max_file_uncompressed_size": 2048,
        "max_compression_ratio": 200.0,
    }

    @staticmethod
    def _zip_with_lying_file_size(payload: bytes, declared_size: int):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("a.xml", payload)
        original_infolist = zipfile.ZipFile.infolist

        def lying_infolist(self):
            infos = original_infolist(self)
            infos[0].file_size = declared_size
            return infos

        return buffer.getvalue(), lying_infolist

    def test_unzip_safe_does_not_materialise_entry_with_lying_file_size(self):
        """Kłamiące 1024 B przy payloadzie 32 MiB nie może zjeść pamięci.

        `zipfile` ucina strumień wpisu do zadeklarowanego `file_size` i kończy
        odczyt `BadZipFile` (CRC-32 nie zgadza się z deklaracją), ale samo
        rozmnożenie treści DEFLATE następowało PRZED tym błędem: peak
        `tracemalloc` rósł do 269,5 MiB dla payloadu 128 MiB (audyt). Teraz
        porcja odczytu ogranicza pojedyncze `decompress()`, więc peak jest rzędu
        limitu, a nie payloadu.
        """
        payload = b"a" * (32 * 1024 * 1024)
        archive, lying_infolist = self._zip_with_lying_file_size(payload, 1024)

        tracemalloc.start()
        try:
            with (
                patch.object(zipfile.ZipFile, "infolist", lying_infolist),
                self.assertRaises((ValueError, zipfile.BadZipFile)),
            ):
                unzip_bytes_safe(archive, **self.LIMITS)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        self.assertLess(peak, 2 * 1024 * 1024, f"peak {peak} B zamiast ~limitu 2048 B")

    def test_unzip_safe_rejects_entry_over_limit_without_reading_it(self):
        payload = b"a" * (32 * 1024 * 1024)
        archive = build_zip({"a.xml": payload})

        tracemalloc.start()
        try:
            with self.assertRaisesRegex(ValueError, "max_file_uncompressed_size"):
                unzip_bytes_safe(archive, **self.LIMITS)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        self.assertLess(peak, 2 * 1024 * 1024, f"peak {peak} B — limitu nie wolno odczytać")

    def test_unzip_safe_streams_legal_entry_byte_for_byte(self):
        """Odczyt porcjami nie może zmienić treści poprawnych archiwów."""
        payload = bytes(range(256)) * 1024
        unzipped = unzip_bytes_safe(build_zip({"a.xml": payload}))
        self.assertEqual(unzipped, {"a.xml": payload})

    def test_untar_gz_safe_counts_really_read_bytes_not_header_size(self):
        archive = build_tar_gz({"a.txt": b"x"})
        stream = _EndlessEntryStream(8 * 1024 * 1024)

        tracemalloc.start()
        try:
            with (
                patch.object(tarfile.TarFile, "extractfile", return_value=stream),
                self.assertRaisesRegex(ValueError, "max_file_uncompressed_size"),
            ):
                untar_gz_bytes_safe(archive, max_file_uncompressed_size=2048)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

        self.assertLess(peak, 2 * 1024 * 1024, f"peak {peak} B zamiast ~limitu 2048 B")

    def test_untar_gz_safe_counts_really_read_bytes_against_total_limit(self):
        archive = build_tar_gz({"a.txt": b"x"})
        stream = _EndlessEntryStream(8 * 1024 * 1024)

        with (
            patch.object(tarfile.TarFile, "extractfile", return_value=stream),
            self.assertRaisesRegex(ValueError, "tar.gz exceeds max_total_uncompressed_size"),
        ):
            untar_gz_bytes_safe(
                archive,
                max_total_uncompressed_size=64,
                max_file_uncompressed_size=1_000_000,
            )


class ArchiveEntryNameTests(unittest.TestCase):
    """Nazwy wpisów nie mogą wnosić znaków sterujących ani być puste.

    Regresja: NUL w nazwie ucinał ją do `""`, a `""`/`"."` normalizowały się do
    `"."` (klucz `"."` przechodził dalej), `\\x01`/`\\x7f` trafiały wprost do
    rozpakowywanych ścieżek, a PAX `path` z NUL-em dochodził do `stat` jako
    surowe „embedded null character in path".
    """

    def test_builders_reject_control_characters_in_entry_names(self):
        for name in ("\x00", "a\x00b.txt", "a\x01b.txt", "a\x7fb.txt"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "control character"):
                    build_zip({name: b"x"})
                with self.assertRaisesRegex(ValueError, "control character"):
                    build_tar_gz({name: b"x"})

    def test_unzip_safe_rejects_control_characters_in_entry_names(self):
        for name in ("a\x01b.txt", "a\x7fb.txt"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "control character"):
                unzip_bytes_safe(_zip_with_entry_name(name, b"x"))

    def test_readers_reject_empty_and_dot_entry_names(self):
        for name in ("", ".", "./"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "must not be empty"):
                    build_zip({name: b"x"})
                with self.assertRaisesRegex(ValueError, "must not be empty"):
                    build_tar_gz({name: b"x"})
                with self.assertRaisesRegex(ValueError, "must not be empty"):
                    untar_gz_bytes_safe(_tar_with_entry_name(name))
        for name in ("", "."):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "must not be empty"):
                unzip_bytes_safe(_zip_with_entry_name(name, b"x"))

    def test_untar_gz_safe_rejects_nul_in_pax_path(self):
        """PAX `path` nie jest terminowany NUL-em, więc NUL dochodził do nazwy."""
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("d" * 110 + "\x00" + "x.txt")
            info.size = 1
            archive.addfile(info, BytesIO(b"x"))

        with self.assertRaisesRegex(ValueError, r"control character \(U\+0000\)"):
            untar_gz_bytes_safe(buffer.getvalue())

    def test_untar_gz_safe_accepts_long_legal_pax_name(self):
        long_name = "d" * 110 + "x.txt"
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo(long_name)
            info.size = 1
            archive.addfile(info, BytesIO(b"x"))

        self.assertEqual(untar_gz_bytes_safe(buffer.getvalue()), {long_name: b"x"})


if __name__ == "__main__":
    unittest.main()
