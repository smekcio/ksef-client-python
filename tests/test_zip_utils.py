import unittest
import zipfile
from io import BytesIO
from unittest.mock import patch

from ksef_client.utils.zip_utils import build_zip, split_bytes, unzip_bytes, unzip_bytes_safe


class ZipUtilsTests(unittest.TestCase):
    def test_zip_roundtrip(self):
        files = {"a.txt": b"hello", "b.txt": b"world"}
        zip_bytes = build_zip(files)
        unzipped = unzip_bytes(zip_bytes)
        self.assertEqual(unzipped["a.txt"], b"hello")
        self.assertEqual(unzipped["b.txt"], b"world")

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


if __name__ == "__main__":
    unittest.main()
