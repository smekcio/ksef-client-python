import unittest
import zipfile
from io import BytesIO

from ksef_client.utils.zip_utils import build_zip, split_bytes, unzip_bytes


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
