import unittest

from ksef_client.services.batch import build_batch_file_info, encrypt_batch_parts
from ksef_client.services.crypto import generate_iv, generate_symmetric_key


class BatchServiceTests(unittest.TestCase):
    def test_build_batch_file_info(self):
        zip_bytes = b"zip"
        parts = [b"part1", b"part2"]
        info = build_batch_file_info(zip_bytes, parts)
        self.assertEqual(info["fileSize"], len(zip_bytes))
        self.assertEqual(len(info["fileParts"]), 2)

    def test_encrypt_batch_parts(self):
        data = b"a" * 50
        key = generate_symmetric_key()
        iv = generate_iv()
        parts, info = encrypt_batch_parts(data, key, iv, max_part_size=10)
        self.assertGreater(len(parts), 1)
        self.assertEqual(info["fileSize"], len(data))


if __name__ == "__main__":
    unittest.main()
