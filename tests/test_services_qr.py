import builtins
import sys
import types
import unittest
from typing import Any, cast
from unittest.mock import patch

from ksef_client.services import qr


class DummyImage:
    def __init__(self, size=(10, 10)):
        self.size = size

    def convert(self, mode):
        return self

    def save(self, buf, format="PNG"):
        buf.write(b"PNG")

    def resize(self, size):
        self.size = size
        return self

    def paste(self, img, box):
        return None


class DummyQrCode:
    def __init__(self, box_size=10, border=4):
        self.box_size = box_size
        self.border = border
        self.data = None

    def add_data(self, payload):
        self.data = payload

    def make(self, fit=True):
        return None

    def make_image(self, fill_color="black", back_color="white"):
        return DummyImage()


class DummyImageModule:
    @staticmethod
    def open(buf):
        return DummyImage()

    @staticmethod
    def new(mode, size, color):
        return DummyImage(size=size)


class DummyDraw:
    def __init__(self, img):
        self.img = img

    def textbbox(self, pos, text, font=None):
        return (0, 0, len(text) * 6, 10)

    def text(self, pos, text, fill=None, font=None):
        return None


class DummyImageDrawModule:
    @staticmethod
    def Draw(img):
        return DummyDraw(img)


class DummyImageFontModule:
    @staticmethod
    def load_default():
        return object()


class QrServiceTests(unittest.TestCase):
    def test_require_qr_error(self):
        original_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "qrcode" or name.startswith("PIL"):
                raise ImportError("missing")
            return original_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=fake_import), self.assertRaises(RuntimeError):
            qr._require_qr()

    def test_qr_helpers_with_stub(self):
        def stub_require():
            return (
                type("Q", (), {"QRCode": DummyQrCode}),
                DummyImageModule,
                DummyImageDrawModule,
                DummyImageFontModule,
            )

        with patch("ksef_client.services.qr._require_qr", side_effect=stub_require):
            data = qr.generate_qr_png("https://example.com")
            self.assertTrue(data.startswith(b"PNG"))
            resized = qr.resize_png(data, 5, 5)
            self.assertTrue(resized.startswith(b"PNG"))
            labeled = qr.add_label_to_qr(data, "label")
            self.assertTrue(labeled.startswith(b"PNG"))

    def test_require_qr_success(self):
        qrcode_module = types.ModuleType("qrcode")
        cast(Any, qrcode_module).QRCode = DummyQrCode
        pil_module = types.ModuleType("PIL")
        image_module = DummyImageModule
        draw_module = DummyImageDrawModule
        font_module = DummyImageFontModule
        with patch.dict(
            sys.modules,
            {
                "qrcode": qrcode_module,
                "PIL": pil_module,
                "PIL.Image": image_module,
                "PIL.ImageDraw": draw_module,
                "PIL.ImageFont": font_module,
            },
        ):
            qrcode, Image, ImageDraw, ImageFont = qr._require_qr()
        self.assertIs(qrcode, qrcode_module)
        self.assertIs(Image, image_module)


if __name__ == "__main__":
    unittest.main()
