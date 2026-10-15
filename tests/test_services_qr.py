import builtins
import io
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

    def resize(self, size, resample=None):
        self.size = size
        self.resample = resample
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
    class Resampling:
        NEAREST = "nearest"

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


class QrResamplingTests(unittest.TestCase):
    """`resize_png` nie może interpolować obrazu kodu QR.

    Domyślny filtr `Image.resize` wygładza krawędzie modułów (szare piksele),
    a skanery binaryzują obraz na podstawie kontrastu — rozmyty kod QR bywa
    nieczytelny.
    """

    def test_resize_keeps_the_image_bilevel(self):
        try:
            from PIL import Image
        except ImportError:  # pragma: no cover - brak extras 'qr'
            self.skipTest("Pillow nie jest zainstalowane")

        from ksef_client.services.qr import generate_qr_png, resize_png

        png = generate_qr_png("https://qr-test.ksef.mf.gov.pl/invoice/1111111111/x/YQ", box_size=4)
        resized = resize_png(png, 250, 250)

        image = Image.open(io.BytesIO(resized)).convert("L")
        levels = set(image.getdata())
        self.assertLessEqual(len(levels), 2, f"obraz nie jest dwupoziomowy: {sorted(levels)}")

    def test_resize_rejects_non_positive_size(self):
        # Ten test nie może failować w środowisku bez extras `qr` (CI instaluje
        # `requirements-dev.txt`) — `generate_qr_png` rzuca wtedy RuntimeError.
        self._skip_without_qr_extras()
        from ksef_client.services.qr import generate_qr_png, resize_png

        png = generate_qr_png("https://example.com")
        with self.assertRaisesRegex(ValueError, "must be positive"):
            resize_png(png, 0, 100)

    def _skip_without_qr_extras(self) -> None:
        try:
            import PIL  # noqa: F401
            import qrcode  # noqa: F401
        except ImportError:  # pragma: no cover - brak extras 'qr'
            self.skipTest("brak extras 'qr' (qrcode/Pillow)")


def _ink_bbox(image):
    """Bounding box faktycznie namalowanych (nie-białych) pikseli obrazu."""
    return image.convert("L").point(lambda value: 255 - value).getbbox()


class QrLabelTests(unittest.TestCase):
    """Etykieta pod kodem QR: `font_size` działa, a napis nigdy nie wychodzi z obrazu."""

    def _pillow(self):
        try:
            from PIL import Image, ImageDraw, ImageFont
        except ImportError:  # pragma: no cover - brak extras 'qr'
            self.skipTest("Pillow nie jest zainstalowane")
        return Image, ImageDraw, ImageFont

    def test_label_respects_font_size(self):
        Image, _ImageDraw, _ImageFont = self._pillow()
        png = qr.generate_qr_png("https://example.com", box_size=4)
        qr_width, qr_height = Image.open(io.BytesIO(png)).size

        small = Image.open(io.BytesIO(qr.add_label_to_qr(png, "FV/1", font_size=10)))
        large = Image.open(io.BytesIO(qr.add_label_to_qr(png, "FV/1", font_size=30)))

        self.assertEqual(small.size[0], qr_width)  # szerokość kodu QR bez zmian
        self.assertEqual(large.size[0], qr_width)
        self.assertLess(small.size[1], large.size[1])

        small_ink = _ink_bbox(small.crop((0, qr_height, small.size[0], small.size[1])))
        large_ink = _ink_bbox(large.crop((0, qr_height, large.size[0], large.size[1])))
        assert small_ink is not None and large_ink is not None
        self.assertLess(small_ink[3] - small_ink[1], large_ink[3] - large_ink[1])

    def test_label_shrinks_the_font_instead_of_widening_the_qr(self):
        Image, _ImageDraw, _ImageFont = self._pillow()
        png = qr.generate_qr_png("https://example.com", box_size=4)
        qr_width, qr_height = Image.open(io.BytesIO(png)).size

        labeled = Image.open(
            io.BytesIO(qr.add_label_to_qr(png, "FV/1234567890/2026", font_size=40))
        )
        ink = _ink_bbox(labeled.crop((0, qr_height, labeled.size[0], labeled.size[1])))
        assert ink is not None
        self.assertEqual(labeled.size[0], qr_width)
        self.assertGreater(ink[0], 0)
        self.assertLess(ink[2], qr_width)

    def test_long_label_is_not_clipped(self):
        Image, ImageDraw, ImageFont = self._pillow()
        label = "FV/1234567890/2026/04/01/abcdefghijklmnopqrstuvwxyz-1234567890"
        png = qr.generate_qr_png("https://example.com", box_size=4)
        qr_width, qr_height = Image.open(io.BytesIO(png)).size

        labeled = Image.open(io.BytesIO(qr.add_label_to_qr(png, label, font_size=28)))
        width, height = labeled.size
        ink = _ink_bbox(labeled.crop((0, qr_height, width, height)))
        assert ink is not None

        font, text_left, text_top, text_width, text_height = qr._fit_label_font(
            ImageFont=ImageFont,
            draw=ImageDraw.Draw(Image.new("RGB", (10, 10), "white")),
            label=label,
            max_width=qr_width,
            font_size=28,
        )
        # Nawet najmniejszym sensownym fontem napis nie mieści się w szerokości kodu QR...
        self.assertGreater(text_width, qr_width)
        # ...więc kanwa została poszerzona, a etykieta i tak mieści się w obrazie.
        self.assertGreaterEqual(width, text_width)
        self.assertLessEqual(ink[2], width)

        # Napis nie jest ucięty: szerokość namalowanej etykiety = szerokość renderu referencyjnego.
        reference = Image.new("RGB", (text_width + 40, text_height + 40), "white")
        ImageDraw.Draw(reference).text(
            (20 - text_left, 20 - text_top), label, fill="black", font=font
        )
        reference_ink = _ink_bbox(reference)
        assert reference_ink is not None
        self.assertLessEqual(abs((ink[2] - ink[0]) - (reference_ink[2] - reference_ink[0])), 1)

    def test_label_rejects_non_positive_font_size(self):
        Image, _ImageDraw, _ImageFont = self._pillow()
        png = qr.generate_qr_png("https://example.com", box_size=4)
        with self.assertRaisesRegex(ValueError, "font_size must be positive"):
            qr.add_label_to_qr(png, "label", font_size=0)

    def test_label_font_fallback_for_pillow_without_size_parameter(self):
        """Pillow < 10.1: `load_default` bez `size` — schodzimy na `truetype`, potem bitmapę."""
        truetype_calls = []

        class ScalableFallback:
            @staticmethod
            def load_default(**kwargs):
                raise TypeError("load_default() got an unexpected keyword argument 'size'")

            @staticmethod
            def truetype(name, size):
                truetype_calls.append((name, size))
                return f"truetype:{size}"

        class BitmapFallback:
            @staticmethod
            def load_default(**kwargs):
                if kwargs:
                    raise TypeError("load_default() got an unexpected keyword argument 'size'")
                return "bitmap-default"

            @staticmethod
            def truetype(name, size):
                raise OSError("brak pliku fontu")

        self.assertEqual(qr._load_label_font(ScalableFallback, 18), "truetype:18")
        self.assertEqual(truetype_calls, [("DejaVuSans.ttf", 18)])
        self.assertEqual(qr._load_label_font(BitmapFallback, 18), "bitmap-default")

    def test_label_geometry_with_stub_metrics(self):
        """Kontrolowane metryki: font maleje do minimum, a kanwa rośnie dokładnie o napis."""
        recorded: dict[str, Any] = {}
        requested_sizes: list[int] = []

        class StubImage:
            def __init__(self, size):
                self.size = size

            def convert(self, mode):
                return self

            def paste(self, img, box):
                recorded["paste"] = box

            def save(self, buf, format="PNG"):
                buf.write(b"PNG")

        class StubDraw:
            def __init__(self, img):
                self.img = img

            def textbbox(self, pos, text, font=None):
                return (0, 0, len(text) * 6, 10)

            def text(self, pos, text, fill=None, font=None):
                recorded["text"] = pos

        class StubImageModule:
            Resampling = types.SimpleNamespace(NEAREST="nearest")

            @staticmethod
            def open(buf):
                return StubImage((10, 10))

            @staticmethod
            def new(mode, size, color):
                recorded["size"] = size
                return StubImage(size)

        class StubImageDrawModule:
            @staticmethod
            def Draw(img):
                return StubDraw(img)

        class StubFontModule:
            @staticmethod
            def load_default(**kwargs):
                if kwargs:
                    requested_sizes.append(kwargs["size"])
                    raise TypeError("load_default() got an unexpected keyword argument 'size'")
                return "bitmap-default"

        def stub_require():
            return (
                types.SimpleNamespace(QRCode=DummyQrCode),
                StubImageModule,
                StubImageDrawModule,
                StubFontModule,
            )

        label = "0123456789"  # 60 px w metrykach zaślepki, obraz ma 10 px szerokości
        with patch("ksef_client.services.qr._require_qr", side_effect=stub_require):
            labeled = qr.add_label_to_qr(b"PNG", label, font_size=14)

        text_width = len(label) * 6
        canvas_width = text_width + 2
        self.assertTrue(labeled.startswith(b"PNG"))
        self.assertEqual(requested_sizes, list(range(14, 5, -1)))  # font maleje do minimum
        self.assertEqual(recorded["size"], (canvas_width, 13 + 10 + 3))
        self.assertEqual(recorded["paste"], ((canvas_width - 10) // 2, 0))
        self.assertEqual(recorded["text"], ((canvas_width - text_width) // 2, 13))


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
