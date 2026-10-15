from __future__ import annotations

import contextlib
from typing import Any

# Minimalny rozmiar fontu etykiety: poniżej tego napis przestaje być czytelny,
# więc zamiast dalej go zmniejszać, `add_label_to_qr` poszerza kanwę.
_MIN_LABEL_FONT_SIZE = 6
# Zapas po bokach etykiety, gdy napis jest szerszy od kodu QR (antyaliasing krawędzi).
_LABEL_SIDE_PADDING = 2


def _require_qr():
    try:
        import qrcode
        from PIL import Image, ImageDraw, ImageFont

        return qrcode, Image, ImageDraw, ImageFont
    except Exception as exc:
        raise RuntimeError("QR support requires 'qrcode' and 'pillow' extras") from exc


def generate_qr_png(payload_url: str, *, box_size: int = 10, border: int = 4) -> bytes:
    qrcode, Image, ImageDraw, ImageFont = _require_qr()
    qr = qrcode.QRCode(box_size=box_size, border=border)
    qr.add_data(payload_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    with _bytes_io() as buf:
        img.save(buf, format="PNG")
        return buf.getvalue()


def resize_png(png_bytes: bytes, width: int, height: int) -> bytes:
    """Skaluje obraz PNG zachowując charakter kodu QR.

    Domyślny filtr `Image.resize` interpoluje, więc na krawędziach modułów
    powstawały szare piksele — kod QR jest obrazem dwupoziomowym, a rozmyte
    krawędzie obniżają kontrast, na którym binaryzują skanery. Używamy więc
    `NEAREST` (bez interpolacji) i odrzucamy rozmiar niedodatni.
    """
    qrcode, Image, ImageDraw, ImageFont = _require_qr()
    if width <= 0 or height <= 0:
        raise ValueError("width and height must be positive")
    with _bytes_io(png_bytes) as buf:
        img = Image.open(buf)
        img = img.resize((width, height), Image.Resampling.NEAREST)
        with _bytes_io() as out:
            img.save(out, format="PNG")
            return out.getvalue()


def _load_label_font(ImageFont: Any, font_size: int) -> Any:
    """Ładuje font o żądanym rozmiarze, odpornie na Pillow < 10.1.

    Parametr `size` w `ImageFont.load_default` istnieje dopiero od Pillow 10.1,
    a dodatek `qr` dopuszcza `pillow>=10.0.0`. Dlatego próbujemy kolejno:
    skalowalny font domyślny, dołączony DejaVu Sans, a na końcu bitmapowy
    `load_default()` bez rozmiaru — na starym Pillow rozmiar jest wtedy ignorowany,
    ale etykieta nadal się wyrenderuje zamiast wywracać się na `TypeError`.
    """
    with contextlib.suppress(TypeError):
        return ImageFont.load_default(size=font_size)
    truetype = getattr(ImageFont, "truetype", None)
    if truetype is not None:
        with contextlib.suppress(OSError):
            return truetype("DejaVuSans.ttf", font_size)
    return ImageFont.load_default()


def _measure_label(draw: Any, label: str, font: Any) -> tuple[int, int, int, int]:
    """Zwraca `(left, top, width, height)` napisu względem punktu rysowania."""
    left, top, right, bottom = draw.textbbox((0, 0), label, font=font)
    return left, top, right - left, bottom - top


def _fit_label_font(
    *,
    ImageFont: Any,
    draw: Any,
    label: str,
    max_width: int,
    font_size: int,
) -> tuple[Any, int, int, int, int]:
    """Dobiera font tak, by napis mieścił się w szerokości `max_width`.

    Najpierw zmniejszamy rozmiar fontu (do `_MIN_LABEL_FONT_SIZE`) — szerokość kodu
    QR jest ważniejsza niż wielkość podpisu pod nim. Gdy nawet najmniejszy sensowny
    font nie mieści napisu, `add_label_to_qr` poszerza kanwę, żeby etykieta nigdy
    nie została ucięta.
    """
    size = font_size
    while True:
        font = _load_label_font(ImageFont, size)
        text_left, text_top, text_width, text_height = _measure_label(draw, label, font)
        if text_width <= max_width or size <= _MIN_LABEL_FONT_SIZE:
            return font, text_left, text_top, text_width, text_height
        size -= 1


def add_label_to_qr(png_bytes: bytes, label: str, *, font_size: int = 14) -> bytes:
    """Dokleja etykietę pod kodem QR, respektując `font_size`.

    Etykieta zawsze mieści się w wynikowym obrazie: najpierw zmniejszany jest font
    (aż do `_MIN_LABEL_FONT_SIZE`), a gdy to nie wystarcza, poszerzana jest kanwa,
    a kod QR zostaje wyśrodkowany.
    """
    qrcode, Image, ImageDraw, ImageFont = _require_qr()
    if font_size <= 0:
        raise ValueError("font_size must be positive")
    with _bytes_io(png_bytes) as buf:
        qr_img = Image.open(buf).convert("RGB")

    width, height = qr_img.size
    font, text_left, text_top, text_width, text_height = _fit_label_font(
        ImageFont=ImageFont,
        draw=ImageDraw.Draw(qr_img),
        label=label,
        max_width=width,
        font_size=font_size,
    )

    canvas_width = max(width, text_width + _LABEL_SIDE_PADDING)
    label_top = height + 3
    canvas_height = label_top + text_height + 3
    new_img = Image.new("RGB", (canvas_width, canvas_height), "white")
    new_img.paste(qr_img, ((canvas_width - width) // 2, 0))

    draw = ImageDraw.Draw(new_img)
    x = (canvas_width - text_width) // 2
    draw.text((x - text_left, label_top - text_top), label, fill="black", font=font)

    with _bytes_io() as out:
        new_img.save(out, format="PNG")
        return out.getvalue()


def _bytes_io(initial: bytes | None = None):
    import io

    return io.BytesIO(initial if initial is not None else b"")
