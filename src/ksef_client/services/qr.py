from __future__ import annotations

from typing import Optional


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
    qrcode, Image, ImageDraw, ImageFont = _require_qr()
    with _bytes_io(png_bytes) as buf:
        img = Image.open(buf)
        img = img.resize((width, height))
        with _bytes_io() as out:
            img.save(out, format="PNG")
            return out.getvalue()


def add_label_to_qr(png_bytes: bytes, label: str, *, font_size: int = 14) -> bytes:
    qrcode, Image, ImageDraw, ImageFont = _require_qr()
    with _bytes_io(png_bytes) as buf:
        qr_img = Image.open(buf).convert("RGB")

    width, height = qr_img.size
    font = ImageFont.load_default()
    draw = ImageDraw.Draw(qr_img)
    text_width, text_height = draw.textbbox((0, 0), label, font=font)[2:]

    new_img = Image.new("RGB", (width, height + text_height + 6), "white")
    new_img.paste(qr_img, (0, 0))

    draw = ImageDraw.Draw(new_img)
    x = (width - text_width) // 2
    y = height + 3
    draw.text((x, y), label, fill="black", font=font)

    with _bytes_io() as out:
        new_img.save(out, format="PNG")
        return out.getvalue()


def _bytes_io(initial: Optional[bytes] = None):
    import io
    return io.BytesIO(initial if initial is not None else b"")
