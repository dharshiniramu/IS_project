from io import BytesIO

from PIL import Image

MAGIC = b"TSSTEG01"
HEADER_SIZE = len(MAGIC) + 4


def _bits(value: bytes):
    for byte in value:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bytes(bits: list[int]) -> bytes:
    output = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


def embed_text(image_bytes: bytes, secret: str) -> tuple[bytes, int]:
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    secret_bytes = secret.encode("utf-8")
    payload = MAGIC + len(secret_bytes).to_bytes(4, "big") + secret_bytes
    required_bits = len(payload) * 8
    capacity_bits = image.width * image.height * 3
    if required_bits > capacity_bits:
        raise ValueError("The message is too large for this image.")

    pixels = list(image.getdata())
    payload_bits = _bits(payload)
    encoded_pixels = []
    for pixel in pixels:
        encoded_pixel = list(pixel)
        for channel in range(3):
            try:
                encoded_pixel[channel] = (encoded_pixel[channel] & ~1) | next(payload_bits)
            except StopIteration:
                break
        encoded_pixels.append(tuple(encoded_pixel))

    image.putdata(encoded_pixels)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue(), len(secret_bytes)


def extract_text(image_bytes: bytes) -> str:
    image = Image.open(BytesIO(image_bytes)).convert("RGB")
    bits = [channel & 1 for pixel in image.getdata() for channel in pixel]
    header = _bytes(bits[:HEADER_SIZE * 8])
    if not header.startswith(MAGIC):
        raise ValueError("No TraceShield hidden message was found.")
    message_length = int.from_bytes(header[len(MAGIC):HEADER_SIZE], "big")
    end = (HEADER_SIZE + message_length) * 8
    if end > len(bits):
        raise ValueError("The hidden message is incomplete.")
    try:
        return _bytes(bits[HEADER_SIZE * 8:end]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("The hidden message is not valid UTF-8.") from exc
