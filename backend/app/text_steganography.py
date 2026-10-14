MAGIC = b"TSZWS01"
ZERO = "\u200b"
ONE = "\u200c"


def _encode_bytes(value: bytes) -> str:
    return "".join(
        ONE if (byte >> shift) & 1 else ZERO
        for byte in value
        for shift in range(7, -1, -1)
    )


def _decode_bits(value: str) -> bytes:
    bits = [1 if character == ONE else 0 for character in value]
    output = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


def embed_text(carrier: str, secret: str) -> tuple[str, int]:
    secret_bytes = secret.encode("utf-8")
    payload = MAGIC + len(secret_bytes).to_bytes(4, "big") + secret_bytes
    return carrier.rstrip() + "\n" + _encode_bytes(payload), len(secret_bytes)


def extract_text(carrier: str) -> str:
    hidden = "".join(character for character in carrier if character in {ZERO, ONE})
    decoded = _decode_bits(hidden)
    if not decoded.startswith(MAGIC):
        raise ValueError("No TraceShield hidden text was found.")
    length_start = len(MAGIC)
    message_length = int.from_bytes(decoded[length_start:length_start + 4], "big")
    message_start = length_start + 4
    message_end = message_start + message_length
    if message_end > len(decoded):
        raise ValueError("The hidden text is incomplete.")
    try:
        return decoded[message_start:message_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("The hidden text is not valid UTF-8.") from exc
