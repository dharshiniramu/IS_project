import wave

MAGIC = b"TSAUD01"


def _bits(value: bytes):
    for byte in value:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _decode(bits: list[int]) -> bytes:
    output = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index:index + 8]:
            byte = (byte << 1) | bit
        output.append(byte)
    return bytes(output)


def embed_text(audio_bytes: bytes, secret: str) -> tuple[bytes, int]:
    from io import BytesIO

    secret_bytes = secret.encode("utf-8")
    payload = MAGIC + len(secret_bytes).to_bytes(4, "big") + secret_bytes
    with wave.open(BytesIO(audio_bytes), "rb") as source:
        if source.getcomptype() != "NONE" or source.getsampwidth() != 2:
            raise ValueError("Audio steganography requires uncompressed 16-bit PCM WAV.")
        params = source.getparams()
        frames = bytearray(source.readframes(source.getnframes()))
    required_bits = len(payload) * 8
    if required_bits > len(frames):
        raise ValueError("The message is too large for this WAV file.")
    for index, bit in enumerate(_bits(payload)):
        frames[index] = (frames[index] & 0xFE) | bit
    output = BytesIO()
    with wave.open(output, "wb") as destination:
        destination.setparams(params)
        destination.writeframes(frames)
    return output.getvalue(), len(secret_bytes)


def extract_text(audio_bytes: bytes) -> str:
    from io import BytesIO

    with wave.open(BytesIO(audio_bytes), "rb") as source:
        if source.getcomptype() != "NONE" or source.getsampwidth() != 2:
            raise ValueError("Audio steganography requires uncompressed 16-bit PCM WAV.")
        frames = source.readframes(source.getnframes())
    bits = [value & 1 for value in frames]
    header_size = len(MAGIC) + 4
    header = _decode(bits[:header_size * 8])
    if not header.startswith(MAGIC):
        raise ValueError("No TraceShield hidden audio message was found.")
    length = int.from_bytes(header[len(MAGIC):header_size], "big")
    end = (header_size + length) * 8
    if end > len(bits):
        raise ValueError("The hidden audio message is incomplete.")
    try:
        return _decode(bits[header_size * 8:end]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("The hidden audio message is not valid UTF-8.") from exc
