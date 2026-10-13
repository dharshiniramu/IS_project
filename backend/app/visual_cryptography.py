from io import BytesIO
from random import randrange

from PIL import Image


def create_visual_shares(image_bytes: bytes) -> tuple[bytes, bytes]:
    source = Image.open(BytesIO(image_bytes)).convert("L")
    share_one = Image.new("L", (source.width * 2, source.height * 2), 255)
    share_two = Image.new("L", (source.width * 2, source.height * 2), 255)
    pixels_one = share_one.load()
    pixels_two = share_two.load()

    for y in range(source.height):
        for x in range(source.width):
            random_pattern = randrange(2)
            pattern = (0, 255, 255, 0) if random_pattern else (255, 0, 0, 255)
            is_dark = source.getpixel((x, y)) < 128
            other_pattern = (255 - value for value in pattern) if is_dark else pattern
            for index, (first, second) in enumerate(zip(pattern, other_pattern)):
                offset_x = x * 2 + index % 2
                offset_y = y * 2 + index // 2
                pixels_one[offset_x, offset_y] = first
                pixels_two[offset_x, offset_y] = second

    output_one = BytesIO()
    output_two = BytesIO()
    share_one.save(output_one, format="PNG")
    share_two.save(output_two, format="PNG")
    return output_one.getvalue(), output_two.getvalue()
