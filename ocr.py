from PIL import Image
import pytesseract
import io


def image_to_text(image_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(image_bytes))
    # Convert to grayscale for better OCR accuracy
    img = img.convert("L")
    text = pytesseract.image_to_string(img, config="--psm 6")
    return text.strip()
