"""
strippers — format detection and per-format metadata stripping.
"""

from .detector import detect_format
from .image_stripper import ImageStripper
from .pdf_stripper import PDFStripper
from .office_stripper import OfficeStripper

SUPPORTED_FORMATS: frozenset[str] = frozenset({"JPEG", "PNG", "PDF", "DOCX", "XLSX", "PPTX"})

_STRIPPER_MAP: dict[str, object] = {
    "JPEG": ImageStripper,
    "PNG": ImageStripper,
    "PDF": PDFStripper,
    "DOCX": OfficeStripper,
    "XLSX": OfficeStripper,
    "PPTX": OfficeStripper,
}


def get_stripper(fmt: str) -> ImageStripper | PDFStripper | OfficeStripper:
    """Return an instantiated stripper for the given format string."""
    cls = _STRIPPER_MAP.get(fmt)
    if cls is None:
        raise ValueError(f"No stripper available for format: {fmt!r}")
    return cls()  # type: ignore[call-arg]


__all__ = [
    "detect_format",
    "get_stripper",
    "SUPPORTED_FORMATS",
    "ImageStripper",
    "PDFStripper",
    "OfficeStripper",
]
