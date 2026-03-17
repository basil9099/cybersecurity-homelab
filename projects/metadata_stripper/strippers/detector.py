"""
Format detection using file magic bytes (signatures), not file extensions.
"""

import zipfile
from pathlib import Path

# (signature_bytes, format_name) — checked in order
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"),  # All OOXML Office formats
]

# Content-type substrings that identify specific Office variants
_OFFICE_CONTENT_TYPES: list[tuple[str, str]] = [
    ("wordprocessingml.document", "DOCX"),
    ("spreadsheetml.sheet", "XLSX"),
    ("presentationml.presentation", "PPTX"),
]


def detect_format(path: Path) -> str | None:
    """Return the canonical format name for *path*, or None if unsupported."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(8)
    except OSError:
        return None

    fmt: str | None = None
    for sig, name in _MAGIC_SIGNATURES:
        if header.startswith(sig):
            fmt = name
            break

    if fmt == "ZIP":
        fmt = _detect_office_format(path)

    return fmt


def _detect_office_format(path: Path) -> str | None:
    """Peek inside a ZIP archive to determine which Office format it is."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if "[Content_Types].xml" not in names:
                return None
            content = zf.read("[Content_Types].xml").decode("utf-8", errors="ignore")
            for keyword, fmt in _OFFICE_CONTENT_TYPES:
                if keyword in content:
                    return fmt
    except (zipfile.BadZipFile, KeyError, OSError):
        pass
    return None
