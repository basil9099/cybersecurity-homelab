"""
Image metadata stripper for JPEG and PNG files.

Libraries used:
  - Pillow  : open / save images, read PNG text chunks
  - piexif  : structured EXIF tag extraction for JPEG
"""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image
    import piexif

    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _gps_rational_to_decimal(rationals: tuple, ref: str) -> float | None:
    """Convert a piexif GPS rational triple to a signed decimal degree."""
    try:
        deg = rationals[0][0] / rationals[0][1]
        mins = rationals[1][0] / rationals[1][1]
        secs = rationals[2][0] / rationals[2][1]
        val = deg + mins / 60.0 + secs / 3600.0
        if ref in ("S", "W"):
            val = -val
        return round(val, 6)
    except Exception:
        return None


def _decode_value(value: object) -> str:
    """Convert raw EXIF values to a human-readable string."""
    if isinstance(value, bytes):
        try:
            return value.rstrip(b"\x00").decode("utf-8", errors="replace")
        except Exception:
            return repr(value)
    if isinstance(value, tuple) and len(value) == 2 and all(isinstance(v, int) for v in value):
        # Rational number stored as (numerator, denominator)
        num, den = value
        if den != 0:
            return f"{num}/{den} ({num / den:.4f})"
        return f"{num}/0"
    return str(value)


def _extract_jpeg_exif(path: Path) -> dict[str, str]:
    """Return all EXIF fields from a JPEG as {tag_name: value_str}."""
    metadata: dict[str, str] = {}
    try:
        img = Image.open(path)
        exif_bytes: bytes | None = img.info.get("exif")  # type: ignore[assignment]
        if not exif_bytes:
            return metadata

        exif_dict = piexif.load(exif_bytes)
    except Exception:
        return metadata

    ifd_prefix = {
        "0th": "",
        "1st": "Thumbnail.",
        "Exif": "Exif.",
        "GPS": "GPS.",
        "Interop": "Interop.",
    }

    for ifd_name, ifd_data in exif_dict.items():
        if not isinstance(ifd_data, dict):
            continue
        prefix = ifd_prefix.get(ifd_name, f"{ifd_name}.")
        tag_defs = piexif.TAGS.get(ifd_name, {})

        for tag_id, raw_val in ifd_data.items():
            tag_name = tag_defs.get(tag_id, {}).get("name", f"Tag_{tag_id:#06x}")
            full_key = f"{prefix}{tag_name}"

            # Skip nested IFD pointers — they will be read from their own IFD
            if isinstance(raw_val, dict):
                continue

            metadata[full_key] = _decode_value(raw_val)

    # Synthesise human-readable GPS coordinates if present
    gps = exif_dict.get("GPS", {})
    lat_raw = gps.get(piexif.GPSIFD.GPSLatitude)
    lat_ref = gps.get(piexif.GPSIFD.GPSLatitudeRef)
    lon_raw = gps.get(piexif.GPSIFD.GPSLongitude)
    lon_ref = gps.get(piexif.GPSIFD.GPSLongitudeRef)
    if lat_raw and lat_ref and lon_raw and lon_ref:
        try:
            lat_ref_s = lat_ref.decode() if isinstance(lat_ref, bytes) else str(lat_ref)
            lon_ref_s = lon_ref.decode() if isinstance(lon_ref, bytes) else str(lon_ref)
            lat = _gps_rational_to_decimal(lat_raw, lat_ref_s)
            lon = _gps_rational_to_decimal(lon_raw, lon_ref_s)
            if lat is not None and lon is not None:
                metadata["GPS.Coordinates"] = f"{lat}, {lon}"
        except Exception:
            pass

    return metadata


def _extract_png_meta(path: Path) -> dict[str, str]:
    """Return PNG text chunks and any embedded EXIF as {key: value_str}."""
    metadata: dict[str, str] = {}
    try:
        img = Image.open(path)
        info: dict = img.info or {}
    except Exception:
        return metadata

    for key, val in info.items():
        if key == "exif":
            # Some PNGs embed EXIF in a tEXt chunk
            try:
                exif_dict = piexif.load(val)
                for ifd_name, ifd_data in exif_dict.items():
                    if not isinstance(ifd_data, dict):
                        continue
                    tag_defs = piexif.TAGS.get(ifd_name, {})
                    for tag_id, raw_val in ifd_data.items():
                        tag_name = tag_defs.get(tag_id, {}).get("name", f"Tag_{tag_id:#06x}")
                        metadata[f"EXIF.{tag_name}"] = _decode_value(raw_val)
            except Exception:
                pass
        elif key == "text" and isinstance(val, dict):
            for k, v in val.items():
                metadata[f"Text.{k}"] = str(v)
        elif isinstance(val, (str, int, float)):
            metadata[key] = str(val)
        elif isinstance(val, tuple):
            metadata[key] = str(val)

    return metadata


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class ImageStripper:
    """Strip metadata from JPEG and PNG images."""

    def extract_metadata(self, path: Path) -> dict[str, str]:
        if not HAS_DEPS:
            raise RuntimeError("Pillow and piexif are required: pip install Pillow piexif")

        try:
            img = Image.open(path)
            fmt = img.format
        except Exception:
            return {}

        if fmt == "JPEG":
            return _extract_jpeg_exif(path)
        if fmt == "PNG":
            return _extract_png_meta(path)
        return {}

    def strip(self, path: Path, output_path: Path) -> None:
        """Write a metadata-free copy of *path* to *output_path*."""
        if not HAS_DEPS:
            raise RuntimeError("Pillow and piexif are required: pip install Pillow piexif")

        img = Image.open(path)
        fmt = img.format

        # Build a pixel-only copy — no metadata carried over
        mode = img.mode
        if fmt == "JPEG" and mode in ("RGBA", "LA", "P"):
            img = img.convert("RGB")
            mode = "RGB"

        clean = Image.frombytes(mode, img.size, img.tobytes())

        if fmt == "JPEG":
            clean.save(str(output_path), format="JPEG", quality=95, optimize=True)
        elif fmt == "PNG":
            clean.save(str(output_path), format="PNG", optimize=True)
        else:
            raise ValueError(f"Unsupported image format from Pillow: {fmt}")
