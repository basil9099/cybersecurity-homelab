"""
PDF metadata stripper.

Uses pikepdf to:
  - Read the document info dictionary (/Info) and XMP metadata stream
  - Wipe both clean while preserving the rest of the document intact
"""

from __future__ import annotations

from pathlib import Path

try:
    import pikepdf

    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False


# Fields in the /Info dictionary that identify the author / tool chain
_INFO_FIELDS = [
    "/Title",
    "/Author",
    "/Subject",
    "/Keywords",
    "/Creator",
    "/Producer",
    "/CreationDate",
    "/ModDate",
    "/Trapped",
]

# XMP namespace prefixes that commonly carry identity / timestamps
_XMP_NAMESPACES = [
    "dc:",       # Dublin Core
    "xmp:",      # XMP basic
    "xmpMM:",    # XMP Media Management
    "pdf:",      # PDF namespace
    "pdfaid:",   # PDF/A identification
    "prism:",    # Publishing Requirements for Industry Standard Metadata
]


class PDFStripper:
    """Strip metadata from PDF files using pikepdf."""

    def extract_metadata(self, path: Path) -> dict[str, str]:
        if not HAS_DEPS:
            raise RuntimeError("pikepdf is required: pip install pikepdf")

        metadata: dict[str, str] = {}
        try:
            with pikepdf.open(path) as pdf:
                # --- /Info dictionary ---
                info = pdf.docinfo
                for key in info:
                    try:
                        val = info[key]
                        metadata[str(key)] = str(val)
                    except Exception:
                        pass

                # --- XMP stream ---
                try:
                    with pdf.open_metadata() as xmp:
                        for ns_key in xmp:
                            try:
                                metadata[f"XMP.{ns_key}"] = str(xmp[ns_key])
                            except Exception:
                                pass
                except Exception:
                    pass

        except Exception:
            pass

        return metadata

    def strip(self, path: Path, output_path: Path) -> None:
        """Write a metadata-free copy of *path* to *output_path*."""
        if not HAS_DEPS:
            raise RuntimeError("pikepdf is required: pip install pikepdf")

        with pikepdf.open(path, allow_overwriting_input=True) as pdf:
            # Clear the /Info dictionary
            with pdf.open_metadata() as xmp:
                xmp.clear()

            # Remove all /Info entries individually (pikepdf keeps the dict object)
            info = pdf.docinfo
            for key in list(info.keys()):
                try:
                    del info[key]
                except Exception:
                    pass

            pdf.save(str(output_path))
