"""
Office document metadata stripper for DOCX, XLSX, and PPTX files.

All three formats are ZIP archives following the OOXML standard.
Metadata lives in two XML files inside the archive:

  docProps/core.xml  — author, last-modified-by, creation/modification timestamps,
                       revision, title, subject, description, keywords, category
  docProps/app.xml   — application name, company, manager, app version

We rewrite the archive in-place (or to a new path), replacing those two files
with minimal empty equivalents while preserving every other entry untouched.
"""

from __future__ import annotations

import io
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# Minimal replacement XML templates (empty but schema-valid)
# ---------------------------------------------------------------------------

_EMPTY_CORE_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties
  xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:dcmitype="http://purl.org/dc/dcmitype/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
"""

_EMPTY_APP_XML = """\
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"/>
"""

# Namespaces used in core.xml for parsing
_CORE_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}

# Namespace used in app.xml
_APP_NS = {
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def _parse_core_xml(raw: bytes) -> dict[str, str]:
    """Extract core properties from docProps/core.xml as {field: value}."""
    metadata: dict[str, str] = {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return metadata

    for child in root:
        # Strip namespace URI, keep local name
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child.text and child.text.strip():
            metadata[f"core.{local}"] = child.text.strip()

    return metadata


def _parse_app_xml(raw: bytes) -> dict[str, str]:
    """Extract extended (app) properties from docProps/app.xml as {field: value}."""
    metadata: dict[str, str] = {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return metadata

    for child in root:
        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if child.text and child.text.strip():
            metadata[f"app.{local}"] = child.text.strip()

    return metadata


class OfficeStripper:
    """Strip metadata from OOXML Office documents (DOCX, XLSX, PPTX)."""

    def extract_metadata(self, path: Path) -> dict[str, str]:
        metadata: dict[str, str] = {}
        try:
            with zipfile.ZipFile(path, "r") as zf:
                names = zf.namelist()
                if "docProps/core.xml" in names:
                    metadata.update(_parse_core_xml(zf.read("docProps/core.xml")))
                if "docProps/app.xml" in names:
                    metadata.update(_parse_app_xml(zf.read("docProps/app.xml")))
        except (zipfile.BadZipFile, KeyError, OSError):
            pass
        return metadata

    def strip(self, path: Path, output_path: Path) -> None:
        """Rewrite the Office archive with empty core.xml and app.xml."""
        buf = io.BytesIO()

        with zipfile.ZipFile(path, "r") as zf_in:
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_out:
                for item in zf_in.infolist():
                    name = item.filename

                    if name == "docProps/core.xml":
                        zf_out.writestr(item, _EMPTY_CORE_XML.encode("utf-8"))
                    elif name == "docProps/app.xml":
                        zf_out.writestr(item, _EMPTY_APP_XML.encode("utf-8"))
                    else:
                        # Copy every other entry verbatim
                        zf_out.writestr(item, zf_in.read(name))

        output_path.write_bytes(buf.getvalue())
