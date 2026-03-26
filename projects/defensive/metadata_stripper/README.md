# Metadata Stripper

A privacy-focused CLI that permanently removes sensitive metadata from images, PDFs, and Office documents before sharing or publishing them.

---

## What It Removes

| Format | Fields Stripped |
|---|---|
| **JPEG** | GPS coordinates, camera make/model, timestamps, software, artist, copyright, all EXIF IFDs |
| **PNG** | Text chunks (tEXt/iTXt/zTXt), embedded EXIF, creation time, comment blocks |
| **PDF** | Author, title, subject, keywords, creator, producer, creation/modification dates, XMP metadata stream |
| **DOCX / XLSX / PPTX** | Author, last-modified-by, company, manager, revision number, creation/modification timestamps, application name, app version |

> **Smart detection** — format identification uses file magic bytes (signatures), not file extensions, so renamed or mislabelled files are handled correctly.

---

## Requirements

```bash
pip install -r requirements.txt
```

| Package | Purpose |
|---|---|
| `Pillow` | Open and re-encode JPEG / PNG images |
| `piexif` | Structured EXIF tag extraction for JPEG |
| `pikepdf` | Read and rewrite PDF metadata |
| `colorama` | Coloured terminal output (optional) |

---

## Usage

```bash
# Strip a single file (overwrites in place)
python main.py photo.jpg

# Strip multiple files
python main.py photo.jpg document.pdf report.docx

# Preview what would be removed without making changes
python main.py --dir ./uploads --dry-run

# Strip and show a before/after verification report
python main.py photo.jpg --verify

# Write cleaned files to a separate directory (preserves originals)
python main.py --dir ./uploads --output ./clean/

# Process a directory recursively with 8 workers
python main.py --dir ./uploads --recursive --workers 8

# Combine options
python main.py --dir ./uploads --output ./clean/ --verify --workers 8
```

### All options

| Flag | Default | Description |
|---|---|---|
| `FILE [FILE …]` | — | One or more files to process |
| `--dir DIRECTORY` | — | Process all supported files in a directory |
| `--recursive` / `-r` | off | Recurse into sub-directories (requires `--dir`) |
| `--output DIRECTORY` / `-o` | overwrite | Write cleaned files here instead of overwriting originals |
| `--dry-run` | off | Show what would be removed without making changes |
| `--verify` | off | Print a before/after field comparison after stripping |
| `--workers N` / `-w` | `4` | Number of concurrent worker threads |

---

## Example output

```
==============================================================
  Metadata Stripper
==============================================================
  Files   : 3
  Mode    : strip + verify
  Workers : 4
==============================================================

[*] Processing 3 file(s) with 4 worker(s)…

[+] photo.jpg                           JPEG   12 field(s) stripped
[+] document.pdf                        PDF     8 field(s) stripped
[+] report.docx                         DOCX    6 field(s) stripped

Verification Report
──────────────────────────────────────────────────────────────────

  photo.jpg  (JPEG)
    BEFORE                               AFTER
    ──────                               ─────
    GPS.GPSLatitudeRef: N                [removed]
    GPS.GPSLatitude: ((37, 1), (46, 1)…  [removed]
    GPS.Coordinates: 37.7749, -122.4194  [removed]
    0th.Make: Apple                      [removed]
    0th.Model: iPhone 14                 [removed]
    0th.Software: iOS 17.2               [removed]
    Exif.DateTimeOriginal: 2024:01:15 …  [removed]
    ...

──────────────────────────────────────────────────────────────────

Complete.  3 processed | 3 succeeded | 0 failed | 0 skipped | 26 field(s) stripped
```

---

## Architecture

```
metadata_stripper/
├── main.py                    # CLI entry point — arg parsing, concurrency, output
├── requirements.txt
└── strippers/
    ├── __init__.py            # Package exports and stripper dispatch
    ├── detector.py            # Magic-byte format detection
    ├── image_stripper.py      # JPEG / PNG (Pillow + piexif)
    ├── pdf_stripper.py        # PDF (pikepdf)
    └── office_stripper.py     # DOCX / XLSX / PPTX (ZIP/OOXML)
```

### Design notes

- **Concurrent processing** — `ThreadPoolExecutor` lets the tool handle thousands of files efficiently. I/O-bound work (reading and rewriting files) benefits directly from threading.
- **Magic byte detection** — the first 8 bytes of each file are compared against known signatures before any processing begins. ZIP-based Office files are further differentiated by inspecting `[Content_Types].xml` inside the archive.
- **Non-destructive output** — use `--output ./clean/` to write stripped copies alongside the originals, keeping the originals intact.
- **Dry-run mode** — lists every metadata field that *would* be removed per file without touching the files. Useful before processing a large batch.
- **JPEG quality** — stripping requires re-encoding; files are saved at quality 95 to minimise visible degradation. The trade-off between thoroughness and quality is intentional for a privacy tool.
- **Office stripping** — OOXML archives are rewritten with empty `docProps/core.xml` and `docProps/app.xml` files; all other content (text, styles, images) is copied verbatim.

---

## Lab integration

Designed to sanitise files before exfiltration analysis, evidence packaging, or publishing screenshots and documents from the lab environment. Pair with the OSINT Framework project to verify that stripped files no longer leak identifiable metadata.
