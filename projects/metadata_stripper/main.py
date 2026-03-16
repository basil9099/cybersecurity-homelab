#!/usr/bin/env python3
"""
Metadata Stripper
=================
Privacy-focused CLI that strips sensitive metadata from images, PDFs, and
Office documents. Concurrent processing via ThreadPoolExecutor handles
1 000+ files efficiently.

Strips:
  - JPEG / PNG  — GPS coordinates, camera make/model, timestamps, software
  - PDF         — author, creator, producer, creation/modification dates, XMP
  - DOCX / XLSX / PPTX — author, last-modified-by, company, revision, timestamps

Usage:
    python main.py photo.jpg document.pdf report.docx
    python main.py --dir ./uploads --dry-run
    python main.py --dir ./uploads --workers 8 --verify
    python main.py photo.jpg --output ./clean/
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

from strippers import detect_format, get_stripper, SUPPORTED_FORMATS


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if COLORS else text


def info(msg: str) -> None:
    print(_c("[*]", Fore.CYAN if COLORS else "") + f" {msg}")


def success(msg: str) -> None:
    print(_c("[+]", Fore.GREEN if COLORS else "") + f" {msg}")


def warn(msg: str) -> None:
    print(_c("[!]", Fore.YELLOW if COLORS else "") + f" {msg}")


def error(msg: str) -> None:
    print(_c("[-]", Fore.RED if COLORS else "") + f" {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="metadata-stripper",
        description=(
            "Strip sensitive metadata from JPEG, PNG, PDF, DOCX, XLSX, and PPTX files.\n"
            "Format detection uses file signatures (magic bytes), not extensions."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py photo.jpg
  python main.py photo.jpg document.pdf report.docx --verify
  python main.py --dir ./uploads --dry-run
  python main.py --dir ./uploads --workers 8 --output ./clean/
  python main.py --dir ./uploads --recursive
        """,
    )

    parser.add_argument(
        "files",
        nargs="*",
        metavar="FILE",
        help="One or more files to process",
    )
    parser.add_argument(
        "--dir",
        metavar="DIRECTORY",
        help="Process all supported files in a directory",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Recurse into subdirectories when using --dir",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIRECTORY",
        help="Write cleaned files to this directory (default: overwrite originals)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be removed without making any changes",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Show a before/after metadata comparison report after stripping",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        metavar="N",
        help="Number of concurrent worker threads (default: 4)",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def collect_files(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = []

    for f in args.files:
        p = Path(f)
        if not p.exists():
            error(f"File not found: {f}")
        elif not p.is_file():
            error(f"Not a regular file: {f}")
        else:
            paths.append(p)

    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            error(f"Not a directory: {args.dir}")
        else:
            glob = "**/*" if args.recursive else "*"
            for p in sorted(d.glob(glob)):
                if p.is_file():
                    paths.append(p)

    return paths


# ---------------------------------------------------------------------------
# Per-file processing
# ---------------------------------------------------------------------------

def process_file(
    path: Path,
    output_dir: Path | None,
    dry_run: bool,
    verify: bool,
) -> dict:
    """Detect format, extract metadata, and optionally strip it."""

    fmt = detect_format(path)
    if fmt is None:
        return {
            "path": path,
            "format": None,
            "skipped": True,
            "reason": "unsupported format",
        }

    stripper = get_stripper(fmt)

    out_path = (output_dir / path.name) if output_dir else path
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Always capture the before-state
    try:
        before = stripper.extract_metadata(path)
    except Exception as exc:
        return {
            "path": path,
            "format": fmt,
            "skipped": True,
            "reason": f"metadata extraction failed: {exc}",
        }

    if dry_run:
        return {
            "path": path,
            "format": fmt,
            "skipped": False,
            "dry_run": True,
            "before": before,
        }

    # Strip
    try:
        stripper.strip(path, out_path)
    except Exception as exc:
        return {
            "path": path,
            "format": fmt,
            "skipped": False,
            "dry_run": False,
            "success": False,
            "error": str(exc),
            "before": before,
            "after": {},
        }

    after: dict[str, str] = {}
    if verify:
        try:
            after = stripper.extract_metadata(out_path)
        except Exception:
            pass

    return {
        "path": path,
        "format": fmt,
        "skipped": False,
        "dry_run": False,
        "success": True,
        "before": before,
        "after": after,
    }


# ---------------------------------------------------------------------------
# Output / reporting
# ---------------------------------------------------------------------------

def _col(text: str, width: int) -> str:
    """Left-justify *text* within *width* characters."""
    return text[:width].ljust(width)


def print_dry_run_result(result: dict) -> None:
    path = result["path"]
    fmt = result["format"]
    before: dict[str, str] = result.get("before", {})

    label = _c("DRY RUN", Fore.YELLOW if COLORS else "")
    count_str = _c(str(len(before)), Fore.YELLOW if COLORS else "")
    print(f"  [{label}] {_col(path.name, 35)} {_col(fmt, 6)} {count_str} field(s) would be removed")

    if before:
        for key, val in before.items():
            val_display = val[:70] + "…" if len(val) > 70 else val
            print(f"            {_c('–', Fore.YELLOW if COLORS else '')} {key}: {val_display}")


def print_strip_result(result: dict) -> None:
    path = result["path"]
    fmt = result["format"]

    if result.get("success"):
        count = len(result.get("before", {}))
        count_str = _c(str(count), Fore.GREEN if COLORS else "")
        success(f"{_col(path.name, 35)} {_col(fmt, 6)} {count_str} field(s) stripped")
    else:
        error(f"{_col(path.name, 35)} {_col(fmt, 6)} FAILED — {result.get('error', 'unknown error')}")


def print_verification_report(results: list[dict]) -> None:
    stripped_results = [r for r in results if not r.get("skipped") and r.get("success")]
    if not stripped_results:
        return

    divider = _c("─" * 66, Fore.CYAN if COLORS else "")
    print()
    print(_c("Verification Report", Fore.CYAN if COLORS else ""))
    print(divider)

    for result in stripped_results:
        path = result["path"]
        fmt = result["format"]
        before: dict[str, str] = result.get("before", {})
        after: dict[str, str] = result.get("after", {})

        print()
        print(_c(f"  {path.name}  ({fmt})", Fore.WHITE if COLORS else ""))

        if not before:
            print("    No metadata found in original file.")
            continue

        print(f"    {'BEFORE':<35}  AFTER")
        print(f"    {'──────':<35}  ─────")

        for key in before:
            val = before[key]
            val_display = val[:30] + "…" if len(val) > 30 else val
            after_val = after.get(key, "")
            after_display = (
                _c(after_val[:30], Fore.RED if COLORS else "")
                if after_val
                else _c("[removed]", Fore.GREEN if COLORS else "")
            )
            print(f"    {_c(f'{key}: {val_display}', Fore.WHITE if COLORS else ''):<35}  {after_display}")

        if after:
            remaining = set(after) - set(before)
            for key in remaining:
                print(f"    {'(new)':<35}  {_c(f'{key}: {after[key]}', Fore.RED if COLORS else '')}")

    print()
    print(divider)


def print_summary(results: list[dict], dry_run: bool) -> None:
    total = len(results)
    skipped = sum(1 for r in results if r.get("skipped"))
    processed = total - skipped
    succeeded = sum(1 for r in results if not r.get("skipped") and r.get("success", False))
    failed = processed - succeeded
    fields_stripped = sum(len(r.get("before", {})) for r in results if r.get("success"))

    print()
    if dry_run:
        fields_label = sum(len(r.get("before", {})) for r in results if not r.get("skipped"))
        print(
            _c(f"Dry-run complete. ", Fore.CYAN if COLORS else "")
            + f"{total} file(s) scanned | {skipped} skipped | "
            + _c(f"{fields_label} field(s) would be removed", Fore.YELLOW if COLORS else "")
        )
    else:
        status = _c("Complete.", Fore.GREEN if COLORS else "")
        print(
            f"{status}  {processed} processed | "
            + _c(f"{succeeded} succeeded", Fore.GREEN if COLORS else "")
            + f" | "
            + (_c(f"{failed} failed", Fore.RED if COLORS else "") if failed else f"{failed} failed")
            + f" | {skipped} skipped | "
            + _c(f"{fields_stripped} field(s) stripped", Fore.GREEN if COLORS else "")
        )
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    if not args.files and not args.dir:
        error("Provide at least one FILE or use --dir.")
        sys.exit(1)

    paths = collect_files(args)
    if not paths:
        warn("No files found to process.")
        sys.exit(0)

    output_dir = Path(args.output) if args.output else None

    # Banner
    print()
    print(_c("=" * 62, Fore.CYAN if COLORS else ""))
    print(_c("  Metadata Stripper", Fore.CYAN if COLORS else ""))
    print(_c("=" * 62, Fore.CYAN if COLORS else ""))
    mode = "dry-run" if args.dry_run else ("strip + verify" if args.verify else "strip")
    print(f"  Files   : {len(paths)}")
    print(f"  Mode    : {mode}")
    print(f"  Workers : {args.workers}")
    if output_dir:
        print(f"  Output  : {output_dir}")
    print(_c("=" * 62, Fore.CYAN if COLORS else ""))
    print()
    info(f"Processing {len(paths)} file(s) with {args.workers} worker(s)…")
    print()

    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_path = {
            executor.submit(process_file, p, output_dir, args.dry_run, args.verify): p
            for p in paths
        }
        for future in as_completed(future_to_path):
            result = future.result()
            results.append(result)

            if result.get("skipped"):
                reason = result.get("reason", "unknown")
                # Only warn about skipped files if there were explicitly named files
                if result["path"] in [Path(f) for f in args.files]:
                    warn(f"{result['path'].name:<35} skipped ({reason})")
            elif result.get("dry_run"):
                print_dry_run_result(result)
            else:
                print_strip_result(result)

    if args.verify and not args.dry_run:
        print_verification_report(results)

    print_summary(results, args.dry_run)


if __name__ == "__main__":
    main()
