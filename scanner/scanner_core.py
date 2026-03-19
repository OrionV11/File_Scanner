import asyncio
import sys
import os
import csv
import hashlib
from pathlib import Path

from .virustotal import vt_scan_or_lookup
from .em_demo import export_report

MAX_UPLOAD_MB = 16
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "py", "csv"}
SIGNATURE_FILE = Path(__file__).parent / "virus_signatures.csv"


def load_signatures():
    if not SIGNATURE_FILE.exists():
        return []

    signatures = []
    with SIGNATURE_FILE.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                signatures.append(row[0].strip())
    return signatures


def scan_for_signatures(data: bytes):
    text = data.decode(errors="ignore")
    return [sig for sig in load_signatures() if sig in text]


def scan_file_flask(filepath: str):
    with open(filepath, "rb") as f:
        data = f.read()

    filename = Path(filepath).name
    size_bytes = len(data)

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        return {
            "status": "rejected",
            "reason": "Unsupported file type"
        }

    if size_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        return {
            "status": "rejected",
            "reason": "File too large"
        }

    sha256 = hashlib.sha256(data).hexdigest()
    hits = scan_for_signatures(data)
    local_status = "infected" if hits else "clean"

    report_path = filepath + "_report.txt"
    export_report(filepath, sha256, local_status, output_path=report_path)
    try:
        vt_result = asyncio.run(
            vt_scan_or_lookup(
                sha256=sha256,
                data=data,
                filename=filename
            )
        )
    except Exception as e:
        vt_result = {"error": str(e)}

    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "local_scan": local_status,
        "signatures": hits,
        "virustotal": vt_result
    }
