import asyncio
import csv
import hashlib
from pathlib import Path
from dotenv import load_dotenv


from .virustotal import vt_scan_or_lookup
from .em_demo import export_report

load_dotenv()
MAX_UPLOAD_MB = 16
CHUNK_SIZE = 4096  # LDF5: buffered I/O in 4KB chunks
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "py", "csv", "doc", "docx", "avi","mp3","mp4","zip","rar","xls","xlsx","wav", "mov", "gif"}
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


def scan_for_signatures_from_text(text: str):
    return [sig for sig in load_signatures() if sig in text]


def process_file_in_chunks(filepath: str):
    """
    LDF5: Read file using buffered I/O (4KB chunks) instead of loading it all at once.
    Also prints progress to terminal for demo/testing evidence.
    """
    filename = Path(filepath).name
    sha256 = hashlib.sha256()
    total_size = 0
    chunks = []
    text_parts = []

    print(f"[LDF5] Starting buffered read for: {filename}")
    print(f"[LDF5] Chunk size: {CHUNK_SIZE} bytes")

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            total_size += len(chunk)
            sha256.update(chunk)
            chunks.append(chunk)
            text_parts.append(chunk.decode(errors="ignore"))

            print(f"[LDF5] Read chunk: {len(chunk)} bytes | total so far: {total_size} bytes")

            # Early reject if file grows beyond limit
            if total_size > MAX_UPLOAD_MB * 1024 * 1024:
                print(f"[LDF1/LDF5] File exceeded max size during buffered read: {total_size} bytes")
                return {
                    "filename": filename,
                    "size_bytes": total_size,
                    "sha256": None,
                    "data": None,
                    "text": None,
                    "rejected": True,
                    "reason": "File too large",
                }

    file_bytes = b"".join(chunks)
    full_text = "".join(text_parts)
    digest = sha256.hexdigest()

    print(f"[LDF5] Finished buffered read for: {filename}")
    print(f"[LDF5] Final size: {total_size} bytes")
    print(f"[LDF5] SHA256: {digest}")

    return {
        "filename": filename,
        "size_bytes": total_size,
        "sha256": digest,
        "data": file_bytes,
        "text": full_text,
        "rejected": False,
        "reason": None,
    }


def scan_file_flask(filepath: str):
    """
    Flask-compatible scanner wrapper with:
    - LDF1: size/type validation
    - LDF2: local signature scan + VirusTotal
    - LDF3: structured report + export_report
    - LDF5: buffered I/O + terminal output
    """
    filename = Path(filepath).name
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    print("=" * 70)
    print(f"[SCAN] Incoming file: {filename}")

    # Extension check first
    if ext not in ALLOWED_EXT:
        print(f"[LDF1/LDF4] Rejected unsupported extension: .{ext}")
        return {
            "status": "rejected",
            "reason": "Unsupported file type",
        }

    # Buffered file processing (LDF5)
    processed = process_file_in_chunks(filepath)

    if processed["rejected"]:
        print(f"[LDF1] Rejected oversized file: {filename}")
        return {
            "status": "rejected",
            "reason": processed["reason"],
        }

    data = processed["data"]
    size_bytes = processed["size_bytes"]
    sha256 = processed["sha256"]
    full_text = processed["text"]

    # Local signature scan
    hits = scan_for_signatures_from_text(full_text)
    local_status = "infected" if hits else "clean"

    print(f"[LDF2] Local scan result: {local_status}")
    print(f"[LDF2] Signatures found: {hits if hits else 'None'}")

    # Keep your partner's exported report feature
    report_path = filepath + "_report.txt"
    export_report(filepath, sha256, local_status, output_path=report_path)

    # VirusTotal lookup/upload
    try:
        vt_result = asyncio.run(
            vt_scan_or_lookup(
                sha256=sha256,
                data=data,
                filename=filename,
            )
        )
        print(f"[LDF3] VirusTotal source: {vt_result.get('source')}")
        print(f"[LDF3] VirusTotal message: {vt_result.get('message')}")
        print(f"[LDF3] VirusTotal stats: {vt_result.get('last_analysis_stats')}")
    except Exception as e:
        vt_result = {"error": str(e)}
        print(f"[LDF3] VirusTotal error: {e}")

    result = {
        "filename": filename,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "local_scan": local_status,
        "signatures": hits,
        "virustotal": vt_result,
    }

    print(f"[SCAN RESULT] {result}")
    print("=" * 70)

    return result
