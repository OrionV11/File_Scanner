import csv
import hashlib
from pathlib import Path
from typing import List, Tuple

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from .database import get_db
from . import models, schemas
from .virustotal import vt_scan_or_lookup
from .logging_utils import log_scan_event
from .auth import get_current_user as get_active_user

router = APIRouter(tags=["scanner"])

MAX_UPLOAD_MB = 16
CHUNK_SIZE = 4096  # LDF5 buffered I/O
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "py", "csv"}
SIGNATURE_FILE = Path(__file__).parent / "virus_signatures.csv"


def load_signatures() -> List[str]:
    if not SIGNATURE_FILE.exists():
        return []
    signatures = []
    with SIGNATURE_FILE.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if row:
                signatures.append(row[0].strip())
    return signatures


def scan_for_signatures_from_text(text: str) -> List[str]:
    return [sig for sig in load_signatures() if sig in text]


async def read_upload_in_chunks(file: UploadFile) -> Tuple[bytes, str, int, str]:
    """
    LDF5 buffered I/O for FastAPI uploads.
    Returns: data, full_text, size_bytes, sha256
    """
    sha256 = hashlib.sha256()
    total_size = 0
    chunks = []
    text_parts = []

    print("=" * 70)
    print(f"[LDF5] Starting buffered upload read: {file.filename}")
    print(f"[LDF5] Chunk size: {CHUNK_SIZE} bytes")

    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break

        total_size += len(chunk)

        if total_size > MAX_UPLOAD_MB * 1024 * 1024:
            print(f"[LDF1/LDF5] Upload exceeded max size: {total_size} bytes")
            raise HTTPException(status_code=413, detail="File too large (max 16MB).")

        sha256.update(chunk)
        chunks.append(chunk)
        text_parts.append(chunk.decode(errors="ignore"))

        print(f"[LDF5] Read chunk: {len(chunk)} bytes | total so far: {total_size} bytes")

    data = b"".join(chunks)
    full_text = "".join(text_parts)
    digest = sha256.hexdigest()

    print(f"[LDF5] Finished buffered upload read: {file.filename}")
    print(f"[LDF5] Final size: {total_size} bytes")
    print(f"[LDF5] SHA256: {digest}")

    return data, full_text, total_size, digest


@router.post("/files/scan", response_model=schemas.ScanWithVT)
async def scan_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_active_user),
):
    """
    LDF1–LDF5 combined:
    - LDF1: reject files >16MB and unsupported extensions
    - LDF2: local signature scan + API-based threat intelligence (VirusTotal)
    - LDF3: structured report (local + API) and log scan events
    - LDF4: input validation + availability controls
    - LDF5: buffered I/O for memory-efficient processing
    """

    filename = Path(file.filename).name if file.filename else "uploaded_file"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    print("=" * 70)
    print(f"[SCAN] Incoming file: {filename}")

    if ext not in ALLOWED_EXT:
        print(f"[LDF1/LDF4] Rejected unsupported extension: .{ext}")
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Only approved file types are allowed.",
        )

    # LDF5 buffered processing
    data, full_text, size_bytes, sha256 = await read_upload_in_chunks(file)

    # Local signature scan
    hits = scan_for_signatures_from_text(full_text)
    status_s = "infected" if hits else "clean"
    findings = ", ".join(hits) if hits else "No known signatures detected."

    print(f"[LDF2] Local scan result: {status_s}")
    print(f"[LDF2] Signatures found: {hits if hits else 'None'}")

    # Save to DB
    record = models.Scan(
        user_id=user.id,
        filename=filename,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=size_bytes,
        limit_mb=MAX_UPLOAD_MB,
        sha256=sha256,
        status=status_s,
        findings=findings,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # VirusTotal integration
    vt_report_dict = await vt_scan_or_lookup(sha256=sha256, data=data, filename=filename)
    vt_report = schemas.VirusTotalReport(**vt_report_dict)

    print(f"[LDF3] VirusTotal source: {vt_report_dict.get('source')}")
    print(f"[LDF3] VirusTotal message: {vt_report_dict.get('message')}")
    print(f"[LDF3] VirusTotal stats: {vt_report_dict.get('last_analysis_stats')}")

    # Logging
    log_scan_event(user=user, scan=record, vt_report=vt_report_dict)

    print(f"[SCAN RESULT] filename={filename}, local={status_s}, vt={vt_report_dict.get('source')}")
    print("=" * 70)

    return schemas.ScanWithVT(
        message="File accepted and scanned successfully.",
        scan=schemas.ScanRead.from_orm(record),
        virustotal=vt_report,
    )


@router.get("/scans/report", response_model=schemas.ScanList)
async def get_reports(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_active_user),
):
    scans = (
        db.query(models.Scan)
        .filter(models.Scan.user_id == user.id)
        .order_by(models.Scan.created_at.desc())
        .all()
    )
    return {"scans": [schemas.ScanRead.from_orm(s) for s in scans]}


@router.get("/health")
async def health():
    return {"status": "ok"}