# app/scanner.py
from .virustotal import vt_scan_or_lookup
import asyncio
import hashlib
import csv

from pathlib import Path
from typing import List

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session

from .database import get_db
from . import models, schemas
from .virustotal import vt_scan_or_lookup
from .logging_utils import log_scan_event

# use working JWT user extraction
from .auth import get_current_user as get_active_user

router = APIRouter(tags=["scanner"])

# LDF1: fixed upload limit (per updated assignment)
MAX_UPLOAD_MB = 16

# Allowed file extensions
ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg", "py", "csv"}

# Signature list (local signatures file)
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


def scan_for_signatures(data: bytes) -> List[str]:
    text = data.decode(errors="ignore")
    return [sig for sig in load_signatures() if sig in text]


@router.post("/files/scan", response_model=schemas.ScanWithVT)
async def scan_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_active_user),
):
    """
    LDF1–LDF4 (software) combined:
    - LDF1: Reject files >16MB and unsupported extensions
    - LDF2: Local signature scan + API-based threat intelligence (VirusTotal)
    - LDF3: Return structured scan report (local + API) and log scan events
    - LDF4: Input validation + availability controls (size/extension validation)
    """

    # Validate extension (LDF1)
    filename = Path(file.filename).name if file.filename else "uploaded_file"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Only approved file types are allowed.",
        )

    # Read file
    data = await file.read()
    size_bytes = len(data)

    # Enforce 16MB cap (LDF1)
    if size_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="File too large (max 16MB).",
        )

    # SHA256
    sha256 = hashlib.sha256(data).hexdigest()

    # Local signature scanning (LDF2)
    hits = scan_for_signatures(data)
    status_s = "infected" if hits else "clean"
    findings = ", ".join(hits) if hits else "No known signatures detected."

    # Save to DB (LDF3)
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

    # VirusTotal integration (LDF2/LDF3)
    vt_report_dict = await vt_scan_or_lookup(sha256=sha256, data=data, filename=filename)
    vt_report = schemas.VirusTotalReport(**vt_report_dict)

    # Logging (LDF3)
    log_scan_event(user=user, scan=record, vt_report=vt_report_dict)

    # Response
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
def scan_file_flask(filepath: str):
    """
    Flask-compatible scanner wrapper
    """
    from pathlib import Path

    # Read file
    with open(filepath, "rb") as f:
        data = f.read()

    filename = Path(filepath).name
    size_bytes = len(data)

    # Extension check (LDF1)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        return {
            "status": "rejected",
            "reason": "Unsupported file type"
        }

    # Size check (LDF1)
    if size_bytes > MAX_UPLOAD_MB * 1024 * 1024:
        return {
            "status": "rejected",
            "reason": "File too large"
        }

    # Hash
    sha256 = hashlib.sha256(data).hexdigest()

    # Local scan (LDF2)
    hits = scan_for_signatures(data)
    local_status = "infected" if hits else "clean"

    # VirusTotal (LDF3)
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