# app/virustotal.py
"""
VirusTotal public API integration (limited/free tier friendly).

Flow:
1) Try hash lookup: GET /api/v3/files/{sha256}
2) If not found and file <= 32MB, upload: POST /api/v3/files
3) Poll analysis: GET /api/v3/analyses/{id} until completed (bounded)
4) Return a compact report dict suitable for API responses/logging.

Environment:
- VIRUSTOTAL_API_KEY must be set in your shell (e.g., export VIRUSTOTAL_API_KEY="...")

Notes:
- VirusTotal public API has rate limits (e.g., 4 lookups/min on free tier).
- This module handles common errors with user-friendly messages.
"""
from __future__ import annotations

import os
import asyncio
from typing import Dict, Optional

import httpx
from dotenv import load_dotenv

# Load .env
load_dotenv()

# Get API key
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("VIRUSTOTAL_API_KEY is not set")

VT_BASE = "https://www.virustotal.com/api/v3"
VT_GUI_FILE = "https://www.virustotal.com/gui/file/{sha256}/detection"

VT_MAX_UPLOAD_BYTES = 32 * 1024 * 1024
DEFAULT_POLL_ATTEMPTS = 10
DEFAULT_POLL_SLEEP_SECONDS = 3



def _headers() -> Dict[str, str]:
    return {"x-apikey": VT_API_KEY}


def _compact_report(
    *,
    sha256: str,
    filename: str,
    source: str,
    permalink: str,
    last_analysis_stats: Optional[Dict[str, int]] = None,
    analysis_id: Optional[str] = None,
    message: Optional[str] = None,
) -> Dict:
    return {
        "sha256": sha256,
        "filename": filename,
        "source": source,
        "permalink": permalink,
        "analysis_id": analysis_id,
        "message": message,
        "last_analysis_stats": last_analysis_stats or {},
    }


async def _vt_get_file(sha256: str) -> httpx.Response:
    async with httpx.AsyncClient(timeout=30) as client:
        return await client.get(f"{VT_BASE}/files/{sha256}", headers=_headers())


async def _vt_upload_file(data: bytes, filename: str) -> httpx.Response:
    async with httpx.AsyncClient(timeout=60) as client:
        files = {"file": (filename, data, "application/octet-stream")}
        return await client.post(f"{VT_BASE}/files", headers=_headers(), files=files)


async def _vt_get_analysis(analysis_id: str) -> httpx.Response:
    async with httpx.AsyncClient(timeout=30) as client:
        return await client.get(f"{VT_BASE}/analyses/{analysis_id}", headers=_headers())


async def vt_scan_or_lookup(
    *,
    sha256: str,
    data: bytes,
    filename: str,
    poll_attempts: int = DEFAULT_POLL_ATTEMPTS,
    poll_sleep_seconds: int = DEFAULT_POLL_SLEEP_SECONDS,
) -> Dict:
    """
    Returns a compact VirusTotal report dict:
    {
      sha256, filename, source, permalink, analysis_id, message, last_analysis_stats
    }
    """
    permalink = VT_GUI_FILE.format(sha256=sha256)

    # 1) Hash lookup
    try:
        r = await _vt_get_file(sha256)
    except Exception as e:
        return _compact_report(
            sha256=sha256,
            filename=filename,
            source="virustotal_error",
            permalink=permalink,
            message=f"VirusTotal lookup failed: {type(e).__name__}",
        )

    if r.status_code == 200:
        js = r.json()
        stats = (
            js.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        return _compact_report(
            sha256=sha256,
            filename=filename,
            source="virustotal_lookup",
            permalink=permalink,
            last_analysis_stats=stats,
        )

    # Common auth / rate limit errors
    if r.status_code in (401, 403):
        return _compact_report(
            sha256=sha256,
            filename=filename,
            source="virustotal_error",
            permalink=permalink,
            message="VirusTotal API key unauthorized/forbidden. Verify VIRUSTOTAL_API_KEY.",
        )

    if r.status_code == 429:
        return _compact_report(
            sha256=sha256,
            filename=filename,
            source="virustotal_rate_limited",
            permalink=permalink,
            message="VirusTotal rate limit hit. Try again in ~60 seconds.",
        )

    # Not found: attempt upload if small enough
    if r.status_code == 404:
        if len(data) > VT_MAX_UPLOAD_BYTES:
            return _compact_report(
                sha256=sha256,
                filename=filename,
                source="virustotal_skipped",
                permalink=permalink,
                message="File not found by hash lookup and file is >32MB, so upload was skipped.",
            )

        # 2) Upload for analysis
        up = await _vt_upload_file(data, filename)
        if up.status_code not in (200, 202):
            msg = f"VirusTotal upload failed (HTTP {up.status_code})."
            try:
                msg += f" {up.json()}"
            except Exception:
                pass
            return _compact_report(
                sha256=sha256,
                filename=filename,
                source="virustotal_error",
                permalink=permalink,
                message=msg,
            )

        up_js = up.json()
        analysis_id = up_js.get("data", {}).get("id")

        if not analysis_id:
            return _compact_report(
                sha256=sha256,
                filename=filename,
                source="virustotal_error",
                permalink=permalink,
                message="VirusTotal upload succeeded but analysis id was missing.",
            )

        # 3) Poll analysis (bounded)
        for _ in range(max(1, poll_attempts)):
            a = await _vt_get_analysis(analysis_id)
            if a.status_code == 200:
                a_js = a.json()
                status = a_js.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    # after completion, file report should exist
                    r2 = await _vt_get_file(sha256)
                    if r2.status_code == 200:
                        js2 = r2.json()
                        stats2 = (
                            js2.get("data", {})
                            .get("attributes", {})
                            .get("last_analysis_stats", {})
                        )
                        return _compact_report(
                            sha256=sha256,
                            filename=filename,
                            source="virustotal_upload",
                            permalink=permalink,
                            analysis_id=analysis_id,
                            last_analysis_stats=stats2,
                        )
                    # If still not available, return pending with analysis id.
                    return _compact_report(
                        sha256=sha256,
                        filename=filename,
                        source="virustotal_pending",
                        permalink=permalink,
                        analysis_id=analysis_id,
                        message="Analysis completed but file report not yet available by hash.",
                    )
            await asyncio.sleep(poll_sleep_seconds)

        return _compact_report(
            sha256=sha256,
            filename=filename,
            source="virustotal_pending",
            permalink=permalink,
            analysis_id=analysis_id,
            message="VirusTotal analysis still in progress. Try again later.",
        )

    # Other statuses
    return _compact_report(
        sha256=sha256,
        filename=filename,
        source="virustotal_error",
        permalink=permalink,
        message=f"Unexpected VirusTotal response (HTTP {r.status_code}).",
    )
