"""
Test script for application.py's file scanner endpoints.
Uses the EICAR test string — a harmless, industry-standard string
that antivirus engines are designed to flag as malicious.
Safe to create and store on your machine.
"""

import requests
import tempfile
import os
import json

BASE_URL = "http://127.0.0.1:5000"

# -------------------------------------------------------------------
# EICAR test string — completely harmless, universally recognized
# https://www.eicar.org/download-anti-malware-testfile/
# -------------------------------------------------------------------
EICAR_STRING = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def print_result(label: str, response: requests.Response):
    print(f"\n{'='*50}")
    print(f"  {label}")
    print(f"  Status : {response.status_code}")
    try:
        print(f"  Body   : {json.dumps(response.json(), indent=2)}")
    except Exception:
        print(f"  Body   : {response.text[:300]}")
    print(f"{'='*50}")


# -------------------------------------------------------------------
# 1. Upload a clean (empty) file — should NOT be quarantined
# -------------------------------------------------------------------
def test_clean_upload():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"This is a perfectly normal text file.")
        tmp_path = f.name

    with open(tmp_path, "rb") as f:
        resp = requests.post(f"{BASE_URL}/upload", files={"files": ("clean.txt", f, "text/plain")})

    os.remove(tmp_path)
    print_result("Clean file upload", resp)
    return resp.json()


# -------------------------------------------------------------------
# 2. Upload an EICAR test file — scanner should flag it
# -------------------------------------------------------------------
def test_eicar_upload():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write(EICAR_STRING)
        tmp_path = f.name

    with open(tmp_path, "rb") as f:
        resp = requests.post(f"{BASE_URL}/upload", files={"files": ("eicar_test.txt", f, "text/plain")})

    os.remove(tmp_path)
    print_result("EICAR test file upload", resp)
    return resp.json()


# -------------------------------------------------------------------
# 3. List all uploaded files
# -------------------------------------------------------------------
def test_list_files():
    resp = requests.get(f"{BASE_URL}/files")
    print_result("List files", resp)
    return resp.json()


# -------------------------------------------------------------------
# 4. List quarantined files
# -------------------------------------------------------------------
def test_list_quarantine():
    resp = requests.get(f"{BASE_URL}/files")
    print(f"Status code: {resp.status_code}")
    print(f"Response text: {repr(resp.text)}")
    return resp.json()


# -------------------------------------------------------------------
# 5. Delete a specific file by stored name
# -------------------------------------------------------------------
def test_delete_file(stored_name: str):
    resp = requests.delete(f"{BASE_URL}/delete/{stored_name}")
    print_result(f"Delete file: {stored_name}", resp)


# -------------------------------------------------------------------
# 6. Upload with no files attached — should return 400
# -------------------------------------------------------------------
def test_no_file_upload():
    resp = requests.post(f"{BASE_URL}/upload", data={})
    print_result("Upload with no files (expect 400)", resp)


# -------------------------------------------------------------------
# 7. Upload a file with an invalid/empty filename
# -------------------------------------------------------------------
def test_invalid_filename():
    resp = requests.post(
        f"{BASE_URL}/upload",
        files={"files": ("", b"some content", "text/plain")},
    )
    print_result("Upload with empty filename (expect rejection)", resp)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    print("\n Starting scanner tests against", BASE_URL)
    print("Make sure your Flask app is running before proceeding.\n")

    test_no_file_upload()
    test_invalid_filename()

    clean_result = test_clean_upload()
    eicar_result = test_eicar_upload()

    test_list_files()
    test_list_quarantine()

    # Clean up the clean file if it was stored successfully
    for f in clean_result.get("files", []):
        stored = f.get("stored_as")
        if stored:
            test_delete_file(stored)

    print("\n All tests complete.")
