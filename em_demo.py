import hashlib
import os
from datetime import datetime

# ----------------------------
# EMF1: File Integrity Check
# ----------------------------
def calculate_file_hash(filepath):
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            chunk = f.read(4096)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(4096)
        return hasher.hexdigest()
    except FileNotFoundError:
        return None


# ----------------------------
# EMF2: Scan File (Simple Keyword Scan)
# ----------------------------
def scan_file(filepath):
    suspicious_keywords = ["virus", "malware", "attack", "worm"]
    scan_result = "Clean"

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read().lower()
            for keyword in suspicious_keywords:
                if keyword in content:
                    scan_result = f"Suspicious content detected: '{keyword}'"
                    break
    except:
        scan_result = "Unable to scan (file may be binary or unreadable)"

    return scan_result


# ----------------------------
# EMF4: Export Scan Report
# ----------------------------
def export_report(filepath, file_hash, scan_result, output_path="scan_report.txt"):
    try:
        with open(output_path, "w") as report:
            report.write("SCAN REPORT\n")
            report.write("-------------------------\n")
            report.write(f"file_scanned: {filepath}\n")
            report.write(f"scan_time: {datetime.now()}\n")
            report.write(f"integrity_hash: {file_hash}\n")
            report.write(f"scan_result: {scan_result}\n")
        return True
    except:
        return False


# ----------------------------
# MAIN PROGRAM (User Interaction)
# ----------------------------
def main():
    print("=== EM Functional Requirements Demo (EMF1, EMF2, EMF4) ===")
    filepath = input("Enter the path of the file to scan: ")

    if not os.path.exists(filepath):
        print("Error: File not found.")
        return

    # EMF1: Integrity Check
    print("\n[1] Performing file integrity check...")
    file_hash = calculate_file_hash(filepath)
    if file_hash is None:
        print("Integrity check failed.")
        return
    print("SHA-256 Hash:", file_hash)

    # EMF2: File Scan
    print("\n[2] Scanning file...")
    scan_result = scan_file(filepath)
    print("Scan Result:", scan_result)

    # EMF4: Export Report
    print("\n[3] Exporting scan report...")
    if export_report(filepath, file_hash, scan_result):
        print("Report exported as 'scan_report.txt'")
    else:
        print("Failed to export report.")

    print("\n--- EM Requirements Completed (EMF1, EMF2, EMF4) ---")


if __name__ == "__main__":
    main()
