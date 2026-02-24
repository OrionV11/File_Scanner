# EM Functional Requirements – README (Emmanuel Moonga)

This README explains the implementation and testing of my assigned functional requirements for the EM portion of the project. The updated code includes EMF1, EMF2, and EMF4. It performs file integrity checks, scans files for suspicious content, and exports a report containing the scan results.

## Functional Requirements Implemented

### EMF1 – File Integrity Check
The program uses SHA-256 hashing to calculate a unique fingerprint for any file the user selects. This verifies file integrity and allows detection of tampering or changes.

### EMF2 – File Scanning
The script scans the file contents for suspicious keywords such as:
- virus
- malware
- attack
- worm

If any keyword is found, the file is marked as suspicious. If the file cannot be read (binary files), the program safely returns:  
"Unable to scan (file may be binary or unreadable)."

### EMF4 – Export Scan Report
After scanning, the program creates a downloadable file named `scan_report.txt` that includes:
- File scanned path  
- Scan timestamp  
- SHA-256 integrity hash  
- Final scan result (Clean / Suspicious / Unable to scan)

This verifies the report export functionality.

## How to Run and Test the Program in VS Code

1. Make sure Python is installed:
   python --version

2. Create a new Python file in VS Code:
   em_demo.py  
   Paste the full EM code into this file.

3. Create a test file to scan, for example:
   badfile.txt  
   Add text such as:  
   "This file contains a virus."

4. Open the VS Code terminal:
   Ctrl + `

5. Run the program:
   python em_demo.py

6. When asked for the file path, enter the full path to the file you want to scan. Example:
   C:\Users\yvnga\badfile.txt

7. The program will:
   - Compute the file's integrity hash  
   - Scan the file for suspicious keywords  
   - Generate and save a scan report as `scan_report.txt`

## Example Test Result
When scanning a file containing the word "virus," the program successfully detected the suspicious content and exported the results into `scan_report.txt`. This confirms the correct operation of EMF1, EMF2, and EMF4.
