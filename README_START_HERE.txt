AVÉRION SIH26261 - ALL-IN-ONE STARTER PACKAGE
=============================================

WHAT IS INCLUDED
- frontend/index.html: a working minimal dashboard with image upload and actual OCR results
- backend/main.py: FastAPI backend that runs EasyOCR and basic image checks
- backend/requirements.txt: Python dependencies
- backend/start_backend.bat: Windows helper to install dependencies and start the API

IMPORTANT
This is a starter prototype, not the complete SIH solution yet.
It does real OCR, but does NOT authenticate a document or prove whether it is genuine.
It does not yet implement cross-document matching, real tamper detection, duplicate detection,
a trained ML model, or jurisdiction-specific regulatory rules. Results stay REVIEW / NOT_VERIFIED.

SETUP ON WINDOWS
1. Install Python 3.11 64-bit. During installation, enable "Add Python to PATH" if offered.
2. Extract this ZIP to a normal folder, e.g. C:\Users\YourUser\AVERION_SIH26261.
3. Open the extracted folder, then open backend.
4. Double-click start_backend.bat.
   - First installation can take several minutes and download OCR model files.
   - Keep the terminal window open.
   - If PowerShell execution policy is not involved, this .bat file should work from Explorer.
5. Open frontend/index.html in Chrome or Edge.
6. Choose a clear PNG/JPG with printed text and click "Extract text with OCR".
7. The first OCR run can be slow while EasyOCR loads/downloads its model.

API TEST
- Health: http://127.0.0.1:8000/api/health
- Interactive API docs: http://127.0.0.1:8000/docs

TROUBLESHOOTING
- "Python 3.11 not found": install Python 3.11 64-bit, then reopen the terminal.
- Installation error: copy the complete final error from the backend terminal and ask for help.
- OCR download failure: check internet access and retry.
- Browser says backend not connected: ensure start_backend.bat is still running.
- This starter currently accepts PNG/JPEG/WebP images up to 15 MB, not PDFs.

PRIVACY / SECURITY
Use synthetic sample documents only while testing. Do not upload sensitive real identity or financial documents.
The CORS policy is open for local prototyping; restrict it before deployment.
Do not deploy this starter publicly as-is.
