@echo off
title AVÉRION - AI Document Validation Platform (SIH26261)
color 0B
echo =====================================================================
echo          AVÉRION: AI Document Compliance & Fraud Detection
echo               Smart India Hackathon 2026 (SIH26261)
echo =====================================================================
echo.

cd /d "%~dp0backend"
if not exist .venv (
    echo [ERROR] Virtual environment not found in %~dp0backend\.venv
    pause
    exit /b 1
)

echo [1/3] Activating Python environment...
call .venv\Scripts\activate

echo [2/3] Launching AVÉRION Frontend in default browser...
start "" "%~dp0frontend\index.html"

echo [3/3] Starting FastAPI Backend on http://127.0.0.1:8000 ...
echo [INFO] EasyOCR, OpenCV, and ELA Forensics are active!
echo [INFO] Keep this terminal window open while using AVÉRION.
echo.
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
pause
