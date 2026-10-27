@echo off
cd /d "%~dp0"
if not exist .venv (
  echo Creating Python virtual environment...
  py -3.11 -m venv .venv
  if errorlevel 1 (
    echo Could not find Python 3.11. Install Python 3.11 64-bit and try again.
    pause
    exit /b 1
  )
)
call .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
echo.
echo Starting AVÉRION API at http://127.0.0.1:8000
echo Keep this window open while using the frontend.
uvicorn main:app --reload
pause
