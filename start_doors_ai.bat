@echo off
cd /d %~dp0

if not exist .venv\Scripts\python.exe (
    echo [ERROR] Missing .venv. Create it with: python -m venv .venv
    echo [ERROR] Then install dependencies with: .venv\Scripts\python.exe -m pip install -r requirements.txt
    pause
    exit /b 1
)

echo [INFO] Launching Doors AI app...
.venv\Scripts\python.exe app.py

pause
