@echo off
echo ==================================================
echo Starting Vulnerability Scanner System...
echo ==================================================

if exist venv\Scripts\python.exe (
    set PYTHON_BIN=venv\Scripts\python.exe
) else (
    set PYTHON_BIN=python
)

echo Launching Backend (FastAPI)...
start "Backend (FastAPI)" %PYTHON_BIN% -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

echo Launching Frontend (React + Vite)...
start "Frontend (React)" cmd /k "cd frontend && npm run dev"

echo.
echo Services started in separate terminal windows!
echo   Frontend Dashboard: http://localhost:5173
echo   Backend API Docs:  http://127.0.0.1:8000/docs
echo.
pause
