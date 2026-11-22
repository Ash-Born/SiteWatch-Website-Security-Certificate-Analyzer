import os
import sys
import subprocess

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to python interpreter in venv if present, otherwise current sys.executable
    if os.name == 'nt':
        venv_python = os.path.join(root_dir, "venv", "Scripts", "python.exe")
        npm_cmd = "npm.cmd"
    else:
        venv_python = os.path.join(root_dir, "venv", "bin", "python")
        npm_cmd = "npm"

    python_exe = venv_python if os.path.exists(venv_python) else sys.executable

    print("==================================================")
    print("Starting Vulnerability Scanner System...")
    print("==================================================")
    print(f"Python Executable: {python_exe}")
    
    # Start Backend
    print("Launching Backend API (FastAPI)...")
    backend_proc = subprocess.Popen(
        [python_exe, "-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000"],
        cwd=root_dir
    )

    # Start Frontend
    print("Launching Frontend Dashboard (React + Vite)...")
    frontend_dir = os.path.join(root_dir, "frontend")
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=frontend_dir
    )

    print("\nAll services successfully launched!")
    print("   Frontend Dashboard: http://localhost:5173")
    print("   Backend API & Docs: http://127.0.0.1:8000/docs")
    print("\nPress Ctrl+C in this terminal window to stop all services.\n")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping all services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Done.")
        sys.exit(0)

if __name__ == "__main__":
    main()
