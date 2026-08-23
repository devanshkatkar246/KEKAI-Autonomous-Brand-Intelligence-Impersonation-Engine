#!/usr/bin/env python3
"""
KEIKAI Anti-Impersonation Engine — One-Click Local Development Launcher

This script starts:
1. FastAPI Backend Server on http://localhost:8000
2. Vite + React Frontend Development Server on http://localhost:5173
3. Launches the web browser automatically once servers are healthy.

Usage:
    python steps.py
"""

import sys
import os
import time
import subprocess
import webbrowser
from pathlib import Path

# Working directory setup
ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "frontend"
MODELS_DIR = ROOT_DIR / "Phishpedia" / "models"


def print_banner():
    print("=" * 70)
    print("        KEIKAI - ANTI-IMPERSONATION ENGINE LOCAL LAUNCHER        ")
    print("=" * 70)


def check_prerequisites():
    print("\n[STEP 1/4] Checking environment & prerequisites...")
    
    # Check Python version
    py_ver = sys.version.split()[0]
    print(f"  [OK] Python version: {py_ver}")

    # Check Node.js & npm
    try:
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        npm_ver = subprocess.check_output([npm_cmd, "--version"], text=True).strip()
        print(f"  [OK] Node.js npm version: {npm_ver}")
    except Exception:
        print("  [WARNING] 'npm' was not found on system PATH. Frontend may fail to start.")

    # Check frontend directory
    if not FRONTEND_DIR.exists():
        print("  [ERROR] './frontend' directory missing.")
        sys.exit(1)

    # Check frontend node_modules
    node_modules = FRONTEND_DIR / "node_modules"
    if not node_modules.exists():
        print("  [INFO] 'node_modules' missing in './frontend'. Running 'npm install'...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "install"], cwd=str(FRONTEND_DIR), check=True)
        print("  [OK] Frontend dependencies installed.")

    # Check Phishpedia weights
    required_weights = ["rcnn_bet365.pth", "resnetv2_rgb_new.pth.tar", "domain_map.pkl", "expand_targetlist.zip"]
    missing_weights = [w for w in required_weights if not (MODELS_DIR / w).exists()]
    if missing_weights:
        print(f"  [INFO] Phishpedia deep learning model weights missing ({len(missing_weights)} files).")
        print("         (App will run in fallback pHash mode until weights are downloaded via 'python scripts/download_phishpedia_weights.py')")
    else:
        print("  [OK] Full Phishpedia Deep Learning Model Weights Present.")


def start_backend():
    print("\n[STEP 2/4] Launching FastAPI Backend Server...")
    cmd = [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--host", "127.0.0.1", "--port", "8000"]
    proc = subprocess.Popen(cmd, cwd=str(ROOT_DIR))
    print(f"  [OK] Backend starting on http://localhost:8000 (Process PID: {proc.pid})")
    return proc


def start_frontend():
    print("\n[STEP 3/4] Launching Vite React Frontend Server...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    cmd = [npm_cmd, "run", "dev"]
    proc = subprocess.Popen(cmd, cwd=str(FRONTEND_DIR))
    print(f"  [OK] Frontend starting on http://localhost:5173 (Process PID: {proc.pid})")
    return proc


def wait_and_open_browser():
    print("\n[STEP 4/4] Performing health check & launching browser...")
    time.sleep(3)
    target_url = "http://localhost:5173"
    print(f"  [LAUNCH] Opening browser to {target_url}...")
    try:
        webbrowser.open(target_url)
    except Exception as e:
        print(f"  [INFO] Could not auto-open browser: {e}. Please visit {target_url} manually.")


def main():
    print_banner()
    check_prerequisites()

    backend_proc = None
    frontend_proc = None

    try:
        backend_proc = start_backend()
        frontend_proc = start_frontend()

        wait_and_open_browser()

        print("\n" + "=" * 70)
        print("  KEIKAI IS NOW RUNNING LOCALLY!")
        print("  - Frontend UI:  http://localhost:5173")
        print("  - Backend API:  http://localhost:8000")
        print("  - API Docs:     http://localhost:8000/docs")
        print("  Press Ctrl+C to stop both servers.")
        print("=" * 70 + "\n")

        # Keep running until Ctrl+C
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Stopping KEIKAI local servers...")
    finally:
        if backend_proc:
            print(f"  - Terminating Backend (PID: {backend_proc.pid})...")
            backend_proc.terminate()
        if frontend_proc:
            print(f"  - Terminating Frontend (PID: {frontend_proc.pid})...")
            frontend_proc.terminate()
        print("  [OK] All servers stopped cleanly. Goodbye!")


if __name__ == "__main__":
    main()
