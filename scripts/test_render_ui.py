"""
Local-only UI rendering test using Playwright.
This script is excluded from CI via pytest.ini (collect_ignore).
Run manually on your local machine for visual UI verification.
"""
import subprocess
import time
import os
import sys
import platform
from pathlib import Path

# Skip in CI environments
if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
    print("Skipping UI rendering test in CI environment")
    sys.exit(0)

# Use platform-independent paths relative to this script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = PROJECT_ROOT / ".test_artifacts"
ARTIFACT_DIR.mkdir(exist_ok=True)

is_windows = platform.system() == "Windows"

# Determine correct Python executable
if is_windows:
    python_exe = str(PROJECT_ROOT / ".venv" / "Scripts" / "python.exe")
    if not Path(python_exe).exists():
        python_exe = sys.executable
else:
    python_exe = str(PROJECT_ROOT / ".venv" / "bin" / "python")
    if not Path(python_exe).exists():
        python_exe = sys.executable

from playwright.sync_api import sync_playwright

# Start backend
print("Starting backend...")
backend_proc = subprocess.Popen(
    [python_exe, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8000"],
    cwd=str(PROJECT_ROOT),
)

# Start frontend
print("Starting frontend...")
frontend_proc = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=str(PROJECT_ROOT / "frontend"),
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)

# Detect port
port = 5173
start_time = time.time()
while time.time() - start_time < 15:
    line = frontend_proc.stdout.readline()
    print(line, end="")
    if "Local:" in line or "➜" in line:
        parts = line.split(":")
        if len(parts) >= 3:
            port_part = parts[2].split("/")[0].strip()
            port_part = "".join(filter(str.isdigit, port_part))
            if port_part.isdigit():
                port = int(port_part)
                print(f"\n[Detected active Vite port: {port}]")
                break

print("Waiting a brief moment for servers to settle...")
time.sleep(3)

try:
    with sync_playwright() as p:
        print("Launching headless Chromium...")
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

        # 1. Open login page
        login_url = f"http://127.0.0.1:{port}/login"
        print(f"Navigating to login page: {login_url}")
        page.goto(login_url, timeout=20000)
        time.sleep(2)

        # Take login screenshot
        login_screenshot_path = str(ARTIFACT_DIR / "screenshot_login.png")
        page.screenshot(path=login_screenshot_path)
        print(f"Saved login screenshot to {login_screenshot_path}")

        # 2. Click GitHub SSO button
        print("Attempting to click GitHub SSO login button...")
        page.click("button:has-text('GitHub')", timeout=10000)

        # Wait for redirect and state updates to settle
        time.sleep(5)

        # 3. Take dashboard page screenshot
        dashboard_url = f"http://127.0.0.1:{port}/"
        print(f"Navigating/confirming dashboard page: {dashboard_url}")
        dashboard_screenshot_path = str(ARTIFACT_DIR / "screenshot_dashboard.png")
        page.screenshot(path=dashboard_screenshot_path)
        print(f"Saved dashboard screenshot to {dashboard_screenshot_path}")

        browser.close()
except Exception as e:
    print(f"Error occurred during automated rendering check: {e}")
finally:
    print("Terminating servers...")
    backend_proc.terminate()

    # Kill subprocesses (platform-aware)
    if is_windows:
        subprocess.run("taskkill /f /im node.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run("pkill -f 'npm run dev'", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        backend_proc.wait(timeout=2)
    except Exception:
        pass
    print("Test finished.")
