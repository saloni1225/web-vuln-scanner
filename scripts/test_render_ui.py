import subprocess
import time
import os
import sys
from playwright.sync_api import sync_playwright

artifact_dir = r"C:\Users\Anmol\.gemini\antigravity\brain\d0230a13-7479-4e60-a82d-869f3e6a288a"
os.makedirs(artifact_dir, exist_ok=True)

# Start backend
print("Starting backend...")
backend_proc = subprocess.Popen(
    [r".venv\Scripts\python.exe", "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8000"],
    cwd=r"c:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner",
)

# Start frontend
print("Starting frontend...")
frontend_proc = subprocess.Popen(
    ["npm", "run", "dev"],
    cwd=r"c:\Users\Anmol\OneDrive\Desktop\web_scanner\adaptive-web-vuln-scanner\frontend",
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
            # e.g. "http://127.0.0.1:5174/" -> "5174"
            port_part = parts[2].split("/")[0].strip()
            # remove formatting
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
        login_screenshot_path = os.path.join(artifact_dir, "screenshot_login.png")
        page.screenshot(path=login_screenshot_path)
        print(f"Saved login screenshot to {login_screenshot_path}")
        
        # 2. Click GitHub SSO button
        print("Attempting to click GitHub SSO login button...")
        # Since we use simple text 'GitHub' on the button:
        page.click("button:has-text('GitHub')", timeout=10000)
        
        # Wait for redirect and state updates to settle
        time.sleep(5)
        
        # 3. Take dashboard page screenshot
        dashboard_url = f"http://127.0.0.1:{port}/"
        print(f"Navigating/confirming dashboard page: {dashboard_url}")
        dashboard_screenshot_path = os.path.join(artifact_dir, "screenshot_dashboard.png")
        page.screenshot(path=dashboard_screenshot_path)
        print(f"Saved dashboard screenshot to {dashboard_screenshot_path}")
        
        browser.close()
except Exception as e:
    print(f"Error occurred during automated rendering check: {e}")
finally:
    print("Terminating servers...")
    backend_proc.terminate()
    
    # Kill npm and vite subprocesses
    subprocess.run("taskkill /f /im node.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("taskkill /f /im cmd.exe /fi \"windowtitle eq npm*\"", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    try:
        backend_proc.wait(timeout=2)
    except:
        pass
    print("Test finished.")
