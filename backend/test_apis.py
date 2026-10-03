import subprocess
import time
import json
import sys

# Start the server
print("Starting FastAPI server...")
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"],
    cwd="C:\\ai-soc\\backend",
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
time.sleep(3)  # Wait for server to start

import requests
API_BASE = "http://localhost:8000"

endpoints = [
    ("GET /health", f"{API_BASE}/health"),
    ("GET /stats", f"{API_BASE}/stats"),
    ("GET /live-feed/status", f"{API_BASE}/live-feed/status"),
    ("GET /incidents?limit=5", f"{API_BASE}/incidents?limit=5"),
    ("GET /kb", f"{API_BASE}/kb"),
    ("GET /events/live?limit=5", f"{API_BASE}/events/live?limit=5"),
]

print("\nTesting endpoints:")
for name, url in endpoints:
    try:
        r = requests.get(url, timeout=5)
        status = res_ok = r.status_code < 400
        data_preview = str(r.json())[:80] if res_ok else "error"
        print(f"  {name}: {r.status_code} - {data_preview}")
    except Exception as e:
        print(f"  {name}: Error - {str(e)[:60]}")

# Stop the server
proc.terminate()
proc.wait()
print("\nDone testing endpoints")