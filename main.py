#!/usr/bin/env python3
"""
Secure Vault & Identity Platform — one-click launcher.

Executing this file:
  1. Starts the PHP built-in web server for the project.
  2. Waits until the app responds.
  3. Opens the project in Google Chrome.
  4. Keeps the server running until you press Ctrl+C.

Usage:
    python3 main.py [--port 8000] [--host 127.0.0.1] [--no-browser]
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
ROUTER_ROOT = PROJECT_ROOT / "router.php"          # docroot = project root
ROUTER_PUBLIC = PROJECT_ROOT / "public" / "router.php"  # docroot = public/

CHROME_CANDIDATES = [
    "google-chrome-stable",
    "google-chrome",
    "chrome",
    "chromium",
    "chromium-browser",
]


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) != 0


def url_serves_app(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            body = r.read(4096).decode("utf-8", errors="ignore")
            return r.status in (200, 301, 302) and (
                "Secure Vault" in body or "vault" in body.lower()
            )
    except Exception:
        return False


def wait_until_ready(url: str, proc: subprocess.Popen, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False  # PHP server died
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status in (200, 301, 302):
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def find_chrome() -> str | None:
    for name in CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def open_in_chrome(url: str) -> bool:
    """Try Google Chrome specifically, fall back to default browser. Never crash."""
    # 1) Explicit Chrome binary (Linux / Windows / macOS names).
    chrome = find_chrome()
    if chrome:
        try:
            subprocess.Popen(
                [chrome, "--new-window", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return True
        except Exception as exc:
            print(f"Could not launch '{chrome}': {exc}")

    # 2) macOS `open -a "Google Chrome"`.
    if sys.platform == "darwin":
        try:
            subprocess.Popen(
                ["open", "-a", "Google Chrome", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            pass

    # 3) Python's browser registry ("chrome" / "google-chrome").
    for name in ("chrome", "google-chrome", "chromium"):
        try:
            browser = webbrowser.get(name)
            browser.open_new(url)
            return True
        except Exception:
            continue

    # 4) System default browser (may be Chrome already).
    try:
        webbrowser.open_new(url)
        return True
    except Exception as exc:
        print(f"Could not open a browser automatically: {exc}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Launch Secure Vault in Google Chrome.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true",
                    help="Start the server without opening Chrome.")
    args = ap.parse_args()

    php = shutil.which("php")
    if not php:
        print("ERROR: PHP was not found on PATH. Install PHP >= 8.1 first.")
        return 1

    # Encrypted-file storage must exist (Crypto/config expect it).
    (PROJECT_ROOT / "storage" / "uploads").mkdir(parents=True, exist_ok=True)

    host, port = args.host, args.port

    # If something already serves the app on the requested port, just open it.
    base_url = f"http://{host}:{port}/"
    if not is_port_free(host, port) and url_serves_app(base_url):
        print(f"Project is already running at {base_url}")
        if not args.no_browser:
            open_in_chrome(base_url)
        return 0

    # Otherwise find a free port (8000 -> 8001 -> ...).
    for _ in range(20):
        if is_port_free(host, port):
            break
        port += 1
    base_url = f"http://{host}:{port}/"

    # Build the PHP server command. Prefer root router (serves /public/* + /api/*).
    if ROUTER_ROOT.is_file():
        cmd = [php, "-S", f"{host}:{port}", str(ROUTER_ROOT)]
        cwd = str(PROJECT_ROOT)
    elif ROUTER_PUBLIC.is_file():
        cmd = [php, "-S", f"{host}:{port}", "-t", str(PROJECT_ROOT / "public"),
               str(ROUTER_PUBLIC)]
        cwd = str(PROJECT_ROOT)
    else:  # last resort: serve public/ statically
        cmd = [php, "-S", f"{host}:{port}", "-t", str(PROJECT_ROOT / "public")]
        cwd = str(PROJECT_ROOT)

    print(f"Starting Secure Vault & Identity Platform at {base_url} ...")
    try:
        proc = subprocess.Popen(cmd, cwd=cwd)
    except Exception as exc:
        print(f"ERROR: could not start PHP server: {exc}")
        return 1

    if not wait_until_ready(base_url, proc):
        if proc.poll() is not None:
            print("ERROR: PHP server exited immediately. "
                  "Run the command manually to see the error:")
            print(f"  cd {cwd} && {' '.join(cmd)}")
        else:
            print(f"WARNING: server did not respond at {base_url} within 20s.")
            proc.terminate()
        return 1

    print(f"Ready! Open {base_url} in your browser.")
    if not args.no_browser:
        if open_in_chrome(base_url):
            print("Opened Google Chrome.")
        else:
            print(f"Please open manually: {base_url}")

    print("Press Ctrl+C to stop the server.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\nStopping server ...")
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    print("Server stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
