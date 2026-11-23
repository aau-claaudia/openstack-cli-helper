#!/usr/bin/env python3
"""
AAU Strato Cloud Login Helper with WAYF Single Sign-On (SSO)
============================================================
Automates the retrieval of the OpenStack `X-Subject-Token` for CLAAUDIA Strato
via WAYF / SAML2 authentication as documented at:
https://hpc.aau.dk/strato/advanced-guides/command-line-interface-access/#linux

How it works:
1. Launches Chrome / Edge / Chromium with remote debugging enabled.
2. Navigates to:
   https://strato-new.claaudia.aau.dk:5000/v3/OS-FEDERATION/identity_providers/WAYF/protocols/saml2/auth
3. Listens to Chrome DevTools Protocol network responses in real-time.
4. Once you complete your AAU WAYF / Microsoft login (including MFA if prompted),
   it automatically captures the `X-Subject-Token` header.
5. Queries Keystone for your available OpenStack projects.
6. Obtains a project-scoped token and writes a ready-to-use OpenStack RC file
   (`strato-openrc.sh`) so you can immediately use `openstack` CLI or SDK.
"""

import argparse
import base64
import getpass
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    import requests
except ImportError:
    requests = None

# Default Endpoints
STRATO_BASE_URL = "https://strato-new.claaudia.aau.dk"
KEYSTONE_AUTH_URL = "https://strato-new.claaudia.aau.dk:5000"
WAYF_SAML_AUTH_URL = (
    "https://strato-new.claaudia.aau.dk:5000/v3/OS-FEDERATION/identity_providers/WAYF/protocols/saml2/auth"
)


# ==============================================================================
# Minimal Lightweight RFC 6455 WebSocket Client (Zero External Dependencies)
# ==============================================================================
class SimpleWebSocketClient:
    """Lightweight WebSocket client to communicate with Chrome DevTools Protocol."""

    def __init__(self, ws_url: str, timeout: float = 10.0):
        parsed = urllib.parse.urlparse(ws_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((self.host, self.port))
        self.buf = bytearray()
        self._handshake()

    def _handshake(self):
        sec_key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {sec_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        res = b""
        while b"\r\n\r\n" not in res:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshake failed: socket closed")
            res += chunk

        headers_part, _, rest = res.partition(b"\r\n\r\n")
        status_line = headers_part.split(b"\r\n")[0].decode(errors="replace")
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket upgrade rejected: {status_line}")
        self.buf.extend(rest)

    def send_json(self, payload: dict):
        msg = json.dumps(payload).encode("utf-8")
        length = len(msg)
        mask = os.urandom(4)
        if length <= 125:
            header = bytes([0x81, 0x80 | length]) + mask
        elif length <= 65535:
            header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length) + mask
        else:
            header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length) + mask
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(msg))
        self.sock.sendall(header + masked_payload)

    def recv_msg(self, timeout: float = 1.0):
        self.sock.settimeout(timeout)
        while True:
            if len(self.buf) >= 2:
                b0, b1 = self.buf[0], self.buf[1]
                opcode = b0 & 0x0F
                is_masked = bool(b1 & 0x80)
                payload_len = b1 & 0x7F
                offset = 2

                if payload_len == 126:
                    if len(self.buf) >= 4:
                        payload_len = struct.unpack("!H", self.buf[2:4])[0]
                        offset = 4
                    else:
                        payload_len = None
                elif payload_len == 127:
                    if len(self.buf) >= 10:
                        payload_len = struct.unpack("!Q", self.buf[2:10])[0]
                        offset = 10
                    else:
                        payload_len = None

                if payload_len is not None:
                    mask_len = 4 if is_masked else 0
                    total_frame = offset + mask_len + payload_len
                    if len(self.buf) >= total_frame:
                        mask = self.buf[offset : offset + 4] if is_masked else None
                        p_start = offset + mask_len
                        payload = self.buf[p_start : p_start + payload_len]
                        if is_masked:
                            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
                        del self.buf[:total_frame]

                        if opcode == 0x8:  # Close frame
                            return None
                        elif opcode == 0x9:  # Ping frame
                            pong = bytes([0x8A, 0x80 | len(payload)]) + b"\x00\x00\x00\x00"
                            self.sock.sendall(pong + payload)
                            continue
                        elif opcode in (0x1, 0x2):  # Text or binary
                            return payload.decode("utf-8", errors="replace")

            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return None
                self.buf.extend(chunk)
            except (socket.timeout, TimeoutError):
                return ""

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ==============================================================================
# Browser Discovery & Management
# ==============================================================================
def find_browser_executable(custom_path: str = None) -> str:
    """Find a Chromium-based browser capable of remote debugging."""
    if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
        return custom_path

    candidates = []
    if sys.platform == "darwin":  # macOS
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            os.path.expanduser("~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            os.path.expanduser("~/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ]
    elif sys.platform.startswith("linux"):  # Linux
        binaries = [
            "google-chrome",
            "google-chrome-stable",
            "chromium-browser",
            "chromium",
            "microsoft-edge",
            "microsoft-edge-stable",
            "brave-browser",
        ]
        for name in binaries:
            p = shutil.which(name)
            if p:
                candidates.append(p)
    elif sys.platform == "win32":  # Windows
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]

    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""


def get_free_port() -> int:
    """Find an available local port for the CDP server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def capture_token_via_browser(browser_path: str, timeout: int = 240) -> str:
    """
    Launches browser with remote debugging, navigates to the WAYF SAML2 auth URL,
    and intercepts the HTTP response header 'X-Subject-Token'.
    """
    port = get_free_port()
    # Use a persistent user-data-dir in ~/.strato so AAU logins / cookies can be saved
    profile_dir = os.path.expanduser("~/.strato/browser_profile")
    os.makedirs(profile_dir, exist_ok=True)

    cmd = [
        browser_path,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        WAYF_SAML_AUTH_URL,
    ]

    print(f"\n[*] Launching browser ({os.path.basename(browser_path)}) on debug port {port}...")
    print(f"[*] Navigating to WAYF Auth: {WAYF_SAML_AUTH_URL}")
    print("[*] Please complete your AAU / WAYF login in the opened browser window.")
    print("    (MFA / Microsoft Authenticator prompt will be handled there)\n")

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for the CDP server to respond on /json/version or /json/list
    version_url = f"http://127.0.0.1:{port}/json/version"
    list_url = f"http://127.0.0.1:{port}/json/list"

    start_wait = time.time()
    targets = []
    while time.time() - start_wait < 15:
        try:
            with urllib.request.urlopen(list_url, timeout=1.0) as resp:
                targets = json.loads(resp.read().decode())
                if targets:
                    break
        except Exception:
            time.sleep(0.3)

    if not targets:
        proc.terminate()
        raise RuntimeError(f"Could not connect to browser CDP on port {port}.")

    # Locate the target page tab
    page_target = None
    for t in targets:
        if t.get("type") == "page":
            page_target = t
            break
    if not page_target:
        page_target = targets[0]

    ws_url = page_target.get("webSocketDebuggerUrl")
    if not ws_url:
        proc.terminate()
        raise RuntimeError("No webSocketDebuggerUrl found for the browser page target.")

    # Connect via WebSocket to DevTools
    ws = SimpleWebSocketClient(ws_url, timeout=10.0)

    # Enable Network tracking
    ws.send_json({"id": 1, "method": "Network.enable", "params": {}})

    token = None
    deadline = time.time() + timeout
    print(f"[*] Listening for OpenStack 'X-Subject-Token' (timeout: {timeout}s)...")

    try:
        while time.time() < deadline:
            msg = ws.recv_msg(timeout=0.5)
            if msg is None:  # closed
                break
            if not msg:
                continue

            try:
                data = json.loads(msg)
            except Exception:
                continue

            method = data.get("method")
            if method == "Network.responseReceived":
                resp_info = data.get("params", {}).get("response", {})
                req_url = resp_info.get("url", "")
                headers = resp_info.get("headers", {})

                # Check if headers contain X-Subject-Token (case-insensitive)
                for h_key, h_val in headers.items():
                    if h_key.lower() == "x-subject-token":
                        token = h_val.strip()
                        print("\n[+] SUCCESS! Captured X-Subject-Token from response headers!")
                        print(f"    Origin URL: {req_url}")
                        break

                if token:
                    break

            # If user opened a new tab, check /json/list periodically
            if int(time.time() - start_wait) % 5 == 0:
                try:
                    with urllib.request.urlopen(list_url, timeout=0.5) as r:
                        current_targets = json.loads(r.read().decode())
                        for ct in current_targets:
                            if ct.get("type") == "page" and ct.get("id") != page_target.get("id"):
                                # If needed, we could attach, but SAML POST is usually in the same tab
                                pass
                except Exception:
                    pass

    finally:
        ws.close()
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            pass

    if not token:
        raise TimeoutError("Timed out waiting for X-Subject-Token. Did login complete?")

    return token


# ==============================================================================
# OpenStack Keystone API Helpers (Unscoped & Scoped Tokens)
# ==============================================================================
def get_available_projects(unscoped_token: str, keystone_url: str = KEYSTONE_AUTH_URL) -> list:
    """Fetch projects accessible to the federated user with the unscoped token."""
    endpoints = ["/v3/auth/projects", "/v3/OS-FEDERATION/projects"]
    headers = {"X-Auth-Token": unscoped_token, "Accept": "application/json"}

    for ep in endpoints:
        url = f"{keystone_url.rstrip('/')}{ep}"
        try:
            if requests:
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code == 200:
                    return r.json().get("projects", [])
            else:
                req = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=10) as r:
                    data = json.loads(r.read().decode())
                    return data.get("projects", [])
        except Exception:
            continue
    return []


def scope_token_to_project(
    unscoped_token: str, project_id: str, keystone_url: str = KEYSTONE_AUTH_URL
) -> tuple:
    """
    Exchange the unscoped federated token for a project-scoped OpenStack token.
    Returns (scoped_token_string, token_json_details).
    """
    url = f"{keystone_url.rstrip('/')}/v3/auth/tokens"
    payload = {
        "auth": {
            "identity": {
                "methods": ["token"],
                "token": {"id": unscoped_token},
            },
            "scope": {
                "project": {"id": project_id},
            },
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        if requests:
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                scoped = r.headers.get("X-Subject-Token")
                return scoped, r.json().get("token", {})
            else:
                print(f"[!] Warning: Token scoping returned status {r.status_code}: {r.text}")
        else:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                scoped = r.headers.get("X-Subject-Token")
                data = json.loads(r.read().decode())
                return scoped, data.get("token", {})
    except Exception as e:
        print(f"[!] Failed to exchange for scoped token: {e}")

    return unscoped_token, {}


def authenticate_with_password(
    username: str,
    password: str,
    domain: str = "Default",
    keystone_url: str = KEYSTONE_AUTH_URL,
) -> str:
    """
    Authenticate with Keystone v3 using standard username/password credentials.
    Returns an unscoped X-Subject-Token string.
    """
    url = f"{keystone_url.rstrip('/')}/v3/auth/tokens"
    payload = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": domain},
                        "password": password,
                    }
                },
            }
        }
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    if requests:
        r = requests.post(url, json=payload, headers=headers, timeout=15)
        if r.status_code in (200, 201):
            token = r.headers.get("X-Subject-Token")
            if not token:
                raise RuntimeError("Authentication succeeded but X-Subject-Token header was missing.")
            return token
        elif r.status_code == 401:
            raise RuntimeError("Invalid username, password, or domain (HTTP 401 Unauthorized).")
        else:
            raise RuntimeError(f"Keystone authentication failed (HTTP {r.status_code}): {r.text}")
    else:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                token = r.headers.get("X-Subject-Token")
                if not token:
                    raise RuntimeError("Authentication succeeded but X-Subject-Token header was missing.")
                return token
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            if e.code == 401:
                raise RuntimeError("Invalid username, password, or domain (HTTP 401 Unauthorized).")
            raise RuntimeError(f"Keystone authentication failed (HTTP {e.code}): {err_body}")


def copy_to_clipboard(text: str) -> bool:
    """Attempt copying text to the operating system clipboard."""
    # Try pbcopy (macOS)
    if sys.platform == "darwin":
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return True
        except Exception:
            pass

    # Try xclip or xsel (Linux)
    if sys.platform.startswith("linux"):
        for clip_cmd in [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]:
            try:
                p = subprocess.Popen(clip_cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                return True
            except Exception:
                pass

    # Try pyperclip
    try:
        import pyperclip

        pyperclip.copy(text)
        return True
    except Exception:
        pass

    return False


# ==============================================================================
# Main Interactive & CLI Flow
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Login to AAU Strato (strato-new.claaudia.aau.dk) via WAYF and obtain X-Subject-Token."
    )
    parser.add_argument(
        "--browser",
        help="Path to Chrome / Edge / Chromium executable (auto-detected if omitted)",
        default=None,
    )
    parser.add_argument(
        "--normal",
        action="store_true",
        help="Login with standard OpenStack username and password instead of WAYF SSO",
    )
    parser.add_argument(
        "--username",
        "-u",
        help="OpenStack username (for --normal login)",
        default=None,
    )
    parser.add_argument(
        "--password",
        help="OpenStack password (for --normal login; prompted securely if omitted)",
        default=None,
    )
    parser.add_argument(
        "--domain",
        help="OpenStack user domain name for --normal login (default: Default)",
        default="Default",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Skip browser automation and paste X-Subject-Token manually",
    )
    parser.add_argument(
        "--project",
        "-p",
        help="OpenStack project name or ID to scope to (auto-detected if user has 1 project)",
        default=None,
    )
    parser.add_argument(
        "--output-rc",
        "-o",
        help="Filename to save the sourceable openrc environment script (default: strato-openrc.sh)",
        default="strato-openrc.sh",
    )
    parser.add_argument(
        "--test",
        "-t",
        action="store_true",
        help="Test connection with openstack server list after authentication",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(" AAU Strato (CLAAUDIA) WAYF OpenStack Authentication Helper")
    print(" Docs: https://hpc.aau.dk/strato/advanced-guides/command-line-interface-access/#linux")
    print("=" * 70)

    unscoped_token = None

    if args.normal:
        print("\n[*] Standard OpenStack User Authentication (--normal)")
        username = args.username or os.environ.get("OS_USERNAME")
        if not username:
            try:
                username = input("Username: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)
        if not username:
            print("[!] Error: Username cannot be empty.")
            sys.exit(1)

        password = args.password or os.environ.get("OS_PASSWORD")
        if not password:
            try:
                password = getpass.getpass("Password: ")
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)
        if not password:
            print("[!] Error: Password cannot be empty.")
            sys.exit(1)

        domain = args.domain or os.environ.get("OS_USER_DOMAIN_NAME") or "Default"
        try:
            print(f"[*] Authenticating '{username}' (domain: '{domain}') against Keystone...")
            unscoped_token = authenticate_with_password(username, password, domain=domain)
            print("[+] Password authentication succeeded!")
        except Exception as e:
            print(f"[!] Authentication failed: {e}")
            sys.exit(1)
    else:
        if not args.manual:
            browser_exec = find_browser_executable(args.browser)
            if browser_exec:
                try:
                    unscoped_token = capture_token_via_browser(browser_exec)
                except Exception as e:
                    print(f"[!] Browser automation failed or was cancelled: {e}")
                    print("[*] Falling back to manual token input.\n")
            else:
                print("[!] No supported Chromium-based browser found on your system.")
                print("[*] Falling back to manual token input.\n")

        if not unscoped_token:
            print("\n--- Manual Token Instructions ---")
            print("1. Open the following link in your browser:")
            print(f"   {WAYF_SAML_AUTH_URL}")
            print("2. Open Browser Developer Tools (F12 or right-click -> Inspect -> Network tab).")
            print("3. Filter by 'Doc' or 'Fetch/XHR' and complete your AAU / WAYF login.")
            print("4. Click on the 'auth' request and look under 'Response Headers' for 'X-Subject-Token'.")
            print("5. Copy that token string and paste it below.\n")

            while not unscoped_token:
                try:
                    raw_input = input("Enter X-Subject-Token: ").strip()
                    if raw_input:
                        unscoped_token = raw_input
                except (KeyboardInterrupt, EOFError):
                    print("\nAborted.")
                    sys.exit(1)

    print(f"\n[+] Active X-Subject-Token: {unscoped_token[:10]}...{unscoped_token[-6:]}")

    # Discover available projects
    print("\n[*] Querying Keystone for authorized OpenStack projects...")
    projects = get_available_projects(unscoped_token)

    selected_project = None
    if projects:
        print(f"[+] Found {len(projects)} accessible project(s):")
        for i, proj in enumerate(projects, 1):
            p_name = proj.get("name", "Unknown")
            p_id = proj.get("id", "")
            print(f"    [{i}] {p_name} (ID: {p_id})")

        # Select project based on CLI flag or prompt
        if args.project:
            for proj in projects:
                if args.project in (proj.get("name"), proj.get("id")):
                    selected_project = proj
                    break
            if not selected_project:
                print(f"[!] Project '{args.project}' not found among accessible projects.")

        if not selected_project:
            if len(projects) == 1:
                selected_project = projects[0]
                print(f"[*] Automatically selecting project: {selected_project.get('name')}")
            else:
                while not selected_project:
                    try:
                        choice = input(f"Select project [1-{len(projects)}]: ").strip()
                        choice_idx = int(choice) - 1
                        if 0 <= choice_idx < len(projects):
                            selected_project = projects[choice_idx]
                    except ValueError:
                        print("Please enter a valid number.")
                    except (KeyboardInterrupt, EOFError):
                        print("\nAborted.")
                        sys.exit(1)
    else:
        print("[!] Note: Could not auto-discover projects using unscoped token.")
        if args.project:
            selected_project = {"id": args.project, "name": args.project}
        else:
            proj_id = input(
                "Enter your OS_PROJECT_ID (from Strato OpenStack RC file, or leave blank): "
            ).strip()
            if proj_id:
                selected_project = {"id": proj_id, "name": proj_id}

    final_token = unscoped_token
    project_id = ""
    project_name = ""

    if selected_project:
        project_id = selected_project.get("id", "")
        project_name = selected_project.get("name", "")
        print(f"\n[*] Scoping token to project '{project_name}' ({project_id})...")
        scoped_tok, _ = scope_token_to_project(unscoped_token, project_id)
        if scoped_tok:
            final_token = scoped_tok
            print("[+] Successfully received project-scoped token!")

    # Format RC environment variables according to AAU HPC documentation
    rc_content = f"""# AAU Strato OpenStack RC file generated by strato-login.py
# Reference: https://hpc.aau.dk/strato/advanced-guides/command-line-interface-access/#linux
export OS_AUTH_TYPE=token
export OS_IDENTITY_API_VERSION=3
export OS_AUTH_URL={KEYSTONE_AUTH_URL}
export OS_PROJECT_ID={project_id}
export OS_PROJECT_NAME="{project_name}"
export OS_TOKEN={final_token}
"""

    if args.output_rc:
        rc_path = os.path.abspath(args.output_rc)
        with open(rc_path, "w") as f:
            f.write(rc_content)
        # Set rw-r--r-- or rw------- for security
        os.chmod(rc_path, 0o600)
        print(f"\n[+] OpenStack RC environment saved to:\n    {rc_path}")

    # Copy token to clipboard
    if copy_to_clipboard(f"export OS_TOKEN={final_token}"):
        print("[+] 'export OS_TOKEN=...' copied to your clipboard!")

    print("\n" + "=" * 70)
    print(" TO USE OPENSTACK CLI IN YOUR TERMINAL:")
    print("=" * 70)
    if args.output_rc:
        print(f"Run this command to load your credentials:\n")
        print(f"    source {args.output_rc}\n")
    else:
        print(rc_content)

    print("Then you can run:")
    print("    openstack server list")
    print("    openstack flavor list")
    print("    openstack image list")
    print("=" * 70)

    # Optional test command
    if args.test:
        print("\n[*] Testing OpenStack CLI (`openstack server list`)...")
        env = os.environ.copy()
        env["OS_AUTH_TYPE"] = "token"
        env["OS_IDENTITY_API_VERSION"] = "3"
        env["OS_AUTH_URL"] = KEYSTONE_AUTH_URL
        env["OS_PROJECT_ID"] = project_id
        env["OS_PROJECT_NAME"] = project_name
        env["OS_TOKEN"] = final_token

        try:
            res = subprocess.run(["openstack", "server", "list"], env=env, capture_output=True, text=True)
            if res.returncode == 0:
                print(res.stdout)
            else:
                print(f"[!] openstack command exited with code {res.returncode}:\n{res.stderr}")
        except FileNotFoundError:
            print("[!] 'openstack' command not found in PATH.")


if __name__ == "__main__":
    main()
