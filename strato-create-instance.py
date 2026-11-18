#!/usr/bin/env python3
"""
AAU Strato Cloud Instance Provisioning Helper
============================================
Creates OpenStack instances on AAU Strato (strato-new.claaudia.aau.dk)
based on project resource availability, quota limits, and images.

Features:
1. Quota-aware: queries project limits (vCPUs, RAM, instances) and evaluates
   flavor compatibility to prevent out-of-quota launch errors.
2. SSH Keypair automation: detects existing keypairs; if missing (or requested),
   generates a new keypair in OpenStack and saves the private key locally
   (default: ~/.ssh/<key_name>.pem with chmod 0600).
3. Dual Mode:
   - Dynamic Interactive CLI: guided step-by-step selection menus.
   - One-Command Setup: fire-and-forget single command line execution.
4. Floating IP: automatically allocates and associates a public floating IP.
5. OS-aware SSH command generation with automatic clipboard copy.
6. Zero external dependencies: works with Python standard library (urllib)
   and requests if installed.
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
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

# Default AAU Strato Endpoints
DEFAULT_KEYSTONE_URL = "https://strato-new.claaudia.aau.dk:5000"
DEFAULT_RC_FILE = "strato-openrc.sh"


# ==============================================================================
# Clipboard Helper
# ==============================================================================
def copy_to_clipboard(text: str) -> bool:
    """Attempt copying text to the operating system clipboard."""
    if sys.platform == "darwin":  # macOS
        try:
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(text.encode("utf-8"))
            return True
        except Exception:
            pass

    if sys.platform.startswith("linux"):  # Linux
        for clip_cmd in [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]:
            try:
                p = subprocess.Popen(clip_cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                return True
            except Exception:
                pass

    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass

    return False


# ==============================================================================
# OpenStack RC File & Environment Parser
# ==============================================================================
def load_rc_file(rc_path: str = DEFAULT_RC_FILE) -> dict:
    """Parse an OpenStack openrc.sh file and return exported variables."""
    loaded = {}
    if not os.path.isfile(rc_path):
        return loaded

    try:
        with open(rc_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Handle `export KEY=VALUE` or `export KEY="VALUE"`
                match = re.match(r"^export\s+([A-Za-z0-9_]+)=(.*)$", line)
                if match:
                    key, val = match.group(1), match.group(2).strip()
                    # Strip single or double quotes
                    if (val.startswith('"') and val.endswith('"')) or (
                        val.startswith("'") and val.endswith("'")
                    ):
                        val = val[1:-1]
                    loaded[key] = val
                    if key not in os.environ:
                        os.environ[key] = val
    except Exception as e:
        print(f"[!] Warning: Could not read RC file '{rc_path}': {e}")

    return loaded


# ==============================================================================
# Lightweight OpenStack REST Client
# ==============================================================================
class OpenStackClient:
    """
    Direct OpenStack REST API client supporting Keystone v3, Nova v2.1,
    Glance v2, and Neutron v2.0 using requests or standard urllib.
    """

    def __init__(self, auth_url: str, token: str, project_id: str = ""):
        self.auth_url = auth_url.rstrip("/")
        # Ensure /v3 suffix if missing
        if not self.auth_url.endswith("/v3"):
            self.auth_url += "/v3"
        self.token = token
        self.project_id = project_id

        # Discovered public endpoints
        self.compute_url = ""
        self.image_url = ""
        self.network_url = ""
        self.identity_url = self.auth_url

        self.service_catalog = []
        self._discover_catalog()

    def _request(self, method: str, url: str, payload: dict = None, timeout: int = 25) -> dict:
        """Execute authenticated HTTP request with JSON payload and response."""
        headers = {
            "X-Auth-Token": self.token,
            "Accept": "application/json",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        else:
            body = None

        if requests:
            resp = requests.request(
                method,
                url,
                json=payload if payload is not None else None,
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code in (200, 201, 202, 204):
                if resp.status_code == 204 or not resp.content:
                    return {}
                return resp.json()
            elif resp.status_code == 401:
                raise RuntimeError(
                    f"HTTP 401 Unauthorized: OpenStack token expired or invalid.\n"
                    f"    Please re-authenticate with: python3 strato-login.py\n"
                    f"    Server response: {resp.text}"
                )
            else:
                error_msg = f"HTTP {resp.status_code} ({method} {url}): {resp.text}"
                raise RuntimeError(error_msg)
        else:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            ctx = ssl.create_default_context()
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    res_body = r.read().decode("utf-8", errors="replace")
                    if not res_body:
                        return {}
                    return json.loads(res_body)
            except urllib.error.HTTPError as e:
                err_text = e.read().decode("utf-8", errors="replace")
                if e.code == 401:
                    raise RuntimeError(
                        f"HTTP 401 Unauthorized: OpenStack token expired or invalid.\n"
                        f"    Please re-authenticate with: python3 strato-login.py\n"
                        f"    Server response: {err_text}"
                    )
                raise RuntimeError(f"HTTP {e.code} ({method} {url}): {err_text}")

    def _discover_catalog(self):
        """Fetch Keystone token details and extract service endpoints from catalog."""
        url = f"{self.auth_url}/auth/tokens"
        headers = {
            "X-Auth-Token": self.token,
            "X-Subject-Token": self.token,
            "Accept": "application/json",
        }

        token_info = {}
        try:
            if requests:
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    token_info = r.json().get("token", {})
            else:
                req = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=15) as r:
                    token_info = json.loads(r.read().decode()).get("token", {})
        except Exception as e:
            # Token validation via GET might fail if endpoint expects POST or unscoped;
            pass

        if token_info:
            if not self.project_id:
                self.project_id = token_info.get("project", {}).get("id", "")
            self.service_catalog = token_info.get("catalog", [])
            for service in self.service_catalog:
                s_type = service.get("type")
                endpoints = service.get("endpoints", [])
                public_urls = [
                    ep.get("url") for ep in endpoints if ep.get("interface") == "public"
                ]
                endpoint_url = public_urls[0] if public_urls else (endpoints[0].get("url") if endpoints else "")

                if s_type == "compute":
                    self.compute_url = endpoint_url.rstrip("/")
                elif s_type == "image":
                    self.image_url = endpoint_url.rstrip("/")
                elif s_type == "network":
                    self.network_url = endpoint_url.rstrip("/")

        # Sensible defaults for AAU Strato if catalog wasn't parsed
        base_host = urllib.parse.urlparse(self.auth_url).hostname or "strato-new.claaudia.aau.dk"
        scheme = urllib.parse.urlparse(self.auth_url).scheme or "https"
        if not self.compute_url:
            self.compute_url = f"{scheme}://{base_host}:8774/v2.1"
        if not self.image_url:
            self.image_url = f"{scheme}://{base_host}:9292"
        if not self.network_url:
            self.network_url = f"{scheme}://{base_host}:9696"

    # --------------------------------------------------------------------------
    # Compute / Quota Limits
    # --------------------------------------------------------------------------
    def get_compute_limits(self) -> dict:
        """Fetch compute quota and usage limits from Nova."""
        url = f"{self.compute_url}/limits"
        data = self._request("GET", url)
        return data.get("limits", {}).get("absolute", {})

    # --------------------------------------------------------------------------
    # Flavors
    # --------------------------------------------------------------------------
    def list_flavors(self) -> list:
        """Fetch all available compute flavors with detailed specs."""
        url = f"{self.compute_url}/flavors/detail"
        data = self._request("GET", url)
        flavors = data.get("flavors", [])
        # Sort flavors primarily by vCPUs, then RAM, then Disk
        flavors.sort(key=lambda f: (f.get("vcpus", 0), f.get("ram", 0), f.get("disk", 0)))
        return flavors

    # --------------------------------------------------------------------------
    # Images
    # --------------------------------------------------------------------------
    def list_images(self) -> list:
        """Fetch all active images from Glance."""
        url = f"{self.image_url}/v2/images?status=active"
        data = self._request("GET", url)
        images = data.get("images", [])
        # Sort by name
        images.sort(key=lambda img: img.get("name", "").lower())
        return images

    # --------------------------------------------------------------------------
    # Networks
    # --------------------------------------------------------------------------
    def list_networks(self) -> list:
        """Fetch available networks from Neutron (both tenant and external)."""
        url = f"{self.network_url}/v2.0/networks"
        data = self._request("GET", url)
        nets = data.get("networks", [])
        # Also query external networks to ensure public floating pools are found
        try:
            ext_url = f"{self.network_url}/v2.0/networks?router:external=true"
            ext_data = self._request("GET", ext_url)
            existing_ids = {n.get("id") for n in nets}
            for en in ext_data.get("networks", []):
                if en.get("id") not in existing_ids:
                    nets.append(en)
        except Exception:
            pass
        return nets

    def create_network(self, name: str = "strato-net") -> dict:
        """Create a new tenant network."""
        url = f"{self.network_url}/v2.0/networks"
        payload = {"network": {"name": name, "admin_state_up": True}}
        data = self._request("POST", url, payload=payload)
        return data.get("network", {})

    def create_subnet(
        self,
        network_id: str,
        name: str = "strato-subnet",
        cidr: str = "10.0.0.0/24",
        dns_nameservers: list = None,
    ) -> dict:
        """Create a subnet for a network."""
        url = f"{self.network_url}/v2.0/subnets"
        payload = {
            "subnet": {
                "network_id": network_id,
                "name": name,
                "ip_version": 4,
                "cidr": cidr,
                "dns_nameservers": dns_nameservers or ["130.225.8.8", "8.8.8.8", "1.1.1.1"],
            }
        }
        data = self._request("POST", url, payload=payload)
        return data.get("subnet", {})

    def create_router(self, name: str = "strato-router", external_net_id: str = None) -> dict:
        """Create a virtual router."""
        url = f"{self.network_url}/v2.0/routers"
        r_dict = {"name": name, "admin_state_up": True}
        if external_net_id:
            r_dict["external_gateway_info"] = {"network_id": external_net_id}
        data = self._request("POST", url, payload={"router": r_dict})
        return data.get("router", {})

    def add_router_interface(self, router_id: str, subnet_id: str) -> dict:
        """Attach a subnet to a router."""
        url = f"{self.network_url}/v2.0/routers/{router_id}/add_router_interface"
        return self._request("PUT", url, payload={"subnet_id": subnet_id})

    def auto_create_network_topology(self, net_name: str = "strato-net", ext_net_id: str = None) -> dict:
        """
        Create complete network topology: network + subnet + router connected to external gateway.
        """
        print(f"[*] Creating network '{net_name}'...")
        net = self.create_network(name=net_name)
        net_id = net.get("id")

        print(f"[*] Creating subnet (10.0.0.0/24) for '{net_name}'...")
        subnet = self.create_subnet(net_id, name=f"{net_name}-subnet", cidr="10.0.0.0/24")
        subnet_id = subnet.get("id")

        if ext_net_id:
            try:
                print(f"[*] Creating router connected to external network...")
                router = self.create_router(name=f"{net_name}-router", external_net_id=ext_net_id)
                r_id = router.get("id")
                self.add_router_interface(r_id, subnet_id)
                print(f"[+] Router configured and connected to external gateway!")
            except Exception as e:
                print(f"[!] Note: Router gateway attachment skipped: {e}")

        print(f"[+] Private network '{net_name}' ready (ID: {net_id})!")
        return net

    # --------------------------------------------------------------------------
    # Keypairs
    # --------------------------------------------------------------------------
    def list_keypairs(self) -> list:
        """Fetch user SSH keypairs registered in OpenStack."""
        url = f"{self.compute_url}/os-keypairs"
        data = self._request("GET", url)
        # Result format: [{"keypair": {...}}, ...]
        return [item.get("keypair", {}) for item in data.get("keypairs", [])]

    def create_keypair(self, name: str, public_key: str = None) -> dict:
        """
        Create a new keypair in OpenStack.
        If public_key is omitted, OpenStack generates a new keypair and
        returns the private_key in the response.
        """
        url = f"{self.compute_url}/os-keypairs"
        payload = {"keypair": {"name": name}}
        if public_key:
            payload["keypair"]["public_key"] = public_key
        data = self._request("POST", url, payload=payload)
        return data.get("keypair", {})

    # --------------------------------------------------------------------------
    # Security Groups
    # --------------------------------------------------------------------------
    def list_security_groups(self) -> list:
        """Fetch security groups."""
        url = f"{self.network_url}/v2.0/security-groups"
        data = self._request("GET", url)
        return data.get("security_groups", [])

    def delete_security_group(self, security_group_id: str) -> None:
        """Delete a security group."""
        url = f"{self.network_url}/v2.0/security-groups/{security_group_id}"
        self._request("DELETE", url)

    def delete_security_group_rule(self, rule_id: str) -> None:
        """Delete a security group rule by ID."""
        url = f"{self.network_url}/v2.0/security-group-rules/{rule_id}"
        self._request("DELETE", url)

    def list_server_security_groups(self, server_id: str) -> list:
        """List security groups attached to a server (with full Neutron rule details)."""
        url = f"{self.compute_url}/servers/{server_id}/os-security-groups"
        data = self._request("GET", url)
        nova_sgs = data.get("security_groups", [])
        nova_ids = {sg.get("id") for sg in nova_sgs if sg.get("id")}
        nova_names = {sg.get("name") for sg in nova_sgs if sg.get("name")}

        all_neutron_sgs = self.list_security_groups()
        matched = [
            sg for sg in all_neutron_sgs
            if sg.get("id") in nova_ids or sg.get("name") in nova_names
        ]
        return matched if matched else nova_sgs

    def add_security_group_to_server(self, server_id: str, sg_name: str) -> None:
        """Attach an existing security group to a server."""
        url = f"{self.compute_url}/servers/{server_id}/action"
        payload = {"addSecurityGroup": {"name": sg_name}}
        self._request("POST", url, payload=payload)

    def add_security_group_rule(
        self,
        security_group_id: str,
        port_min: int = None,
        port_max: int = None,
        protocol: str = "tcp",
        remote_ip_prefix: str = "0.0.0.0/0",
        direction: str = "ingress",
    ) -> dict:
        """Add a port or port-range rule to a security group."""
        rule_url = f"{self.network_url}/v2.0/security-group-rules"
        rule_dict = {
            "security_group_id": security_group_id,
            "direction": direction,
            "ethertype": "IPv4",
            "protocol": protocol.lower(),
            "remote_ip_prefix": remote_ip_prefix,
        }
        if port_min is not None and port_max is not None and protocol.lower() != "icmp":
            rule_dict["port_range_min"] = port_min
            rule_dict["port_range_max"] = port_max

        payload = {"security_group_rule": rule_dict}
        try:
            return self._request("POST", rule_url, payload=payload)
        except Exception as e:
            # If rule already exists (409 Conflict), ignore safely
            if "409" in str(e) or "already exists" in str(e).lower():
                return {}
            raise

    def ensure_instance_security_group(
        self,
        instance_name: str,
        allow_ssh: bool = True,
        port_rules: list = None,
    ) -> str:
        """
        Create a dedicated, isolated security group for this instance (<instance_name>-sg).
        Guarantees that ports opened for this instance apply ONLY to this instance
        and do not leak to other project instances.
        """
        sg_name = f"{instance_name}-sg"
        sgs = self.list_security_groups()
        sg = next((s for s in sgs if s.get("name") == sg_name), None)
        if not sg:
            url = f"{self.network_url}/v2.0/security-groups"
            payload = {
                "security_group": {
                    "name": sg_name,
                    "description": f"Dedicated isolated security group for instance '{instance_name}'",
                }
            }
            res = self._request("POST", url, payload=payload)
            sg_id = res.get("security_group", {}).get("id")
        else:
            sg_id = sg.get("id")

        # Ingress SSH (port 22) and ICMP (ping)
        if allow_ssh:
            try:
                self.add_security_group_rule(
                    security_group_id=sg_id,
                    port_min=22,
                    port_max=22,
                    protocol="tcp",
                )
            except Exception as e:
                print(f"[!] Warning: Could not add SSH rule to '{sg_name}': {e}")

            try:
                self.add_security_group_rule(
                    security_group_id=sg_id,
                    protocol="icmp",
                )
            except Exception as e:
                print(f"[!] Warning: Could not add ICMP ping rule to '{sg_name}': {e}")

        # Instance-specific custom ports and port ranges
        if port_rules:
            for min_p, max_p, proto in port_rules:
                try:
                    self.add_security_group_rule(
                        security_group_id=sg_id,
                        port_min=min_p,
                        port_max=max_p,
                        protocol=proto,
                    )
                    range_str = f"{min_p}-{max_p}" if min_p != max_p else str(min_p)
                    print(f"[+] Security rule enabled for '{instance_name}': {range_str}/{proto} (ingress)")
                except Exception as e:
                    print(f"[!] Warning: Could not add rule for {min_p}-{max_p}/{proto} to '{sg_name}': {e}")

        return sg_id

    def ensure_ssh_security_group(self, name: str = "strato-ssh") -> str:
        """Legacy helper for backward compatibility."""
        return self.ensure_instance_security_group(instance_name=name.replace("-ssh", ""), allow_ssh=True)

    def ensure_ports_security_group(self, name: str, port_rules: list) -> str:
        """Legacy helper for backward compatibility."""
        return self.ensure_instance_security_group(instance_name=name.replace("-ports", ""), allow_ssh=False, port_rules=port_rules)

    # --------------------------------------------------------------------------
    # Server / Instance Management
    # --------------------------------------------------------------------------
    def create_server(
        self,
        name: str,
        image_id: str,
        flavor_id: str,
        key_name: str,
        network_id: str,
        security_groups: list,
    ) -> dict:
        """Provision a new compute instance."""
        url = f"{self.compute_url}/servers"
        server_dict = {
            "name": name,
            "imageRef": image_id,
            "flavorRef": flavor_id,
            "key_name": key_name,
            "networks": [{"uuid": network_id}],
        }
        if security_groups:
            # Accepts list of {"name": ...}
            server_dict["security_groups"] = [{"name": sg} for sg in security_groups]

        payload = {"server": server_dict}
        data = self._request("POST", url, payload=payload)
        return data.get("server", {})

    def get_server(self, server_id: str) -> dict:
        """Fetch current instance details and status."""
        url = f"{self.compute_url}/servers/{server_id}"
        data = self._request("GET", url)
        return data.get("server", {})

    def wait_for_server(self, server_id: str, timeout: int = 300) -> dict:
        """Poll server status until it reaches ACTIVE or ERROR."""
        start_time = time.time()
        dots = 0
        while time.time() - start_time < timeout:
            server = self.get_server(server_id)
            status = server.get("status", "UNKNOWN")
            elapsed = int(time.time() - start_time)

            if status == "ACTIVE":
                print(f"\r[+] Instance status: ACTIVE! (took {elapsed}s)                    ")
                return server
            elif status == "ERROR":
                fault = server.get("fault", {}).get("message", "Unknown error")
                print(f"\r[!] Instance entered ERROR status: {fault}                        ")
                return server

            dots = (dots + 1) % 4
            status_line = f"[*] Waiting for instance to become ACTIVE... Status: {status} ({elapsed}s){'.' * dots}"
            print(f"\r{status_line:<70}", end="", flush=True)
            time.sleep(3)

        print()
        raise TimeoutError(f"Instance '{server_id}' did not reach ACTIVE within {timeout}s.")

    def list_servers(self) -> list:
        """Fetch all instances belonging to the project."""
        url = f"{self.compute_url}/servers/detail"
        data = self._request("GET", url)
        servers = data.get("servers", [])
        servers.sort(key=lambda s: s.get("name", "").lower())
        return servers

    def find_server(self, name_or_id: str) -> dict:
        """Find an instance by exact ID or name (or case-insensitive match)."""
        servers = self.list_servers()
        # 1. Exact ID
        for s in servers:
            if s.get("id") == name_or_id:
                return s
        # 2. Exact Name
        for s in servers:
            if s.get("name") == name_or_id:
                return s
        # 3. Case-insensitive exact name
        for s in servers:
            if s.get("name", "").lower() == name_or_id.lower():
                return s
        # 4. Case-insensitive substring
        matches = [s for s in servers if name_or_id.lower() in s.get("name", "").lower()]
        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            names = ", ".join([f"'{m.get('name')}' ({m.get('id')[:8]})" for m in matches])
            raise ValueError(f"Multiple instances matched '{name_or_id}': {names}. Please specify exact name or ID.")
        return None

    def stop_server(self, server_id: str) -> None:
        """Stop an instance (power off)."""
        url = f"{self.compute_url}/servers/{server_id}/action"
        self._request("POST", url, payload={"os-stop": None})

    def start_server(self, server_id: str) -> None:
        """Start an instance (power on)."""
        url = f"{self.compute_url}/servers/{server_id}/action"
        self._request("POST", url, payload={"os-start": None})

    def reboot_server(self, server_id: str, reboot_type: str = "SOFT") -> None:
        """Reboot an instance (SOFT or HARD)."""
        url = f"{self.compute_url}/servers/{server_id}/action"
        self._request("POST", url, payload={"reboot": {"type": reboot_type}})

    def delete_server(self, server_id: str) -> None:
        """Terminate and permanently delete an instance."""
        url = f"{self.compute_url}/servers/{server_id}"
        self._request("DELETE", url)

    def release_floating_ip(self, floating_ip_id: str) -> None:
        """Release a floating IP back to the pool."""
        url = f"{self.network_url}/v2.0/floatingips/{floating_ip_id}"
        self._request("DELETE", url)

    def wait_for_server_status(self, server_id: str, target_status: str, timeout: int = 120) -> dict:
        """Poll server status until it reaches target_status (e.g. SHUTOFF, ACTIVE, or DELETED)."""
        start_time = time.time()
        dots = 0
        status = "UNKNOWN"
        while time.time() - start_time < timeout:
            elapsed = int(time.time() - start_time)
            try:
                server = self.get_server(server_id)
                status = server.get("status", "UNKNOWN")
                if status == target_status:
                    print(f"\r[+] Instance reached status '{target_status}'! ({elapsed}s)          ")
                    return server
            except Exception as e:
                if target_status == "DELETED" and ("404" in str(e) or "not found" in str(e).lower()):
                    print(f"\r[+] Instance successfully deleted! ({elapsed}s)                     ")
                    return {}
                if target_status != "DELETED":
                    raise

            dots = (dots + 1) % 4
            status_line = f"[*] Waiting for status '{target_status}'... Current: {status} ({elapsed}s){'.' * dots}"
            print(f"\r{status_line:<70}", end="", flush=True)
            time.sleep(2)

        print()
        if target_status == "DELETED":
            return {}
        raise TimeoutError(f"Instance '{server_id}' did not reach status '{target_status}' within {timeout}s.")

    # --------------------------------------------------------------------------
    # Floating IP Management
    # --------------------------------------------------------------------------
    def get_server_port(self, server_id: str, max_retries: int = 10) -> dict:
        """Find the Neutron port associated with the server, with retry polling."""
        url = f"{self.network_url}/v2.0/ports?device_id={server_id}"
        for _ in range(max_retries):
            data = self._request("GET", url)
            ports = data.get("ports", [])
            if ports:
                return ports[0]
            time.sleep(2)
        return {}

    def list_floating_ips(self) -> list:
        """Fetch all project floating IPs."""
        url = f"{self.network_url}/v2.0/floatingips"
        data = self._request("GET", url)
        return data.get("floatingips", [])

    def allocate_and_attach_floating_ip(self, server_id: str, external_net_id: str) -> str:
        """
        Allocate or reuse an unassociated floating IP from the external network
        and bind it to the server's network interface port.
        """
        # Find server port
        port = self.get_server_port(server_id)
        port_id = port.get("id")

        if not port_id:
            raise RuntimeError(f"Could not find network interface port for instance '{server_id}'")

        # Check if an unassociated floating IP already exists in project pool
        existing_fips = self.list_floating_ips()
        reusable_fip = None
        for fip in existing_fips:
            if (
                fip.get("floating_network_id") == external_net_id
                and not fip.get("port_id")
                and fip.get("status") in ("DOWN", "ACTIVE")
            ):
                reusable_fip = fip
                break

        if reusable_fip:
            fip_id = reusable_fip.get("id")
            url = f"{self.network_url}/v2.0/floatingips/{fip_id}"
            payload = {"floatingip": {"port_id": port_id}}
            data = self._request("PUT", url, payload=payload)
            return data.get("floatingip", {}).get("floating_ip_address", reusable_fip.get("floating_ip_address"))
        else:
            url = f"{self.network_url}/v2.0/floatingips"
            payload = {
                "floatingip": {
                    "floating_network_id": external_net_id,
                    "port_id": port_id,
                    "description": f"Auto-allocated for instance {server_id}",
                }
            }
            data = self._request("POST", url, payload=payload)
            fip = data.get("floatingip", {})
            return fip.get("floating_ip_address", "")


# ==============================================================================
# Quota Analysis & Verification
# ==============================================================================
class QuotaChecker:
    """Evaluates project limits and checks whether requested flavors fit quota."""

    def __init__(self, limits: dict):
        self.max_instances = limits.get("maxTotalInstances", -1)
        self.used_instances = limits.get("totalInstancesUsed", 0)

        self.max_cores = limits.get("maxTotalCores", -1)
        self.used_cores = limits.get("totalCoresUsed", 0)

        self.max_ram_mb = limits.get("maxTotalRAMSize", -1)
        self.used_ram_mb = limits.get("totalRAMUsed", 0)

        # Calculate remaining
        self.free_instances = (
            (self.max_instances - self.used_instances) if self.max_instances != -1 else float("inf")
        )
        self.free_cores = (
            (self.max_cores - self.used_cores) if self.max_cores != -1 else float("inf")
        )
        self.free_ram_mb = (
            (self.max_ram_mb - self.used_ram_mb) if self.max_ram_mb != -1 else float("inf")
        )

    def print_quota_table(self):
        """Display an ASCII table summarizing quota limits and usage."""
        print("=" * 72)
        print(" PROJECT RESOURCE QUOTA & USAGE OVERVIEW")
        print("=" * 72)
        header = f"{'Resource':<16} | {'Used':<10} | {'Max Quota':<12} | {'Remaining':<12} | {'Status':<10}"
        print(header)
        print("-" * 72)

        def fmt_row(name, used_val, max_val, free_val, is_ram=False):
            unit = " GB" if is_ram else ""
            if is_ram:
                used_str = f"{used_val / 1024:.1f}{unit}"
                max_str = f"{max_val / 1024:.1f}{unit}" if max_val != -1 else "Unlimited"
                free_str = f"{free_val / 1024:.1f}{unit}" if free_val != float("inf") else "Unlimited"
            else:
                used_str = str(used_val)
                max_str = str(max_val) if max_val != -1 else "Unlimited"
                free_str = str(free_val) if free_val != float("inf") else "Unlimited"
            status = "OK" if free_val > 0 else "EXHAUSTED"
            print(f"{name:<16} | {used_str:<10} | {max_str:<12} | {free_str:<12} | {status:<10}")

        fmt_row("Instances", self.used_instances, self.max_instances, self.free_instances)
        fmt_row("vCPUs (Cores)", self.used_cores, self.max_cores, self.free_cores)
        fmt_row("RAM (Memory)", self.used_ram_mb, self.max_ram_mb, self.free_ram_mb, is_ram=True)
        print("=" * 72)

    def check_flavor(self, flavor: dict) -> tuple:
        """
        Returns (fits_quota: bool, reason: str).
        Evaluates instances, vCPUs, and RAM.
        """
        vcpus = flavor.get("vcpus", 1)
        ram_mb = flavor.get("ram", 512)

        if self.free_instances <= 0:
            return False, "Project instance quota reached (0 instances remaining)"

        if vcpus > self.free_cores:
            return (
                False,
                f"Needs {vcpus} vCPU(s), but only {int(self.free_cores)} core(s) free in quota",
            )

        if ram_mb > self.free_ram_mb:
            req_gb = ram_mb / 1024.0
            free_gb = self.free_ram_mb / 1024.0
            return (
                False,
                f"Needs {req_gb:.1f} GB RAM, but only {free_gb:.1f} GB free in quota",
            )

        return True, "Fits within available quota"


# ==============================================================================
# SSH Key Management
# ==============================================================================
def resolve_or_create_ssh_key(
    client: OpenStackClient,
    requested_key_name: str = None,
    custom_key_path: str = None,
    interactive: bool = False,
) -> tuple:
    """
    Ensures an SSH keypair exists in OpenStack.
    If none exist or requested key does not exist:
    - Generates a new keypair in OpenStack
    - Saves the private key locally to ~/.ssh/<key_name>.pem with 0600 permissions
    Returns (key_name, local_private_key_path).
    """
    existing_keys = client.list_keypairs()
    existing_names = {k.get("name"): k for k in existing_keys}

    # If key was explicitly requested and already exists
    if requested_key_name and requested_key_name in existing_names:
        # Check if local matching key file exists
        candidate_paths = [
            custom_key_path,
            os.path.expanduser(f"~/.ssh/{requested_key_name}.pem"),
            os.path.expanduser(f"~/.ssh/{requested_key_name}"),
            os.path.expanduser(f"~/.ssh/id_rsa"),
            os.path.expanduser(f"~/.ssh/id_ed25519"),
        ]
        found_local = None
        for p in candidate_paths:
            if p and os.path.isfile(p):
                found_local = p
                break
        return requested_key_name, found_local

    # If in interactive mode and keys exist, let user choose or create new
    if interactive and existing_keys and not requested_key_name:
        print(f"\n[+] Found {len(existing_keys)} existing SSH keypair(s) in OpenStack:")
        key_list = list(existing_names.keys())
        for idx, k_name in enumerate(key_list, 1):
            fp = existing_names[k_name].get("fingerprint", "")
            print(f"    [{idx}] {k_name} (fingerprint: {fp})")
        print(f"    [{len(key_list) + 1}] [+] Create and download a NEW keypair from OpenStack")

        while True:
            try:
                choice = input(f"Select SSH keypair [1-{len(key_list) + 1}]: ").strip()
                if not choice:
                    choice = "1"
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(key_list):
                    chosen_name = key_list[c_idx]
                    local_p = os.path.expanduser(f"~/.ssh/{chosen_name}.pem")
                    if not os.path.isfile(local_p):
                        local_p = os.path.expanduser(f"~/.ssh/{chosen_name}")
                        if not os.path.isfile(local_p):
                            local_p = None
                    return chosen_name, local_p
                elif c_idx == len(key_list):
                    break  # Create new
            except ValueError:
                print("Please enter a valid number.")
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)

    # Need to create a new keypair
    if not requested_key_name:
        if interactive:
            default_new_name = f"strato-key-{datetime.datetime.now().strftime('%Y%m%d')}"
            try:
                val = input(f"Enter name for new SSH keypair [{default_new_name}]: ").strip()
                requested_key_name = val if val else default_new_name
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)
        else:
            requested_key_name = f"strato-key-{datetime.datetime.now().strftime('%Y%m%d%H%M')}"

    print(f"\n[*] Creating new OpenStack keypair '{requested_key_name}'...")
    keypair_data = client.create_keypair(requested_key_name)
    private_key_text = keypair_data.get("private_key")
    if not private_key_text:
        raise RuntimeError("OpenStack did not return a private key during keypair creation.")

    # Determine local save path
    if custom_key_path:
        local_path = os.path.abspath(custom_key_path)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(private_key_text)
    else:
        ssh_dir = os.path.expanduser("~/.ssh")
        try:
            os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
            candidate = os.path.join(ssh_dir, f"{requested_key_name}.pem")
            with open(candidate, "w", encoding="utf-8") as f:
                f.write(private_key_text)
            local_path = candidate
        except Exception:
            local_path = os.path.abspath(f"{requested_key_name}.pem")
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(private_key_text)

    try:
        os.chmod(local_path, 0o600)
    except Exception:
        pass

    # Save public key if available
    public_key_text = keypair_data.get("public_key")
    if public_key_text:
        try:
            with open(f"{local_path}.pub", "w", encoding="utf-8") as f:
                f.write(public_key_text.strip() + "\n")
        except Exception:
            pass

    print(f"[+] Keypair successfully created in OpenStack!")
    print(f"[+] Private key saved locally to: {local_path}")
    print(f"[+] File permissions set to 0600 (read/write by owner only).")

    return requested_key_name, local_path


# ==============================================================================
# OS Distribution & Default User Detection
# ==============================================================================
def detect_default_ssh_user(image_name: str) -> str:
    """Identify the default SSH user based on common Linux distribution image names."""
    name = image_name.lower()
    if "ubuntu" in name:
        return "ubuntu"
    elif "debian" in name:
        return "debian"
    elif "rocky" in name:
        return "rocky"
    elif "alma" in name or "almalinux" in name:
        return "almalinux"
    elif "centos" in name:
        return "centos"
    elif "fedora" in name:
        return "fedora"
    elif "arch" in name:
        return "arch"
    elif "cirros" in name:
        return "cirros"
    elif "rhel" in name or "redhat" in name:
        return "cloud-user"
    return "ubuntu"


# ==============================================================================
# Port & Range Specification Parser
# ==============================================================================
def parse_port_specs(port_str: str) -> list:
    """
    Parse a string of ports and port ranges into a list of (min_port, max_port, protocol).
    Examples:
      '80' -> [(80, 80, 'tcp')]
      '8000-8080' -> [(8000, 8080, 'tcp')]
      '80, 443, 8000-8080, 53/udp' -> [(80, 80, 'tcp'), (443, 443, 'tcp'), (8000, 8080, 'tcp'), (53, 53, 'udp')]
    """
    if not port_str:
        return []

    rules = []
    tokens = [t.strip() for t in re.split(r"[,;\s]+", port_str) if t.strip()]

    for token in tokens:
        protocol = "tcp"
        if "/" in token:
            port_part, proto_part = token.split("/", 1)
            protocol = proto_part.lower().strip()
            if protocol not in ("tcp", "udp"):
                raise ValueError(f"Unsupported protocol '{protocol}' in '{token}'. Use 'tcp' or 'udp'.")
        else:
            port_part = token

        if "-" in port_part:
            min_s, max_s = port_part.split("-", 1)
            try:
                min_p, max_p = int(min_s.strip()), int(max_s.strip())
            except ValueError:
                raise ValueError(f"Invalid port range '{token}'.")
        else:
            try:
                min_p = max_p = int(port_part.strip())
            except ValueError:
                raise ValueError(f"Invalid port number '{token}'.")

        if not (1 <= min_p <= 65535 and 1 <= max_p <= 65535):
            raise ValueError(f"Port numbers in '{token}' must be between 1 and 65535.")
        if min_p > max_p:
            min_p, max_p = max_p, min_p

        rules.append((min_p, max_p, protocol))

    return rules


# ==============================================================================
# Dynamic Interactive CLI Wizard
# ==============================================================================
def run_interactive_wizard(
    client: OpenStackClient, quota: QuotaChecker, args: argparse.Namespace = None
) -> dict:
    """Guides user step-by-step through configuring and creating an instance."""
    print("\n" + "=" * 72)
    print(" AAU Strato - Dynamic Instance Creation Wizard")
    print("=" * 72)

    # 1. Instance Name
    if args and args.name:
        instance_name = args.name.strip()
        print(f"\n[1/7] Instance Name: '{instance_name}' (from --name, skipping prompt)")
    else:
        default_name = f"strato-vm-{datetime.datetime.now().strftime('%m%d-%H%M')}"
        instance_name = input(f"\n[1/7] Instance Name [{default_name}]: ").strip()
        if not instance_name:
            instance_name = default_name

    # 2. Select Image
    selected_image = None
    if args and args.image:
        images = client.list_images()
        for img in images:
            if args.image == img.get("id") or args.image.lower() in img.get("name", "").lower():
                selected_image = img
                print(f"\n[2/7] Image: '{selected_image.get('name')}' (from --image, skipping prompt)")
                break
        if not selected_image:
            print(f"\n[2/7] Image: Specified '{args.image}' not found, displaying available images...")

    if not selected_image:
        print("\n[2/7] Fetching available Images from Glance...")
        images = client.list_images()
        if not images:
            raise RuntimeError("No active images found in OpenStack project.")

        print(f"[+] Available Images ({len(images)} found):")
        for idx, img in enumerate(images, 1):
            size_gb = img.get("size", 0) / (1024**3)
            size_str = f"{size_gb:.1f} GB" if size_gb >= 0.1 else "N/A"
            print(f"    [{idx:>2}] {img.get('name')} (Min Disk: {img.get('min_disk', 0)}GB, Size: {size_str})")

        while not selected_image:
            try:
                choice = input(f"Select Image [1-{len(images)}] (default: 1): ").strip()
                if not choice:
                    choice = "1"
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(images):
                    selected_image = images[c_idx]
            except ValueError:
                print("Please enter a valid number.")

    # 3. Select Flavor (Quota-Aware: Only list flavors that fit remaining quota)
    all_flavors = client.list_flavors()
    if not all_flavors:
        raise RuntimeError("No flavors found in OpenStack.")

    # Only include flavors that fit within the remaining quota
    flavors = [flv for flv in all_flavors if quota.check_flavor(flv)[0]]

    if not flavors:
        print("[!] No flavors fit within your project's remaining quota!")
        quota.print_quota_table()
        raise RuntimeError(
            "Cannot create instance: project resource quota has been exhausted. "
            "Please delete unused instances or request a quota increase."
        )

    selected_flavor = None
    if args and args.flavor:
        for flv in flavors:
            if args.flavor in (flv.get("id"), flv.get("name")):
                selected_flavor = flv
                print(f"\n[3/7] Flavor: '{selected_flavor.get('name')}' (from --flavor, skipping prompt)")
                break
        if not selected_flavor:
            exceeded = [f for f in all_flavors if args.flavor in (f.get("id"), f.get("name"))]
            if exceeded:
                _, reason = quota.check_flavor(exceeded[0])
                print(f"\n[3/7] Specified flavor '{args.flavor}' exceeds quota: {reason}")
            else:
                print(f"\n[3/7] Specified flavor '{args.flavor}' not found.")
            print("[*] Please select a flavor that fits within quota from the list below.")

    if not selected_flavor:
        print("\n[3/7] Fetching compute Flavors and evaluating against quota...")
        # Default to first flavor that fits quota and has >= 1 vCPU and >= 1 GB RAM
        default_flv_idx = 1
        for idx, flv in enumerate(flavors, 1):
            if flv.get("vcpus", 1) >= 1 and flv.get("ram", 0) >= 1024:
                default_flv_idx = idx
                break

        exceeded_count = len(all_flavors) - len(flavors)
        exceeded_note = f" ({exceeded_count} larger flavor(s) omitted due to quota)" if exceeded_count > 0 else ""
        print(f"[+] Available Flavors ({len(flavors)} within quota{exceeded_note}):")
        for idx, flv in enumerate(flavors, 1):
            vcpus = flv.get("vcpus", 1)
            ram_gb = flv.get("ram", 512) / 1024.0
            disk_gb = flv.get("disk", 0)
            suggest_tag = " (Suggested)" if idx == default_flv_idx else ""
            print(
                f"    [{idx:>2}] {flv.get('name'):<16} | {vcpus:>2} vCPU | {ram_gb:>4.1f} GB RAM | {disk_gb:>3} GB Disk{suggest_tag}"
            )

        while not selected_flavor:
            try:
                choice = input(f"Select Flavor [1-{len(flavors)}] (default: {default_flv_idx}): ").strip()
                if not choice:
                    choice = str(default_flv_idx)
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(flavors):
                    selected_flavor = flavors[c_idx]
            except ValueError:
                print("Please enter a valid number.")

    # 4. Select Network
    networks = client.list_networks()
    tenant_nets = [n for n in networks if not n.get("router:external")]
    ext_nets = [n for n in networks if n.get("router:external")]

    selected_network = None
    if args and args.network:
        for net in networks:
            if args.network in (net.get("id"), net.get("name")):
                selected_network = net
                print(f"\n[4/7] Network: '{selected_network.get('name')}' (from --network, skipping prompt)")
                break
        if not selected_network:
            print(f"[!] Warning: Specified network '{args.network}' not found.")

    if not selected_network:
        print("\n[4/7] Fetching project networks...")
        available_nets = tenant_nets if tenant_nets else list(networks)
        if not available_nets:
            raise RuntimeError("No existing networks found in your OpenStack project.")

        if len(available_nets) == 1:
            selected_network = available_nets[0]
            print(f"[*] Automatically selecting network: {selected_network.get('name')}")
        else:
            print("[+] Available Networks:")
            for idx, net in enumerate(available_nets, 1):
                ext_tag = " [External/Public]" if net.get("router:external") else ""
                print(f"    [{idx}] {net.get('name')}{ext_tag} (ID: {net.get('id')})")
            while not selected_network:
                try:
                    choice = input(f"Select Network [1-{len(available_nets)}] (default: 1): ").strip()
                    if not choice:
                        choice = "1"
                    c_idx = int(choice) - 1
                    if 0 <= c_idx < len(available_nets):
                        selected_network = available_nets[c_idx]
                except ValueError:
                    print("Please enter a valid number.")

    # 5. SSH Keypair
    if args and args.key_name:
        key_name, local_key_path = resolve_or_create_ssh_key(
            client,
            requested_key_name=args.key_name,
            custom_key_path=args.key_file if args else None,
            interactive=False,
        )
        print(f"\n[5/7] SSH Keypair: '{key_name}' (from --key-name, skipping prompt)")
    else:
        print("\n[5/7] Configuring SSH Keypair...")
        key_name, local_key_path = resolve_or_create_ssh_key(
            client,
            requested_key_name=None,
            custom_key_path=args.key_file if args else None,
            interactive=True,
        )

    # 6. Security Group & Ingress Ports
    print("\n[6/7] Configuring Security Groups & Ingress Ports...")
    sgs = client.list_security_groups()
    default_sg = next((sg for sg in sgs if sg.get("name") == "default"), None)
    base_sg_name = (
        (args.secgroup if args and args.secgroup else None)
        or (default_sg.get("name") if default_sg else (sgs[0].get("name") if sgs else "default"))
    )
    print(f"[*] Base security group: '{base_sg_name}'")
    ensure_ssh = input("Ensure SSH (port 22) and ICMP (ping) ingress rules are enabled? [Y/n]: ").strip().lower()
    allow_ssh = ensure_ssh != "n"

    # Ingress Port / Port Range configuration
    port_rules = []
    if args and args.ports:
        raw_ports = args.ports
        print(f"[*] Ingress Ports: '{raw_ports}' (from --ports, skipping prompt)")
    else:
        port_prompt = "Additional port(s) or port range(s) to open (e.g. '80, 443, 8000-8080', or Enter for none): "
        raw_ports = input(port_prompt).strip()

    if raw_ports:
        try:
            port_rules = parse_port_specs(raw_ports)
        except Exception as e:
            print(f"[!] Warning: Could not parse ports '{raw_ports}': {e}")

    # Build dedicated instance security group if SSH or custom ports are enabled
    selected_sgs = [base_sg_name]
    configured_ports = []
    if allow_ssh or port_rules:
        inst_sg_name = f"{instance_name}-sg"
        client.ensure_instance_security_group(
            instance_name=instance_name,
            allow_ssh=allow_ssh,
            port_rules=port_rules,
        )
        if inst_sg_name not in selected_sgs:
            selected_sgs.append(inst_sg_name)

        if allow_ssh:
            configured_ports.append("22/tcp (SSH)")
            configured_ports.append("ICMP (ping)")
        if port_rules:
            for p_min, p_max, proto in port_rules:
                range_str = f"{p_min}-{p_max}" if p_min != p_max else str(p_min)
                configured_ports.append(f"{range_str}/{proto}")

    # 7. Floating IP
    enable_fip = True
    if selected_network.get("router:external"):
        print(
            f"\n[7/7] Floating IP: Note: '{selected_network.get('name')}' is an external network. Instance will receive a public IP directly."
        )
        enable_fip = False
    elif args and args.floating_ip is not None:
        enable_fip = args.floating_ip
        print(f"\n[7/7] Floating IP: {'Enabled' if enable_fip else 'Disabled'} (from CLI flag, skipping prompt)")
    elif ext_nets:
        print("\n[7/7] Floating (Public) IP configuration...")
        fip_choice = input(
            f"Allocate and attach a Public Floating IP from '{ext_nets[0].get('name')}'? [Y/n]: "
        ).strip().lower()
        if fip_choice:
            enable_fip = fip_choice == "y"
        else:
            enable_fip = True
    else:
        print("\n[7/7] Note: No external floating IP network detected in project.")
        enable_fip = False

    # Summary
    print("\n" + "=" * 72)
    print(" INSTANCE LAUNCH CONFIGURATION SUMMARY")
    print("=" * 72)
    print(f" Instance Name:   {instance_name}")
    print(f" Image:           {selected_image.get('name')} ({selected_image.get('id')[:8]}...)")
    print(
        f" Flavor:          {selected_flavor.get('name')} ({selected_flavor.get('vcpus')} vCPUs, {selected_flavor.get('ram')/1024:.1f} GB RAM, {selected_flavor.get('disk')} GB Disk)"
    )
    print(f" Network:         {selected_network.get('name')} ({selected_network.get('id')[:8]}...)")
    print(f" SSH Keypair:     {key_name} (Local: {local_key_path or 'Not specified'})")
    print(f" Security Groups: {', '.join(selected_sgs)}")
    if configured_ports:
        print(f" Open Ports:      {', '.join(configured_ports)}")
    print(f" Floating IP:     {'Yes' if enable_fip else 'No'}")
    print("=" * 72)

    proceed = input("\nReady to launch instance? [Y/n]: ").strip().lower()
    if proceed == "n":
        print("Launch cancelled by user.")
        sys.exit(0)

    return {
        "name": instance_name,
        "image": selected_image,
        "flavor": selected_flavor,
        "network": selected_network,
        "key_name": key_name,
        "local_key_path": local_key_path,
        "security_groups": selected_sgs,
        "open_ports": configured_ports,
        "floating_ip": enable_fip,
        "external_network": ext_nets[0] if ext_nets else None,
    }


# ==============================================================================
# One-Command Non-Interactive Execution
# ==============================================================================
def resolve_one_command_params(client: OpenStackClient, quota: QuotaChecker, args: argparse.Namespace) -> dict:
    """Resolves parameters for single-command CLI setup."""
    # Instance Name
    instance_name = args.name or f"strato-vm-{datetime.datetime.now().strftime('%m%d-%H%M')}"

    # Image
    images = client.list_images()
    if not images:
        raise RuntimeError("No active images found in OpenStack.")

    selected_image = None
    if args.image:
        # Match by ID or case-insensitive substring
        for img in images:
            if args.image == img.get("id") or args.image.lower() in img.get("name", "").lower():
                selected_image = img
                break
        if not selected_image:
            raise ValueError(f"Image matching '{args.image}' not found.")
    else:
        # Default to newest Ubuntu or first image
        ubuntu_imgs = [img for img in images if "ubuntu" in img.get("name", "").lower()]
        selected_image = ubuntu_imgs[0] if ubuntu_imgs else images[0]

    # Flavor
    flavors = client.list_flavors()
    if not flavors:
        raise RuntimeError("No flavors found in OpenStack.")

    selected_flavor = None
    if args.flavor:
        for flv in flavors:
            if args.flavor in (flv.get("id"), flv.get("name")):
                selected_flavor = flv
                break
        if not selected_flavor:
            raise ValueError(f"Flavor '{args.flavor}' not found.")
    else:
        # Find a flavor that fits quota (prefer small/medium)
        for flv in flavors:
            fits, _ = quota.check_flavor(flv)
            if fits and flv.get("vcpus", 1) >= 1 and flv.get("ram", 0) >= 1024:
                selected_flavor = flv
                break
        if not selected_flavor:
            selected_flavor = flavors[0]

    # Quota check
    fits, reason = quota.check_flavor(selected_flavor)
    if not fits and not args.yes:
        print(f"[!] Warning: Flavor '{selected_flavor.get('name')}' exceeds quota: {reason}")
        confirm = input("Proceed anyway? [y/N]: ").strip().lower()
        if confirm != "y":
            sys.exit(1)

    # Network
    networks = client.list_networks()
    tenant_nets = [n for n in networks if not n.get("router:external")]
    ext_nets = [n for n in networks if n.get("router:external")]

    if not tenant_nets:
        if networks:
            tenant_nets = list(networks)
        else:
            print("[*] No networks found in project. Auto-creating private network 'strato-net'...")
            ext_id = ext_nets[0].get("id") if ext_nets else None
            new_net = client.auto_create_network_topology(ext_net_id=ext_id)
            tenant_nets = [new_net]

    selected_network = None
    if args.network:
        for net in tenant_nets:
            if args.network in (net.get("id"), net.get("name")):
                selected_network = net
                break
        if not selected_network:
            for net in networks:
                if args.network in (net.get("id"), net.get("name")):
                    selected_network = net
                    break
        if not selected_network:
            raise ValueError(f"Network '{args.network}' not found.")
    else:
        selected_network = tenant_nets[0]

    # SSH Keypair
    key_name, local_key_path = resolve_or_create_ssh_key(
        client,
        requested_key_name=args.key_name,
        custom_key_path=args.key_file,
        interactive=False,
    )

    # Security Group & Dedicated Instance Firewall
    base_sg_name = args.secgroup if args.secgroup else "default"
    selected_sgs = [base_sg_name]

    port_rules = []
    if args.ports:
        port_rules = parse_port_specs(args.ports)

    # Dedicated instance-specific security group ensures ports do not leak to other VMs
    inst_sg_name = f"{instance_name}-sg"
    client.ensure_instance_security_group(
        instance_name=instance_name,
        allow_ssh=True,
        port_rules=port_rules,
    )
    if inst_sg_name not in selected_sgs:
        selected_sgs.append(inst_sg_name)

    configured_ports = ["22/tcp (SSH)", "ICMP (ping)"]
    if port_rules:
        for p_min, p_max, proto in port_rules:
            range_str = f"{p_min}-{p_max}" if p_min != p_max else str(p_min)
            configured_ports.append(f"{range_str}/{proto}")

    # Floating IP
    if selected_network.get("router:external"):
        enable_fip = False
    else:
        enable_fip = args.floating_ip if args.floating_ip is not None else bool(ext_nets)

    return {
        "name": instance_name,
        "image": selected_image,
        "flavor": selected_flavor,
        "network": selected_network,
        "key_name": key_name,
        "local_key_path": local_key_path,
        "security_groups": selected_sgs,
        "open_ports": configured_ports,
        "floating_ip": enable_fip,
        "external_network": ext_nets[0] if ext_nets else None,
    }


# ==============================================================================
# Instance Provisioning & Post-Launch Handling
# ==============================================================================
def deploy_instance(client: OpenStackClient, config: dict, wait: bool = True) -> dict:
    """Executes server creation, waits for ACTIVE state, and attaches Floating IP."""
    print(f"\n[*] Requesting server creation: '{config['name']}'...")
    server = client.create_server(
        name=config["name"],
        image_id=config["image"]["id"],
        flavor_id=config["flavor"]["id"],
        key_name=config["key_name"],
        network_id=config["network"]["id"],
        security_groups=config["security_groups"],
    )
    server_id = server.get("id")
    print(f"[+] Server creation initiated! Server ID: {server_id}")

    if not wait:
        print("[*] --no-wait specified. Returning immediately.")
        return server

    # Poll status until ACTIVE
    server = client.wait_for_server(server_id)
    if server.get("status") != "ACTIVE":
        return server

    # Floating IP attachment
    floating_ip_addr = ""
    if config["floating_ip"] and config["external_network"]:
        ext_net_id = config["external_network"]["id"]
        print(f"[*] Allocating and binding Floating IP from '{config['external_network']['name']}'...")
        try:
            floating_ip_addr = client.allocate_and_attach_floating_ip(server_id, ext_net_id)
            print(f"[+] Floating IP attached: {floating_ip_addr}")
        except Exception as e:
            print(f"[!] Warning: Failed to attach floating IP: {e}")

    # Extract private IP
    addresses = server.get("addresses", {})
    private_ips = []
    for net_name, ip_list in addresses.items():
        for ip_info in ip_list:
            if ip_info.get("OS-EXT-IPS:type") == "fixed" or ip_info.get("type") == "fixed":
                private_ips.append(ip_info.get("addr"))

    target_ip = floating_ip_addr or (private_ips[0] if private_ips else "INSTANCE_IP")
    default_user = detect_default_ssh_user(config["image"].get("name", ""))
    key_flag = f"-i {config['local_key_path']} " if config.get("local_key_path") else ""
    ssh_cmd = f"ssh {key_flag}{default_user}@{target_ip}"

    # Print Final Summary
    print("\n" + "=" * 72)
    print(" INSTANCE SUCCESSFULLY DEPLOYED!")
    print("=" * 72)
    print(f" Instance Name:   {config['name']}")
    print(f" Instance ID:     {server_id}")
    print(f" Status:          {server.get('status')}")
    print(f" Flavor:          {config['flavor'].get('name')}")
    print(f" Image:           {config['image'].get('name')}")
    print(f" Private IP(s):   {', '.join(private_ips) if private_ips else 'N/A'}")
    print(f" Floating IP:     {floating_ip_addr or 'None'}")
    if config.get("open_ports"):
        print(f" Open Ports:      {', '.join(config['open_ports'])}")
    print(f" SSH Key:         {config['key_name']} ({config.get('local_key_path') or 'Local file unknown'})")
    print("=" * 72)
    print(" SSH LOGIN COMMAND:")
    print(f"   {ssh_cmd}")
    print("=" * 72)

    if copy_to_clipboard(ssh_cmd):
        print("[+] SSH command copied to your clipboard!")

    return server


# ==============================================================================
# Instance Management Handlers (Stop, Start, Delete, List)
# ==============================================================================
def print_instances_table(client: OpenStackClient) -> None:
    """Print an ASCII table of all instances in the project."""
    servers = client.list_servers()
    print("=" * 76)
    print(" PROJECT INSTANCES OVERVIEW")
    print("=" * 76)
    if not servers:
        print("  No instances found in project.")
        print("=" * 76)
        return

    header = f"{'Instance Name':<22} | {'Status':<10} | {'IP Address(es)':<24} | {'ID':<12}"
    print(header)
    print("-" * 76)
    for s in servers:
        name = s.get("name", "Unknown")[:22]
        status = s.get("status", "UNKNOWN")
        s_id = (s.get("id", "")[:8] + "...") if s.get("id") else ""
        ips = []
        for net_name, ip_list in s.get("addresses", {}).items():
            for ip in ip_list:
                ips.append(ip.get("addr"))
        ip_str = ", ".join(ips) if ips else "None"
        if len(ip_str) > 24:
            ip_str = ip_str[:21] + "..."
        print(f"{name:<22} | {status:<10} | {ip_str:<24} | {s_id:<12}")
    print("=" * 76)


def handle_stop_instance(client: OpenStackClient, name_or_id: str = None, wait: bool = True) -> None:
    """Stop an instance."""
    if not name_or_id:
        servers = client.list_servers()
        if not servers:
            print("[!] No instances found in project.")
            return
        active_servers = [s for s in servers if s.get("status") == "ACTIVE"]
        display_list = active_servers if active_servers else servers
        print(f"\nSelect instance to STOP ({len(display_list)} available):")
        for idx, s in enumerate(display_list, 1):
            print(f"  [{idx}] {s.get('name')} (ID: {s.get('id')[:8]}...) | Status: {s.get('status')}")
        while True:
            choice = input(f"Select instance [1-{len(display_list)}]: ").strip()
            try:
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(display_list):
                    server = display_list[c_idx]
                    break
            except ValueError:
                pass
    else:
        server = client.find_server(name_or_id)
        if not server:
            print(f"[!] Error: Instance '{name_or_id}' not found.")
            return

    server_id = server.get("id")
    server_name = server.get("name")

    if server.get("status") == "SHUTOFF":
        print(f"[*] Instance '{server_name}' is already SHUTOFF.")
        return

    print(f"[*] Stopping instance '{server_name}' ({server_id})...")
    client.stop_server(server_id)

    if wait:
        client.wait_for_server_status(server_id, target_status="SHUTOFF")
    else:
        print("[+] Stop signal sent.")


def handle_start_instance(client: OpenStackClient, name_or_id: str = None, wait: bool = True) -> None:
    """Start an instance."""
    if not name_or_id:
        servers = client.list_servers()
        if not servers:
            print("[!] No instances found in project.")
            return
        shutoff_servers = [s for s in servers if s.get("status") == "SHUTOFF"]
        display_list = shutoff_servers if shutoff_servers else servers
        print(f"\nSelect instance to START ({len(display_list)} available):")
        for idx, s in enumerate(display_list, 1):
            print(f"  [{idx}] {s.get('name')} (ID: {s.get('id')[:8]}...) | Status: {s.get('status')}")
        while True:
            choice = input(f"Select instance [1-{len(display_list)}]: ").strip()
            try:
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(display_list):
                    server = display_list[c_idx]
                    break
            except ValueError:
                pass
    else:
        server = client.find_server(name_or_id)
        if not server:
            print(f"[!] Error: Instance '{name_or_id}' not found.")
            return

    server_id = server.get("id")
    server_name = server.get("name")

    if server.get("status") == "ACTIVE":
        print(f"[*] Instance '{server_name}' is already ACTIVE.")
        return

    print(f"[*] Starting instance '{server_name}' ({server_id})...")
    client.start_server(server_id)

    if wait:
        client.wait_for_server_status(server_id, target_status="ACTIVE")
    else:
        print("[+] Start signal sent.")


def handle_delete_instance(
    client: OpenStackClient,
    name_or_id: str = None,
    yes: bool = False,
    release_fip: bool = True,
    wait: bool = True,
) -> None:
    """Delete an instance and optionally release its associated floating IP."""
    if not name_or_id:
        servers = client.list_servers()
        if not servers:
            print("[!] No instances found in project.")
            return
        print(f"\nSelect instance to DELETE ({len(servers)} available):")
        for idx, s in enumerate(servers, 1):
            ips = []
            for net_name, ip_list in s.get("addresses", {}).items():
                for ip in ip_list:
                    ips.append(ip.get("addr"))
            ip_str = ", ".join(ips) if ips else "No IP"
            print(f"  [{idx}] {s.get('name')} (ID: {s.get('id')[:8]}...) | Status: {s.get('status')} | {ip_str}")
        while True:
            choice = input(f"Select instance [1-{len(servers)}]: ").strip()
            try:
                c_idx = int(choice) - 1
                if 0 <= c_idx < len(servers):
                    server = servers[c_idx]
                    break
            except ValueError:
                pass
    else:
        server = client.find_server(name_or_id)
        if not server:
            print(f"[!] Error: Instance '{name_or_id}' not found.")
            return

    server_id = server.get("id")
    server_name = server.get("name")

    # Find associated floating IPs
    associated_fips = []
    try:
        fips = client.list_floating_ips()
        server_port = client.get_server_port(server_id, max_retries=1)
        port_id = server_port.get("id") if server_port else None
        for fip in fips:
            if port_id and fip.get("port_id") == port_id:
                associated_fips.append(fip)
    except Exception:
        pass

    if not yes:
        fip_note = (
            f" (and release floating IP {associated_fips[0].get('floating_ip_address')})"
            if associated_fips
            else ""
        )
        confirm = input(
            f"Are you sure you want to PERMANENTLY DELETE '{server_name}'{fip_note}? [y/N]: "
        ).strip().lower()
        if confirm != "y":
            print("Deletion cancelled by user.")
            return

    print(f"[*] Deleting instance '{server_name}' ({server_id})...")
    client.delete_server(server_id)

    # Release floating IP if requested
    if release_fip and associated_fips:
        for fip in associated_fips:
            try:
                print(f"[*] Releasing associated floating IP '{fip.get('floating_ip_address')}'...")
                client.release_floating_ip(fip.get("id"))
                print(f"[+] Floating IP released.")
            except Exception as e:
                print(f"[!] Warning: Could not release floating IP: {e}")

    if wait:
        client.wait_for_server_status(server_id, target_status="DELETED")
        # Automatically clean up the dedicated instance security group
        for sg in client.list_security_groups():
            if sg.get("name") in (f"{server_name}-sg", f"{server_name}-ports"):
                try:
                    print(f"[*] Cleaning up dedicated security group '{sg.get('name')}'...")
                    client.delete_security_group(sg.get("id"))
                    print(f"[+] Security group '{sg.get('name')}' deleted.")
                except Exception as e:
                    print(f"[!] Note: Could not delete security group '{sg.get('name')}': {e}")
    else:
        print(f"[+] Delete command sent for '{server_name}'.")


# ==============================================================================
# Main CLI Entry Point
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Create OpenStack instances on AAU Strato dynamically or in one command with quota awareness and SSH key automation."
    )
    # Target / Specification flags
    parser.add_argument("--name", "-n", help="Instance name (default: auto-generated)", default=None)
    parser.add_argument("--image", "-i", help="Image name or ID substring (e.g. 'Ubuntu 24.04')", default=None)
    parser.add_argument("--flavor", "-f", help="Flavor name or ID (e.g. 'm1.small')", default=None)
    parser.add_argument("--network", "--net", help="Tenant network name or ID", default=None)
    parser.add_argument(
        "--key-name",
        "-k",
        help="SSH keypair name (auto-created in OpenStack & saved locally if missing)",
        default=None,
    )
    parser.add_argument(
        "--key-file",
        help="Local path to save the private key (default: ~/.ssh/<key-name>.pem)",
        default=None,
    )
    parser.add_argument("--secgroup", "-s", help="Security group name (default: 'default')", default=None)
    parser.add_argument(
        "--ports",
        "--port-range",
        help="Port(s) or port range(s) to open in security group (e.g. '80,443', '8000-8080', '53/udp')",
        default=None,
    )
    parser.add_argument(
        "--floating-ip",
        action="store_true",
        dest="floating_ip",
        default=None,
        help="Allocate and associate a public Floating IP (default: true if external net exists)",
    )
    parser.add_argument(
        "--no-floating-ip",
        action="store_false",
        dest="floating_ip",
        help="Do not attach a Floating IP",
    )
    # Execution mode flags
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive step-by-step selection wizard",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip confirmation prompts and warnings",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Do not wait for instance status to become ACTIVE",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display resolved configuration and quota validation without launching",
    )
    # Discovery query flags
    parser.add_argument("--list-instances", "--list-servers", action="store_true", help="List project instances with status & IPs")
    parser.add_argument("--list-quota", action="store_true", help="Display project quota and usage limits")
    parser.add_argument("--list-flavors", action="store_true", help="List available compute flavors with quota status")
    parser.add_argument("--list-images", action="store_true", help="List available active images")
    parser.add_argument("--list-networks", action="store_true", help="List available networks")
    parser.add_argument("--list-keys", action="store_true", help="List registered OpenStack SSH keypairs")
    # Instance management actions
    parser.add_argument(
        "--stop",
        nargs="?",
        const="",
        metavar="INSTANCE",
        help="Stop an instance (interactive selection if name/ID omitted)",
    )
    parser.add_argument(
        "--start",
        nargs="?",
        const="",
        metavar="INSTANCE",
        help="Start an instance (interactive selection if name/ID omitted)",
    )
    parser.add_argument(
        "--delete",
        nargs="?",
        const="",
        metavar="INSTANCE",
        help="Permanently delete an instance and release floating IP (interactive selection if name/ID omitted)",
    )
    # Auth flags
    parser.add_argument(
        "--rc-file",
        help="Path to sourceable OpenStack RC file (default: strato-openrc.sh)",
        default=DEFAULT_RC_FILE,
    )
    parser.add_argument("--auth-url", help="OpenStack Keystone auth URL", default=None)
    parser.add_argument("--token", help="OpenStack authentication token", default=None)
    parser.add_argument("--project-id", help="OpenStack project ID", default=None)

    args = parser.parse_args()

    # 1. Load credentials
    load_rc_file(args.rc_file)

    auth_url = args.auth_url or os.environ.get("OS_AUTH_URL") or DEFAULT_KEYSTONE_URL
    token = args.token or os.environ.get("OS_TOKEN")
    project_id = args.project_id or os.environ.get("OS_PROJECT_ID", "")

    if not token:
        print("[!] Error: No OpenStack authentication token found in environment or RC file.")
        print("    Please log in first using:")
        print("        python3 strato-login.py")
        print("    or source your OpenStack credentials:")
        print("        source strato-openrc.sh\n")
        sys.exit(1)

    # 2. Connect client
    client = OpenStackClient(auth_url=auth_url, token=token, project_id=project_id)

    # Handle management commands (list, stop, start, delete)
    if args.list_instances:
        print_instances_table(client)
        sys.exit(0)

    if args.stop is not None:
        handle_stop_instance(client, name_or_id=args.stop or None, wait=not args.no_wait)
        sys.exit(0)

    if args.start is not None:
        handle_start_instance(client, name_or_id=args.start or None, wait=not args.no_wait)
        sys.exit(0)

    if args.delete is not None:
        handle_delete_instance(
            client,
            name_or_id=args.delete or None,
            yes=args.yes,
            wait=not args.no_wait,
        )
        sys.exit(0)

    # 3. Fetch limits & initialize QuotaChecker
    try:
        limits = client.get_compute_limits()
        quota = QuotaChecker(limits)
    except Exception as e:
        print(f"[!] Warning: Could not fetch compute quota limits: {e}")
        quota = QuotaChecker({})

    # 4. Handle info listing requests
    if args.list_quota:
        quota.print_quota_table()
        sys.exit(0)

    if args.list_flavors:
        quota.print_quota_table()
        all_flavors = client.list_flavors()
        flavors = [flv for flv in all_flavors if quota.check_flavor(flv)[0]]
        exceeded_count = len(all_flavors) - len(flavors)
        exceeded_note = f" ({exceeded_count} larger flavor(s) omitted due to quota)" if exceeded_count > 0 else ""
        print(f"\nAVAILABLE FLAVORS ({len(flavors)} within quota{exceeded_note}):")
        for flv in flavors:
            print(
                f"  {flv.get('name'):<16} | {flv.get('vcpus'):>2} vCPU | {flv.get('ram')/1024:>4.1f} GB RAM | {flv.get('disk'):>3} GB Disk"
            )
        sys.exit(0)

    if args.list_images:
        images = client.list_images()
        print(f"\nAVAILABLE ACTIVE IMAGES ({len(images)}):")
        for img in images:
            size_gb = img.get("size", 0) / (1024**3)
            size_str = f"{size_gb:.1f} GB" if size_gb >= 0.1 else "N/A"
            print(f"  {img.get('name'):<40} | Min Disk: {img.get('min_disk', 0):>2} GB | Size: {size_str}")
        sys.exit(0)

    if args.list_networks:
        networks = client.list_networks()
        print(f"\nAVAILABLE NETWORKS ({len(networks)}):")
        for net in networks:
            ext_tag = "External/Floating" if net.get("router:external") else "Internal/Tenant"
            print(f"  {net.get('name'):<25} | {ext_tag:<18} | ID: {net.get('id')}")
        sys.exit(0)

    if args.list_keys:
        keys = client.list_keypairs()
        print(f"\nOPENSTACK SSH KEYPAIRS ({len(keys)}):")
        for k in keys:
            print(f"  {k.get('name'):<25} | Type: {k.get('type', 'ssh'):<6} | Fingerprint: {k.get('fingerprint')}")
        sys.exit(0)

    # 5. Determine Interactive vs One-Command Execution
    is_interactive = args.interactive or (
        sys.stdin.isatty() and not (args.name and args.image and args.flavor and args.yes)
    )

    if is_interactive and not (args.image and args.flavor):
        quota.print_quota_table()
        config = run_interactive_wizard(client, quota, args=args)
    else:
        config = resolve_one_command_params(client, quota, args)

    # 6. Dry run check
    if args.dry_run:
        print("\n" + "=" * 72)
        print(" DRY RUN - CONFIGURATION VALIDATED")
        print("=" * 72)
        print(f" Instance Name:   {config['name']}")
        print(f" Image:           {config['image'].get('name')} ({config['image'].get('id')})")
        print(f" Flavor:          {config['flavor'].get('name')} ({config['flavor'].get('id')})")
        print(f" Network:         {config['network'].get('name')} ({config['network'].get('id')})")
        print(f" SSH Key:         {config['key_name']} (Local: {config.get('local_key_path')})")
        print(f" Security Groups: {config['security_groups']}")
        print(f" Floating IP:     {config['floating_ip']}")
        print("=" * 72)
        print("[+] Dry run complete. No resources were modified.")
        sys.exit(0)

    # 7. Provision Instance
    deploy_instance(client, config, wait=not args.no_wait)


if __name__ == "__main__":
    main()
