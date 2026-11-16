#!/usr/bin/env python3
"""
AAU Strato Cloud Instance Management Helper
===========================================
Manage existing OpenStack instances on AAU Strato (strato-new.claaudia.aau.dk):
stop, start, reboot, inspect, and delete instances with floating IP cleanup.

Usage:
  Interactive Mode:
    python3 strato-manage-instance.py

  One-Command CLI:
    python3 strato-manage-instance.py --list
    python3 strato-manage-instance.py --stop my-vm
    python3 strato-manage-instance.py --start my-vm
    python3 strato-manage-instance.py --reboot my-vm
    python3 strato-manage-instance.py --delete my-vm --yes
"""

import argparse
import importlib
import os
import sys

# Import OpenStack client and helpers from strato-create-instance
try:
    sci = importlib.import_module("strato-create-instance")
except ImportError:
    # If executed from another directory, add script directory to sys.path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    sci = importlib.import_module("strato-create-instance")

DEFAULT_KEYSTONE_URL = "https://strato-new.claaudia.aau.dk:5000"
DEFAULT_RC_FILE = "strato-openrc.sh"


def run_interactive_manager(client) -> None:
    """Guided interactive instance management console."""
    print("=" * 76)
    print(" AAU Strato - Instance Management Console")
    print("=" * 76)

    servers = client.list_servers()
    if not servers:
        print("\n[!] No instances found in your OpenStack project.")
        print("    You can create one using:")
        print("        python3 strato-create-instance.py\n")
        return

    print(f"\nFound {len(servers)} instance(s) in project:")
    for idx, s in enumerate(servers, 1):
        name = s.get("name", "Unknown")
        status = s.get("status", "UNKNOWN")
        s_id = s.get("id", "")[:8] + "..."
        ips = []
        for net_name, ip_list in s.get("addresses", {}).items():
            for ip in ip_list:
                ips.append(ip.get("addr"))
        ip_str = ", ".join(ips) if ips else "No IP"
        print(f"  [{idx:>2}] {name:<22} | Status: {status:<8} | {ip_str:<22} (ID: {s_id})")

    selected_server = None
    while not selected_server:
        try:
            choice = input(f"\nSelect instance [1-{len(servers)}] (or 'q' to quit): ").strip().lower()
            if choice in ("q", "quit", "exit"):
                return
            c_idx = int(choice) - 1
            if 0 <= c_idx < len(servers):
                selected_server = servers[c_idx]
        except ValueError:
            print("Please enter a valid number or 'q'.")

    s_name = selected_server.get("name")
    s_id = selected_server.get("id")
    s_status = selected_server.get("status")

    print("\n" + "-" * 76)
    print(f" Management Options for '{s_name}' (Current Status: {s_status})")
    print("-" * 76)
    print("  [1] Stop instance (Power Off)")
    print("  [2] Start instance (Power On)")
    print("  [3] Reboot instance (Soft Reboot)")
    print("  [4] DELETE instance (Permanent Deletion & Release Floating IP)")
    print("  [q] Cancel")

    while True:
        action = input("\nSelect action [1-4, q]: ").strip().lower()
        if action in ("q", "cancel"):
            print("Cancelled.")
            return

        if action == "1":
            sci.handle_stop_instance(client, name_or_id=s_id, wait=True)
            break
        elif action == "2":
            sci.handle_start_instance(client, name_or_id=s_id, wait=True)
            break
        elif action == "3":
            print(f"[*] Sending reboot signal to '{s_name}'...")
            client.reboot_server(s_id, reboot_type="SOFT")
            print("[+] Reboot signal sent.")
            break
        elif action == "4":
            sci.handle_delete_instance(client, name_or_id=s_id, yes=False, release_fip=True, wait=True)
            break
        else:
            print("Please select 1, 2, 3, 4, or 'q'.")


def main():
    parser = argparse.ArgumentParser(
        description="Stop, start, reboot, inspect, and delete OpenStack instances on AAU Strato."
    )
    parser.add_argument("--list", "-l", action="store_true", help="List all instances in project with statuses and IPs")
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
        "--reboot",
        metavar="INSTANCE",
        help="Soft reboot an instance by name or ID",
        default=None,
    )
    parser.add_argument(
        "--delete",
        nargs="?",
        const="",
        metavar="INSTANCE",
        help="Permanently delete an instance and release floating IP (interactive selection if omitted)",
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt on deletion")
    parser.add_argument("--no-wait", action="store_true", help="Do not wait for action status completion")
    parser.add_argument(
        "--rc-file",
        help="Path to sourceable OpenStack RC file (default: strato-openrc.sh)",
        default=DEFAULT_RC_FILE,
    )
    parser.add_argument("--auth-url", help="OpenStack Keystone auth URL", default=None)
    parser.add_argument("--token", help="OpenStack authentication token", default=None)
    parser.add_argument("--project-id", help="OpenStack project ID", default=None)

    args = parser.parse_args()

    # Load credentials
    sci.load_rc_file(args.rc_file)

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

    client = sci.OpenStackClient(auth_url=auth_url, token=token, project_id=project_id)

    # 1. List
    if args.list:
        sci.print_instances_table(client)
        sys.exit(0)

    # 2. Stop
    if args.stop is not None:
        sci.handle_stop_instance(client, name_or_id=args.stop or None, wait=not args.no_wait)
        sys.exit(0)

    # 3. Start
    if args.start is not None:
        sci.handle_start_instance(client, name_or_id=args.start or None, wait=not args.no_wait)
        sys.exit(0)

    # 4. Reboot
    if args.reboot:
        server = client.find_server(args.reboot)
        if not server:
            print(f"[!] Error: Instance '{args.reboot}' not found.")
            sys.exit(1)
        print(f"[*] Sending soft reboot signal to '{server.get('name')}' ({server.get('id')})...")
        client.reboot_server(server.get("id"), reboot_type="SOFT")
        print("[+] Reboot signal sent.")
        sys.exit(0)

    # 5. Delete
    if args.delete is not None:
        sci.handle_delete_instance(
            client,
            name_or_id=args.delete or None,
            yes=args.yes,
            wait=not args.no_wait,
        )
        sys.exit(0)

    # Default to interactive manager if no specific action provided
    run_interactive_manager(client)


if __name__ == "__main__":
    main()
