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
    python3 strato-manage-instance.py --list-ports my-vm
    python3 strato-manage-instance.py --instance my-vm --add-ports "80, 443, 8000-8080"
    python3 strato-manage-instance.py --instance my-vm --remove-ports "8000-8080"
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


def _resolve_server(client, name_or_id: str = None) -> dict:
    """Resolve a server by name/ID or prompt the user interactively."""
    if name_or_id:
        server = client.find_server(name_or_id)
        if not server:
            raise RuntimeError(f"Instance '{name_or_id}' not found.")
        return server

    servers = client.list_servers()
    if not servers:
        raise RuntimeError("No instances found in your OpenStack project.")

    print(f"\nFound {len(servers)} instance(s) in project:")
    for idx, s in enumerate(servers, 1):
        name = s.get("name", "Unknown")
        status = s.get("status", "UNKNOWN")
        s_id = s.get("id", "")[:12] + "..."
        ips = []
        for _, ip_list in s.get("addresses", {}).items():
            for ip in ip_list:
                ips.append(ip.get("addr"))
        ip_str = ", ".join(ips) if ips else "No IP"
        print(f"  [{idx:>2}] {name:<22} | Status: {status:<8} | {ip_str:<22} (ID: {s_id})")

    while True:
        try:
            choice = input(f"\nSelect instance [1-{len(servers)}] (or 'q' to cancel): ").strip().lower()
            if choice in ("q", "quit", "exit"):
                return {}
            c_idx = int(choice) - 1
            if 0 <= c_idx < len(servers):
                return servers[c_idx]
        except ValueError:
            print("Please enter a valid number or 'q'.")


def _get_instance_ingress_rules(client, server: dict) -> list:
    """
    Return a list of (sg_name, sg_id, rule_dict) for all ingress rules
    currently attached to the instance. Dedicated <name>-sg is ordered first.
    """
    s_name = server.get("name", "")
    dedicated_sg_name = f"{s_name}-sg"
    sgs = client.list_server_security_groups(server.get("id"))

    # Sort so dedicated <instance>-sg appears first
    sgs_sorted = sorted(sgs, key=lambda g: (0 if g.get("name") == dedicated_sg_name else 1, g.get("name", "")))

    rules = []
    for sg in sgs_sorted:
        sg_name = sg.get("name", "unknown")
        sg_id = sg.get("id", "")
        sg_rules = sg.get("security_group_rules") or sg.get("rules") or []
        for r in sg_rules:
            direction = r.get("direction", "ingress")
            if direction == "ingress":
                rules.append((sg_name, sg_id, r))
    return rules


def _format_rule_summary(rule: dict) -> str:
    """Format a Neutron/Nova security group rule into a readable string."""
    proto = (rule.get("protocol") or rule.get("ip_protocol") or "any").upper()
    p_min = rule.get("port_range_min") if rule.get("port_range_min") is not None else rule.get("from_port")
    p_max = rule.get("port_range_max") if rule.get("port_range_max") is not None else rule.get("to_port")
    remote = rule.get("remote_ip_prefix") or (rule.get("ip_range") or {}).get("cidr") or "0.0.0.0/0"
    ethertype = rule.get("ethertype", "IPv4")

    if proto.lower() == "icmp":
        port_str = "ICMP"
    elif p_min is not None and p_max is not None:
        port_str = f"{p_min}" if p_min == p_max else f"{p_min}-{p_max}"
    else:
        port_str = "All Ports"

    return f"{port_str:<12} | {proto:<6} | {ethertype:<4} | From: {remote}"


def handle_list_ports(client, name_or_id: str = None) -> list:
    """Display all open ingress port rules for an instance."""
    server = _resolve_server(client, name_or_id)
    if not server:
        return []
    s_name = server.get("name")
    rules = _get_instance_ingress_rules(client, server)

    print("\n" + "-" * 76)
    print(f" Open Ingress Ports for '{s_name}'")
    print("-" * 76)
    if not rules:
        print("  (No ingress rules found)")
    else:
        for idx, (sg_name, _, r) in enumerate(rules, 1):
            print(f"  [{idx:>2}] {_format_rule_summary(r)} | SG: {sg_name}")
    return rules


def handle_add_ports(client, name_or_id: str = None, ports_str: str = None) -> None:
    """Add port or port-range openings to an instance's dedicated security group."""
    server = _resolve_server(client, name_or_id)
    if not server:
        return
    s_name = server.get("name")
    s_id = server.get("id")

    if not ports_str:
        ports_str = input("Enter port(s) or range(s) to open (e.g. '80, 443, 8000-8080, 53/udp'): ").strip()
    if not ports_str:
        print("[*] No ports specified.")
        return

    port_rules = sci.parse_port_specs(ports_str)
    if not port_rules:
        print("[!] No valid port rules parsed.")
        return

    # Ensure dedicated <instance>-sg exists with the requested port rules
    dedicated_sg_name = f"{s_name}-sg"
    client.ensure_instance_security_group(
        instance_name=s_name,
        allow_ssh=False,
        port_rules=port_rules,
    )

    # Attach dedicated SG to the instance if not already attached
    attached_sgs = client.list_server_security_groups(s_id)
    attached_names = {sg.get("name") for sg in attached_sgs}
    if dedicated_sg_name not in attached_names:
        print(f"[*] Attaching dedicated security group '{dedicated_sg_name}' to '{s_name}'...")
        client.add_security_group_to_server(s_id, dedicated_sg_name)
        print(f"[+] Security group '{dedicated_sg_name}' attached to '{s_name}'.")


def handle_remove_ports(client, name_or_id: str = None, ports_str: str = None, yes: bool = False) -> None:
    """Remove port or port-range openings from an instance."""
    server = _resolve_server(client, name_or_id)
    if not server:
        return
    s_name = server.get("name")
    dedicated_sg_name = f"{s_name}-sg"
    rules = _get_instance_ingress_rules(client, server)

    if not rules:
        print(f"\n[!] No ingress port rules found on instance '{s_name}'.")
        return

    # Interactive selection if ports_str is not provided
    if not ports_str:
        print("\n" + "-" * 76)
        print(f" Current Open Ingress Rules for '{s_name}'")
        print("-" * 76)
        for idx, (sg_name, _, r) in enumerate(rules, 1):
            tag = " (dedicated)" if sg_name == dedicated_sg_name else " (shared)"
            print(f"  [{idx:>2}] {_format_rule_summary(r)} | SG: {sg_name}{tag}")

        selection = input(
            "\nEnter rule number(s) (e.g. '1, 3') or port(s) to close (e.g. '80, 8000-8080'), or 'q' to cancel: "
        ).strip()
        if not selection or selection.lower() in ("q", "quit", "cancel"):
            print("Cancelled.")
            return

        # Check if user entered rule numbers (digits separated by commas/spaces, matching 1..len(rules))
        tokens = [t.strip() for t in selection.replace(",", " ").split() if t.strip()]
        if tokens and all(t.isdigit() and 1 <= int(t) <= len(rules) for t in tokens):
            to_delete = [rules[int(t) - 1] for t in tokens]
        else:
            # Parse as port spec
            ports_str = selection
            to_delete = None
    else:
        to_delete = None

    if to_delete is None:
        target_specs = sci.parse_port_specs(ports_str)
        to_delete = []
        for min_p, max_p, proto in target_specs:
            # Prefer matching rules in dedicated SG first, then other SGs
            matches = [
                item for item in rules
                if (item[2].get("protocol") or "").lower() == proto.lower()
                and item[2].get("port_range_min") == min_p
                and item[2].get("port_range_max") == max_p
            ]
            dedicated_matches = [m for m in matches if m[0] == dedicated_sg_name]
            if dedicated_matches:
                to_delete.extend(dedicated_matches)
            elif matches:
                to_delete.extend(matches)
            else:
                range_str = f"{min_p}-{max_p}" if min_p != max_p else str(min_p)
                print(f"[!] No matching ingress rule found for {range_str}/{proto} on '{s_name}'.")

    if not to_delete:
        return

    # Deduplicate by rule ID
    seen_ids = set()
    for sg_name, _, rule in to_delete:
        r_id = rule.get("id")
        if not r_id or r_id in seen_ids:
            continue
        seen_ids.add(r_id)

        if sg_name != dedicated_sg_name and not yes:
            confirm = input(
                f"[!] Rule ({_format_rule_summary(rule).strip()}) belongs to shared SG '{sg_name}' "
                f"and may affect other instances. Remove anyway? [y/N]: "
            ).strip().lower()
            if confirm != "y":
                print(f"[*] Skipped rule in '{sg_name}'.")
                continue

        client.delete_security_group_rule(r_id)
        p_min = rule.get("port_range_min")
        p_max = rule.get("port_range_max")
        proto = (rule.get("protocol") or "any").lower()
        if p_min is not None and p_max is not None:
            p_str = f"{p_min}-{p_max}" if p_min != p_max else str(p_min)
        else:
            p_str = proto
        print(f"[-] Removed ingress rule {p_str}/{proto} from '{sg_name}' (Instance: '{s_name}').")


def run_interactive_port_menu(client, server: dict) -> None:
    """Interactive sub-menu for viewing, adding, and removing instance ports."""
    s_name = server.get("name")
    while True:
        handle_list_ports(client, name_or_id=server.get("id"))
        print("\n  Port Options:")
        print("    [1] Add port(s) or port range(s) (e.g. '80, 443, 8000-8080')")
        print("    [2] Remove open port rule(s)")
        print("    [b] Back")
        sub = input("\nSelect port action [1-2, b]: ").strip().lower()
        if sub in ("b", "back", "q", "quit"):
            break
        elif sub == "1":
            handle_add_ports(client, name_or_id=server.get("id"))
        elif sub == "2":
            handle_remove_ports(client, name_or_id=server.get("id"))
        else:
            print("Please select 1, 2, or 'b'.")


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
        s_id = s.get("id", "") + "..."
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
    print("  [4] Manage Ports / Firewall (View, Add, or Remove Open Ports)")
    print("  [5] DELETE instance (Permanent Deletion & Release Floating IP)")
    print("  [q] Cancel")

    while True:
        action = input("\nSelect action [1-5, q]: ").strip().lower()
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
            run_interactive_port_menu(client, selected_server)
            break
        elif action == "5":
            sci.handle_delete_instance(client, name_or_id=s_id, yes=False, release_fip=True, wait=True)
            break
        else:
            print("Please select 1, 2, 3, 4, 5, or 'q'.")


def main():
    parser = argparse.ArgumentParser(
        description="Stop, start, reboot, manage ports, inspect, and delete OpenStack instances on AAU Strato."
    )
    parser.add_argument("--list", "-l", action="store_true", help="List all instances in project with statuses and IPs")
    parser.add_argument(
        "--instance",
        "-n",
        metavar="INSTANCE",
        help="Target instance name or ID (used with --add-ports / --remove-ports / --list-ports)",
        default=None,
    )
    parser.add_argument(
        "--list-ports",
        nargs="?",
        const="",
        metavar="INSTANCE",
        help="List open ingress ports for an instance (interactive selection if omitted)",
    )
    parser.add_argument(
        "--add-ports",
        metavar="PORTS",
        help="Open port(s) or port range(s) on the instance (e.g. '80, 443, 8000-8080')",
        default=None,
    )
    parser.add_argument(
        "--remove-ports",
        nargs="?",
        const="",
        metavar="PORTS",
        help="Close/remove open port(s) or port range(s) from the instance (interactive if omitted)",
    )
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

    # 2. List Ports
    if args.list_ports is not None:
        handle_list_ports(client, name_or_id=args.list_ports or args.instance or None)
        sys.exit(0)

    # 3. Add Ports
    if args.add_ports is not None:
        handle_add_ports(client, name_or_id=args.instance, ports_str=args.add_ports)
        sys.exit(0)

    # 4. Remove Ports
    if args.remove_ports is not None:
        handle_remove_ports(
            client,
            name_or_id=args.instance,
            ports_str=args.remove_ports or None,
            yes=args.yes,
        )
        sys.exit(0)

    # 5. Stop
    if args.stop is not None:
        sci.handle_stop_instance(client, name_or_id=args.stop or None, wait=not args.no_wait)
        sys.exit(0)

    # 6. Start
    if args.start is not None:
        sci.handle_start_instance(client, name_or_id=args.start or None, wait=not args.no_wait)
        sys.exit(0)

    # 7. Reboot
    if args.reboot:
        server = client.find_server(args.reboot)
        if not server:
            print(f"[!] Error: Instance '{args.reboot}' not found.")
            sys.exit(1)
        print(f"[*] Sending soft reboot signal to '{server.get('name')}' ({server.get('id')})...")
        client.reboot_server(server.get("id"), reboot_type="SOFT")
        print("[+] Reboot signal sent.")
        sys.exit(0)

    # 8. Delete
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
