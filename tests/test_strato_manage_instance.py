import importlib
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

smi = importlib.import_module("strato-manage-instance")


class TestManageInstancePorts(unittest.TestCase):
    def _mock_client(self):
        client = MagicMock()
        client.find_server.return_value = {
            "id": "srv-1",
            "name": "my-vm",
            "status": "ACTIVE",
        }
        client.list_server_security_groups.return_value = [
            {
                "id": "sg-1",
                "name": "my-vm-sg",
                "security_group_rules": [
                    {
                        "id": "r-1",
                        "direction": "ingress",
                        "protocol": "tcp",
                        "port_range_min": 80,
                        "port_range_max": 80,
                        "remote_ip_prefix": "0.0.0.0/0",
                        "ethertype": "IPv4",
                    },
                    {
                        "id": "r-2",
                        "direction": "ingress",
                        "protocol": "tcp",
                        "port_range_min": 8000,
                        "port_range_max": 8080,
                        "remote_ip_prefix": "0.0.0.0/0",
                        "ethertype": "IPv4",
                    },
                ],
            }
        ]
        return client

    def test_list_ports(self):
        client = self._mock_client()
        rules = smi.handle_list_ports(client, name_or_id="my-vm")
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0][0], "my-vm-sg")

    def test_add_ports_attaches_dedicated_sg_if_missing(self):
        client = MagicMock()
        client.find_server.return_value = {
            "id": "srv-2",
            "name": "legacy-vm",
            "status": "ACTIVE",
        }
        client.list_server_security_groups.return_value = [
            {"id": "sg-def", "name": "default", "security_group_rules": []}
        ]

        smi.handle_add_ports(
            client, name_or_id="legacy-vm", ports_str="443, 9000-9010/udp"
        )

        client.ensure_instance_security_group.assert_called_once_with(
            instance_name="legacy-vm",
            allow_ssh=False,
            port_rules=[(443, 443, "tcp"), (9000, 9010, "udp")],
        )
        client.add_security_group_to_server.assert_called_once_with(
            "srv-2", "legacy-vm-sg"
        )

    def test_remove_ports_by_spec(self):
        client = self._mock_client()
        smi.handle_remove_ports(client, name_or_id="my-vm", ports_str="80, 8000-8080")
        self.assertEqual(client.delete_security_group_rule.call_count, 2)
        client.delete_security_group_rule.assert_any_call("r-1")
        client.delete_security_group_rule.assert_any_call("r-2")

    def test_remove_shared_sg_rule_requires_confirm_unless_yes(self):
        client = MagicMock()
        client.find_server.return_value = {"id": "srv-1", "name": "my-vm", "status": "ACTIVE"}
        client.list_server_security_groups.return_value = [
            {
                "id": "sg-shared",
                "name": "default",
                "security_group_rules": [
                    {
                        "id": "r-shared",
                        "direction": "ingress",
                        "protocol": "tcp",
                        "port_range_min": 22,
                        "port_range_max": 22,
                        "remote_ip_prefix": "0.0.0.0/0",
                        "ethertype": "IPv4",
                    }
                ],
            }
        ]

        with patch("builtins.input", return_value="n"):
            smi.handle_remove_ports(client, name_or_id="my-vm", ports_str="22", yes=False)
        client.delete_security_group_rule.assert_not_called()

        smi.handle_remove_ports(client, name_or_id="my-vm", ports_str="22", yes=True)
        client.delete_security_group_rule.assert_called_once_with("r-shared")


if __name__ == "__main__":
    unittest.main()
