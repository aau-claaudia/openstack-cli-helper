import argparse
import importlib
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

sci = importlib.import_module("strato-create-instance")


class TestQuotaChecker(unittest.TestCase):
    def test_flavor_within_and_exceeding_quota(self):
        limits = {
            "maxTotalInstances": 5,
            "totalInstancesUsed": 2,
            "maxTotalCores": 8,
            "totalCoresUsed": 4,
            "maxTotalRAMSize": 8192,
            "totalRAMUsed": 4096,
        }
        qc = sci.QuotaChecker(limits)

        fits_ok, _ = qc.check_flavor({"vcpus": 4, "ram": 4096})
        self.assertTrue(fits_ok)

        fits_cpu, msg_cpu = qc.check_flavor({"vcpus": 6, "ram": 2048})
        self.assertFalse(fits_cpu)
        self.assertIn("vCPU", msg_cpu)

        fits_ram, msg_ram = qc.check_flavor({"vcpus": 2, "ram": 8192})
        self.assertFalse(fits_ram)
        self.assertIn("RAM", msg_ram)

    def test_unlimited_quota_prints_cleanly(self):
        limits = {
            "maxTotalInstances": -1,
            "totalInstancesUsed": 1,
            "maxTotalCores": -1,
            "totalCoresUsed": 2,
            "maxTotalRAMSize": -1,
            "totalRAMUsed": 2048,
        }
        qc = sci.QuotaChecker(limits)
        fits, _ = qc.check_flavor({"vcpus": 64, "ram": 131072})
        self.assertTrue(fits)
        # Should not raise TypeError comparing str and int
        qc.print_quota_table()


class TestPortParserAndOSUser(unittest.TestCase):
    def test_parse_port_specs_valid(self):
        rules = sci.parse_port_specs("80, 443, 8000-8080, 53/udp, 5000-5010/udp, 9000-8000")
        self.assertEqual(
            rules,
            [
                (80, 80, "tcp"),
                (443, 443, "tcp"),
                (8000, 8080, "tcp"),
                (53, 53, "udp"),
                (5000, 5010, "udp"),
                (8000, 9000, "tcp"),
            ],
        )

    def test_parse_port_specs_invalid(self):
        with self.assertRaises(ValueError):
            sci.parse_port_specs("0")
        with self.assertRaises(ValueError):
            sci.parse_port_specs("70000")
        with self.assertRaises(ValueError):
            sci.parse_port_specs("abc")
        with self.assertRaises(ValueError):
            sci.parse_port_specs("80/sctp")

    def test_detect_default_ssh_user(self):
        self.assertEqual(sci.detect_default_ssh_user("Ubuntu 24.04 LTS"), "ubuntu")
        self.assertEqual(sci.detect_default_ssh_user("Debian 12"), "debian")
        self.assertEqual(sci.detect_default_ssh_user("Rocky Linux 9"), "rocky")
        self.assertEqual(sci.detect_default_ssh_user("AlmaLinux 9"), "almalinux")
        self.assertEqual(sci.detect_default_ssh_user("Fedora 40"), "fedora")


class TestSSHKeyManagement(unittest.TestCase):
    def test_creates_new_keypair_and_saves_private_key(self):
        client = MagicMock()
        client.list_keypairs.return_value = []
        client.create_keypair.return_value = {
            "name": "auto-key",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----\n",
            "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "auto-key.pem")
            name, saved_path = sci.resolve_or_create_ssh_key(
                client,
                requested_key_name="auto-key",
                custom_key_path=key_path,
                interactive=False,
            )

            self.assertEqual(name, "auto-key")
            self.assertEqual(saved_path, key_path)
            self.assertTrue(os.path.isfile(key_path))
            self.assertTrue(os.path.isfile(key_path + ".pub"))
            self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)


class TestSecurityGroupIsolation(unittest.TestCase):
    def test_dedicated_security_group_per_instance(self):
        client = sci.OpenStackClient.__new__(sci.OpenStackClient)
        client.network_url = "https://strato.example:9696"
        client.list_security_groups = MagicMock(return_value=[])
        client._request = MagicMock(
            side_effect=[
                {"security_group": {"id": "sg-vm1"}},  # create sg
                {},  # rule 22
                {},  # rule icmp
                {},  # rule 8000-8080
            ]
        )

        sg_id = client.ensure_instance_security_group(
            instance_name="vm1",
            allow_ssh=True,
            port_rules=[(8000, 8080, "tcp")],
        )

        self.assertEqual(sg_id, "sg-vm1")
        create_call = client._request.call_args_list[0]
        self.assertEqual(
            create_call.kwargs["payload"]["security_group"]["name"], "vm1-sg"
        )


class TestNetworkResolutionAndWizard(unittest.TestCase):
    def _mock_client(self, networks):
        client = MagicMock()
        client.list_images.return_value = [{"id": "img-1", "name": "Ubuntu 24.04"}]
        client.list_flavors.return_value = [
            {"id": "flv-1", "name": "AAU.CPU.d.4-12", "vcpus": 4, "ram": 12288, "disk": 40}
        ]
        client.list_networks.return_value = networks
        client.list_keypairs.return_value = [{"name": "my-key", "fingerprint": "abc"}]
        return client

    def test_defaults_to_campus_network_02(self):
        client = self._mock_client(
            [
                {
                    "id": "net-1",
                    "name": "other-net",
                    "router:external": False,
                    "subnets": ["sub-1"],
                    "admin_state_up": True,
                },
                {
                    "id": "net-campus",
                    "name": "Campus Network 02",
                    "router:external": True,
                    "subnets": ["sub-c"],
                    "admin_state_up": True,
                },
            ]
        )
        quota = MagicMock()
        quota.check_flavor.return_value = (True, "OK")
        args = argparse.Namespace(
            name="my-vm",
            image="Ubuntu 24.04",
            flavor="AAU.CPU.d.4-12",
            network=None,
            key_name="my-key",
            key_file=None,
            secgroup=None,
            ports=None,
            floating_ip=None,
            yes=True,
        )

        cfg = sci.resolve_one_command_params(client, quota, args)
        self.assertEqual(cfg["network"]["name"], "Campus Network 02")

    def test_skips_empty_subnet_network(self):
        client = self._mock_client(
            [
                {
                    "id": "net-empty",
                    "name": "empty-net",
                    "router:external": False,
                    "subnets": [],
                    "admin_state_up": True,
                },
                {
                    "id": "net-ok",
                    "name": "private-net",
                    "router:external": False,
                    "subnets": ["sub-1"],
                    "admin_state_up": True,
                },
            ]
        )
        quota = MagicMock()
        quota.check_flavor.return_value = (True, "OK")
        args = argparse.Namespace(
            name="my-vm",
            image="Ubuntu 24.04",
            flavor="AAU.CPU.d.4-12",
            network=None,
            key_name="my-key",
            key_file=None,
            secgroup=None,
            ports=None,
            floating_ip=None,
            yes=True,
        )

        cfg = sci.resolve_one_command_params(client, quota, args)
        self.assertEqual(cfg["network"]["id"], "net-ok")

    def test_wizard_skips_prefilled_cli_args_and_uses_existing_networks(self):
        client = self._mock_client(
            [
                {
                    "id": "net-campus",
                    "name": "Campus Network 02",
                    "router:external": True,
                    "subnets": ["sub-c"],
                    "admin_state_up": True,
                }
            ]
        )
        client.list_security_groups.return_value = [{"id": "sg-def", "name": "default"}]
        quota = MagicMock()
        quota.check_flavor.return_value = (True, "OK")
        args = argparse.Namespace(
            name="hejsa",
            image="Ubuntu 24.04",
            flavor="AAU.CPU.d.4-12",
            network=None,
            key_name="my-key",
            key_file=None,
            secgroup=None,
            ports="8080",
            floating_ip=None,
        )

        # Only prompt remaining should be SSH/ICMP confirm (Enter -> Y) and summary confirm (y)
        with patch("builtins.input", side_effect=["", "y"]):
            cfg = sci.run_interactive_wizard(client, quota, args=args)

        self.assertEqual(cfg["name"], "hejsa")
        self.assertEqual(cfg["network"]["name"], "Campus Network 02")
        self.assertIn("hejsa-sg", cfg["security_groups"])
        client.auto_create_network_topology.assert_not_called()

    def test_delete_instance_cleans_up_dedicated_sg(self):
        client = MagicMock()
        client.find_server.return_value = {
            "id": "srv-1",
            "name": "hejsa",
            "status": "ACTIVE",
            "addresses": {},
        }
        client.list_floating_ips.return_value = []
        client.list_security_groups.return_value = [
            {"id": "sg-def", "name": "default"},
            {"id": "sg-hejsa", "name": "hejsa-sg"},
        ]

        sci.handle_delete_instance(client, name_or_id="hejsa", yes=True, wait=True)

        client.delete_server.assert_called_once_with("srv-1")
        client.wait_for_server_status.assert_called_once_with("srv-1", target_status="DELETED")
        client.delete_security_group.assert_called_once_with("sg-hejsa")


if __name__ == "__main__":
    unittest.main()
