import importlib
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path for hyphenated module imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

sl = importlib.import_module("strato-login")


class TestPasswordAuth(unittest.TestCase):
    def test_authenticate_with_password_success_requests(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"X-Subject-Token": "unscoped-tok-123"}

        with patch.object(sl, "requests") as mock_req:
            mock_req.post.return_value = mock_resp
            token = sl.authenticate_with_password("alice", "secret", domain="Default")

        self.assertEqual(token, "unscoped-tok-123")
        payload = mock_req.post.call_args.kwargs["json"]
        self.assertEqual(payload["auth"]["identity"]["methods"], ["password"])
        self.assertEqual(
            payload["auth"]["identity"]["password"]["user"],
            {"name": "alice", "domain": {"name": "Default"}, "password": "secret"},
        )

    def test_authenticate_with_password_unauthorized(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "Unauthorized"

        with patch.object(sl, "requests") as mock_req:
            mock_req.post.return_value = mock_resp
            with self.assertRaises(RuntimeError) as ctx:
                sl.authenticate_with_password("alice", "wrong")

        self.assertIn("401 Unauthorized", str(ctx.exception))

    def test_authenticate_with_password_missing_header(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {}

        with patch.object(sl, "requests") as mock_req:
            mock_req.post.return_value = mock_resp
            with self.assertRaises(RuntimeError) as ctx:
                sl.authenticate_with_password("alice", "secret")

        self.assertIn("X-Subject-Token", str(ctx.exception))

    def test_authenticate_with_password_urllib_fallback(self):
        mock_resp = MagicMock()
        mock_resp.headers = {"X-Subject-Token": "urllib-tok-456"}
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_resp
        mock_ctx.__exit__.return_value = False

        with patch.object(sl, "requests", None), patch(
            "urllib.request.urlopen", return_value=mock_ctx
        ):
            token = sl.authenticate_with_password("bob", "pw", domain="AAU")

        self.assertEqual(token, "urllib-tok-456")


class TestProjectsAndScoping(unittest.TestCase):
    def test_get_available_projects(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "projects": [{"id": "p1", "name": "proj-one"}]
        }

        with patch.object(sl, "requests") as mock_req:
            mock_req.get.return_value = mock_resp
            projects = sl.get_available_projects("tok-abc")

        self.assertEqual(projects, [{"id": "p1", "name": "proj-one"}])

    def test_scope_token_to_project_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.headers = {"X-Subject-Token": "scoped-tok-999"}
        mock_resp.json.return_value = {"token": {"project": {"id": "p1"}}}

        with patch.object(sl, "requests") as mock_req:
            mock_req.post.return_value = mock_resp
            scoped, details = sl.scope_token_to_project("unscoped-tok", "p1")

        self.assertEqual(scoped, "scoped-tok-999")
        self.assertEqual(details["project"]["id"], "p1")


class TestMainNormalFlow(unittest.TestCase):
    def test_main_normal_writes_openrc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rc_path = os.path.join(tmpdir, "test-openrc.sh")
            argv = [
                "strato-login.py",
                "--normal",
                "--username",
                "alice",
                "--password",
                "secret",
                "--output-rc",
                rc_path,
            ]
            with patch.object(sys, "argv", argv), patch.object(
                sl, "authenticate_with_password", return_value="unscoped-1"
            ), patch.object(
                sl,
                "get_available_projects",
                return_value=[{"id": "proj-1", "name": "MyProject"}],
            ), patch.object(
                sl,
                "scope_token_to_project",
                return_value=("scoped-final-1", {}),
            ), patch.object(
                sl, "copy_to_clipboard", return_value=False
            ):
                sl.main()

            self.assertTrue(os.path.isfile(rc_path))
            mode = stat.S_IMODE(os.stat(rc_path).st_mode)
            self.assertEqual(mode, 0o600)
            with open(rc_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("export OS_TOKEN=scoped-final-1", content)
            self.assertIn("export OS_PROJECT_ID=proj-1", content)
            self.assertIn('export OS_PROJECT_NAME="MyProject"', content)


if __name__ == "__main__":
    unittest.main()
