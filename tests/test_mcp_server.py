import shutil
import tempfile
import unittest
from pathlib import Path

from sift_sentinel.mcp_server import SentinelMCPServer


REPO_ROOT = Path(__file__).resolve().parents[1]


class MCPServerTest(unittest.TestCase):
    def test_tools_list_and_case_manifest_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "demo-case"
            shutil.copytree(REPO_ROOT / "cases" / "demo-case", case_dir, ignore=shutil.ignore_patterns("outputs"))
            server = SentinelMCPServer()

            listed = server._handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertIn("tools", listed["result"])
            tool_names = {tool["name"] for tool in listed["result"]["tools"]}
            self.assertIn("sift_sentinel_spoliation_check", tool_names)
            self.assertIn("sift_sentinel_disk_amcache", tool_names)

            response = server._handle(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "sift_sentinel_case_manifest",
                        "arguments": {"case_file": str(case_dir / "case.json")},
                    },
                }
            )
            text = response["result"]["content"][0]["text"]
            self.assertIn("demo-evil-001", text)
            self.assertIn("sha256", text)

    def test_spoliation_check_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "demo-case"
            shutil.copytree(REPO_ROOT / "cases" / "demo-case", case_dir, ignore=shutil.ignore_patterns("outputs"))
            server = SentinelMCPServer()

            response = server._handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "sift_sentinel_spoliation_check",
                        "arguments": {"case_file": str(case_dir / "case.json")},
                    },
                }
            )

            text = response["result"]["content"][0]["text"]
            self.assertIn('"ok": true', text)
            self.assertIn("write_probe_inside_evidence_root", text)


if __name__ == "__main__":
    unittest.main()
