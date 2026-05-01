import shutil
import tempfile
import unittest
from pathlib import Path

from sift_sentinel.sift_wrappers import SiftWrappers
from sift_sentinel.validation import spoliation_check, validate_case


REPO_ROOT = Path(__file__).resolve().parents[1]


class ValidationTest(unittest.TestCase):
    def test_validate_case_and_spoliation_check_pass_demo_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "demo-case"
            shutil.copytree(REPO_ROOT / "cases" / "demo-case", case_dir, ignore=shutil.ignore_patterns("outputs"))
            case_file = case_dir / "case.json"

            validation = validate_case(case_file)
            spoliation = spoliation_check(case_file)

            self.assertTrue(validation["ok"])
            self.assertTrue(spoliation["ok"])
            self.assertGreaterEqual(len(spoliation["checks"]), 2)

    def test_tool_contracts_cover_core_sift_artifact_families(self):
        contracts = SiftWrappers.tool_contracts()

        for name in ("volatility_json", "evtxecmd_csv", "mftecmd_csv", "recmd_batch_csv", "pecmd_csv", "amcacheparser_csv"):
            self.assertIn(name, contracts)
            self.assertEqual(contracts[name]["destructive_risk"], "none exposed")


if __name__ == "__main__":
    unittest.main()

