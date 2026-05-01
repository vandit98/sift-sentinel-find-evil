import shutil
import tempfile
import unittest
from pathlib import Path

from sift_sentinel.agent import SentinelAgent


REPO_ROOT = Path(__file__).resolve().parents[1]


class AgentLoopTest(unittest.TestCase):
    def test_agent_confirms_truth_and_refutes_prefetch_trap(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "demo-case"
            shutil.copytree(REPO_ROOT / "cases" / "demo-case", case_dir, ignore=shutil.ignore_patterns("outputs"))
            result = SentinelAgent().run(case_dir / "case.json", run_id="unit", max_iterations=3)

            statuses = {finding.finding_id: finding.status for finding in result.findings}
            self.assertEqual(statuses["F-001"], "confirmed")
            self.assertEqual(statuses["F-002"], "refuted")
            self.assertEqual(statuses["F-003"], "confirmed")
            self.assertEqual(statuses["F-004"], "confirmed")
            self.assertLessEqual(result.iterations, 3)
            self.assertTrue(result.integrity["comparison"]["ok"])
            self.assertTrue((result.output_dir / "analysis" / "execution_log.jsonl").exists())
            self.assertTrue((result.output_dir / "analysis" / "evidence_integrity.json").exists())


if __name__ == "__main__":
    unittest.main()
