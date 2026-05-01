import shutil
import tempfile
import unittest
from pathlib import Path

from sift_sentinel.agent import SentinelAgent
from sift_sentinel.case import CaseConfig
from sift_sentinel.scoring import load_ground_truth, score_findings


REPO_ROOT = Path(__file__).resolve().parents[1]


class ScoringTest(unittest.TestCase):
    def test_demo_case_scores_without_hallucinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "demo-case"
            shutil.copytree(REPO_ROOT / "cases" / "demo-case", case_dir, ignore=shutil.ignore_patterns("outputs"))
            result = SentinelAgent().run(case_dir / "case.json", run_id="score", max_iterations=3)
            truth = load_ground_truth(CaseConfig.load(case_dir / "case.json"))
            score = score_findings(result.findings, truth)

            self.assertEqual(score["precision"], 1.0)
            self.assertEqual(score["recall"], 1.0)
            self.assertEqual(score["hallucination_count"], 0)
            self.assertEqual(score["refuted_finding_ids"], ["F-002"])


if __name__ == "__main__":
    unittest.main()

