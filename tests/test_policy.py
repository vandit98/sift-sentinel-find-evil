import tempfile
import unittest
from pathlib import Path

from sift_sentinel.policies import EvidencePolicy, PolicyViolation


class EvidencePolicyTest(unittest.TestCase):
    def test_denies_writes_inside_evidence_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            outputs = root / "outputs"
            evidence.mkdir()
            outputs.mkdir()
            policy = EvidencePolicy(root, evidence, outputs)

            with self.assertRaises(PolicyViolation):
                policy.assert_output_path(evidence / "tamper.txt")

    def test_allows_writes_inside_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            outputs = root / "outputs"
            evidence.mkdir()
            outputs.mkdir()
            policy = EvidencePolicy(root, evidence, outputs)

            expected = (outputs / "analysis" / "log.jsonl").resolve()
            self.assertEqual(policy.assert_output_path(outputs / "analysis" / "log.jsonl"), expected)

    def test_allows_readable_evidence_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            outputs = root / "outputs"
            artifact_dir = evidence / "evtx"
            artifact_dir.mkdir(parents=True)
            outputs.mkdir()
            policy = EvidencePolicy(root, evidence, outputs)

            self.assertEqual(policy.assert_readable_evidence_path(artifact_dir), artifact_dir.resolve())


if __name__ == "__main__":
    unittest.main()
