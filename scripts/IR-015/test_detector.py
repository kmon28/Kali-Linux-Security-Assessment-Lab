#!/usr/bin/env python3
"""Unit tests for the new IR-015 portfolio detector, using temporary fixtures."""
import tempfile
import unittest
from pathlib import Path
from user_service_detector import scan

class DetectorTests(unittest.TestCase):
    def test_enabled_and_user_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user = root / "systemd" / "user"
            wants = user / "default.target.wants"
            wants.mkdir(parents=True)
            unit = user / "ir015-sim-agent.service"
            unit.write_text("[Service]\nExecStart=/usr/bin/bash /home/test/agent.sh\n")
            (wants / unit.name).symlink_to(unit)
            results = scan(root)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["risk_score"], 4)

    def test_benign_and_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            user = root / "systemd" / "user"
            user.mkdir(parents=True)
            (user / "benign.service").write_text("[Service]\nExecStart=/usr/bin/true\n")
            (user / "suspicious.service").write_text(
                "[Service]\nExecStart=/usr/bin/bash /tmp/example.sh\n"
            )
            scores = {r["service"]: r["risk_score"] for r in scan(root)}
            self.assertEqual(scores["benign.service"], 0)
            self.assertEqual(scores["suspicious.service"], 2)

    def test_missing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan(Path(tmp)), [])

if __name__ == "__main__":
    unittest.main()
