#!/usr/bin/env python3
"""Exercise interactive selection in preview mode; never compile or attach."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SelectorTests(unittest.TestCase):
    def select(self, answers, preview=True):
        command = [sys.executable, "scripts/build_selector.py"]
        if preview:
            command.append("--dry-run")
        result = subprocess.run(command, cwd=ROOT, input=answers,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_defaults(self):
        output = self.select("\n\n\n\n\n\n\n\n")
        self.assertIn("fastcache-t0-l0-full", output)
        self.assertIn("Preview only", output)
        self.assertIn("RATE_LIMIT=1", output)
        self.assertIn("ANTI_SPOOF=1", output)
        self.assertIn("CONN_LIMIT=1", output)
        self.assertIn("SYN rate limiting (build-time)", output)

    def test_logging_requires_full(self):
        output = self.select("1\n1\n2\n1\n1\n1\n4\n")
        self.assertIn("fastcache-t0-l1-full", output)
        self.assertIn("-j4", output)
        self.assertIn("required by network logging", output)

    def test_timing_excludes_none(self):
        output = self.select("3\n2\n1\n3\n2\n1\n1\n1\n2\n")
        self.assertIn("Please enter one of the listed numbers", output)
        self.assertIn("dualmap-t1-l0-minimal", output)

    def test_lean_and_invalid_input(self):
        output = self.select("bad\n2\n1\n1\n3\n2\n2\n2\n0\n2\n")
        self.assertIn("stateful-t0-l0-none", output)
        self.assertIn("positive integer", output)
        self.assertIn("RATE_LIMIT=0", output)
        self.assertIn("stateful-t0-l0-none-r0", output)
        self.assertIn("ANTI_SPOOF=0", output)
        self.assertIn("stateful-t0-l0-none-r0-a0", output)
        self.assertIn("CONN_LIMIT=0", output)
        self.assertIn("stateful-t0-l0-none-r0-a0-c0", output)
        self.assertIn("compiled out (runtime settings ignored)", output)

    def test_cancel(self):
        output = self.select("\n\n\n\n\n\n\n\nno\n", preview=False)
        self.assertIn("Cancelled", output)

    def test_eof_cancels(self):
        self.assertIn("Cancelled", self.select(""))


if __name__ == "__main__":
    unittest.main()
