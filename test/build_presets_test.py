#!/usr/bin/env python3
"""Check preset selection without compiling or attaching packet filters."""
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def make(*args):
    return subprocess.run(["make", "--no-print-directory", *args], cwd=ROOT,
                          capture_output=True, text=True)


class PresetTests(unittest.TestCase):
    def test_presets(self):
        profiles = {
            "default": "t0-l0-full", "logging": "t0-l1-full",
            "timing": "t1-l0-minimal", "minimal": "t0-l0-minimal",
            "lean": "t0-l0-none", "debug": "t1-l1-full",
        }
        for preset, suffix in profiles.items():
            for engine in ("fastcache", "stateful", "dualmap"):
                with self.subTest(preset=preset, engine=engine):
                    result = make(f"PRESET={preset}", f"ENGINE={engine}", "print-config")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"output=build/profiles/{engine}-{suffix}", result.stdout)
            # Dry runs select identical defaults for the shortcut target.
            result = make("-n", preset, "print-config")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"output=build/profiles/fastcache-{suffix}", result.stdout)

    def test_override(self):
        result = make("PRESET=logging", "TIMING=1", "print-config")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fastcache-t1-l1-full", result.stdout)

    def test_invalid(self):
        for args in (("PRESET=typo",), ("logging", "lean"),
                     ("logging", "PRESET=lean"),
                     ("PRESET=logging", "OBSERVABILITY=none"),
                     ("PRESET=lean", "TIMING=1")):
            with self.subTest(args=args):
                self.assertNotEqual(make(*args, "print-config").returncode, 0)

    def test_help_and_default(self):
        result = make("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Build only", result.stdout)
        self.assertNotIn("clang -", result.stdout)
        self.assertIn("fastcache-t0-l0-full", make("print-config").stdout)


if __name__ == "__main__":
    unittest.main()
