import argparse
import importlib.util
import ipaddress
import unittest
import json
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("network_logs", "scripts/network_logs.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FilterTests(unittest.TestCase):
    def test_offline_summary(self):
        with tempfile.NamedTemporaryFile(mode="w", dir="/tmp/opencode") as stream:
            for port, count in ((1234, 2), (5678, 3)):
                stream.write(json.dumps(dict(type="network", src_ip="192.0.2.1",
                    dst_ip="198.51.100.1", src_port=port, dst_port=443, protocol=6,
                    direction="out", action="drop", reason="policy", event_count=count)) + "\n")
            stream.write(json.dumps(dict(type="telemetry_health")) + "\n")
            stream.flush()
            result = subprocess.run(["python3", "scripts/network_logs.py", stream.name,
                                     "--summary", "--ip", "192.0.2.1"],
                                    check=True, capture_output=True, text=True)
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_count"], 5)

    def test_filters(self):
        args = argparse.Namespace(ip=ipaddress.ip_network("192.0.2.0/24"),
                                  action="drop", direction="out", port=443,
                                  reason="policy", health=False)
        event = dict(type="network", src_ip="192.0.2.1", dst_ip="198.51.100.1",
                     action="drop", direction="out", src_port=1234,
                     dst_port=443, reason="policy")
        self.assertTrue(module.matches(event, args))
        event["direction"] = "in"
        self.assertFalse(module.matches(event, args))
        self.assertFalse(module.matches(dict(type="telemetry_health"), args))


if __name__ == "__main__":
    unittest.main()
