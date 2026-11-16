import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("audit_xkeen", Path(__file__).parents[1] / "audit-xkeen-snapshot.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class XkeenSnapshotAuditTests(unittest.TestCase):
    def test_direct_outbound_and_balancer_are_reported_without_configuration_secrets(self):
        config = {"outbounds": [{"tag": "private-tag", "protocol": "freedom", "password": "private-secret"}],
                  "routing": {"rules": [{"balancerTag": "private-balancer"}]}}
        result = "\n".join(audit.inspect({"sensitive-name.json": json.dumps(config)}))
        self.assertIn("freedom", result)
        self.assertIn("балансировщик", result)
        self.assertIn("не подтверждает блокировку", result)
        for secret in ["private-tag", "private-secret", "private-balancer", "sensitive-name"]:
            self.assertNotIn(secret, result)

    def test_encrypted_outbound_is_not_mistaken_for_proof(self):
        result = audit.inspect({"config.json": json.dumps({"outbounds": [{"protocol": "vless"}]})})
        self.assertEqual(len(result), 1)
        self.assertIn("не подтверждает блокировку", result[0])

    def test_reports_proxy_chain(self):
        result = audit.inspect({"a.json": json.dumps({"outbounds": [{"protocol": "vless", "proxySettings": {"tag": "x"}}]})})
        self.assertTrue(any("цепочка" in item for item in result))

    def test_invalid_and_duplicate_json_is_rejected(self):
        for text in ['{"outbounds": 1}', '{"routing": {"rules": 1}}', '{"outbounds": [], "outbounds": []}', '[]',
                     '{"outbounds":[{"streamSettings":null}]}', '{"outbounds":[{"streamSettings":{"sockopt":null}}]}']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.inspect({"test.json": text})

    def test_snapshot_rejects_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "original"
            source.write_text('{}')
            link = root / "config.json"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                audit.read_snapshot(root)
            link.unlink()
            link.write_bytes(b'x' * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                audit.read_snapshot(root)

    def test_empty_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(ValueError):
                audit.read_snapshot(Path(name))


if __name__ == "__main__":
    unittest.main()
