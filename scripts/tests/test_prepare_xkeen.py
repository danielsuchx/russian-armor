import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("prepare_xkeen", Path(__file__).parents[1] / "prepare-xkeen.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class XkeenConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.outbound = {"tag": "vpn", "protocol": "vless", "streamSettings": {"security": "tls"}}
        self.configs = {
            "04-outbounds.json": json.dumps({"outbounds": [self.outbound]}),
            "05-routing.json": json.dumps({"routing": {"rules": [{"type": "field", "outboundTag": "direct", "network": "tcp,udp"}]}}),
        }

    def prepare(self, **changes):
        args = dict(configs=self.configs, host="192.168.1.1", port=19843, outbound_tag="vpn", password="fixture-only")
        args.update(changes)
        return module.prepare_configs(**args)

    def test_dedicated_inbound_always_uses_encrypted_outbound_before_direct_rule(self):
        result = self.prepare()
        rules = result["05-routing.json"]["routing"]["rules"]
        self.assertEqual(rules[0], {"type": "field", "inboundTag": ["russian-armour"], "outboundTag": "vpn"})
        self.assertEqual(rules[1]["outboundTag"], "direct")
        inbound = result["00-russian-armour-inbound.json"]["inbounds"][0]
        self.assertEqual(inbound["listen"], "192.168.1.1")
        self.assertFalse(inbound["settings"]["udp"])
        self.assertEqual(inbound["settings"]["auth"], "password")
        self.assertEqual(inbound["streamSettings"]["security"], "tls")

    def test_rejects_unencrypted_or_direct_or_insecure_routes(self):
        for outbound in [
            {"tag": "vpn", "protocol": "freedom"},
            {"tag": "vpn", "protocol": "vless"},
            {"tag": "vpn", "protocol": "socks"},
            {"tag": "vpn", "protocol": "blackhole"},
            {"tag": "vpn", "protocol": "vless", "streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": True}}},
        ]:
            with self.subTest(outbound=outbound):
                configs = dict(self.configs)
                configs["04-outbounds.json"] = json.dumps({"outbounds": [outbound]})
                with self.assertRaises(ValueError):
                    self.prepare(configs=configs)

    def test_rejects_ambiguous_tag_and_port_collision(self):
        configs = dict(self.configs)
        configs["04-outbounds.json"] = json.dumps({"outbounds": [self.outbound, copy.deepcopy(self.outbound)]})
        with self.assertRaises(ValueError):
            self.prepare(configs=configs)
        configs = dict(self.configs)
        configs["03-inbounds.json"] = json.dumps({"inbounds": [{"port": "19843"}]})
        with self.assertRaises(ValueError):
            self.prepare(configs=configs)

    def test_preserves_comments_inside_strings_and_rejects_duplicate_keys(self):
        self.assertEqual(module.read_jsonc('/* comment */ {"url":"https://example.test/a//b",//comment\n "a":1}'),
                         {"url": "https://example.test/a//b", "a": 1})
        with self.assertRaises(ValueError):
            module.read_jsonc('{"outboundTag":"vpn","outboundTag":"direct"}')
        with self.assertRaises(ValueError):
            module.read_jsonc('/* unterminated')

    def test_no_wildcard_public_loopback_or_link_local_listener(self):
        for host in ["0.0.0.0", "8.8.8.8", "127.0.0.1", "169.254.1.1", "router.local", "::1"]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.prepare(host=host)


if __name__ == "__main__":
    unittest.main()
