"""Opt-in actual Xray fixture. XRAY_BINARY points to a verified local binary.

Uses loopback-only listeners and temporary credentials; never touches a router.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import unittest


@unittest.skipUnless(os.environ.get("XRAY_BINARY"), "Set XRAY_BINARY for the real loopback-only Xray test")
class XrayFailClosedIntegrationTests(unittest.TestCase):
    def test_tls_socks_inlet_cannot_fall_through_to_existing_direct_rule(self):
        binary = str(Path(os.environ["XRAY_BINARY"]).resolve())
        scripts = Path(__file__).parents[1]
        spec = importlib.util.spec_from_file_location("xkeen_integration_preparer", scripts / "prepare-xkeen.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix="armour-xray-test.") as directory:
            root = Path(directory)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            # Keep a direct first/default outbound and a direct catch-all rule.
            # The dedicated inbound must still select only the failed TLS outbound.
            unreachable = socket.socket()
            unreachable.bind(("127.0.0.1", 0))
            unreachable_port = unreachable.getsockname()[1]
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.3)
            destination_port = listener.getsockname()[1]
            reserve = socket.socket()
            reserve.bind(("127.0.0.1", 0))
            inbound_port = reserve.getsockname()[1]
            reserve.close()
            outbound = {"tag": "vpn", "protocol": "vless", "settings": {"vnext": [{
                "address": "127.0.0.1", "port": unreachable_port,
                "users": [{"id": "00000000-0000-4000-8000-000000000001", "encryption": "none"}]
            }]}, "streamSettings": {"network": "tcp", "security": "tls",
                                     "tlsSettings": {"serverName": "unreachable.example.test"}}}
            (snapshot / "04-outbounds.json").write_text(json.dumps({"outbounds": [
                {"tag": "direct", "protocol": "freedom"}, outbound]}))
            (snapshot / "05-routing.json").write_text(json.dumps({"routing": {"rules": [
                {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]}}))
            stage = root / "stage"
            subprocess.run(["python3", str(scripts / "prepare-xkeen.py"), "--snapshot", str(snapshot),
                            "--output", str(stage), "--router", "192.168.1.1", "--port", str(inbound_port),
                            "--outbound", "vpn"], check=True, stdout=subprocess.DEVNULL)
            inbound_path = stage / "configs" / "00-russian-armour-inbound.json"
            inbound = json.loads(inbound_path.read_text())
            # Only the isolated fixture is rebound to loopback. Production
            # preparation/endpoint validation still refuse loopback addresses.
            inlet = inbound["inbounds"][0]
            inlet["listen"] = "127.0.0.1"
            certificate = inlet["streamSettings"]["tlsSettings"]["certificates"][0]
            certificate["certificateFile"] = str(stage / "router.crt")
            certificate["keyFile"] = str(stage / "router.key")
            inbound_path.write_text(json.dumps(inbound))
            process = None
            try:
                checked = subprocess.run([binary, "run", "-test", "-confdir", str(stage / "configs")],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertEqual(checked.returncode, 0, "Generated inlet must pass actual Xray validation")
                process = subprocess.Popen([binary, "run", "-confdir", str(stage / "configs")],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                client = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    self.assertIsNone(process.poll(), "Xray fixture exited")
                    try:
                        client = socket.create_connection(("127.0.0.1", inbound_port), timeout=0.2)
                        break
                    except OSError:
                        time.sleep(0.03)
                self.assertIsNotNone(client, "Xray fixture did not listen")
                # Apple Python's LibreSSL cannot anchor a CA:FALSE leaf. This
                # isolated fixture authenticates the exact self-signed leaf by
                # its provisioned SHA-256 before sending any SOCKS credentials.
                # The production client additionally uses Security.framework's
                # SSL/SAN/date trust evaluator, covered in RouterTLSTests.
                descriptor = json.loads((stage / "endpoint.json").read_text())
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(client, server_hostname="russian-armour.router") as tls:
                    peer_pin = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    self.assertEqual(peer_pin, descriptor["routerCertificateSHA256"])
                    tls.settimeout(5)
                    tls.sendall(b"\x05\x01\x02")
                    self.assertEqual(tls.recv(2), b"\x05\x02")
                    password = (stage / "password.txt").read_bytes()
                    username = b"russian-armour"
                    tls.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
                    self.assertEqual(tls.recv(2), b"\x01\x00")
                    tls.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + destination_port.to_bytes(2, "big"))
                    # Some Xray versions acknowledge SOCKS before the lazy
                    # encrypted outbound dials. A payload forces that dial.
                    tls.sendall(b"fixture-data-that-must-not-arrive-directly")
                    try:
                        tls.recv(512)
                        tls.recv(512)
                    except (OSError, ssl.SSLError):
                        pass
                with self.assertRaises(socket.timeout, msg="Selected encrypted outbound must not fall through to direct"):
                    leaked, _ = listener.accept()
                    leaked.close()
            finally:
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                listener.close()
                unreachable.close()


if __name__ == "__main__":
    unittest.main()
