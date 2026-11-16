#!/usr/bin/env python3
"""Stage a dedicated, TLS-pinned Xkeen inlet. Never writes to a live router."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess

TAG = "russian-armour"
SERVER_NAME = "russian-armour.router"
REMOTE_SECRETS = "/opt/etc/xray/russian-armour"


def read_jsonc(text):
    """Remove Xray JSON comments without interpreting comment markers in strings."""
    result, position, in_string = [], 0, False
    while position < len(text):
        current = text[position]
        if in_string:
            result.append(current)
            if current == "\\":
                position += 1
                if position >= len(text):
                    raise ValueError("Unterminated JSON string")
                result.append(text[position])
            elif current == '"':
                in_string = False
        elif current == '"':
            in_string = True
            result.append(current)
        elif text.startswith("//", position):
            end = text.find("\n", position)
            position = len(text) if end < 0 else end
            result.append("\n")
            continue
        elif text.startswith("/*", position):
            end = text.find("*/", position + 2)
            if end < 0:
                raise ValueError("Unterminated JSON comment")
            result.append(" ")
            position = end + 2
            continue
        else:
            result.append(current)
        position += 1

    def unique_keys(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON key")
            value[key] = item
        return value

    return json.loads("".join(result), object_pairs_hook=unique_keys)


def secure_outbound(outbound):
    """VLESS itself isn't encrypted: require TLS/REALITY and verified TLS."""
    protocol = outbound.get("protocol")
    if protocol == "wireguard":
        return bool(outbound.get("settings", {}).get("peers"))
    if protocol == "shadowsocks":
        servers = outbound.get("settings", {}).get("servers", [])
        methods = {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
                   "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                   "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
        return bool(servers) and all(server.get("method") in methods for server in servers)
    if protocol not in {"vless", "vmess", "trojan"}:
        return False
    stream = outbound.get("streamSettings", {})
    security = stream.get("security")
    if security == "tls":
        tls = stream.get("tlsSettings", {})
        return not tls.get("allowInsecure", False)
    if security == "reality":
        reality = stream.get("realitySettings", {})
        return bool(reality.get("publicKey") or reality.get("password")) and bool(reality.get("serverName"))
    return False


def prepare_configs(configs, host, port, outbound_tag, password):
    # The SOCKS listener is bound to a literal LAN address; no wildcard/LAN leak.
    address = ipaddress.IPv4Address(host)
    if not (address in ipaddress.IPv4Network("10.0.0.0/8") or
            address in ipaddress.IPv4Network("172.16.0.0/12") or
            address in ipaddress.IPv4Network("192.168.0.0/16")):
        raise ValueError("Router address must be an RFC1918 IPv4 address")
    if not 1024 <= port <= 65535:
        raise ValueError("Invalid router listener port")
    ordered = sorted(configs)
    if not ordered or len(ordered) > 100:
        raise ValueError("Expected a bounded Xray configuration snapshot")
    values = {name: read_jsonc(configs[name]) for name in ordered}
    if any(not isinstance(value, dict) for value in values.values()):
        raise ValueError("Expected Xray JSON objects")
    outbounds = [outbound for value in values.values() for outbound in value.get("outbounds", [])]
    selected = [outbound for outbound in outbounds if outbound.get("tag") == outbound_tag]
    if len(selected) != 1 or not secure_outbound(selected[0]):
        raise ValueError("Select one encrypted outbound; direct/balancer/insecure TLS are refused")
    chosen = selected[0]
    # A nested outbound chain or reverse/multiplex transport needs its own
    # analysis; don't silently trust a proxySettings/dialerProxy detour.
    if chosen.get("proxySettings") or chosen.get("mux", {}).get("enabled") or chosen.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy"):
        raise ValueError("Chained or multiplexed outbounds require explicit validation")
    inbound_file = "00-russian-armour-inbound.json"
    if inbound_file in values:
        raise ValueError("Russian Armour inlet already exists; inspect it before changing it")
    for value in values.values():
        for inbound in value.get("inbounds", []):
            if inbound.get("tag") == TAG or str(inbound.get("port")) == str(port):
                raise ValueError("Inbound tag or port already in use")
    routing_files = [name for name in ordered if "routing" in values[name]]
    if not routing_files:
        raise ValueError("No existing Xray routing configuration found")
    routing = values[routing_files[0]]["routing"]
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("Invalid routing rules")
    # This must precede domain and catch-all rules, irrespective of destination.
    rules.insert(0, {"type": "field", "inboundTag": [TAG], "outboundTag": outbound_tag})
    values[inbound_file] = {"inbounds": [{
        "tag": TAG, "listen": host, "port": port, "protocol": "socks",
        "settings": {"auth": "password", "accounts": [{"user": TAG, "pass": password}], "udp": False},
        "sniffing": {"enabled": False},
        "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
            "minVersion": "1.2", "certificates": [{
                "certificateFile": REMOTE_SECRETS + "/router.crt",
                "keyFile": REMOTE_SECRETS + "/router.key"
            }]
        }}
    }]}
    return values


def private_write(path, data):
    # Refuse symlinks and existing files; stages are private and never overwrite configs.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--router", required=True)
    parser.add_argument("--port", type=int, default=19843)
    parser.add_argument("--outbound", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    configs = {}
    for path in sorted(args.snapshot.iterdir()):
        if path.suffix != ".json":
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError("Unsafe snapshot file")
        configs[path.name] = path.read_text()
    password = secrets.token_urlsafe(32)
    prepared = prepare_configs(configs, args.router, args.port, args.outbound, password)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    (args.output / "configs").mkdir(mode=0o700)
    for name, value in prepared.items():
        private_write(args.output / "configs" / name, json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    # No credentials in endpoint.json; the password is imported separately into Keychain.
    certificate_config = args.output / "certificate.cnf"
    private_write(certificate_config, "[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=" + SERVER_NAME +
                  "\n[ext]\nsubjectAltName=DNS:" + SERVER_NAME + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
                    "-config", str(certificate_config), "-keyout", str(args.output / "router.key"),
                    "-out", str(args.output / "router.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    der = subprocess.run(["/usr/bin/openssl", "x509", "-in", str(args.output / "router.crt"), "-outform", "DER"],
                         check=True, stdout=subprocess.PIPE).stdout
    descriptor = {"version": 1, "host": args.router, "port": args.port, "username": TAG,
                  "routerCertificateSHA256": hashlib.sha256(der).hexdigest(), "tlsServerName": SERVER_NAME}
    private_write(args.output / "endpoint.json", json.dumps(descriptor, indent=2) + "\n")
    private_write(args.output / "password.txt", password)
    private_write(args.output / "connection.armour.json", json.dumps(dict(descriptor, password=password), indent=2) + "\n")
    print("Staged dedicated TLS SOCKS inlet and first routing rule. Live router unchanged.")
    print("Before deployment: validate the full staged config with the router's Xray binary; back up existing files.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError, subprocess.SubprocessError):
        # Configuration text or subprocess stderr may contain VPN credentials.
        raise SystemExit("Preparation failed. Check the snapshot, encrypted outbound selection and output directory.")
