#!/usr/bin/env python3
"""Offline Xray/Xkeen snapshot review. This does not establish a kill switch."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat

_PREPARER = Path(__file__).with_name("prepare-xkeen.py")
_SPEC = importlib.util.spec_from_file_location("armour_xkeen_preparer", _PREPARER)
_PREP = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PREP)


def inspect(configs):
    """Return generic findings only; never return credentials, config or endpoints."""
    if not configs or len(configs) > 100:
        raise ValueError("Expected between 1 and 100 configuration files")
    outbounds, rules = [], []
    for text in configs.values():
        value = _PREP.read_jsonc(text)
        if not isinstance(value, dict):
            raise ValueError("Expected configuration objects")
        entries = value.get("outbounds", [])
        if not isinstance(entries, list) or any(not isinstance(x, dict) for x in entries):
            raise ValueError("Invalid outbounds")
        outbounds.extend(entries)
        routing = value.get("routing", {})
        if not isinstance(routing, dict) or not isinstance(routing.get("rules", []), list):
            raise ValueError("Invalid routing")
        if any(not isinstance(x, dict) for x in routing.get("rules", [])):
            raise ValueError("Invalid routing rules")
        rules.extend(routing.get("rules", []))

    findings = []
    if not outbounds:
        findings.append("В снимке не найдены выходы Xray.")
    if any(str(outbound.get("protocol", "")).lower() == "freedom" for outbound in outbounds):
        findings.append("Найден прямой выход freedom; некоторые правила могут направлять трафик в обход VPN.")
    if any("balancerTag" in rule for rule in rules):
        findings.append("Найден балансировщик: его маршруты и резервные выходы требуют отдельной проверки.")
    for outbound in outbounds:
        stream = outbound.get("streamSettings", {})
        if not isinstance(stream, dict) or not isinstance(stream.get("sockopt", {}), dict):
            raise ValueError("Invalid outbound stream settings")
    if any(outbound.get("proxySettings") or outbound.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy")
           for outbound in outbounds):
        findings.append("Найдена цепочка выходов: её поведение при сбое требует отдельной проверки.")
    findings.append("Снимок не подтверждает блокировку: правила Keenetic, обход Xray, IPv6 и поведение при сбое не проверены.")
    return findings


def read_snapshot(directory):
    """Read regular files only, without following symlinks or printing contents."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Expected a real directory")
    paths = sorted(directory.glob("*.json"))
    if not 1 <= len(paths) <= 100:
        raise ValueError("Expected between 1 and 100 JSON files")
    configs = {}
    for path in paths:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise ValueError("Invalid snapshot file")
            with os.fdopen(fd, "rb") as source:
                fd = -1
                raw = source.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Snapshot file too large")
            configs[path.name] = raw.decode("utf-8")
        finally:
            if fd >= 0:
                os.close(fd)
    return configs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="directory containing a local Xray JSON snapshot")
    args = parser.parse_args()
    try:
        findings = inspect(read_snapshot(args.snapshot))
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        raise SystemExit("Не удалось проверить снимок. Проверьте каталог и формат JSON/JSONC.")
    print("Только локальный предварительный анализ; защита не подтверждена:")
    for finding in findings:
        print("- " + finding)


if __name__ == "__main__":
    main()
