"""Collect notices for linked Rust packages, without machine-specific paths."""
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
cargo = sys.argv[1]
result = subprocess.run([cargo, "metadata", "--locked", "--format-version=1", "--filter-platform", "aarch64-apple-darwin",
                         "--manifest-path", str(root / "NetworkEngine/src-tauri/Cargo.toml")],
                        check=True, stdout=subprocess.PIPE)
metadata = json.loads(result.stdout)
resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
output = ["Russian Armor network engine — third-party Rust licenses\n"]
for package in sorted(metadata["packages"], key=lambda package: (package["name"], package["version"])):
    if package["id"] not in resolved:
        continue
    output += ["\n" + "=" * 72, f"{package['name']} {package['version']}",
               f"License expression: {package.get('license') or 'See included license'}",
               f"Source: {package.get('repository') or 'crates.io'}"]
    base = Path(package["manifest_path"]).parent
    files = {path for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*") for path in base.glob(pattern) if path.is_file()}
    if package.get("license_file"):
        files.add(base / package["license_file"])
    for path in sorted(files):
        if path.is_file():
            output += [f"\n--- {path.name} ---", path.read_text(errors="replace")]
destination = root / ".build/network-engine/ThirdPartyLicenses.txt"
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text("\n".join(output))
print(f"Collected third-party license notices for {len(resolved)} Rust packages.")
