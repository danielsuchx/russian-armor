"""Sign canonical version/size/SHA-256 metadata for a Russian Armor disk image."""
from pathlib import Path
import argparse
import base64
import hashlib
import plistlib
from cryptography.hazmat.primitives import serialization

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--key", type=Path, default=root / ".release-signing/private.pem")
parser.add_argument("--image", type=Path, default=root / "dist/Russian-Armor.dmg")
args = parser.parse_args()
with (root / "dist/Russian Armor.app/Contents/Info.plist").open("rb") as file:
    version = plistlib.load(file)["CFBundleShortVersionString"]
with args.image.open("rb") as image:
    digest = hashlib.file_digest(image, "sha256").hexdigest()
payload = f"Russian Armor release\nversion={version}\nsize={args.image.stat().st_size}\nsha256={digest}\n".encode()
key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
public = base64.b64decode((root / "Support/UpdatePublicKey.txt").read_text().strip(), validate=True)
actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
if actual != public:
    raise SystemExit("Signing key does not match the app's pinned public key.")
signature = args.image.with_name(args.image.name + ".sig")
signature.write_text(base64.b64encode(key.sign(payload)).decode() + "\n")
print("Signed release:", signature)
