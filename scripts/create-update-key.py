"""Create a local release-signing key once; never print or commit private bytes."""
from pathlib import Path
import base64
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

root = Path(__file__).resolve().parents[1]
private = root / ".release-signing/private.pem"
public = root / "Support/UpdatePublicKey.txt"
if public.exists():
    raise SystemExit("Public update key already exists; refusing to replace the trust anchor.")
private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
key = Ed25519PrivateKey.generate()
raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
fd = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as file:
    file.write(raw)
    file.flush()
    os.fsync(file.fileno())
public.write_text(base64.b64encode(key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode() + "\n")
print("Public trust anchor:", public)
print("Private signing key created locally in .release-signing/private.pem; back it up privately.")
