"""Debug helper smoke test without network probes or user-configuration changes."""
from pathlib import Path
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[1]
binary = root / "NetworkEngine/src-tauri/target/debug/zastava"
with tempfile.TemporaryDirectory(prefix="ra-ipc-", dir="/private/tmp") as folder:
    directory = Path(folder)
    os.chmod(directory, 0o700)
    token = secrets.token_hex(32)
    with os.fdopen(os.open(directory / "session", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w") as file:
        file.write(token)
    endpoint = str(directory / "engine.sock")
    child = subprocess.Popen([str(binary), "--native-bridge", endpoint, "--native-smoke-test", "--minimized"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def call(command, args=None, credential=token):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(5)
            channel.connect(endpoint)
            channel.sendall(json.dumps({"token": credential, "command": command, "args": args or {}}).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = channel.recv(65536)
                if not chunk: return None
                data += chunk
                assert len(data) < 8 * 1024 * 1024
            return json.loads(data)
    try:
        deadline = time.monotonic() + 20
        while not Path(endpoint).exists():
            if child.poll() is not None: raise RuntimeError("Native helper exited before binding IPC")
            if time.monotonic() > deadline: raise TimeoutError("Native helper did not bind IPC")
            time.sleep(0.05)
        assert os.stat(endpoint).st_mode & 0o777 == 0o600
        assert call("native_ping")["value"]["protocol"] == 1
        assert call("native_ping", credential="0" * 64) is None
        assert call("get_state")["ok"] is True
        assert call("get_startup_state")["ok"] is True
        assert call("toggle_sysproxy", {"enable": True})["ok"] is False
        assert call("arbitrary_shell_command")["ok"] is False
        assert call("native_shutdown")["ok"] is True
        child.wait(timeout=10)
        assert child.returncode == 0
        print("Native helper IPC: private socket, authentication, state, mutation refusal and clean shutdown passed.")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
