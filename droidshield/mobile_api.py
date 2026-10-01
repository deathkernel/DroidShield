from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .adb import AdbClient
from .scanner import scan_device

class MobileHandler(BaseHTTPRequestHandler):
    server_version = "DroidShieldMobile/1.0"

    def _authorized(self) -> bool:
        expected = self.server.token
        supplied = self.headers.get("Authorization", "")
        return bool(expected) and supplied == f"Bearer {expected}"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"service": "droidshield", "status": "ok"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/api/v1/scan":
            self._send(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length) or b"{}")
            serial = request.get("serial")
            hash_apks = bool(request.get("hash_apks", False))
            report = scan_device(AdbClient(), serial, hash_apks=hash_apks)
            self._send(200, {"ok": True, "report": report})
        except Exception as exc:
            self._send(500, {"ok": False, "error": str(exc)})

def serve_mobile(host: str, port: int, token: str) -> None:
    if not token:
        raise ValueError("A non-empty --token is required for the mobile API.")
    server = ThreadingHTTPServer((host, port), MobileHandler)
    server.token = token
    print(f"DroidShield mobile API listening on http://{host}:{port}")
    server.serve_forever()
