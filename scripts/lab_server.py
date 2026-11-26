#!/usr/bin/env python3
"""Serveur HTTP de laboratoire, local et jetable.

Sert une page minimale sur 127.0.0.1:8080 (modifiable) pour tester les modules
web de Try_Tools sans cible externe. N'émet volontairement AUCUN en-tête de
sécurité ni cookie durci, afin que les contrôles aient quelque chose à signaler.

Usage : python scripts/lab_server.py [port]
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"<html><body><h1>Try_Tools lab</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Cookie volontairement non durci (pour la démo du module cookie_check).
        self.send_header("Set-Cookie", "demo=1; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = HTTPServer(("127.0.0.1", port), _Handler)
    print(f"Lab HTTP sur http://127.0.0.1:{port}  (Ctrl+C pour arrêter)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\narrêt")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
