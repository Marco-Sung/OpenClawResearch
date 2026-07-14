"""Dependency-free web server (stdlib). Serves the built HTML fixtures in
./out/web over HTTP, so the web connector fetches a real URL instead of a
Python string. Leave it running in its own shell:
 
    python tests/transport/server.py
"""
import functools
import http.server
import socketserver
from pathlib import Path
 
ROOT = Path(__file__).resolve().parent / "out" / "web"
PORT = 8080
 
if __name__ == "__main__":
    ROOT.mkdir(parents=True, exist_ok=True)
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(ROOT)
    )
    with socketserver.TCPServer(("127.0.0.1", PORT), handler) as httpd:
        print(f"serving {ROOT} at http://127.0.0.1:{PORT}/")
        httpd.serve_forever()
 