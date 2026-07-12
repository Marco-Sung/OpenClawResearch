"""RECEIVE stage: pull raw bytes back OUT of a channel, the way OpenClaw's
connector would, then hand them to the parsers. This is what the runner
calls ON OPENCLAW'S BEHALF -- OpenClaw itself never imports this file.
"""
from __future__ import annotations
 
import poplib
import urllib.request
from pathlib import Path
 
HARNESS = Path(__file__).resolve().parent
DROPBOX = HARNESS / "dropbox"
 
 
class ServerDown(RuntimeError):
    """Raised when a channel server isn't running, with a hint."""
 
 
def reset_mailbox(host: str = "localhost", api_port: int = 8025) -> None:
    """Delete ALL messages currently sitting in Mailpit. Call this before
    each attack (or at least each run) -- receive_email() always grabs the
    'newest' message, so any leftover mail from a previous run/attack can
    get fetched instead of the one you just sent, silently testing the
    WRONG content. This is the email-channel equivalent of
    reset_workspace_test()."""
    import urllib.request
    req = urllib.request.Request(
        f"http://{host}:{api_port}/api/v1/messages", method="DELETE"
    )
    try:
        urllib.request.urlopen(req)
    except urllib.error.URLError as e:
        raise ServerDown("Mailpit API not reachable on :8025 -- run "
                         "`docker compose up -d`.") from e
 
 
def receive_email(host: str = "localhost", port: int = 1110,
                  user: str = "test", password: str = "test") -> bytes:
    """Fetch the newest message over POP3. Needs Mailpit up (docker compose
    up -d) with POP3 auth enabled. Zero-auth fallback: GET the REST API at
    http://localhost:8025/api/v1/messages then /message/{ID}/raw."""
    try:
        pop = poplib.POP3(host, port)
    except ConnectionRefusedError as e:
        raise ServerDown("Mailpit not reachable on :1110 -- run "
                         "`docker compose up -d`.") from e
    try:
        pop.user(user)
        pop.pass_(password)
        count = len(pop.list()[1])
        if count == 0:
            return b""
        _, lines, _ = pop.retr(count)  # newest
        return b"\r\n".join(lines)
    finally:
        pop.quit()
 
 
def receive_web(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url) as r:
            return r.read()
    except urllib.error.URLError as e:
        raise ServerDown(f"Web server not reachable for {url} -- run "
                         f"`python tests/channels/harness/servers/web/serve.py`.") from e
 
 
def receive_file(name: str) -> bytes:
    return (DROPBOX / name).read_bytes()
 