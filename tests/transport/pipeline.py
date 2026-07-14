"""The one switch that separates DIRECT (in-process) from TRANSPORT (over a
real channel). Both return the extracted payload string, which the runner then
hands -- unchanged -- to safe_write(). The defense wiring never changes; only
how the payload is produced does.
"""
from __future__ import annotations
 
from tests.extraction.text import extract
from tests.extraction.files import extract_file
from tests.transport import build, deliver, receive
from tests.transport.received_files import parse_file_bytes
 
WEB_URL = "http://127.0.0.1:8080"
 
 
def extract_direct(attack: dict, strategy: str | None) -> str:
    """Current behavior: parse in-process, no channel."""
    if "raw" in attack:
        return extract(attack["raw"], attack.get("extract_kind", "html"), strategy)
    if "spec" in attack:
        return extract_file(attack["spec"], strategy)
    return attack["payload"]          # core attack: plain string, no extraction
 
 
def extract_transport(attack: dict, strategy: str | None) -> str:
    """Build the artifact, push it through a channel, receive it back, then
    parse. Requires the relevant server to be running (see README)."""
    if "raw" in attack:
        kind = attack.get("extract_kind", "html")
        if kind == "html":
            # Opt-in: attacks can set "web_encoding": "iso-8859-1" (or any
            # codec) to write real non-UTF-8 bytes to disk, exercising the
            # declared-vs-actual charset mismatch. Default stays UTF-8, so
            # existing attacks behave exactly as before.
            enc = attack.get("web_encoding")
            if enc:
                path = build.build_html_encoded(attack["raw"], attack["name"], enc)
            else:
                path = build.build_html(attack["raw"], attack["name"])
            raw = receive.receive_web(f"{WEB_URL}/{path.name}")
            return extract(raw.decode(errors="replace"), "html", strategy)
        # email: attack["raw"] is already a full MIME message
        receive.reset_mailbox()          # <- clear leftover mail first
        # Opt-in: attacks can set "email_encoding": "iso-8859-1" to send the
        # message as real non-UTF-8 bytes over SMTP, even though direct mode
        # keeps parsing attack["raw"] as a clean, correctly-decoded string.
        # Same idea as "web_encoding" above, applied to the email channel.
        enc = attack.get("email_encoding")
        if enc:
            deliver.deliver_email_raw(attack["raw"].encode(enc, errors="replace"))
        else:
            deliver.deliver_email_raw(attack["raw"])
        raw = receive.receive_email()
        return extract(raw.decode(errors="replace"), "email", strategy)
 
    if "spec" in attack:
        fmt = (strategy or "txt").split("_")[0]        # pdf / docx / txt
        if fmt == "pdf":
            art = build.build_pdf(attack["spec"], attack["name"])
        elif fmt == "docx":
            art = build.build_docx(attack["spec"], attack["name"])
        else:
            art = build.build_txt(attack["spec"], attack["name"])
        deliver.deliver_file(art)
        raw = receive.receive_file(art.name)
        return parse_file_bytes(raw, strategy)
 
    return attack["payload"]          # core attack: nothing to transport
 