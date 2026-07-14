"""DELIVER stage: push a built artifact INTO a channel.
 
  email -> SMTP submit to Mailpit (localhost:1025)
  file  -> copy into the dropbox the file connector reads
  web   -> nothing here; serve.py already serves it from out/web
"""
from __future__ import annotations
 
import shutil
import smtplib
from pathlib import Path
 
HARNESS = Path(__file__).resolve().parent
DROPBOX = HARNESS / "dropbox"
 
 
def deliver_email_raw(raw: str | bytes,
                      host: str = "localhost", port: int = 1025,
                      sender: str = "prof@university.edu",
                      to: str = "openbuddy@workspace.local") -> None:
    """Submit a raw RFC822 message string over SMTP. Used for email attacks
    whose ``raw`` field is already a full MIME message."""
    data = raw.encode() if isinstance(raw, str) else raw
    with smtplib.SMTP(host, port) as s:
        s.sendmail(sender, [to], data)
 
 
def deliver_email(eml_path: str | Path, **kw) -> None:
    deliver_email_raw(Path(eml_path).read_bytes(), **kw)
 
 
def deliver_file(artifact_path: str | Path) -> Path:
    DROPBOX.mkdir(parents=True, exist_ok=True)
    dst = DROPBOX / Path(artifact_path).name
    shutil.copy2(artifact_path, dst)
    return dst
 