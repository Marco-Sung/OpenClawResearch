# tools/workspace_switcher.py

import subprocess
import json
from pathlib import Path

OPENCLAW_JSON  = Path.home() / ".openclaw" / "openclaw.json"
REAL_WORKSPACE = str(Path.home() / ".openclaw" / "workspace")
TEST_WORKSPACE = str(Path.home() / ".openclaw" / "workspace_test")

def backup():
    backup_path = OPENCLAW_JSON.with_suffix(".json.switcher_backup")
    backup_path.write_text(OPENCLAW_JSON.read_text())
    print(f"  ✓ Backup saved")

def sed_replace(old, new):
    result = subprocess.run(
        ["sed", "-i", f"s|{old}|{new}|g", str(OPENCLAW_JSON)],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"  ✗ sed error: {result.stderr}")
        return False
    return True

def restore_backup():
    backup_path = OPENCLAW_JSON.with_suffix(".json.switcher_backup")
    if backup_path.exists():
        OPENCLAW_JSON.write_text(backup_path.read_text())
        print("  ✓ Restored from switcher backup")
    else:
        print("  ✗ No backup found — run:")
        print("    cp /root/.openclaw/openclaw.json.last-good /root/.openclaw/openclaw.json")

def switch_to_test():
    text = OPENCLAW_JSON.read_text()

    # Already in test mode — do nothing
    if TEST_WORKSPACE in text:
        print("  Already pointing at TEST workspace — no change needed")
        current()
        return

    backup()
    success = sed_replace(REAL_WORKSPACE, TEST_WORKSPACE)
    if success:
        print("✓ Switched to TEST workspace")
        current()
    else:
        print("✗ Switch failed — restoring backup")
        restore_backup()

def switch_to_real():
    text = OPENCLAW_JSON.read_text()

    # Already in real mode — do nothing
    if TEST_WORKSPACE not in text:
        print("  Already pointing at REAL workspace — no change needed")
        current()
        return

    backup()
    success = sed_replace(TEST_WORKSPACE, REAL_WORKSPACE)
    if success:
        print("✓ Switched to REAL workspace")
        current()
    else:
        print("✗ Switch failed — restoring backup")
        restore_backup()

def current():
    text = OPENCLAW_JSON.read_text()

    # Determine which workspace is active
    if TEST_WORKSPACE in text:
        active = TEST_WORKSPACE
    elif REAL_WORKSPACE in text:
        active = REAL_WORKSPACE
    else:
        active = "unknown"

    # Count occurrences — expect exactly 2
    count = text.count(active)

    print(f"  [1] agents.defaults.workspace       → {active}")
    print(f"  [2] plugins.gmail.config.attachmentsDir → {active}/gmail")
    print(f"  Paths switched: {count}/2")

    if count == 2:
        print("  ✓ Both paths consistent")
    else:
        print("  ⚠ WARNING: only {count}/2 paths switched — check openclaw.json manually")

def verify_openclaw():
    result = subprocess.run(
        ["openclaw", "doctor"],
        capture_output=True,
        text=True
    )
    output = result.stdout.lower()
    if "invalid" in output:
        print("  ✗ openclaw doctor flagged an issue:")
        print(f"    {result.stdout[:200]}")
        return False
    else:
        print("  ✓ openclaw doctor reports config is valid")
        return True

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "current"

    if cmd == "test":
        switch_to_test()
        verify_openclaw()
    elif cmd == "real":
        switch_to_real()
        verify_openclaw()
    elif cmd == "restore":
        restore_backup()
    else:
        current()