"""Diagnostic: run ONE attack through both direct and transport, print the
extracted text from each AND the sanitizer's actual verdict on each. Text
differing is not the same as the verdict differing -- this checks both.
 
Usage:
    python -m tests.diagnostics.diff_attack email email_charset_adjacent_trigger
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / "openclaw-security"))
 
from tests.research_runner import ATTACK_SETS
from tests.transport import pipeline
from defenses.input_sanitizer import safe_write
 
 
def diff_attack(channel: str, name: str):
    attacks = ATTACK_SETS[channel]
    attack = next((a for a in attacks if a["name"] == name), None)
    if attack is None:
        print(f"No attack named {name!r} in channel {channel!r}")
        return
 
    strategy = attack.get("extract")
    source = attack.get("source", "external")
    target = attack["target"]
 
    direct_text = pipeline.extract_direct(attack, strategy)
    transport_text = pipeline.extract_transport(attack, strategy)
 
    direct_verdict = safe_write(target, direct_text, source)
    transport_verdict = safe_write(target, transport_text, source)
 
    print(f"\n{'='*70}\nATTACK: {name}\n{'='*70}")
 
    print(f"\n--- DIRECT ({len(direct_text)} chars) ---")
    print(repr(direct_text))
    print(f"verdict: {direct_verdict}")
 
    print(f"\n--- TRANSPORT ({len(transport_text)} chars) ---")
    print(repr(transport_text))
    print(f"verdict: {transport_verdict}")
 
    print(f"\n--- TEXT MATCH? --- {'IDENTICAL' if direct_text == transport_text else 'DIFFERENT'}")
    print(f"--- VERDICT MATCH? --- {'SAME' if direct_verdict == transport_verdict else 'DIFFERENT <-- real divergence'}")
 
    if direct_text != transport_text:
        for i, (a, b) in enumerate(zip(direct_text, transport_text)):
            if a != b:
                print(f"First text diff at index {i}: direct={a!r} vs transport={b!r}")
                break
 
 
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python -m tests.diagnostics.diff_attack <channel> <attack_name>")
        sys.exit(1)
    diff_attack(sys.argv[1], sys.argv[2])
 