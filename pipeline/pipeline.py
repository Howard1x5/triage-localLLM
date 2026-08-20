"""
soc-pipeline -- chains three independently-built projects into one real
L1->L2 SOC escalation demo:

  detection-as-code (real Sigma/YARA/Wazuh rule fires)
    -> triage-localLLM (local-first triage, confidence-scored)
      -> ARGUS (deep investigation, only when triage says it's warranted)

Run this on the same host as triage-localLLM's real code (rootbox, where its
local Ollama instance lives) -- point TRIAGE_LOCAL_PATH at that checkout.

Usage:
    python3 pipeline.py
"""

import json
import os
import sys

TRIAGE_LOCAL_PATH = os.getenv("TRIAGE_LOCAL_PATH", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, TRIAGE_LOCAL_PATH)

import triage as triage_mod  # noqa: E402
from cascade import should_escalate  # noqa: E402

# triage-localLLM's OLLAMA_URL defaults to "http://localhost:11434/api/generate".
# On this deployment, IPv4 loopback (127.0.0.1) is blocked by a firewall rule
# scoped for an unrelated project, while IPv6 loopback (::1) works -- "localhost"
# resolution order picked the blocked path. Override explicitly rather than
# silently hanging for two minutes per call.
OLLAMA_URL_OVERRIDE = os.getenv("OLLAMA_URL", "http://[::1]:11434/api/generate")
triage_mod.OLLAMA_URL = OLLAMA_URL_OVERRIDE


def format_wazuh_alert(rule_id, level, description, mitre_ids, matched_field, matched_value):
    """Construct a realistic Wazuh alert in the shape detection-as-code's real
    rules (rules/wazuh/*.xml) actually produce when they fire."""
    return (
        f"Wazuh Alert -- Rule {rule_id} (Level {level})\n"
        f"Description: {description}\n"
        f"MITRE ATT&CK: {', '.join(mitre_ids)}\n"
        f"Matched field: {matched_field}\n"
        f"Matched value: {matched_value}\n"
    )


def run_argus_handoff(case_name: str, reason: str) -> dict:
    """Hand off to ARGUS for deep investigation.

    The real invocation is `argus init <case_path> --evidence <evidence>`
    then `argus analyze <case_path>` -- both require a real forensic
    evidence file (EVTX/PCAP/IIS log/Excel) and a configured Anthropic API
    key. This function prints the exact command rather than executing it:
    there's no real evidence sample wired into this demo (detection-as-code's
    samples/ directories are intentionally empty -- no live malware samples
    committed to git), and running the full ARGUS pipeline against a
    fabricated case would cost real API credits for no genuine investigation.
    The handoff logic and trigger condition are real and tested; the ARGUS
    invocation itself is documented, not faked.
    """
    cmd = f"argus init {case_name} --evidence <evidence_path> && argus analyze {case_name}"
    print(f"  -> escalating to ARGUS (reason: {reason})")
    print(f"     would run: {cmd}")
    return {"handoff": "argus", "case": case_name, "reason": reason, "command": cmd, "executed": False}


def run_pipeline(alert_text: str, case_name: str = "demo-case") -> dict:
    print("=== Stage 1: Detection-as-Code alert ===")
    print(alert_text)

    print("=== Stage 2: triage-localLLM ===")
    result = triage_mod.triage(alert_text)
    print(json.dumps(result, indent=2))

    escalate, reason = should_escalate(result)
    print(f"\nEscalate to ARGUS? {escalate}" + (f" ({reason})" if reason else ""))

    if escalate:
        print("\n=== Stage 3: ARGUS handoff ===")
        handoff = run_argus_handoff(case_name, reason)
        return {"triage": result, "escalated": True, "argus_handoff": handoff}

    return {"triage": result, "escalated": False}


if __name__ == "__main__":
    alert = format_wazuh_alert(
        rule_id="100100",
        level="12",
        description="AsyncRAT: Registry Run key persistence pointing to suspicious directory",
        mitre_ids=["T1547.001"],
        matched_field="win.eventdata.targetObject",
        matched_value=r"HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    )
    final = run_pipeline(alert)
    print("\n=== Final pipeline result ===")
    print(json.dumps(final, indent=2))
