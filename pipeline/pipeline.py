"""
soc-pipeline -- chains three independently-built projects into one real
L1->L2 SOC escalation demo:

  detection-as-code (real Sigma/YARA/Wazuh rule fires)
    -> triage-localLLM (local-first triage, confidence-scored)
      -> ARGUS (deep investigation, only when triage says it's warranted)

Run this on the same host as triage-localLLM's real code (where its local
Ollama instance lives) -- point TRIAGE_LOCAL_PATH at that checkout.

Usage:
    python3 pipeline.py                          # built-in AsyncRAT demo alert
    python3 pipeline.py --list                   # show available demo alerts
    python3 pipeline.py --alert-id kerberoast    # run a specific demo alert
    python3 pipeline.py --alert-file alert.txt   # triage an alert from a file
    python3 pipeline.py --alert-text "..."       # triage an inline alert string
"""

import argparse
import json
import os
import sys

TRIAGE_LOCAL_PATH = os.getenv(
    "TRIAGE_LOCAL_PATH", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, TRIAGE_LOCAL_PATH)

try:
    import triage as triage_mod
    from cascade import should_escalate
except ImportError as e:
    sys.exit(
        f"Could not import triage-localLLM modules from {TRIAGE_LOCAL_PATH!r}: {e}\n"
        "Set TRIAGE_LOCAL_PATH to the directory containing triage.py and cascade.py, e.g.:\n"
        "    TRIAGE_LOCAL_PATH=~/triage-local python3 pipeline.py"
    )

# triage-localLLM's own default is used unless OLLAMA_URL is set. On one
# deployment host, IPv4 loopback was blocked by an unrelated firewall rule
# while IPv6 worked, and "localhost" resolution picked the blocked path --
# every call then hung for a full 120s timeout. That's environment-specific,
# so it's an opt-in override here rather than a hardcoded default that would
# surprise anyone running this elsewhere:
#     OLLAMA_URL="http://[::1]:11434/api/generate" python3 pipeline.py
_ollama_override = os.getenv("OLLAMA_URL")
if _ollama_override:
    triage_mod.OLLAMA_URL = _ollama_override


def format_wazuh_alert(rule_id, level, description, mitre_ids, matched_field, matched_value):
    """Construct a Wazuh alert in the shape detection-as-code's real rules
    (rules/wazuh/*.xml) produce when they fire.

    Note: this *constructs* an alert matching the real rule's output shape --
    it does not run a live Wazuh instance. The rule content (ID, description,
    MITRE mapping, matched field) is copied from the actual rule definitions
    in the detection-as-code repo, so the triage stage receives realistic
    input, but stage 1 is reconstructed rather than captured live.
    """
    return (
        f"Wazuh Alert -- Rule {rule_id} (Level {level})\n"
        f"Description: {description}\n"
        f"MITRE ATT&CK: {', '.join(mitre_ids)}\n"
        f"Matched field: {matched_field}\n"
        f"Matched value: {matched_value}\n"
    )


# Demo alerts built from real detection-as-code rule content. Each exercises a
# different triage path -- the point is to show the escalation decision varying
# with the input, not to always trip the same branch.
DEMO_ALERTS = {
    "asyncrat": dict(
        rule_id="100100",
        level="12",
        description="AsyncRAT: Registry Run key persistence pointing to suspicious directory",
        mitre_ids=["T1547.001"],
        matched_field="win.eventdata.targetObject",
        matched_value=r"HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
    ),
    "credential-dump": dict(
        rule_id="100200",
        level="14",
        description="Credential dumping: LSASS process access with suspicious granted rights",
        mitre_ids=["T1003.001"],
        matched_field="win.eventdata.targetImage",
        matched_value=r"C:\Windows\System32\lsass.exe",
    ),
    "kerberoast": dict(
        rule_id="100300",
        level="10",
        description="Possible Kerberoasting: multiple service tickets requested by single account",
        mitre_ids=["T1558.003"],
        matched_field="win.eventdata.serviceName",
        matched_value="svc-sql-prod",
    ),
}


def format_real_wazuh_alert(alert: dict) -> str:
    """Render a REAL Wazuh alert (a parsed line from /var/ossec/logs/alerts/alerts.json)
    into the text form the triage stage consumes.

    Unlike format_wazuh_alert() above, nothing here is reconstructed: every value
    comes from an alert Wazuh actually produced, decoded by windows_eventchannel
    from a live agent's Sysmon eventchannel forward.
    """
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    mitre = rule.get("mitre", {})
    eventdata = (
        alert.get("data", {}).get("win", {}).get("eventdata", {})
    )

    lines = [
        f"Wazuh Alert -- Rule {rule.get('id')} (Level {rule.get('level')})",
        f"Description: {rule.get('description')}",
    ]
    if mitre.get("id"):
        techniques = ", ".join(mitre["id"])
        tactics = ", ".join(mitre.get("tactic", []))
        lines.append(f"MITRE ATT&CK: {techniques}" + (f" ({tactics})" if tactics else ""))
    if agent:
        lines.append(f"Agent: {agent.get('name')} ({agent.get('ip', 'n/a')})")
    if alert.get("timestamp"):
        lines.append(f"Timestamp: {alert['timestamp']}")

    # Surface the Sysmon fields an analyst would actually read first. The
    # eventchannel decoder emits doubled backslashes; normalize for readability.
    for key in ("eventType", "image", "targetObject", "details", "user",
                "commandLine", "parentImage", "destinationIp", "destinationPort"):
        val = eventdata.get(key)
        if val:
            lines.append(f"{key}: {str(val).replace(chr(92) * 2, chr(92))}")

    return "\n".join(lines) + "\n"


def load_wazuh_alert(path: str) -> dict:
    """Load a Wazuh alert from a file containing one alerts.json line (or a
    whole alerts.json, in which case the last parseable alert is used)."""
    last = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    if last is None:
        raise ValueError(f"no parseable JSON alert found in {path!r}")
    return last


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
    return {
        "handoff": "argus",
        "case": case_name,
        "reason": reason,
        "command": cmd,
        "executed": False,
    }


def run_pipeline(alert_text: str, case_name: str = "demo-case") -> dict:
    print("=== Stage 1: Detection-as-Code alert ===")
    print(alert_text)

    print("=== Stage 2: triage-localLLM ===")
    try:
        result = triage_mod.triage(alert_text)
    except Exception as e:
        # A triage failure is itself a pipeline outcome worth reporting, not a
        # crash -- the real run that surfaced the blocked-loopback bug failed
        # exactly here, and that failure is what first exercised the escalation
        # path (cascade treats error results as escalation-worthy, by design).
        print(f"  triage call failed: {type(e).__name__}: {e}", file=sys.stderr)
        print(
            "  (if this hangs then fails, check OLLAMA_URL -- see module docstring)",
            file=sys.stderr,
        )
        return {"triage": None, "error": str(e), "escalated": False}

    print(json.dumps(result, indent=2))

    escalate, reason = should_escalate(result)
    print(f"\nEscalate to ARGUS? {escalate}" + (f" ({reason})" if reason else ""))

    if escalate:
        print("\n=== Stage 3: ARGUS handoff ===")
        handoff = run_argus_handoff(case_name, reason)
        return {"triage": result, "escalated": True, "argus_handoff": handoff}

    return {"triage": result, "escalated": False}


def main():
    parser = argparse.ArgumentParser(
        description="Chain a detection-as-code alert through triage-localLLM into an ARGUS handoff.",
    )
    src = parser.add_mutually_exclusive_group()
    src.add_argument("--alert-id", choices=sorted(DEMO_ALERTS), help="run a built-in demo alert")
    src.add_argument("--alert-file", help="path to a file containing raw alert text")
    src.add_argument("--alert-text", help="raw alert text passed inline")
    src.add_argument(
        "--alert-json",
        help="path to a REAL Wazuh alert (a line from /var/ossec/logs/alerts/alerts.json)",
    )
    parser.add_argument("--list", action="store_true", help="list built-in demo alerts and exit")
    parser.add_argument("--case-name", default="demo-case", help="case name used in the ARGUS handoff")
    parser.add_argument("--json", action="store_true", help="print only the final JSON result")
    args = parser.parse_args()

    if args.list:
        for name, spec in sorted(DEMO_ALERTS.items()):
            print(f"{name:18} rule {spec['rule_id']} (level {spec['level']}) -- {spec['description']}")
        return

    if args.alert_json:
        try:
            raw = load_wazuh_alert(args.alert_json)
        except (OSError, ValueError) as e:
            sys.exit(f"Could not load --alert-json {args.alert_json!r}: {e}")
        alert = format_real_wazuh_alert(raw)
        rid = raw.get("rule", {}).get("id")
        print(f"(loaded real Wazuh alert: rule {rid}, agent "
              f"{raw.get('agent', {}).get('name')})\n")
    elif args.alert_file:
        try:
            alert = open(args.alert_file, encoding="utf-8").read()
        except OSError as e:
            sys.exit(f"Could not read --alert-file {args.alert_file!r}: {e}")
    elif args.alert_text:
        alert = args.alert_text
    else:
        alert = format_wazuh_alert(**DEMO_ALERTS[args.alert_id or "asyncrat"])

    final = run_pipeline(alert, case_name=args.case_name)

    if args.json:
        print(json.dumps(final, indent=2))
    else:
        print("\n=== Final pipeline result ===")
        print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
