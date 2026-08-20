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
    python3 pipeline.py --alert-json a.json      # a REAL captured Wazuh alert
    python3 pipeline.py --list-scenarios         # show threat-intel scenarios
    python3 pipeline.py --scenario clickfix_stealc
"""

import argparse
import json
import os
import subprocess
import sys

SCENARIO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")

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
    """Load a Wazuh alert from either a pretty-printed single alert or a raw
    alerts.json (JSON Lines, one alert per line -- the last one is used).

    Both shapes matter in practice: alerts.json on the manager is JSON Lines,
    but a single alert saved out for a demo is usually pretty-printed. Parse
    the whole file as one object first, and only fall back to line-by-line if
    that fails -- doing it the other way round makes a pretty-printed file
    parse a bare quoted line (e.g. a lone string value) as the "alert".
    """
    with open(path, encoding="utf-8") as fh:
        content = fh.read()

    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list) and parsed and isinstance(parsed[-1], dict):
            return parsed[-1]
    except json.JSONDecodeError:
        pass

    last = None
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            last = candidate

    if last is None:
        raise ValueError(f"no parseable JSON alert object found in {path!r}")
    return last


def list_scenarios() -> list:
    """Scenario names available in pipeline/scenarios/."""
    if not os.path.isdir(SCENARIO_DIR):
        return []
    return sorted(
        f[:-5] for f in os.listdir(SCENARIO_DIR) if f.endswith(".json")
    )


def load_scenario(name: str) -> dict:
    """Load a threat-intel scenario by name from pipeline/scenarios/."""
    path = os.path.join(SCENARIO_DIR, f"{name}.json")
    if not os.path.isfile(path):
        avail = ", ".join(list_scenarios()) or "(none found)"
        raise ValueError(f"unknown scenario {name!r}. Available: {avail}")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def format_scenario(scenario: dict) -> str:
    """Render a scenario into the alert text the triage stage consumes.

    Scenarios carry richer context than a bare Wazuh alert (campaign intel,
    kill chain, provenance) but the triage stage should see roughly what an
    analyst sees in their queue: the detection, the telemetry fields, and
    the MITRE mapping. The intel block is deliberately NOT fed to the model --
    including the campaign name and 'delivers: StealC' would hand the model
    the answer and make the triage result meaningless as a signal.
    """
    alert = scenario.get("alert", {})
    src = scenario.get("source", {})
    mitre = scenario.get("mitre", {})

    lines = [
        f"Alert -- {alert.get('description', scenario.get('title', 'unknown'))}",
        f"Severity level: {alert.get('level', 'n/a')}",
        f"Telemetry source: {src.get('telemetry', 'unknown')}",
        f"Detection: {src.get('detection', 'unknown')}",
    ]
    if mitre.get("id"):
        techniques = ", ".join(mitre["id"])
        tactics = ", ".join(mitre.get("tactic", []))
        lines.append(f"MITRE ATT&CK: {techniques}" + (f" ({tactics})" if tactics else ""))
    if alert.get("host"):
        lines.append(f"Host: {alert['host']}")
    if alert.get("user"):
        lines.append(f"User: {alert['user']}")
    if scenario.get("timestamp"):
        lines.append(f"Timestamp: {scenario['timestamp']}")

    for key, val in (alert.get("fields") or {}).items():
        lines.append(f"{key}: {val}")

    return "\n".join(lines) + "\n"


def run_argus_investigation(case_name: str, alert_text: str, reason: str) -> dict:
    """Actually invoke ARGUS's LLM backend for a real investigation.

    Only works where ARGUS is importable. ARGUS lives on the workstation, not
    on the triage host (its dependency set -- weasyprint/pandas/python-evtx --
    is heavy and the triage host only needs Ollama), so in the normal two-host
    demo this returns unavailable and the caller falls back to printing the
    handoff. Run with --argus-exec on a host where ARGUS is installed.

    Uses ARGUS's llm_backend, which defaults to the 'subscription' backend
    (shells out to the `claude` CLI). No metered API spend.
    """
    argus_src = os.getenv("ARGUS_SRC", os.path.expanduser(
        "~/Documents/Projects/local/argus/src"))
    if argus_src not in sys.path:
        sys.path.insert(0, argus_src)
    try:
        from argus.llm_backend import call_llm, get_backend, backend_available
    except ImportError as e:
        return {
            "handoff": "argus",
            "case": case_name,
            "reason": reason,
            "executed": False,
            "unavailable": f"ARGUS not importable from {argus_src!r}: {e}",
        }

    ok, detail = backend_available()
    if not ok:
        return {
            "handoff": "argus", "case": case_name, "reason": reason,
            "executed": False, "unavailable": f"backend unavailable: {detail}",
        }

    prompt = (
        "You are the deep-investigation stage of a SOC escalation pipeline. "
        "A local triage model flagged the alert below for escalation.\n\n"
        f"Escalation reason: {reason}\n\n"
        f"--- ALERT ---\n{alert_text}\n"
        "--- END ALERT ---\n\n"
        "Produce a concise investigation: (1) what most likely happened, "
        "(2) the specific next evidence you would pull and from which source, "
        "(3) containment actions warranted right now, "
        "(4) what would make this a false positive. Be specific and terse."
    )
    print(f"  -> running real ARGUS investigation (backend: {get_backend()})")
    try:
        out = call_llm(prompt, max_tokens=900)
    except Exception as e:
        return {
            "handoff": "argus", "case": case_name, "reason": reason,
            "executed": False, "error": f"{type(e).__name__}: {e}",
        }

    text, meta = out if isinstance(out, tuple) else (out, {})
    print("\n--- ARGUS investigation ---")
    print(text)
    return {
        "handoff": "argus",
        "case": case_name,
        "reason": reason,
        "executed": True,
        "backend": (meta or {}).get("backend", get_backend()),
        "investigation": text,
    }


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


def run_pipeline(alert_text: str, case_name: str = "demo-case",
                 argus_exec: bool = False) -> dict:
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
        if argus_exec:
            handoff = run_argus_investigation(case_name, alert_text, reason)
            if not handoff.get("executed"):
                # ARGUS not reachable from this host -- fall back to printing
                # the handoff rather than failing the run.
                why = handoff.get("unavailable") or handoff.get("error")
                print(f"  (real ARGUS run unavailable: {why})")
                handoff = run_argus_handoff(case_name, reason)
        else:
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
    src.add_argument("--scenario", help="run a threat-intel scenario from pipeline/scenarios/")
    parser.add_argument("--list", action="store_true", help="list built-in demo alerts and exit")
    parser.add_argument("--list-scenarios", action="store_true",
                        help="list threat-intel scenarios and exit")
    parser.add_argument("--argus-exec", action="store_true",
                        help="on escalation, run a REAL ARGUS investigation "
                             "(requires ARGUS installed on this host)")
    parser.add_argument("--case-name", default="demo-case", help="case name used in the ARGUS handoff")
    parser.add_argument("--json", action="store_true", help="print only the final JSON result")
    args = parser.parse_args()

    if args.list:
        for name, spec in sorted(DEMO_ALERTS.items()):
            print(f"{name:18} rule {spec['rule_id']} (level {spec['level']}) -- {spec['description']}")
        return

    if args.list_scenarios:
        names = list_scenarios()
        if not names:
            print(f"No scenarios found in {SCENARIO_DIR}")
            return
        for name in names:
            try:
                sc = load_scenario(name)
            except (ValueError, json.JSONDecodeError) as e:
                print(f"{name:26} <unreadable: {e}>")
                continue
            src_t = sc.get("source", {}).get("telemetry", "?")
            print(f"{name:26} {sc.get('title', '')}")
            print(f"{'':26} source: {src_t}")
        return

    if args.scenario:
        try:
            sc = load_scenario(args.scenario)
        except (ValueError, OSError, json.JSONDecodeError) as e:
            sys.exit(f"Could not load --scenario: {e}")
        alert = format_scenario(sc)
        print(f"(scenario: {sc.get('title')})")
        print(f"(source: {sc.get('source', {}).get('telemetry')} "
              f"| provenance: {sc.get('source', {}).get('provenance')})\n")
    elif args.alert_json:
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

    final = run_pipeline(alert, case_name=args.case_name, argus_exec=args.argus_exec)

    if args.json:
        print(json.dumps(final, indent=2))
    else:
        print("\n=== Final pipeline result ===")
        print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
