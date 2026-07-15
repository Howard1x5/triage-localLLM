#!/usr/bin/env python3
"""
wiz_triage.py — Cloud finding triage with local LLM risk scoring

Takes a Wiz CSV export and re-prioritizes findings using a local LLM that
assesses PHI proximity, exploitability, and blast radius in a healthcare
environment. Auto-dismisses non-production and informational noise before
spending any LLM cycles.

Part of the triage-localLLM toolkit — same cascade architecture, different
input surface.

Usage:
  python wiz_triage.py --demo                       # mock findings, no Wiz needed
  python wiz_triage.py --input findings.csv
  python wiz_triage.py --input findings.csv --output risk_ranked.csv
"""

import csv
import json
import sys
import argparse
import requests
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1:8b"

SEVERITY_SCORE = {
    "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFORMATIONAL": 0
}

PHI_NAME_SIGNALS = [
    "member", "patient", "phi", "health", "medical", "claim", "hipaa",
    "record", "pii", "provider", "rx", "prescription", "diagnosis",
    "benefit", "enrollment", "eligibility", "coverage"
]

NON_PROD_SIGNALS = [
    "dev-", "test-", "staging-", "sandbox-", "-dev", "-test",
    "-staging", "-sandbox", "qa-", "-qa"
]


def auto_dismiss(finding: dict) -> tuple[bool, str]:
    """Fast-path dismissal — skip LLM entirely for clear non-issues."""
    severity = finding.get("Severity", "").upper()
    status = finding.get("Status", "").lower()
    resource = (finding.get("Entity Name", "") + " " +
                finding.get("Subscription", "")).lower()

    if status in ("resolved", "rejected"):
        return True, f"Status: {finding.get('Status')}"
    if severity == "INFORMATIONAL":
        return True, "Informational — no action threshold"
    if any(s in resource for s in NON_PROD_SIGNALS):
        return True, "Non-production resource"
    return False, ""


def heuristic_phi_score(finding: dict) -> int:
    """Quick PHI proximity estimate before LLM — used as context in prompt."""
    text = " ".join([
        finding.get("Entity Name", ""),
        finding.get("Entity Type", ""),
        finding.get("Title", ""),
    ]).lower()
    return min(sum(2 for kw in PHI_NAME_SIGNALS if kw in text), 10)


def score_with_llm(finding: dict, phi_hint: int) -> dict:
    """Send finding to local LLM for risk assessment. Falls back to heuristic."""
    prompt = (
        "You are a cloud security engineer at a healthcare company handling "
        "2.5 million members' PHI under HIPAA. Assess this Wiz finding.\n\n"
        f"Title: {finding.get('Title', 'Unknown')}\n"
        f"Severity: {finding.get('Severity', 'Unknown')}\n"
        f"Resource: {finding.get('Entity Name', 'Unknown')} "
        f"({finding.get('Entity Type', 'Unknown')})\n"
        f"Cloud Platform: {finding.get('Cloud Platform', 'Unknown')}\n"
        f"Account/Subscription: {finding.get('Subscription', 'Unknown')}\n\n"
        "Respond ONLY with valid JSON, no other text:\n"
        "{\n"
        '  "phi_proximity": <1-10, likelihood this resource stores or accesses PHI>,\n'
        '  "exploitability": <1-10, likelihood of active exploitation>,\n'
        '  "blast_radius": <1-10, impact if exploited in a healthcare context>,\n'
        '  "risk_score": <1-10, composite risk for this environment>,\n'
        '  "reasoning": "<one sentence — what specifically makes this risky or not>"\n'
        "}"
    )

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt,
                  "stream": False, "options": {"temperature": 0.1}},
            timeout=90
        )
        resp.raise_for_status()
        text = resp.json().get("response", "")
        start, end = text.find("{"), text.rfind("}") + 1
        if start >= 0 and end > start:
            parsed = json.loads(text[start:end])
            # Validate expected keys present
            if all(k in parsed for k in ("phi_proximity", "risk_score", "reasoning")):
                return {**parsed, "source": "local_llm"}
    except Exception:
        pass

    # Heuristic fallback — no LLM available
    sev = SEVERITY_SCORE.get(finding.get("Severity", "").upper(), 3)
    risk = min((phi_hint * 2 + sev) // 3, 10)
    return {
        "phi_proximity": phi_hint,
        "exploitability": min(sev, 8),
        "blast_radius": min(phi_hint + sev // 2, 10),
        "risk_score": risk,
        "reasoning": "Heuristic fallback — verify manually",
        "source": "heuristic",
    }


def priority_label(risk_score: int, phi: int) -> str:
    if risk_score >= 9 or (risk_score >= 7 and phi >= 7):
        return "CRITICAL-PHI"
    if risk_score >= 7:
        return "HIGH"
    if risk_score >= 4:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Mock findings — realistic Wiz export shape, healthcare environment context
# ---------------------------------------------------------------------------
MOCK_FINDINGS = [
    {
        "Title": "S3 bucket with member claims data publicly accessible",
        "Severity": "CRITICAL", "Status": "Open",
        "Entity Name": "garner-member-claims-prod",
        "Entity Type": "S3 Bucket", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "RDS instance not encrypted at rest",
        "Severity": "HIGH", "Status": "Open",
        "Entity Name": "provider-directory-db-prod",
        "Entity Type": "RDS Instance", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "Lambda with wildcard IAM permissions",
        "Severity": "HIGH", "Status": "Open",
        "Entity Name": "claims-processor-fn-prod",
        "Entity Type": "Lambda Function", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "Security group allows inbound RDP from 0.0.0.0/0",
        "Severity": "HIGH", "Status": "Open",
        "Entity Name": "analytics-server-prod",
        "Entity Type": "Security Group", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "CloudTrail logging disabled in us-west-2",
        "Severity": "HIGH", "Status": "Open",
        "Entity Name": "us-west-2",
        "Entity Type": "Region", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "Unused IAM access keys older than 90 days",
        "Severity": "MEDIUM", "Status": "Open",
        "Entity Name": "svc-member-reporting",
        "Entity Type": "IAM User", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "S3 bucket versioning disabled",
        "Severity": "LOW", "Status": "Open",
        "Entity Name": "member-health-records-archive",
        "Entity Type": "S3 Bucket", "Cloud Platform": "AWS",
        "Subscription": "garner-prod-001",
    },
    {
        "Title": "EC2 instance with public IP",
        "Severity": "MEDIUM", "Status": "Open",
        "Entity Name": "dev-test-instance-01",
        "Entity Type": "EC2 Instance", "Cloud Platform": "AWS",
        "Subscription": "garner-dev-sandbox",
    },
    {
        "Title": "MFA not enforced for IAM user",
        "Severity": "INFORMATIONAL", "Status": "Open",
        "Entity Name": "contractor-temp-user",
        "Entity Type": "IAM User", "Cloud Platform": "AWS",
        "Subscription": "garner-staging-env",
    },
    {
        "Title": "Snowflake table with PHI missing row-level security",
        "Severity": "HIGH", "Status": "Open",
        "Entity Name": "MEMBER_ELIGIBILITY_PROD",
        "Entity Type": "Snowflake Table", "Cloud Platform": "Snowflake",
        "Subscription": "garner-snowflake-prod",
    },
]


def run(findings: list[dict]) -> tuple[list, list]:
    scored, dismissed = [], []

    for i, finding in enumerate(findings, 1):
        title = finding.get("Title", "Unknown")[:58]
        sev = finding.get("Severity", "?")
        print(f"[{i:02}/{len(findings)}] {sev:<12} {title}")

        skip, reason = auto_dismiss(finding)
        if skip:
            print(f"            AUTO-DISMISS: {reason}")
            dismissed.append({**finding, "action": "AUTO_DISMISS",
                               "dismiss_reason": reason, "ai_risk_score": 0})
            continue

        phi_hint = heuristic_phi_score(finding)
        scores = score_with_llm(finding, phi_hint)
        risk = scores.get("risk_score", 0)
        label = priority_label(risk, scores.get("phi_proximity", phi_hint))
        src = scores.get("source", "?")

        print(f"            [{label}] risk={risk}/10  "
              f"phi={scores.get('phi_proximity','?')}  "
              f"exploit={scores.get('exploitability','?')}  "
              f"[{src}]")
        print(f"            {scores.get('reasoning', '')[:75]}")

        scored.append({
            **finding,
            "ai_risk_score": risk,
            "phi_proximity": scores.get("phi_proximity"),
            "exploitability": scores.get("exploitability"),
            "blast_radius": scores.get("blast_radius"),
            "ai_reasoning": scores.get("reasoning", ""),
            "priority_label": label,
            "score_source": src,
        })

    scored.sort(key=lambda r: r.get("ai_risk_score", 0), reverse=True)
    return scored, dismissed


def print_summary(scored: list, dismissed: list, total: int):
    labels = [r["priority_label"] for r in scored]
    print(f"\n{'='*70}")
    print("  TRIAGE RESULTS")
    print(f"{'='*70}")
    print(f"  Total processed : {total}")
    print(f"  Auto-dismissed  : {len(dismissed)}  (non-prod, resolved, informational)")
    print(f"  AI-scored       : {len(scored)}")
    print(f"  CRITICAL-PHI    : {labels.count('CRITICAL-PHI')}")
    print(f"  HIGH            : {labels.count('HIGH')}")
    print(f"  MEDIUM          : {labels.count('MEDIUM')}")
    print(f"  LOW             : {labels.count('LOW')}")
    if scored:
        print(f"\n  TOP FINDINGS (address first):")
        for r in scored[:5]:
            print(f"\n  [{r['ai_risk_score']}/10] {r.get('Severity','?'):<10} "
                  f"{r.get('Title','')[:55]}")
            print(f"         Resource : {r.get('Entity Name','?')} "
                  f"({r.get('Entity Type','?')})")
            print(f"         PHI:{r['phi_proximity']}  "
                  f"Exploit:{r['exploitability']}  "
                  f"Blast:{r['blast_radius']}")
            print(f"         {r['ai_reasoning'][:78]}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Wiz finding triage — local LLM risk scoring for healthcare cloud environments"
    )
    parser.add_argument("--input", "-i", help="Wiz findings CSV export")
    parser.add_argument("--output", "-o", help="Write risk-ranked results to CSV")
    parser.add_argument("--demo", action="store_true",
                        help="Run against built-in mock findings (no Wiz needed)")
    args = parser.parse_args()

    if args.demo:
        findings = MOCK_FINDINGS
        print(f"Demo mode — {len(findings)} mock findings (healthcare cloud context)\n")
    elif args.input:
        path = Path(args.input)
        if not path.exists():
            print(f"ERROR: {args.input} not found")
            sys.exit(1)
        with open(path, newline="", encoding="utf-8") as f:
            findings = list(csv.DictReader(f))
        print(f"Loaded {len(findings)} findings from {path.name}\n")
    else:
        parser.print_help()
        sys.exit(1)

    scored, dismissed = run(findings)
    print_summary(scored, dismissed, len(findings))

    if args.output:
        all_rows = scored + dismissed
        if all_rows:
            out = Path(args.output)
            with open(out, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
                writer.writeheader()
                writer.writerows(all_rows)
            print(f"Risk-ranked results → {out}")


if __name__ == "__main__":
    main()
