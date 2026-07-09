import os
import logging
import anthropic
from scrubber import scrub

logger = logging.getLogger(__name__)

ESCALATION_CONFIDENCE_THRESHOLD = int(os.getenv("ESCALATION_CONFIDENCE_THRESHOLD", "70"))
ESCALATION_SEVERITIES = {"CRITICAL"}

CLAUDE_PROMPT = """You are a senior security analyst reviewing a pre-triaged alert.
A local model already assessed this alert. Provide a deeper analysis.

ALERT (sensitive data redacted before transmission):
{alert_text}

LOCAL MODEL ASSESSMENT:
{local_assessment}

Provide your analysis as structured text covering:
1. Do you agree with the severity assessment? Why or why not?
2. Additional MITRE ATT&CK context or techniques the local model may have missed
3. Specific investigation steps (commands, queries, pivots)
4. Any threat intel context relevant to this pattern
5. Final recommended action"""


def should_escalate(result: dict) -> tuple[bool, str]:
    if result.get("error"):
        return True, "local triage failed"
    if result["confidence"] < ESCALATION_CONFIDENCE_THRESHOLD:
        return True, f"low confidence ({result['confidence']}%)"
    if result["severity"] in ESCALATION_SEVERITIES:
        return True, f"severity is {result['severity']}"
    if len(result.get("mitre_techniques", [])) >= 4:
        return True, "complex multi-technique alert"
    return False, ""


def escalate_to_claude(alert_text: str, local_result: dict) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return "⚠️ Escalation skipped: ANTHROPIC_API_KEY not configured."

    scrubbed_alert, replacements = scrub(alert_text)
    redaction_count = len(replacements)

    prompt = CLAUDE_PROMPT.format(
        alert_text=scrubbed_alert,
        local_assessment=str(local_result),
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        analysis = message.content[0].text
        note = f"\n\n_🔒 {redaction_count} sensitive value(s) redacted before cloud transmission._"
        return analysis + note
    except Exception as e:
        logger.error(f"Claude escalation error: {e}")
        return f"⚠️ Escalation failed: {e}"
