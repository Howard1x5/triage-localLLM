import requests
import json
import logging

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

TRIAGE_PROMPT = """You are an expert security analyst. Analyze the security alert below and respond ONLY with a valid JSON object — no markdown, no explanation, just the JSON.

ALERT:
{alert_text}

Respond with exactly this JSON structure:
{{
  "severity": "CRITICAL or HIGH or MEDIUM or LOW",
  "false_positive_probability": <integer 0-100>,
  "mitre_techniques": ["T1234", "T5678"],
  "summary": "<one sentence describing what happened>",
  "recommended_action": "<specific concrete next step for an analyst>",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentences explaining your assessment>"
}}"""


def triage(alert_text: str) -> dict:
    prompt = TRIAGE_PROMPT.format(alert_text=alert_text.strip())
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "num_ctx": 4096,
                    "temperature": 0.1,
                    "top_p": 0.9,
                },
            },
            timeout=120,
        )
        resp.raise_for_status()
        raw = resp.json()["response"]
        result = json.loads(raw)
        # Normalise keys
        result.setdefault("severity", "UNKNOWN")
        result.setdefault("false_positive_probability", 50)
        result.setdefault("mitre_techniques", [])
        result.setdefault("summary", "")
        result.setdefault("recommended_action", "Manual review required.")
        result.setdefault("confidence", 50)
        result.setdefault("reasoning", "")
        return result
    except Exception as e:
        logger.error(f"Triage error: {e}")
        return {
            "severity": "UNKNOWN",
            "false_positive_probability": 50,
            "mitre_techniques": [],
            "summary": "Triage failed — manual review required.",
            "recommended_action": "Review alert manually.",
            "confidence": 0,
            "reasoning": str(e),
            "error": True,
        }


def format_result(result: dict, escalated: bool = False) -> str:
    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(
        result["severity"], "⚪"
    )
    fp = result["false_positive_probability"]
    conf = result["confidence"]
    techniques = ", ".join(result["mitre_techniques"]) or "None identified"
    source = "☁️ Claude (escalated)" if escalated else "🖥️ Local (llama3.1:8b)"

    lines = [
        f"{sev_emoji} *{result['severity']}* — FP probability: {fp}%",
        f"*Summary:* {result['summary']}",
        f"*MITRE:* {techniques}",
        f"*Action:* {result['recommended_action']}",
        f"*Reasoning:* {result['reasoning']}",
        f"_Confidence: {conf}% | Source: {source}_",
    ]
    return "\n".join(lines)
