# triage-localLLM

Privacy-preserving security triage toolkit — local LLM inference for alert triage and cloud finding risk scoring. Nothing leaves your machine unless the local model isn't confident, and even then sensitive data gets scrubbed before it touches a cloud API.

## Tools

| Tool | Input | Use case |
|------|-------|----------|
| `bot.py` | Telegram + alert text | Real-time SIEM alert triage via Telegram interface |
| `wiz_triage.py` | Wiz CSV export | Re-prioritize cloud findings by PHI proximity and exploitability |

---

## Alert Triage (`bot.py`)

### The problem

When triaging alerts in an MDR or IR environment, alerts contain real data — internal IPs, hostnames, usernames, account IDs. Piping that directly into a cloud LLM violates data handling agreements and in some cases client NDAs. Most "AI-assisted" triage tools ignore this entirely.

### How it works

```
Alert text (Telegram)
        │
        ▼
  Local Triage Engine
  (llama3.1:8b via Ollama)
        │
        ├── confidence ≥ 70% + severity < CRITICAL
        │         └──► Return result to Telegram
        │
        └── confidence < 70% OR severity = CRITICAL
                  │
                  ▼
          PII Scrubber
          (strips IPs, emails, usernames, tokens, ARNs)
                  │
                  ▼
          Claude API (cloud escalation)
                  │
                  └──► Return enriched analysis to Telegram
```

### Features

- Local inference via Ollama — llama3.1:8b, 4.9GB, runs on a GTX 1080 Ti
- Telegram interface — paste alert text, get structured triage back
- Structured output — severity, FP probability, MITRE ATT&CK techniques, confidence score, recommended action
- LLM cascade — auto-escalates to Claude when local model confidence is low or severity is CRITICAL
- PII scrubbing — before any cloud call, strips internal IPs (RFC 1918), emails, usernames, AWS ARNs, hostnames, and session tokens

### Example output

```
CRITICAL — FP probability: 8%
Summary: Lateral movement via pass-the-hash from compromised workstation
MITRE: T1550.002, T1021.002
Action: Isolate source endpoint immediately, collect memory dump
Confidence: 82% | Source: Local (llama3.1:8b)
```

---

## Wiz Finding Triage (`wiz_triage.py`)

Re-prioritizes Wiz cloud security findings using local LLM risk scoring tuned for healthcare environments. Built for environments where PHI proximity changes the risk equation — a misconfigured S3 bucket near member data is not the same as one near build artifacts.

### How it works

1. **Auto-dismiss** — filters non-production resources, resolved findings, and informational noise before spending any LLM cycles
2. **PHI heuristic** — quick keyword-based PHI proximity estimate (runs in memory, no LLM call)
3. **LLM scoring** — local model assesses each finding across three axes:
   - `phi_proximity` — how likely is this resource to store or access PHI?
   - `exploitability` — how likely is active exploitation in this context?
   - `blast_radius` — how bad if it's compromised?
4. **Risk ranking** — re-sorts by composite score, labels CRITICAL-PHI / HIGH / MEDIUM / LOW

### Usage

```bash
# Demo mode — no Wiz needed, uses built-in healthcare mock findings
python wiz_triage.py --demo

# Real Wiz export
python wiz_triage.py --input findings.csv

# Write risk-ranked results to CSV
python wiz_triage.py --input findings.csv --output risk_ranked.csv
```

### Example output

```
[01/10] CRITICAL     S3 bucket with member claims data publicly accessible
            [CRITICAL-PHI] risk=9/10  phi=9  exploit=8  [local_llm]
            S3 bucket contains member claims data — PHI under HIPAA, public access is a breach.

[08/10] MEDIUM       EC2 instance with public IP
            AUTO-DISMISS: Non-production resource

======================================================================
  TRIAGE RESULTS
======================================================================
  Total processed : 10
  Auto-dismissed  : 2  (non-prod, resolved, informational)
  AI-scored       : 8
  CRITICAL-PHI    : 7
  HIGH            : 0
  MEDIUM          : 1
  LOW             : 0
```

---

## Requirements

- Linux with NVIDIA GPU (6GB+ VRAM — tested on GTX 1080 Ti)
- [Ollama](https://ollama.com) with `llama3.1:8b` pulled
- Python 3.10+

## Setup

```bash
git clone https://github.com/Howard1x5/triage-localLLM.git
cd triage-localLLM

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in your Telegram bot token and optionally your Anthropic API key
```

## Configuration

```env
TELEGRAM_TOKEN=your_bot_token
ANTHROPIC_API_KEY=your_key          # optional — only used for cloud escalation
ESCALATION_CONFIDENCE_THRESHOLD=70  # escalate if local confidence < this value
```

## PII scrubbing

Before anything reaches the Claude API, the scrubber replaces:

| Pattern | Replacement |
|---------|-------------|
| Internal IPs (RFC 1918) | `[INTERNAL-IP-N]` |
| Email addresses | `[EMAIL-REDACTED]` |
| AWS ARNs | `[AWS-ARN-REDACTED]` |
| AWS account IDs (12-digit) | `[AWS-ACCOUNT-REDACTED]` |
| Usernames in paths | `[USER-N]` |
| Internal hostnames (`.local`, `.internal`, `.corp`) | `[INTERNAL-HOST]` |
| Session tokens / base64 strings >40 chars | `[TOKEN-REDACTED]` |

## Project structure

```
triage-localLLM/
├── bot.py                 # Telegram bot interface
├── triage.py              # Local LLM triage engine (Ollama)
├── cascade.py             # Escalation logic + Claude API integration
├── scrubber.py            # PII scrubbing before cloud transmission
├── wiz_triage.py          # Wiz finding triage with PHI-aware risk scoring
├── requirements.txt
├── .env.example
└── triage-local.service   # systemd unit for background deployment
```

## License

MIT
