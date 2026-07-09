# triage-localLLM

Security alert triage on a local LLM. Drop in an alert as text or a phone screenshot — get back structured output: severity, MITRE techniques, false positive probability, and a recommended action. Nothing leaves your machine unless the local model isn't confident, and even then sensitive data gets scrubbed before it touches a cloud API.

## The problem this solves

When you're triaging alerts in an MDR or IR environment, the alerts contain real data — internal IPs, hostnames, usernames, account IDs. Piping that directly into a cloud LLM violates data handling agreements and in some cases client NDAs. Most "AI-assisted" triage tools ignore this entirely.

This project runs inference locally (Ollama + llama3.1:8b) and only escalates to Claude when the local model isn't confident or when severity is CRITICAL. Before any escalation, a scrubber strips PII from the payload.

## How it works

```
Telegram (text or photo)
        │
        ▼
   OCR (Tesseract)         ← photo inputs only
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
          Claude API
                  │
                  └──► Return enriched analysis to Telegram
```

## Features

- Local inference via Ollama — llama3.1:8b, 4.9GB, runs on a GTX 1080 Ti
- Telegram interface — works from your phone, paste text or send a screenshot
- OCR support — snap a photo of any screen, bot extracts the text and triages it
- Structured output — severity, FP probability, MITRE ATT&CK techniques, confidence score, recommended action
- LLM cascade — auto-escalates to Claude when local model confidence is low or severity is CRITICAL
- PII scrubbing — before any cloud call, strips internal IPs (RFC 1918), emails, usernames, AWS ARNs, hostnames, and session tokens

## Requirements

- Linux with NVIDIA GPU (6GB+ VRAM — tested on GTX 1080 Ti)
- [Ollama](https://ollama.com) with `llama3.1:8b` pulled
- Python 3.10+
- Tesseract OCR: `sudo apt install tesseract-ocr`

## Setup

```bash
git clone https://github.com/Howard1x5/triage-localLLM.git
cd triage-localLLM

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in your Telegram bot token (required) and Anthropic API key (optional)
```

Get a Telegram token: message `@BotFather` on Telegram → `/newbot`.

## Configuration

```bash
TELEGRAM_TOKEN=your_bot_token
ANTHROPIC_API_KEY=your_key          # optional — only used for cloud escalation
ESCALATION_CONFIDENCE_THRESHOLD=70  # escalate if local confidence < this value
```

## Running

```bash
source .env && venv/bin/python bot.py
```

A systemd unit is included (`triage-local.service`) if you want it running as a background service.

## Usage

Once the bot is up, open Telegram and:

- Send alert text directly → immediate triage
- Send a photo of your screen → bot OCRs and triages
- `/start` → welcome message

### Example output

```
CRITICAL — FP probability: 8%
Summary: Lateral movement via pass-the-hash from compromised workstation
MITRE: T1550.002, T1021.002
Action: Isolate source endpoint immediately, collect memory dump
Confidence: 82% | Source: Local (llama3.1:8b)
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
├── bot.py                 # Telegram bot — handles text and photo inputs
├── triage.py              # Local LLM triage engine (Ollama)
├── cascade.py             # Escalation logic + Claude API integration
├── scrubber.py            # PII scrubbing before cloud transmission
├── ocr.py                 # Tesseract OCR for image inputs
├── requirements.txt
├── .env.example
└── triage-local.service   # systemd unit
```

## License

MIT
