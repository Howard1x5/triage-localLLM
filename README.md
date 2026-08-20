# triage-localLLM

LLM benchmark harness for security alert triage — test the same synthetic alerts across multiple models and GPUs, compare cost/latency/quality, and evaluate a privacy-preserving cascade architecture that keeps sensitive data off cloud APIs.

## What this does

Runs a fixed set of synthetic security alerts through a configurable LLM cascade:

```
Synthetic alert
      │
      ▼
Local inference engine (Ollama — llama3.1:8b on GTX 1080 Ti)
      │
      ├── confidence ≥ 70% + severity < CRITICAL
      │         └──► Return structured result ✅
      │
      └── confidence < 70% OR severity = CRITICAL
                │
                ▼
          PII Scrubber (strips IPs, emails, tokens, ARNs, hostnames)
                │
                ▼
          Cloud fallback (RunPod pod OR Claude API)
                │
                └──► Return enriched analysis ✅
```

The cascade ensures sensitive data stays local unless the model needs help — and when it escalates, the scrubber runs first. **All alerts in this repo are synthetic samples.**

---

## Tools

| Tool | Purpose |
|------|---------|
| `triage.py` | Core triage engine — runs a single alert through the cascade |
| `benchmark.py` | Multi-model benchmark — same alert set across multiple endpoints (local Ollama, RunPod, Claude) |
| `wiz_triage.py` | Cloud finding re-prioritizer — PHI-proximity scoring on Wiz CSV exports |
| `bot.py` | Telegram interface for local testing with the cascade |
| `scrubber.py` | PII scrubber module — used automatically before any cloud escalation |

---

## Benchmark (`benchmark.py`)

The core of this project. Runs a fixed set of synthetic security alert scenarios through each configured model endpoint and produces a comparison report.

### What it measures

| Metric | Description |
|--------|-------------|
| Latency | Time to first structured output (seconds) |
| Cost | Estimated cost per alert at cloud/RunPod rates |
| Severity accuracy | Does the model agree with ground truth severity? |
| MITRE accuracy | Correct ATT&CK technique classification |
| FP detection | Does the model correctly identify false positives? |
| Confidence calibration | Does stated confidence correlate with accuracy? |

### Supported endpoints

```yaml
# config/endpoints.yml
endpoints:
  local_1080ti:
    type: ollama
    url: http://localhost:11434
    model: llama3.1:8b
    notes: GTX 1080 Ti (11GB VRAM)

  runpod_a100:
    type: runpod
    model: llama3.1:70b
    gpu: A100 80GB
    notes: On-demand, ~$2.39/hr

  runpod_4090:
    type: runpod
    model: mistral-nemo
    gpu: RTX 4090
    notes: On-demand, ~$0.74/hr

  claude_sonnet:
    type: anthropic
    model: claude-sonnet-4-6
    notes: Cloud fallback baseline
```

### Usage

```bash
# Run full benchmark across all configured endpoints
python benchmark.py --config config/endpoints.yml --alerts samples/alerts.json

# Run a single alert through all endpoints
python benchmark.py --alert samples/alerts.json --id lateral_movement_001

# Output a markdown comparison report
python benchmark.py --config config/endpoints.yml --output BENCHMARKS.md
```

### Sample output

```
======================================================================
  BENCHMARK RESULTS — 20 synthetic alerts, 4 endpoints
======================================================================

  Model                  | Latency | Cost/alert | Severity | MITRE | FP Rate
  -----------------------|---------|------------|----------|-------|--------
  llama3.1:8b (1080 Ti)  |  3.2s   |   $0.000   |   87%    |  71%  |  82%
  llama3.1:70b (A100)    |  8.1s   |   $0.004   |   94%    |  88%  |  91%
  mistral-nemo (4090)    |  4.7s   |   $0.001   |   89%    |  79%  |  85%
  claude-sonnet-4-6      |  2.1s   |   $0.018   |   97%    |  93%  |  96%
  -----------------------------------------------------------------------
  Cascade (8b → 70b → claude on escalation):
                         |  3.4s   |   $0.002   |   95%    |  90%  |  94%
======================================================================
```

---

## Alert Triage Engine (`triage.py`)

Single-alert interface for testing the cascade with a custom input.

```bash
python triage.py --alert "Failed login from 192.0.2.45 — 847 attempts in 60s, account locked"
```

```
Severity    : HIGH
FP Prob     : 6%
MITRE       : T1110.001 (Brute Force: Password Guessing)
Action      : Investigate source, check for successful auth before lockout
Confidence  : 91%
Source      : Local (llama3.1:8b)
```

---

## Wiz Finding Triage (`wiz_triage.py`)

Re-prioritizes Wiz cloud security findings using local LLM risk scoring tuned for healthcare environments. PHI proximity changes the risk equation — a misconfigured S3 bucket near member data is not the same risk as one near build artifacts.

```bash
# Demo mode — built-in synthetic healthcare findings, no Wiz needed
python wiz_triage.py --demo

# Real Wiz CSV export
python wiz_triage.py --input findings.csv --output risk_ranked.csv
```

---

## Synthetic Alert Samples (`samples/`)

All test alerts are synthetic — representative of real alert patterns but containing no real infrastructure data.

```json
[
  {
    "id": "lateral_movement_001",
    "text": "Pass-the-hash detected: NTLM auth from WORKSTATION-42 to DC-01 using credential of svc-backup",
    "ground_truth": { "severity": "CRITICAL", "mitre": ["T1550.002", "T1021.002"], "fp": false }
  },
  {
    "id": "phishing_001",
    "text": "Suspicious attachment opened: invoice_final.xlsm — macro execution via WINWORD.EXE spawning cmd.exe",
    "ground_truth": { "severity": "HIGH", "mitre": ["T1566.001", "T1059.003"], "fp": false }
  },
  {
    "id": "fp_001",
    "text": "Vulnerability scan detected from 192.0.2.50 — 2,400 SYN packets/sec across port range 1-65535",
    "ground_truth": { "severity": "LOW", "mitre": ["T1046"], "fp": true, "reason": "Authorized Nessus scanner" }
  }
]
```

---

## PII Scrubber (`scrubber.py`)

Runs automatically before any cloud escalation. Designed so the cascade is safe to adapt for production environments where alert data is sensitive.

| Pattern | Replacement |
|---------|-------------|
| Internal IPs (RFC 1918) | `[INTERNAL-IP-N]` |
| Email addresses | `[EMAIL-REDACTED]` |
| AWS ARNs | `[AWS-ARN-REDACTED]` |
| AWS account IDs (12-digit) | `[AWS-ACCOUNT-REDACTED]` |
| Usernames in paths | `[USER-N]` |
| Internal hostnames | `[INTERNAL-HOST]` |
| Session tokens / base64 >40 chars | `[TOKEN-REDACTED]` |

---

## Setup

```bash
git clone https://github.com/Howard1x5/triage-localLLM.git
cd triage-localLLM
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

```env
# .env.example
ANTHROPIC_API_KEY=        # optional — cloud fallback only
RUNPOD_API_KEY=           # optional — RunPod endpoints only
ESCALATION_THRESHOLD=70   # escalate if local confidence < this
TELEGRAM_TOKEN=           # optional — only needed for bot.py
```

## Requirements

- Python 3.10+
- For local inference: NVIDIA GPU with 6GB+ VRAM, [Ollama](https://ollama.com) with `llama3.1:8b` pulled
- For RunPod endpoints: RunPod account + API key

## Project structure

```
triage-localLLM/
├── triage.py              # Single-alert cascade engine
├── benchmark.py           # Multi-model benchmark harness
├── scrubber.py            # PII scrubber
├── cascade.py             # Escalation logic
├── bot.py                 # Telegram interface (local testing)
├── wiz_triage.py          # Wiz finding triage with PHI scoring
├── samples/
│   └── alerts.json        # Synthetic alert test set with ground truth
├── config/
│   └── endpoints.yml      # Model/GPU endpoint configuration
├── requirements.txt
└── .env.example
```

## SOC Pipeline Integration -- Implemented

See [`pipeline/`](https://github.com/Howard1x5/triage-localLLM/tree/main/pipeline) in this repo for the real, tested glue code -- chains a real detection-as-code alert through this project's actual `triage()` and `should_escalate()` functions, with an ARGUS handoff on escalation. Stages 1->2 are tested end-to-end against a live local Ollama instance; the ARGUS invocation itself is documented and wired but not executed in the demo (see the pipeline README for exactly why).

Designed to sit downstream of [detection-as-code](https://github.com/Howard1x5/detection-as-code)'s Sigma/YARA/Wazuh detections as the triage layer, and upstream of [ARGUS](https://github.com/Howard1x5/argus) for cases that need deeper investigation. High-severity or low-confidence results are intended to hand off to ARGUS rather than being resolved by triage alone. See detection-as-code's README for the full pipeline picture.

## License

MIT
