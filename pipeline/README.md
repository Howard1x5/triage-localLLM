# soc-pipeline

Glue code chaining three independently-built projects into one real L1→L2 SOC escalation demo:

**[detection-as-code](https://github.com/Howard1x5/detection-as-code)** (real Sigma/YARA/Wazuh rule fires) → **[triage-localLLM](https://github.com/Howard1x5/triage-localLLM)** (local-first triage, confidence-scored) → **[ARGUS](https://github.com/Howard1x5/argus)** (deep investigation, only when triage says it's warranted)

This isn't three projects described side by side — it's three projects wired together, tested against real triage-localLLM code running against a real local Ollama instance, not mocked.

## What's actually tested vs. documented

**Real, tested, and running:**
- Stage 1→2: a realistic Wazuh alert (built from detection-as-code's actual `asyncrat_rules.xml` rule content — same description, MITRE mapping, and matched-field shape a live rule firing would produce) fed into triage-localLLM's real `triage()` function, which makes a real call to Ollama (llama3.1:8b) and returns real structured output.
- The escalation decision (`cascade.should_escalate()`) is triage-localLLM's own real logic, unmodified — reused here to gate the ARGUS handoff instead of (or alongside) its original cloud-escalation path.
- Both branches were exercised for real: a non-escalating run (80% confidence, HIGH severity, single MITRE technique — below all four escalation triggers) and an escalating run (triggered honestly by a real infrastructure failure — see below — not fabricated).

**Documented and wired, not executed end-to-end:**
- Stage 2→3, the actual ARGUS invocation. `run_argus_handoff()` prints the exact real command (`argus init <case> --evidence <path> && argus analyze <case>`) rather than running it, because ARGUS requires a real forensic evidence file (EVTX/PCAP/IIS log/Excel) and a configured Anthropic API key — detection-as-code's `samples/` directories are intentionally empty (no live malware samples committed to git), so there's no real evidence to hand it in this environment, and running the full pipeline against a fabricated case would spend real API credits for no genuine investigation. The handoff trigger condition is real; the ARGUS call itself is documented, not faked.

## A real finding from testing this

Running it surfaced an actual infrastructure issue, not a hypothetical one: triage-localLLM's `OLLAMA_URL` defaults to `http://localhost:11434/api/generate`. On the deployment host, IPv4 loopback (`127.0.0.1`) is blocked by a firewall rule scoped for an unrelated project, while IPv6 loopback (`::1`) works — and `localhost` resolution picked the blocked path, causing every call to hang for a full 120-second timeout before failing. `pipeline.py` overrides the URL explicitly (`OLLAMA_URL` env var, defaults to the working `[::1]` form) rather than silently eating that delay. Also, that same connection failure produced this repo's first real escalation-to-ARGUS trigger — `cascade.should_escalate()` correctly flagged `error: true` results for escalation, exactly as designed, even though the "confidence" and "severity" fields were meaningless placeholders in that case.

## Running it

```bash
# On the host where triage-localLLM actually runs (needs its local Ollama instance):
TRIAGE_LOCAL_PATH=~/triage-local python3 pipeline.py
```

## Why this design

triage-localLLM's own `cascade.py` already had a confidence/severity-based escalation decision — originally built to gate local-vs-cloud-Claude escalation. This reuses that exact same signal to gate a different next step (ARGUS deep investigation) rather than inventing new escalation logic. One trust signal, two possible destinations depending on what the case actually needs.
