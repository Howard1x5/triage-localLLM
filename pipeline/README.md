# soc-pipeline

Glue code chaining three independently-built projects into one real L1→L2 SOC escalation demo:

**[detection-as-code](https://github.com/Howard1x5/detection-as-code)** (real Sigma/YARA/Wazuh rule fires) → **[triage-localLLM](https://github.com/Howard1x5/triage-localLLM)** (local-first triage, confidence-scored) → **[ARGUS](https://github.com/Howard1x5/argus)** (deep investigation, only when triage says it's warranted)

This isn't three projects described side by side — it's three projects wired together, tested against real triage-localLLM code running against a real local Ollama instance, not mocked.

## What's actually tested vs. documented

**Stage 1 is now a genuine Wazuh alert, not a reconstruction.** A live Wazuh 4.9.2 manager, a real Windows 11 agent running Sysmon, a benign MITRE T1547.001 simulation (registry Run-key write, no malware), a real `asyncrat_rules.xml` rule firing, and the resulting alert JSON pulled straight from `/var/ossec/logs/alerts/alerts.json`. A captured alert is committed at [`samples/real_wazuh_alert_t1547.json`](samples/real_wazuh_alert_t1547.json) so the demo is reproducible without rebuilding the lab.

The committed sample has lab-identifying values replaced — source IP uses TEST-NET-1 (`192.0.2.50`, RFC 5737), and the hostname and account SID are placeholders. Rule content, MITRE mapping, decoder, event fields, and detection logic are exactly as Wazuh emitted them.

**Real, tested, and running:**
- Stage 1: rule **100101** (level 14, "AsyncRAT: Registry persistence with suspicious value name matching RAT patterns", MITRE T1547.001) fired on agent `WIN11-LAB01` and was decoded by Wazuh's `windows_eventchannel` decoder.
- Stage 1→2: that real alert fed into triage-localLLM's real `triage()` function, which makes a real call to Ollama (llama3.1:8b) and returns real structured output. It correctly extracted T1547.001, rated severity HIGH, and named the actual binary path in its recommended action.
- The escalation decision (`cascade.should_escalate()`) is triage-localLLM's own real logic, unmodified — reused here to gate the ARGUS handoff instead of (or alongside) its original cloud-escalation path.
- Both branches were exercised for real: a non-escalating run (80% confidence, HIGH severity, single MITRE technique — below all four escalation triggers) and an escalating run (triggered honestly by a real infrastructure failure — see below — not fabricated).

**Documented and wired, not executed end-to-end:**
- Stage 2→3, the actual ARGUS invocation. `run_argus_handoff()` prints the exact real command (`argus init <case> --evidence <path> && argus analyze <case>`) rather than running it, because ARGUS requires a real forensic evidence file (EVTX/PCAP/IIS log/Excel) and a configured Anthropic API key — detection-as-code's `samples/` directories are intentionally empty (no live malware samples committed to git), so there's no real evidence to hand it in this environment, and running the full pipeline against a fabricated case would spend real API credits for no genuine investigation. The handoff trigger condition is real; the ARGUS call itself is documented, not faked.

## A real finding from testing this

Running it surfaced an actual infrastructure issue, not a hypothetical one: triage-localLLM's `OLLAMA_URL` defaults to `http://localhost:11434/api/generate`. On the deployment host, IPv4 loopback (`127.0.0.1`) is blocked by a firewall rule scoped for an unrelated project, while IPv6 loopback (`::1`) works — and `localhost` resolution picked the blocked path, causing every call to hang for a full 120-second timeout before failing. `pipeline.py` overrides the URL explicitly (`OLLAMA_URL` env var, defaults to the working `[::1]` form) rather than silently eating that delay. Also, that same connection failure produced this repo's first real escalation-to-ARGUS trigger — `cascade.should_escalate()` correctly flagged `error: true` results for escalation, exactly as designed, even though the "confidence" and "severity" fields were meaningless placeholders in that case.

## Two detection-engineering bugs this surfaced

Wiring the real detection into the real triage stage exposed two rule defects that no amount of reading the rules would have caught. Both are fixed in [detection-as-code](https://github.com/Howard1x5/detection-as-code).

**1. Doubled backslashes.** Wazuh's `windows_eventchannel` decoder emits Windows paths with *doubled* backslashes (`Software\\Microsoft\\Windows`), but the custom rules were written expecting single ones. Wazuh's own built-in rule 92300 accounts for this — it uses `\\\\` in its regex. The custom rules used `\\`, so `targetObject` could never match on real agent data. Fixed by using `\\+` (one or more), which matches both shapes.

**2. Rule shadowing.** The custom rules chained off `<if_sid>61615</if_sid>` (the generic Sysmon EID13 rule). But Wazuh's built-in rule **92300** also matches Run-key writes, matches *first*, and Wazuh only descends into the matching rule's own children. 92300's children require `.lnk/.vbs/.vba` or `reg.exe`, so a `.exe` in AppData produced no alert at all — the custom rules were never evaluated. Fixed by chaining off `<if_sid>92300</if_sid>` instead, which is the correct way to extend a built-in Wazuh detection.

Both bugs meant these rules had **never actually fired on real data**. That is the argument for building the pipeline rather than describing it.

## Running it

```bash
# Against the committed real Wazuh alert (no lab required):
TRIAGE_LOCAL_PATH=~/triage-local OLLAMA_URL='http://[::1]:11434/api/generate' \
  python3 pipeline.py --alert-json samples/real_wazuh_alert_t1547.json

# Against a live alerts.json on the Wazuh manager:
python3 pipeline.py --alert-json /var/ossec/logs/alerts/alerts.json

# Built-in synthetic demo alerts (no Wazuh needed):
python3 pipeline.py --list
python3 pipeline.py --alert-id credential-dump
```

Note the `OLLAMA_URL` override: on the deployment host IPv4 loopback is firewalled for an unrelated project while IPv6 works, and `localhost` resolves to the blocked path. Omit it anywhere that isn't true.

## Why this design

triage-localLLM's own `cascade.py` already had a confidence/severity-based escalation decision — originally built to gate local-vs-cloud-Claude escalation. This reuses that exact same signal to gate a different next step (ARGUS deep investigation) rather than inventing new escalation logic. One trust signal, two possible destinations depending on what the case actually needs.
