# Demo guide

Driving the SOC escalation pipeline live. Written to be read while nervous.

---

## The one command

SSH to the triage host, then:

```bash
cd ~/triage-local && source venv/bin/activate
export TRIAGE_LOCAL_PATH=~/triage-local
export OLLAMA_URL='http://[::1]:11434/api/generate'
export TRIAGE_SEED=42          # pins the sampler so runs are reproducible

python3 pipeline/pipeline.py --scenario cve_2026_42897_exchange
```

`TRIAGE_SEED` matters for a live demo: without it the same alert can come
back HIGH on one run and CRITICAL on the next, which changes whether the
ARGUS stage fires. With it, verified identical across repeated runs.

That one escalates. If you only run one thing, run that.

Set the two `export` lines **before** the call starts, not during. They are
environment-specific and explaining them mid-demo costs you the thread.

---

## What the pipeline is

Three independently-built projects wired into one escalation path:

```
detection-as-code   ->   triage-localLLM   ->   ARGUS
 (Wazuh/Sigma/YARA)      (local LLM triage,     (deep investigation,
                          confidence-scored)     only on escalation)
```

Stages 1 and 2 run for real on every command below. Stage 3 runs for real
with `--argus-exec` on a host where ARGUS is installed (see caveats).

---

## Scenario menu

```bash
python3 pipeline/pipeline.py --list-scenarios
```

| Scenario | Source | Observed result |
|---|---|---|
| `cve_2026_42897_exchange` | Exchange IIS/OWA + Defender | CRITICAL, 90% → escalated |
| `clickfix_stealc` | Sysmon EID 13 via Wazuh | HIGH, 80% → no escalation |
| `bec_inbox_rule` | M365 Unified Audit Log | HIGH, 80% → no escalation |
| `bec_oauth_consent` | Entra ID audit log | HIGH, 80% → no escalation |

Plus a genuinely captured Wazuh alert from the lab agent:

```bash
python3 pipeline/pipeline.py --alert-json pipeline/samples/real_wazuh_alert_t1547.json
```

That one is not synthetic. Rule 100101 fired on real Sysmon telemetry from a
real Windows agent.

### Results are not deterministic — know this before you demo

`triage.py` calls Ollama at `temperature 0.1` with **no fixed seed**. Low
temperature, not zero, and no seed means the same alert can land on a
different severity between runs. Observed directly while building this: the
captured Wazuh alert returned CRITICAL and escalated on one run, then HIGH
and did not escalate on the next, same input.

The table above is what was observed, not a guarantee.

Two ways to handle it live, both fine:

1. **Own it.** "This is a real model call at temperature 0.1, not a lookup
   table, so borderline alerts land differently between runs. In production
   you would pin a seed or lower the threshold." That answer is stronger
   than a demo that always agrees with the slide.
2. **Avoid the coin flip.** `cve_2026_42897_exchange` is the most reliably
   CRITICAL of the set. Lead with it if you want the escalation path to
   fire on the first try.

Do not promise a specific severity before running the command.

---

## Suggested five-minute run

**1. Lead with the detection bug, not the tool.**

> "I wrote 60 Wazuh detections across six malware families. When I finally
> tested them against real agent telemetry, none of the path-matching rules
> fired. The `windows_eventchannel` decoder emits doubled backslashes and
> every path pattern in the repo assumed single. 42 rules were silently
> dead. I fixed all of them to use `\\+` and verified against real decoder
> output."

That is the strongest thing you have. It is detection engineering, not a demo.

**2. Show the real captured alert.**

```bash
python3 pipeline/pipeline.py --alert-json pipeline/samples/real_wazuh_alert_t1547.json
```

Point out: real rule ID, real agent, real Sysmon event, and the local model
extracting `T1547.001` correctly. Severity varies by run (see above) — read
out whatever it actually returns rather than predicting it.

**3. Show an escalation decision that says no.**

```bash
python3 pipeline/pipeline.py --scenario bec_inbox_rule
```

Typically HIGH at 80% confidence, below the escalation threshold, so it does
not escalate. Say plainly that this is the interesting case: the decision
logic is real, so it sometimes declines. A pipeline that escalates
everything is a pipeline with no logic in it.

**4. If they ask about the last stage**, show the captured investigation:

`pipeline/samples/argus_investigation_cve_2026_42897.md`

Real ARGUS output on the Claude subscription. Worth noting it disagreed with
the scenario's own MITRE mapping, calling `T1203` over-broad for a
script-only payload. That is the model doing analysis rather than echoing.

---

## Talking points that hold up

- **Local-first.** Triage runs on a local llama3.1:8b. No alert content
  leaves the host for the common case. Cost per alert is zero.
- **The escalation logic is not the model.** `should_escalate()` is plain
  Python: confidence threshold, severity set, error state, technique count.
  The model classifies; deterministic code decides. That separation is
  deliberate.
- **Provenance is labelled.** Every scenario file states whether it is
  captured or synthetic and which telemetry source it represents. The BEC
  scenarios are M365/Entra-sourced and say so rather than being dressed up
  as Wazuh alerts they could never have come from.
- **The intel block is withheld from the model.** Scenario files carry
  campaign attribution and kill-chain notes, but `format_scenario()` does
  not pass them to triage. Telling the model "campaign: ClickFix, delivers:
  StealC" would hand it the answer and make the result meaningless.

---

## Caveats to state before they find them

**Stage 3 needs a different host.** ARGUS is installed on the workstation,
not the triage host — its dependency set (weasyprint, pandas, python-evtx)
is heavy and the triage host only needs Ollama. Meanwhile Ollama is
firewalled to the hypervisor, so the workstation cannot reach it. Net
effect: stages 1-2 run on the triage host, stage 3 runs on the workstation.
Without `--argus-exec` the pipeline prints the handoff command instead of
running it, which is the honest default.

**Most scenarios do not escalate.** Three of four typically return HIGH at
80% confidence, just under threshold. Do not act surprised — lead with it.

**Severity varies between runs — unless you set `TRIAGE_SEED`.** At
temperature 0.1 with no seed, the same alert can return HIGH on one run and
CRITICAL on the next, which flips whether stage 3 fires. Export
`TRIAGE_SEED=42` (as in the setup block) and it is reproducible; verified
identical across repeated runs. Without it, never predict the output before
you run it.

If an interviewer asks why a seed is set: same alert should produce the same
verdict. Reproducibility is a property you want in triage tooling, not just
a demo convenience — "why was this HIGH yesterday and CRITICAL today" is a
question worth being able to answer.

**Scenario telemetry is synthetic.** Derived from published threat
reporting, not captured from anyone's production environment. The only
genuinely captured artifact is `real_wazuh_alert_t1547.json`.

---

## When it breaks

| Symptom | Cause | Say this |
|---|---|---|
| Hangs ~120s then fails | `OLLAMA_URL` unset; IPv4 loopback is firewalled on this host, IPv6 works | "Loopback is firewalled here, that is the IPv6 override" |
| `Could not import triage-localLLM modules` | `TRIAGE_LOCAL_PATH` unset or wrong | Set it to the checkout root |
| `real ARGUS run unavailable` | ARGUS not installed on this host | Expected. Show the captured investigation instead |
| Ollama not responding | Service down on the triage host | `systemctl status ollama` |

**Pre-flight, five minutes before the call:**

```bash
curl -s -m 5 http://[::1]:11434/api/tags | head -c 80   # Ollama alive?
python3 pipeline/pipeline.py --list-scenarios            # imports OK?
```

Then run `--scenario cve_2026_42897_exchange` once for real. Model load is
slower on the first call; do not let that first-run latency happen live.

**If the network dies mid-demo:** `pipeline/samples/` has the captured Wazuh
alert and the captured ARGUS investigation. Walk through those. The work is
in the repo, not in the live connection.
