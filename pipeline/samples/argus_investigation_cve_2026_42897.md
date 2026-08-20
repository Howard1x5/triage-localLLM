# ARGUS investigation output (real, captured)

- Scenario: cve_2026_42897_exchange
- Escalation reason: severity is CRITICAL
- ARGUS backend: subscription (Claude subscription via CLI, no metered API spend)
- Captured: 2026-08-20

Reproduce with:

    python3 pipeline.py --scenario cve_2026_42897_exchange --argus-exec

(requires ARGUS installed on the host; see DEMO.md)

---

**Tooling note first:** the Open Brain gate could not be satisfied this session. All four documented paths are unavailable — `Bash`, `Read`, and `Glob` are disabled for this session (so neither the `ssh`/psycopg2 query nor the local `memory/*.md` read is possible), and `ToolSearch` is itself blocked by the gate's PreToolUse hook, so the `search_brain` MCP tool's schema can never load. The gate is unsatisfiable as configured; the analysis below is from the alert content alone, with **no** historical/campaign context from Open Brain. Worth fixing the hook to allow `ToolSearch` through, or it deadlocks any session where Bash/Read are off.

---

# CVE-2026-42897 / EXCH01 — Deep Investigation

## 1. Most likely happened

Thread-hijack phish → stored XSS in OWA → session/token theft.

- Spoofed vendor mail (`SPF=fail DKIM=none DMARC=fail`, `RE:` invoice lure) delivered to `a.pearce`.
- Body carries `<img src=x onerror=...>`. EXCH01 is Exchange 2019 CU14 below the 2026-06-09 SU, so the OWA HTML sanitizer bypass (CVE-2026-42897) applies — the payload survives sanitization and executes **in the OWA origin** when the message is rendered.
- `GetItem` returned `200` → the item rendered. Combined with the Defender browser telemetry correlation, treat execution as **likely, not merely attempted**.
- Objective is `document.cookie` exfil to `mail-verify-cdn[.]workers[.]dev` — disposable Cloudflare Workers infra, typical for session-cookie/token theft that bypasses password and MFA.

Two caveats that change the severity math but not the response:
- OWA auth cookies are normally `HttpOnly`, so `document.cookie` may yield little. **Do not downgrade on that alone** — same-origin JS in OWA can drive EWS/REST directly (read mail, create inbox rules, set forwarding) without ever reading a cookie. The exfil is the noisy part; the API abuse is the damaging part.
- `ClientIP 203.0.113.44` is ambiguous. If it's the user's egress, this is the victim rendering the message. If it's external, it may already be replay of a stolen session — resolve this first, it decides whether you're in "prevent" or "evict" mode.

## 2. Next evidence, by source

| Priority | Evidence | Source |
|---|---|---|
| P0 | Does `203.0.113.44` map to corp egress or external ASN? | NetFlow / proxy / IPAM |
| P0 | Any host resolving or connecting to `mail-verify-cdn[.]workers[.]dev`; browser process tree on a.pearce's device | DfE `DeviceNetworkEvents`, `DeviceEvents`, internal DNS logs |
| P0 | Same OWA session ID / token used from a second IP after 11:52:03Z | IIS W3SVC on EXCH01 + Entra sign-in logs (non-interactive) |
| P0 | `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox -ForwardingSMTPAddress`, `Add-MailboxPermission`, `MailItemsAccessed` for a.pearce | Unified Audit Log / mailbox audit |
| P1 | Raw MIME + `InternetMessageId`; full recipient list for that sender/subject/URL | Message tracking logs, Defender Explorer |
| P1 | All `/owa/service.svc` requests for a.pearce ±2h — `GetItem` followed by anomalous `UpdateInboxRules`/`CreateItem`/`Subscribe` | IIS logs, EXCH01 |
| P1 | Exact build: CU14 **plus SU level** vs. the 2026-06-09 SU | `Get-ExchangeServer`, `ExSetup.exe /fileversion`, registry `Setup` key |
| P2 | Proxy hits to `*.workers.dev` with cookie-shaped query strings, any user | Egress proxy logs |

## 3. Containment now

1. **Revoke every session** for `CORP\a.pearce` (`Revoke-MgUserSignInSession`) + password reset. Session revocation is the control that matters here — password reset alone does not kill a stolen cookie.
2. **Block** `mail-verify-cdn[.]workers[.]dev` at DNS/proxy/firewall. Consider alerting on all `*.workers.dev` if policy tolerates it.
3. **Purge tenant-wide**: soft-delete/purge the message for all recipients; block sender domain `contoso-vendor-example[.]com`.
4. **Audit and strip** inbox rules, forwarding addresses, and delegate/folder permissions on the mailbox — attacker persistence lands here, and it survives the password reset.
5. **Patch EXCH01** to the 2026-06-09 SU or later. This is the actual fix; everything above is cleanup. Until patched, consider restricting external OWA exposure.
6. **Preserve** IIS logs and mailbox audit before any rotation window closes.
7. Endpoint isolation for a.pearce's workstation only if DfE shows follow-on execution — scope first, isolate on evidence.

## 4. What makes this a false positive

- **Payload is inert text.** Detection matched raw MIME rather than rendered DOM, and the string is HTML-encoded (`&lt;img`) in the stored body — i.e. a phishing simulation, a pentest report, or a mail thread *discussing* XSS. Check the stored body encoding.
- **Sanitizer held.** The product string may name only the CU, not the SU. If the June 2026 SU is actually applied, the payload was neutered on render and CVE-2026-42897 doesn't apply.
- **No egress.** Zero DNS or network hits to `workers.dev` from any endpoint → payload never fired.
- **`200` is not execution.** It confirms a successful `GetItem` API response, nothing about script execution. Needs browser telemetry to confirm.
- **Sender auth failure is weak signal alone** — misconfigured vendor bulk mail fails SPF/DKIM/DMARC routinely. It corroborates here but is not exculpatory in the other direction.

**Bottom line:** treat as true-positive credential/session theft until the DNS/network check and the SU-level check both come back negative. The unpatched build plus `200` on render is enough to act now.