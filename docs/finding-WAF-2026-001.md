# Finding WAF-2026-001 — Command injection detected but not blocked

| | |
|---|---|
| **Severity (lab)** | Medium — would be High in front of a vulnerable app |
| **Date** | 25 Oct 2026, 05:36:33 CET |
| **Asset** | `https://shop.lab.local:8443` (SafeLine CE 9.4.3, mode Defense) |
| **Source** | 172.16.134.128 (Kali, Nikto 2.6.1) |
| **Request** | `GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(ls+/etc/)` |
| **WAF verdict** | Module **CMD Inj**, action **Audited (Allow)**, event `41ef8d9eaa6f4240ac6064a060091494` |
| **Origin result** | Apache `404` — request reached the origin |

## Analysis
- The payload uses shell command substitution `$( … )`, as in TP-Link LuCI command-injection exploits (e.g. CVE-2023-1389).
- SafeLine **classified it correctly** but its risk score stayed below the blocking threshold → logged only.
- The WAF normalised the payload (`+` → space: `$(ls /etc/)`), so detection operates on decoded input.
- The client sent browser-like headers (`Sec-Fetch-*`, `Accept: text/html…`), yet its **JA4 TLS fingerprint `t13d901100_…`** differs from a real browser — a sign of a scripted client spoofing its user-agent.
- Impact here was nil (no CGI on the origin), but the same request against a vulnerable device would execute commands.

## Remediation
Custom deny rule `block-shell-substitution`: `URL contains $(` **OR** `URL contains %24%28`.

| Test | Before | After |
|---|---|---|
| plain payload | 404 | **403** |
| URL-encoded payload | 404 | **403** |
| `GET /` | 200 | **200** |

## Lessons
1. **Review Audited events, not only Blocked ones** — that is where false negatives hide.
2. Test every new rule with a malicious case **and** a benign case.
3. Rule logic matters: the first version used AND (never matched, 0 hits); OR fixed it.
