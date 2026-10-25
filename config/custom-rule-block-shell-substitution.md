# SafeLine custom rule — `block-shell-substitution`

Location: **Allow & Deny → Custom Rules → Blacklist → Add rules**

| Setting | Value |
|---|---|
| Type | Deny Rule |
| Name | block-shell-substitution |
| Insert position | First |
| Condition group 1 | URL · Contains · `$(` |
| **OR** condition group 2 | URL · Contains · `%24%28` (URL-encoded `$(`) |
| Monitor mode | Off (block, don't just log) |
| Enabled | Yes |

## Why
Nikto sent `…/cgi-bin/luci/;stok=/locale?…&country=$(ls+/etc/)` (TP-Link LuCI-style
command injection). SafeLine's engine **classified it as CMD Inj but only Audited it**
(stamp: *Allow*), so it reached the origin (HTTP 404).

## Mistake made & fixed
The first version used **ADD AN AND CONDITION** → both strings required at once → the
rule could never match (*Hits Today = 0*). Rebuilt as two **OR** groups → 2 hits, 403.

## Trade-off
`$(` almost never appears in legitimate URLs of this site, so false-positive risk is low.
On an app that legitimately accepts shell-like input, scope the rule to specific paths.
