#!/usr/bin/env bash
# Verifies custom rule 'block-shell-substitution' (run from Kali).
# Before the rule: 404 / 404 / 200  (payload audited, reached origin)
# After the rule:  403 / 403 / 200
T="https://shop.lab.local:8443"
curl -sk -o /dev/null -w "plain   \$(  -> %{http_code}\n" "$T/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=\$(ls+/etc/)"
curl -sk -o /dev/null -w "encoded %24%28 -> %{http_code}\n" "$T/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=%24%28ls+/etc/%29"
curl -sk -o /dev/null -w "normal  /     -> %{http_code}\n" "$T/"
