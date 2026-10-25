#!/usr/bin/env bash
# LAB ONLY — run from Kali against YOUR OWN lab site.
# Requires: echo "<WAF_IP> shop.lab.local" | sudo tee -a /etc/hosts
TARGET="https://shop.lab.local:8443"

echo "== Origin must be unreachable directly =="
curl -m 5 -s -o /dev/null -w "direct origin -> %{http_code}\n" "http://${WAF_IP:-172.16.134.129}:8080" \
  || echo "direct origin -> refused (good)"

echo "== Payload tests (expect 403 for attacks, 200 for /) =="
for u in "/?id=1'%20OR%20'1'='1" \
         "/?q=<script>alert(1)</script>" \
         "/../../etc/passwd" \
         "/download?file=../../../../etc/passwd" \
         "/?cmd=;cat%20/etc/passwd" \
         "/"; do
  printf "%-45s -> " "$u"
  curl -sk --path-as-is -o /dev/null -w "%{http_code}\n" "${TARGET}${u}"
done

echo "== Vulnerability scan =="
nikto -h "${TARGET}" -ssl
