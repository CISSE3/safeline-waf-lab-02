#!/usr/bin/env bash
# Self-signed TLS certificate for shop.lab.local (lab only). Run on the machine
# whose browser you use to upload it into SafeLine (Settings → SSL Cert → Add cert).
set -euo pipefail
mkdir -p ~/lab-cert && cd ~/lab-cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout lab.key -out lab.crt -subj "/CN=shop.lab.local"
openssl x509 -in lab.crt -noout -subject -dates
# Do NOT commit lab.key to git.
