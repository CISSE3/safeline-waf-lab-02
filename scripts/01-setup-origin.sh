#!/usr/bin/env bash
# Origin web server for Lab 02 — run on the SafeLine host (Ubuntu 24.04).
# Apache listens ONLY on the Docker bridge (172.17.0.1:8080):
#  - SafeLine (tengine, host network mode) can reach it
#  - other machines on the LAN cannot → the WAF cannot be bypassed
# Note: SafeLine refuses loopback (127.0.0.1) as an upstream address.
set -euo pipefail
BRIDGE_IP="$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)"
echo "Docker bridge IP: ${BRIDGE_IP}"

sudo apt -y install apache2
sudo sed -i -E "s/^Listen .*8080$|^Listen 80$/Listen ${BRIDGE_IP}:8080/" /etc/apache2/ports.conf
sudo sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-available/000-default.conf
echo "<h1>Lab shop - protected by SafeLine</h1>" | sudo tee /var/www/html/index.html >/dev/null
sudo systemctl restart apache2

grep -n "^Listen" /etc/apache2/ports.conf
sudo ss -tlnp | grep 8080
curl -s "http://${BRIDGE_IP}:8080"
# After a reboot, if the site returns 502: sudo systemctl restart apache2
# (Apache may start before Docker has created docker0.)
