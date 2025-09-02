#!/usr/bin/env bash
set -Eeuo pipefail

URL="https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/autoconfig.sh"

mkdir -p ~/compliantvm && cd ~/compliantvm

# cache-bust via timestamp param + no-cache headers
wget -O autoconfig.sh --header="Cache-Control: no-cache" "${URL}?nocache=$(date +%s)"
chmod 755 autoconfig.sh

# VERBOSE=1 for xtrace; otherwise quiet
VERBOSE="${VERBOSE:-0}" ./autoconfig.sh