#!/usr/bin/env bash
# compliance/run_all.sh — optional aggregator, read-only

set -Eeuo pipefail
COMPLIANCE_DIR="${COMPLIANCE_DIR:-./compliance}"
REPORT_DIR="${REPORT_DIR:-./compliance-reports}"
mkdir -p "$REPORT_DIR"

declare -a modules=()
# Discover scripts named *.sh inside compliance dir (hipaa, cis-gcp, pci, iso27001, etc.)
while IFS= read -r -d '' f; do modules+=("$f"); done < <(find "$COMPLIANCE_DIR" -maxdepth 1 -type f -name '*.sh' -print0 | sort -z)

overall_rc=0
for m in "${modules[@]}"; do
  echo "==== Running $(basename "$m") ===="
  # forward a common CLI surface; each checker can ignore unknown options safely if you keep them consistent
  if ! "$m" --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
            --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
            --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
            --sa-email "$SA_EMAIL" --vm "$VM1" --vm "$VM2" \
            --report-dir "$REPORT_DIR"; then
    overall_rc=2
  fi
done

exit "$overall_rc"
