#!/usr/bin/env bash
# iso27017.sh — ISO/IEC 27017 cloud controls checker (read-only, idempotent)
# Maps automatable signals to CLD.6.3.1, CLD.8.1.5, CLD.9.5.1, CLD.9.5.2, CLD.12.1.5, CLD.12.4.5, CLD.13.1.4
# Mirrors your autoconfig UX: sections, PASS/FAIL/MANUAL scoreboard, JSON evidence.
# Sources (overview & control list): Google Cloud, Microsoft, IT Governance, BSI mapping.

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# ---- CLI / env (uniform with your modules) -----------------------------------
PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-}"
ZONE="${ZONE:-}"

NETWORK="${NETWORK:-}"
SUBNET="${SUBNET:-}"
SUBNET_RANGE="${SUBNET_RANGE:-}"   # used for CLD.9.5.1 segregation check
ROUTER="${ROUTER:-${NETWORK:+${NETWORK}-router}}"
NAT="${NAT:-${NETWORK:+${NETWORK}-nat}}"

KEYRING="${KEYRING:-}"
KEY="${KEY:-}"
KEY_LOC="${KEY_LOC:-}"
SA_EMAIL="${SA_EMAIL:-}"

declare -a VMS=()
REPORT_DIR="${REPORT_DIR:-./compliance-reports}"
STAMPED="${STAMPED:-1}"

SSH_KEY="${SSH_KEY:-}"   # optional: OS Login key path for SSH probes
SSH_COMMON_BASE=(--tunnel-through-iap)
[[ -n "${SSH_KEY}" ]] && SSH_COMMON_BASE+=(--ssh-key-file="$SSH_KEY")

usage() {
  cat <<EOF
Usage: $0 [--project ID] [--region R] [--zone Z] [--network NET] [--subnet SUBNET] [--subnet-range CIDR]
          [--router R] [--nat N] [--keyring KR] [--key K] [--key-loc L]
          [--sa-email SA] [--vm NAME ...] [--report-dir DIR] [--no-stamped]
Env fallbacks: PROJECT_ID, REGION, ZONE, NETWORK, SUBNET, SUBNET_RANGE, ROUTER, NAT, KEYRING, KEY, KEY_LOC,
               SA_EMAIL, REPORT_DIR, SSH_KEY
Exit codes: 0 OK, 2 FAIL found, 3 missing tools/params
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT_ID="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    --zone) ZONE="$2"; shift 2;;
    --network) NETWORK="$2"; shift 2;;
    --subnet) SUBNET="$2"; shift 2;;
    --subnet-range) SUBNET_RANGE="$2"; shift 2;;
    --router) ROUTER="$2"; shift 2;;
    --nat) NAT="$2"; shift 2;;
    --keyring) KEYRING="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --key-loc) KEY_LOC="$2"; shift 2;;
    --sa-email) SA_EMAIL="$2"; shift 2;;
    --vm) VMS+=("$2"); shift 2;;
    --report-dir) REPORT_DIR="$2"; shift 2;;
    --no-stamped) STAMPED=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

# ---- Preflight ----------------------------------------------------------------
section "ISO/IEC 27017 checker preflight"
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1" >&2; exit 3; }; }
need gcloud; need jq; need awk; need sed; need grep; need date

[[ -n "$PROJECT_ID" && -n "$REGION" && -n "$ZONE" ]] || { echo "Need --project/--region/--zone" >&2; exit 3; }
[[ -n "$NETWORK" && -n "$SUBNET" && -n "$ROUTER" && -n "$NAT" ]] || { echo "Need --network/--subnet/--router/--nat" >&2; exit 3; }
mkdir -p "$REPORT_DIR"

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"

OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[?primary=true].username)' || true)"
[[ -z "$OS_LOGIN_USER" ]] && OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[0].username)' || true)"
SSH_COMMON=("${SSH_COMMON_BASE[@]}")
[[ -n "$OS_LOGIN_USER" ]] && SSH_COMMON+=(--ssh-flag="-l ${OS_LOGIN_USER}")

# ---- Helpers ------------------------------------------------------------------
pass_list=(); fail_list=(); manual_list=(); probe_json=()
check() { local name="$1"; shift; if "$@"; then log "PASS: $name"; pass_list+=("$name"); else log "FAIL: $name"; fail_list+=("$name"); fi; }
note()  { manual_list+=("$1"); log "MANUAL: $1"; }
dedup() { awk '!seen[$0]++'; }

# ============================================================================
# CLD.6.3.1 — Shared roles and responsibilities (customer vs provider)
# ============================================================================
section "CLD.6.3.1 Shared roles & responsibilities"
note "Maintain a documented RACI for cloud services (customer vs provider) and reflect it in contracts/SLAs and runbooks. [MANUAL]"

# ============================================================================
# CLD.8.1.5 — Removal/return of customer assets at termination
# ============================================================================
section "CLD.8.1.5 Removal/return of cloud customer assets"
note "Maintain procedures/evidence for asset return and secure deletion at contract end (keys, data, images, logs, backups), with verification. [MANUAL]"

# ============================================================================
# CLD.9.5.1 — Segregation in virtual computing environments
# ============================================================================
section "CLD.9.5.1 Segregation in virtual computing environments"
# No broad ingress; ensure internal-allow is constrained to your CIDR; no VM public IPs.
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/27017_fws.json

check "No 0.0.0.0/0 ingress on $NETWORK [CLD.9.5.1]" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/27017_fws.json >/dev/null'

if [[ -n "$SUBNET_RANGE" ]]; then
  # Validate any 'allow-internal' rule (if present) is restricted to the declared subnet range
  gcloud compute firewall-rules describe allow-internal --project "$PROJECT_ID" --format=json >/tmp/27017_fw_internal.json 2>/dev/null || true
  if [[ -s /tmp/27017_fw_internal.json ]]; then
    check "Internal allow limited to $SUBNET_RANGE [CLD.9.5.1]" \
      bash -lc 'jq -re '\''[.sourceRanges[]?] | index("'"$SUBNET_RANGE"'") != null'\'' /tmp/27017_fw_internal.json >/dev/null'
  else
    log "MANUAL: Confirm micro-segmentation via firewall policies / tags / service perimeters for multi-tenant segregation. [CLD.9.5.1]"
    manual_list+=("Segregation policy & micro-segmentation design [CLD.9.5.1]")
  fi
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/27017_inst.json
    ext="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // empty' /tmp/27017_inst.json)"
    check "No public IP ($inst) [CLD.9.5.1]"  bash -lc '[[ -z "'"$ext"'" ]]'
  done
fi

# ============================================================================
# CLD.9.5.2 — Virtual machine hardening
# ============================================================================
section "CLD.9.5.2 Virtual machine hardening"
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/27017_vm.json
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/27017_vm.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/27017_vm.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/27017_vm.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/27017_vm.json)"
    check "Shielded VM secure boot ($inst) [CLD.9.5.2]"           bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "Shielded VM vTPM ($inst) [CLD.9.5.2]"                  bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Shielded VM integrity monitoring ($inst) [CLD.9.5.2]"  bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst) [CLD.9.5.2]"           bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# ============================================================================
# CLD.12.1.5 — Administrator’s operational security
# ============================================================================
section "CLD.12.1.5 Administrator’s operational security"
# Enforce OS Login, IAP-only SSH, least privilege, and no user-managed SA keys.
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project [CLD.12.1.5]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/27017_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress (tcp:22 from 35.235.240.0/20) [CLD.12.1.5]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/27017_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress [CLD.12.1.5]")
fi

gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/27017_iam.json
check "No human principals with roles/owner [CLD.12.1.5]" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/27017_iam.json >/dev/null'

if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL [CLD.12.1.5]" test -z "$keys"
fi

# ============================================================================
# CLD.12.4.5 — Monitoring of cloud services
# ============================================================================
section "CLD.12.4.5 Monitoring of cloud services"
# Audit logs (ADMIN_READ, DATA_READ, DATA_WRITE) + Flow logs + NAT logging + at least 1 alert policy
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/27017_iam_policy.json
check "Audit logs enabled (ADMIN_READ/DATA_READ/DATA_WRITE) [CLD.12.4.5]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]? | .logType]
            | (index("ADMIN_READ") != null and index("DATA_READ") != null and index("DATA_WRITE") != null)'\'' \
            /tmp/27017_iam_policy.json >/dev/null'

gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/27017_subnet.json
check "VPC Flow Logs enabled on subnet [CLD.12.4.5]" bash -lc 'jq -e ".enableFlowLogs==true" /tmp/27017_subnet.json >/dev/null'

gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/27017_nat.json
check "Cloud NAT logging = ALL [CLD.12.4.5]"          bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/27017_nat.json >/dev/null'

gcloud monitoring alert-policies list --format=json > /tmp/27017_alerts.json || true
check "At least 1 Monitoring alert policy exists [CLD.12.4.5]" bash -lc 'jq -e "length>=1" /tmp/27017_alerts.json >/dev/null' || true

# ============================================================================
# CLD.13.1.4 — Alignment of security management for virtual & physical networks
# ============================================================================
section "CLD.13.1.4 Alignment of virtual & physical network security"
# Private Google Access for egress, plus flow/NAT logging (already checked)
check "Subnet Private Google Access enabled [CLD.13.1.4]" \
  bash -lc 'jq -e ".privateIpGoogleAccess==true" /tmp/27017_subnet.json >/dev/null' || true
# (Additional MANUAL: document how virtual networks map to physical/underlay security.)
note "Document how virtual network policies map to physical/underlay security controls with your CSP (e.g., inter-DC links, underlay ACLs). [MANUAL]"

# ============================================================================
# Optional: cryptography signals tied to cloud use (ISO 27017 builds on 27002)
# ============================================================================
section "Cryptography signals (supporting cloud use)"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/27017_key.json || true
  rot="$(jq -r '.rotationPeriod // empty' /tmp/27017_key.json | sed 's/s$//' || true)"
  if [[ -n "$rot" && "$rot" -le 31536000 ]]; then
    log "PASS: CMEK rotation configured (<=365d)"; pass_list+=("CMEK rotation configured (<=365d)")
  else
    log "FAIL: CMEK rotation configured (<=365d)"; fail_list+=("CMEK rotation configured (<=365d)")
  fi
fi
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst)" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# ============================================================================
# Host probes (support CLD.9.5.2 & CLD.12.1.5/.4.5)
# ============================================================================
section "Host probes (auth/integrity/telemetry signals)"
read -r -d '' REMOTE <<"EOS" || true
set -Eeuo pipefail
echo "HOST=$(hostname)"
state_auditd="$(systemctl is-active auditd || true)"; echo "AUDITD=$state_auditd"
rules_cnt="$(auditctl -l 2>/dev/null | wc -l || true)"; echo "AUDIT_RULES=$rules_cnt"
ops_state="$(systemctl is-active google-cloud-ops-agent 2>/dev/null || true)"; echo "OPS_AGENT=$ops_state"
aide_ver="$(dpkg -s aide 2>/dev/null | awk -F': ' '/Version/{print $2}' || true)"; echo "AIDE_VER=${aide_ver:-none}"
aide_db="$(ls -1 /var/lib/aide/aide.db* 2>/dev/null | head -n1 || true)"; echo "AIDE_DB=${aide_db:-none}"
sshpw="$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}' || true)"; echo "SSH_PASSAUTH=${sshpw:-unknown}"
sshroot="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}' || true)"; echo "SSH_ROOTLOGIN=${sshroot:-unknown}"
ua_pkg="$(dpkg -s unattended-upgrades 2>/dev/null | awk -F': ' '/Status/{print $2}' || true)"; echo "UNATT_UPGR=${ua_pkg:-none}"
ua_on="$(grep -hoE 'APT::Periodic::Unattended-Upgrade\\s+\"?1\"?' /etc/apt/apt.conf.d/* 2>/dev/null | wc -l)"; echo "UNATT_ENABLED=$ua_on"
ntp="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)"; echo "NTP_SYNC=$ntp"
tmout="$(grep -RhsE '^\s*TMOUT=([3-9][0-9]{2,}|[1-9][0-9]{3,})' /etc/profile /etc/profile.d/* 2>/dev/null | wc -l)"; echo "TMOUT_SET=$tmout"
EOS

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    set +e
    out="$(gcloud compute ssh "$inst" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "$REMOTE" 2>/dev/null)"
    rc=$?
    set -e
    if (( rc != 0 )); then
      log "WARN: SSH probe failed on $inst (marking probe checks as FAIL)"
      fail_list+=("Auditd active on $inst"); fail_list+=("Audit rules present on $inst")
      fail_list+=("Ops Agent running on $inst"); fail_list+=("SSH password auth disabled on $inst")
      fail_list+=("SSH root login disabled on $inst"); fail_list+=("AIDE installed on $inst")
      fail_list+=("AIDE baseline present on $inst"); fail_list+=("Unattended upgrades enabled on $inst")
      fail_list+=("NTP sync enabled on $inst");     fail_list+=("Auto logoff (TMOUT) set on $inst")
      continue
    fi

    echo "$out" | sed 's/^/  ['"$inst"'] /'
    auditd="$(grep '^AUDITD=' <<<"$out" | cut -d= -f2-)"
    rules="$(grep '^AUDIT_RULES=' <<<"$out" | cut -d= -f2-)"
    ops="$(grep '^OPS_AGENT=' <<<"$out" | cut -d= -f2-)"
    aidev="$(grep '^AIDE_VER=' <<<"$out" | cut -d= -f2-)"
    aidedb="$(grep '^AIDE_DB=' <<<"$out" | cut -d= -f2-)"
    sshpw="$(grep '^SSH_PASSAUTH=' <<<"$out" | cut -d= -f2-)"
    sshroot="$(grep '^SSH_ROOTLOGIN=' <<<"$out" | cut -d= -f2-)"
    ua="$(grep '^UNATT_UPGR=' <<<"$out" | cut -d= -f2-)"
    uaon="$(grep '^UNATT_ENABLED=' <<<"$out" | cut -d= -f2-)"
    ntp="$(grep '^NTP_SYNC=' <<<"$out" | cut -d= -f2-)"
    tmout="$(grep '^TMOUT_SET=' <<<"$out" | cut -d= -f2-)"

    check "Auditd active on $inst [CLD.12.4.5]"                          bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [CLD.12.4.5]"                    bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [CLD.12.4.5]"                      bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [CLD.12.1.5]"             bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [CLD.12.1.5]"                bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst (FIM) [CLD.9.5.2]"                    bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst [CLD.9.5.2]"                   bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst [CLD.9.5.2]"     bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst [CLD.12.4.5]"                bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst [CLD.12.1.5]"                bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

    probe_json+=("{
      \"instance\":\"$inst\",\"auditd\":\"$auditd\",\"audit_rules\":$rules,
      \"ops_agent\":\"$ops\",\"aide\": \"$aidev\",\"aide_db\":\"$aidedb\",
      \"ssh_passwordauth\":\"$sshpw\",\"ssh_rootlogin\":\"$sshroot\",
      \"unattended_upgrades\":\"$ua\",\"unattended_enabled\":$uaon,
      \"ntp_sync\":\"$ntp\",\"tmout_set\":$tmout
    }")
  done
else
  log "Skipping host probes (no --vm provided)."
fi

# ============================================================================
# Scoreboard & evidence JSON
# ============================================================================
section "ISO/IEC 27017 Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/iso27017-evidence.json"
out_ts="$REPORT_DIR/iso27017-evidence-$ts.json"

jq -n \
  --arg standard "ISO/IEC 27017 (Cloud controls)" \
  --argjson clds '["CLD.6.3.1","CLD.8.1.5","CLD.9.5.1","CLD.9.5.2","CLD.12.1.5","CLD.12.4.5","CLD.13.1.4"]' \
  --arg project "$PROJECT_ID" --arg region "$REGION" --arg zone "$ZONE" \
  --arg network "$NETWORK" --arg subnet "$SUBNET" --arg subnet_range "$SUBNET_RANGE" \
  --arg router "$ROUTER" --arg nat "$NAT" \
  --arg keyring "$KEYRING" --arg key "$KEY" --arg key_loc "$KEY_LOC" \
  --arg sa_email "$SA_EMAIL" --argjson vms "$(printf '%s\n' "${VMS[@]:-}" | jq -R . | jq -s .)" \
  --argjson pass "$(printf '%s\n' "${pass_list[@]}" | jq -R . | jq -s .)" \
  --argjson fail "$(printf '%s\n' "${fail_list[@]}" | jq -R . | jq -s .)" \
  --argjson manual "$(printf '%s\n' "${manual_list[@]}" | jq -R . | jq -s .)" \
  --argjson probes "[ $(IFS=,; echo "${probe_json[*]:-}") ]" \
  --arg timestamp "$ts" '
  {
    standard: $standard, cld_controls: $clds,
    context: {
      project: $project, region: $region, zone: $zone,
      network: $network, subnet: $subnet, subnet_range: $subnet_range,
      router: $router, nat: $nat,
      keyring: $keyring, key: $key, key_loc: $key_loc, sa_email: $sa_email, vms: $vms
    },
    results: { pass: $pass, fail: $fail, manual: $manual },
    vm_probes: $probes,
    timestamp: $timestamp
  }' > "$out_base"

[[ "$STAMPED" == "1" ]] && cp -f "$out_base" "$out_ts"
log "Wrote evidence: $out_base"
[[ "$STAMPED" == "1" ]] && log "Wrote timestamped copy: $out_ts"

if (( ${#fail_list[@]} > 0 )); then
  echo "ISO/IEC 27017 automated checks FAILED for some controls."
  exit 2
fi
echo "ISO/IEC 27017 automated checks PASSED for the technical safeguards tested."
