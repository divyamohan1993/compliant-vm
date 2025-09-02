#!/usr/bin/env bash
# hipaa.sh — HIPAA Security Rule technical & evidence checks (read-only)
# Idempotent, CI-friendly, same UX as autoconfig.sh

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# ---- Defaults / CLI -----------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-}"
ZONE="${ZONE:-}"
NETWORK="${NETWORK:-}"
SUBNET="${SUBNET:-}"
ROUTER="${ROUTER:-${NETWORK:+${NETWORK}-router}}"
NAT="${NAT:-${NETWORK:+${NETWORK}-nat}}"

KEYRING="${KEYRING:-}"
KEY="${KEY:-}"
KEY_LOC="${KEY_LOC:-}"
SA_EMAIL="${SA_EMAIL:-}"

# Repeatable --vm flags -> VMS array
declare -a VMS=()
REPORT_DIR="${REPORT_DIR:-./compliance-reports}"
# If set, also write a timestamped copy
STAMPED="${STAMPED:-1}"

SSH_KEY="${SSH_KEY:-}"         # optional: use your OS Login key if you want to pin it
SSH_COMMON_BASE=(--tunnel-through-iap)
[[ -n "${SSH_KEY}" ]] && SSH_COMMON_BASE+=(--ssh-key-file="$SSH_KEY")

usage() {
  cat <<EOF
Usage: $0 [--project ID] [--region R] [--zone Z] [--network NET] [--subnet SUBNET]
          [--router R] [--nat N] [--keyring KR] [--key K] [--key-loc L]
          [--sa-email SA] [--vm NAME ...] [--report-dir DIR] [--no-stamped]
Env fallbacks: PROJECT_ID, REGION, ZONE, NETWORK, SUBNET, ROUTER, NAT, KEYRING, KEY, KEY_LOC, SA_EMAIL, REPORT_DIR, SSH_KEY
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
section "HIPAA checker preflight"
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1" >&2; exit 3; }; }
need gcloud; need jq; need awk; need sed; need grep; need date

[[ -n "$PROJECT_ID" && -n "$REGION" && -n "$ZONE" ]] || { echo "Need --project/--region/--zone" >&2; exit 3; }
[[ -n "$NETWORK" && -n "$SUBNET" && -n "$ROUTER" && -n "$NAT" ]] || { echo "Need --network/--subnet/--router/--nat" >&2; exit 3; }
[[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]] || log "Note: CMEK details missing; those checks may FAIL."
[[ -n "$SA_EMAIL" ]] || log "Note: SA_EMAIL missing; SA key checks may FAIL."
((${#VMS[@]})) || log "Note: No --vm provided; VM OS checks will be skipped."

mkdir -p "$REPORT_DIR"

# Derive project number (for context only)
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"

# Resolve OS Login username (no mutation; we don't upload keys here)
OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[?primary=true].username)' || true)"
[[ -z "$OS_LOGIN_USER" ]] && OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[0].username)' || true)"
SSH_COMMON=("${SSH_COMMON_BASE[@]}")
[[ -n "$OS_LOGIN_USER" ]] && SSH_COMMON+=(--ssh-flag="-l ${OS_LOGIN_USER}")

# ---- Check helpers ------------------------------------------------------------
hipaa_pass=(); hipaa_fail=(); hipaa_manual=(); probe_json=()

check() { # check "NAME [CFR]" <cmd...>
  local name="$1"; shift
  if "$@"; then log "PASS: $name"; hipaa_pass+=("$name"); else log "FAIL: $name"; hipaa_fail+=("$name"); fi
}
note() { hipaa_manual+=("$1"); log "MANUAL: $1"; }

# ---- 10.1 Audit Controls & Retention -----------------------------------------
section "Audit controls & retention [164.312(b), 164.316]"
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/hipaa_iam_policy.json

check "Data Access logs enabled for allServices (READ/WRITE) [164.312(b)]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/hipaa_iam_policy.json >/dev/null'

gcloud logging buckets describe _Default --location=global --format=json > /tmp/hipaa_logbucket.json || true
check "Log retention >= 2190 days & bucket locked [164.316(b)]" \
  bash -lc 'jq -e ".retentionDays>=2190 and (.locked==true)" /tmp/hipaa_logbucket.json >/dev/null'

gcloud logging cmek-settings describe --project="$PROJECT_ID" --format=json > /tmp/hipaa_cmek.json || true
check "Cloud Logging protected with CMEK [164.312(a)(2)(iv), 164.312(b)]" \
  bash -lc 'jq -r ".kmsKeyName // empty" /tmp/hipaa_cmek.json | grep -q "."'

# ---- 10.2 Transmission Security / Exposure -----------------------------------
section "Transmission security & exposure [164.312(e)]"
# No public IPs on VMs
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    ext="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" \
          --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
    check "No public IP ($inst) [164.312(e)]" test -z "${ext}"
  done
fi

# IAP-only SSH
if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/hipaa_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress [164.312(e)]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/hipaa_fw_iap.json >/dev/null'
else
  hipaa_fail+=("IAP-only SSH ingress [164.312(e)]")
fi

# No 0.0.0.0/0 ingress
# List all firewall rules once (unfiltered) to avoid gcloud filter syntax quirks across versions.
if ! gcloud compute firewall-rules list --project "$PROJECT_ID" --format=json > /tmp/hipaa_fws.json 2>/dev/null; then
  echo "[]" > /tmp/hipaa_fws.json
fi

check "No 0.0.0.0/0 ingress on $NETWORK [164.312(e)]" \
  bash -lc 'jq -e --arg net "'"$NETWORK"'" '\''[
      .[] 
      | select(.network|endswith("/" + $net))
      | select(.direction=="INGRESS")
      | select(.disabled!=true)
      | .sourceRanges[]?
    ] | index("0.0.0.0/0") == null'\'' /tmp/hipaa_fws.json >/dev/null'
    
# gcloud compute firewall-rules list --project "$PROJECT_ID" \
#   --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/hipaa_fws.json
# check "No 0.0.0.0/0 ingress on $NETWORK [164.312(e)]" \
  # bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/hipaa_fws.json >/dev/null'

# Flow logs + NAT logging
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/hipaa_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/hipaa_nat.json
check "VPC Flow Logs enabled [164.312(b)]" bash -lc 'jq -e ".enableFlowLogs==true" /tmp/hipaa_subnet.json >/dev/null'
check "Cloud NAT logging = ALL [164.312(b)]" \
  bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/hipaa_nat.json >/dev/null'

# ---- 10.3 Encryption at Rest & Key Mgmt --------------------------------------
section "Encryption at rest & key rotation [164.312(a)(2)(iv)]"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/hipaa_key.json || true
  check "CMEK rotation configured (<=90d) [164.312(a)(2)(iv)]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 7776000" /tmp/hipaa_key.json >/dev/null'
else
  hipaa_fail+=("CMEK rotation configured (<=90d) [164.312(a)(2)(iv)]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst) [164.312(a)(2)(iv)]" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# ---- 10.4 Person/Entity Auth & Least Privilege --------------------------------
section "Person/entity auth & least privilege [164.312(d), 164.312(a)]"
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project [164.312(d), 164.312(a)(2)(i)]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed SA keys for $SA_EMAIL [164.312(d)]" test -z "$keys"
fi

# ---- 10.5 Contingency (backup evidence) --------------------------------------
section "Contingency planning evidence [164.308(a)(7)]"
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached [164.308(a)(7)]"; hipaa_pass+=("Snapshot schedules attached [164.308(a)(7)]")
  else
    log "FAIL: Snapshot schedules attached [164.308(a)(7)]"; hipaa_fail+=("Snapshot schedules attached [164.308(a)(7)]")
  fi
fi

# ---- 10.6 VM OS probes (read-only) -------------------------------------------
section "VM OS probes [164.312(b),(c),(d),(a)(2)(iii)]"
read -r -d '' REMOTE_HIPAA <<"EOS" || true
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
ua_on="$(grep -hoE 'APT::Periodic::Unattended-Upgrade\s+\"?1\"?' /etc/apt/apt.conf.d/* 2>/dev/null | wc -l)"; echo "UNATT_ENABLED=$ua_on"
ntp="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)"; echo "NTP_SYNC=$ntp"
tmout="$(grep -RhsE '^\s*TMOUT=([3-9][0-9]{2,}|[1-9][0-9]{3,})' /etc/profile /etc/profile.d/* 2>/dev/null | wc -l)"; echo "TMOUT_SET=$tmout"
EOS

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    # We *only* read; if SSH fails, mark FAILs for that host
    set +e
    out="$(gcloud compute ssh "$inst" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "$REMOTE_HIPAA" 2>/dev/null)"
    rc=$?
    set -e
    if (( rc != 0 )); then
      log "WARN: SSH probe failed on $inst (marking probe checks as FAIL)"
      hipaa_fail+=("Auditd active on $inst [164.312(b)]")
      hipaa_fail+=("Audit rules present on $inst [164.312(b)]")
      hipaa_fail+=("Ops Agent running on $inst [164.312(b)]")
      hipaa_fail+=("SSH password auth disabled on $inst [164.312(d)]")
      hipaa_fail+=("SSH root login disabled on $inst [164.312(d)]")
      hipaa_fail+=("AIDE installed on $inst [164.312(c)(1)]")
      hipaa_fail+=("AIDE baseline present on $inst [164.312(c)(1)]")
      hipaa_fail+=("Unattended security updates enabled on $inst [164.308(a)(1)]")
      hipaa_fail+=("Time sync (NTP) enabled on $inst [164.312(b)]")
      hipaa_fail+=("Auto logoff (TMOUT) set on $inst [164.312(a)(2)(iii)]")
      continue
    fi

    echo "$out" | sed 's/^/  ['"$inst"'] /'
    host="$(grep '^HOST=' <<<"$out" | cut -d= -f2-)"
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

    check "Auditd active on $inst [164.312(b)]" bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [164.312(b)]" bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [164.312(b)]" bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [164.312(d)]" bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [164.312(d)]" bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst [164.312(c)(1)]" bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst [164.312(c)(1)]" bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst [164.308(a)(1)]" bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst [164.312(b)]" bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst [164.312(a)(2)(iii)]" bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

    probe_json+=("{
      \"instance\":\"$inst\",\"auditd\":\"$auditd\",\"audit_rules\":$rules,
      \"ops_agent\":\"$ops\",\"aide\": \"$aidev\",\"aide_db\":\"$aidedb\",
      \"ssh_passwordauth\":\"$sshpw\",\"ssh_rootlogin\":\"$sshroot\",
      \"unattended_upgrades\":\"$ua\",\"unattended_enabled\":$uaon,
      \"ntp_sync\":\"$ntp\",\"tmout_set\":$tmout
    }")
  done
else
  log "Skipping VM OS probes (no --vm provided)."
fi

# ---- 10.7 Always-manual evidences --------------------------------------------
section "Manual evidences (cannot be proven via script)"
note "Executed Google Cloud HIPAA BAA for this account/project [Contractual prerequisite]"
note "Formal Risk Analysis & Risk Management documented and current [164.308(a)(1)]"
note "Workforce training & sanction policy in force [164.308(a)(3), 164.308(a)(1)(ii)(C)]"
note "Contingency plan incl. tested backups/DR & emergency access procedures [164.308(a)(7), 164.312(a)(2)(ii)]"
note "Information system activity review process (log review schedule & owners) [164.308(a)(1)(ii)(D)]"

# ---- Scoreboard & Evidence file ----------------------------------------------
section "HIPAA Security Rule Scoreboard"
# Deduplicate lines while preserving order
dedup() { awk '!seen[$0]++'; }
printf "PASS: %s\n" "${hipaa_pass[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n" "${hipaa_fail[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${hipaa_manual[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/hipaa-evidence.json"
out_ts="$REPORT_DIR/hipaa-evidence-$ts.json"

jq -n \
  --arg standard "HIPAA Security Rule" \
  --argjson cfr '["164.312","164.308","164.316"]' \
  --arg project "$PROJECT_ID" --arg region "$REGION" --arg zone "$ZONE" \
  --arg network "$NETWORK" --arg subnet "$SUBNET" --arg router "$ROUTER" --arg nat "$NAT" \
  --arg keyring "$KEYRING" --arg key "$KEY" --arg key_loc "$KEY_LOC" \
  --arg sa_email "$SA_EMAIL" --argjson vms "$(printf '%s\n' "${VMS[@]:-}" | jq -R . | jq -s .)" \
  --argjson pass "$(printf '%s\n' "${hipaa_pass[@]}" | jq -R . | jq -s .)" \
  --argjson fail "$(printf '%s\n' "${hipaa_fail[@]}" | jq -R . | jq -s .)" \
  --argjson manual "$(printf '%s\n' "${hipaa_manual[@]}" | jq -R . | jq -s .)" \
  --argjson probes "[ $(IFS=,; echo "${probe_json[*]:-}") ]" \
  --arg timestamp "$ts" '
  {
    standard: $standard,
    cfr_parts: $cfr,
    context: {
      project: $project, region: $region, zone: $zone,
      network: $network, subnet: $subnet, router: $router, nat: $nat,
      keyring: $keyring, key: $key, key_loc: $key_loc, sa_email: $sa_email, vms: $vms
    },
    results: { pass: $pass, fail: $fail, manual: $manual },
    vm_probes: $probes,
    timestamp: $timestamp
  }' > "$out_base"

if [[ "$STAMPED" == "1" ]]; then cp -f "$out_base" "$out_ts"; fi
log "Wrote evidence: $out_base"
[[ "$STAMPED" == "1" ]] && log "Wrote timestamped copy: $out_ts"

# Exit with 2 if any FAIL to bubble up in CI/CD
if (( ${#hipaa_fail[@]} > 0 )); then
  echo "HIPAA automated checks FAILED for some controls."
  exit 2
fi
echo "HIPAA automated checks PASSED for the technical safeguards tested."
