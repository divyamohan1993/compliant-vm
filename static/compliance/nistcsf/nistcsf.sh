#!/usr/bin/env bash
# nistcsf.sh — NIST Cybersecurity Framework 2.0 technical signals checker
# Read-only, idempotent. Mirrors your autoconfig UX (sections + PASS/FAIL/MANUAL + JSON evidence).
# Maps automatable checks to CSF 2.0 Functions/Categories:
#   GV (Govern — MANUAL artifacts), ID (Identify — mostly MANUAL),
#   PR (Protect — PR.AA, PR.PS, PR.DS), DE (Detect — DE.CM), RS (Respond — MANUAL), RC (Recover — RC.IM MANUAL + backup signal)
# References: CSF 2.0 core + overview + category refs; PR.AA & GV.* names per CSF 2.0. See README/citations.

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
ROUTER="${ROUTER:-${NETWORK:+${NETWORK}-router}}"
NAT="${NAT:-${NETWORK:+${NETWORK}-nat}}"

KEYRING="${KEYRING:-}"
KEY="${KEY:-}"
KEY_LOC="${KEY_LOC:-}"
SA_EMAIL="${SA_EMAIL:-}"

declare -a VMS=()
REPORT_DIR="${REPORT_DIR:-./compliance-reports}"
STAMPED="${STAMPED:-1}"

# Tuning knobs (affect PASS/FAIL only; never mutate cloud resources)
MIN_LOG_RETENTION_DAYS="${MIN_LOG_RETENTION_DAYS:-1}"          # DE.CM/AU-retention: org-defined; assert >0 by default
MAX_KMS_ROTATION_SECONDS="${MAX_KMS_ROTATION_SECONDS:-31536000}"# PR.DS/SC-12-like: strong practice ≤365d

SSH_KEY="${SSH_KEY:-}"   # optional OS Login key for SSH probes
SSH_COMMON_BASE=(--tunnel-through-iap)
[[ -n "${SSH_KEY}" ]] && SSH_COMMON_BASE+=(--ssh-key-file="$SSH_KEY")

usage() {
  cat <<EOF
Usage: $0 [--project ID] [--region R] [--zone Z]
          [--network NET] [--subnet SUBNET] [--router R] [--nat N]
          [--keyring KR] [--key K] [--key-loc L] [--sa-email SA]
          [--vm NAME ...] [--report-dir DIR]
          [--min-log-retention DAYS] [--max-kms-rotation-seconds SECS]
          [--no-stamped]
Env fallbacks: PROJECT_ID, REGION, ZONE, NETWORK, SUBNET, ROUTER, NAT, KEYRING, KEY, KEY_LOC, SA_EMAIL,
               REPORT_DIR, MIN_LOG_RETENTION_DAYS, MAX_KMS_ROTATION_SECONDS, SSH_KEY
Exit: 0 OK, 2 FAIL found, 3 missing tools/params
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
    --min-log-retention) MIN_LOG_RETENTION_DAYS="$2"; shift 2;;
    --max-kms-rotation-seconds) MAX_KMS_ROTATION_SECONDS="$2"; shift 2;;
    --no-stamped) STAMPED=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

# ---- Preflight ----------------------------------------------------------------
section "NIST CSF 2.0 checker preflight"
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
# GV — Govern (CSF 2.0 added function): strategy, policy, roles, oversight, supply chain
# ============================================================================
section "GV — Govern (MANUAL evidence)"
note "GV.OC Organizational context, risk assumptions & constraints documented (MANUAL)."
note "GV.RM Risk management strategy defined & approved (MANUAL)."
note "GV.RR Roles, responsibilities & authorities defined (MANUAL)."
note "GV.PO Cybersecurity policy & standards approved and communicated (MANUAL)."
note "GV.OV Oversight/measurement: KPIs/KRIs, reviews, internal audits (MANUAL)."
note "GV.SC Cybersecurity supply chain risk management (contracts/SLAs, due diligence) (MANUAL)."
# (See CSF 2.0 core for GV.* categories.) 

# ============================================================================
# ID — Identify (assets, risks, improvements)
# ============================================================================
section "ID — Identify (mostly MANUAL)"
note "ID.AM Asset management (systems, data, software, accounts) inventory maintained (MANUAL)."
note "ID.RA Risk assessment and ID.IM improvements tracked (MANUAL)."

# ============================================================================
# PR — Protect: Identity/Access, Platform Security, Data Security
# ============================================================================
section "PR — Protect (PR.AA / PR.PS / PR.DS)"

# PR.AA Identity Management, Authentication, and Access Control
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json >/tmp/csf_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK [PR.AA]" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/csf_fws.json >/dev/null'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/csf_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH (tcp:22 from 35.235.240.0/20) [PR.AA]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/csf_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH present [PR.AA]")
fi

proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enforced at project [PR.AA]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

gcloud projects get-iam-policy "$PROJECT_ID" --format=json >/tmp/csf_iam.json
check "No human principals with roles/owner [PR.AA]" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/csf_iam.json >/dev/null'

if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL [PR.AA]" test -z "$keys"
fi

# PR.PS Platform Security
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/csf_inst.json
    ext="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // empty' /tmp/csf_inst.json)"
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/csf_inst.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/csf_inst.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/csf_inst.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/csf_inst.json)"
    check "No public IP ($inst) [PR.PS]"                     bash -lc '[[ -z "'"$ext"'" ]]'
    check "Secure Boot enabled ($inst) [PR.PS]"              bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "vTPM enabled ($inst) [PR.PS]"                     bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Integrity monitoring enabled ($inst) [PR.PS]"     bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst) [PR.PS]"          bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# PR.DS Data Security (encryption at rest + key mgmt)
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/csf_key.json || true
  check "CMEK rotation <= ${MAX_KMS_ROTATION_SECONDS}s [PR.DS]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= '"$MAX_KMS_ROTATION_SECONDS"'" /tmp/csf_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured [PR.DS]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst) [PR.DS]" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# Host-level protective settings supporting PR.AA/PR.PS
section "Host probes for PR.* (auth/hardening)"
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
      fail_list+=("Auditd active on $inst [DE.CM]"); fail_list+=("Audit rules present on $inst [DE.CM]")
      fail_list+=("Ops Agent running on $inst [DE.CM]"); fail_list+=("SSH password auth disabled on $inst [PR.AA]")
      fail_list+=("SSH root login disabled on $inst [PR.AA]"); fail_list+=("AIDE installed on $inst [PR.PS]")
      fail_list+=("AIDE baseline present on $inst [PR.PS]"); fail_list+=("Unattended upgrades enabled on $inst [PR.PS]")
      fail_list+=("NTP sync enabled on $inst [DE.CM]");    fail_list+=("Auto logoff (TMOUT) set on $inst [PR.AA]")
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

    check "Auditd active on $inst [DE.CM]"                          bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [DE.CM]"                    bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [DE.CM]"                      bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [PR.AA]"             bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [PR.AA]"                bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst (FIM) [PR.PS]"                   bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst [PR.PS]"                  bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst [PR.PS]"    bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst [DE.CM]"                bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst [PR.AA]"                bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

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
# DE — Detect (security continuous monitoring, alerts, telemetry)
# ============================================================================
section "DE — Detect (DE.CM monitoring signals)"
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/csf_iam_policy.json
check "Project audit logs enabled (ADMIN_READ/DATA_READ/DATA_WRITE) [DE.CM]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]? | .logType]
            | (index("ADMIN_READ") != null and index("DATA_READ") != null and index("DATA_WRITE") != null)'\'' \
            /tmp/csf_iam_policy.json >/dev/null'

gcloud logging buckets describe _Default --location=global --format=json > /tmp/csf_logbucket.json || true
check "Cloud Logging retention >= ${MIN_LOG_RETENTION_DAYS} days [DE.CM]" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>='"$MIN_LOG_RETENTION_DAYS" /tmp/csf_logbucket.json >/dev/null'

gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/csf_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/csf_nat.json
check "VPC Flow Logs enabled on subnet [DE.CM]"  bash -lc 'jq -e ".enableFlowLogs==true" /tmp/csf_subnet.json >/dev/null'
check "Cloud NAT logging = ALL [DE.CM]"          bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/csf_nat.json >/dev/null'

gcloud monitoring alert-policies list --format=json > /tmp/csf_alerts.json || true
check "At least 1 Monitoring alert policy exists [DE.CM]" bash -lc 'jq -e "length>=1" /tmp/csf_alerts.json >/dev/null' || true

# ============================================================================
# RS — Respond (plans, comms, analysis, mitigation) — MANUAL artifacts
# ============================================================================
section "RS — Respond (MANUAL)"
note "RS.RP Response planning approved & exercised; RS.CO communications runbooks; RS.MA analysis; RS.IM improvements (MANUAL)."

# ============================================================================
# RC — Recover (plans, improvements) — plus backup signal
# ============================================================================
section "RC — Recover (RC.RP/RC.IM MANUAL + snapshot signal)"
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached (recovery capability signal) [RC]" ; pass_list+=("Snapshot schedules attached [RC]")
  else
    log "FAIL: Snapshot schedules attached (recovery capability signal) [RC]" ; fail_list+=("Snapshot schedules attached [RC]")
  fi
fi
note "Document recovery plan, restoration playbooks, and periodic restore tests with evidence (MANUAL)."

# ============================================================================
# Scoreboard & evidence JSON
# ============================================================================
section "NIST CSF 2.0 Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/nist-csf-evidence.json"
out_ts="$REPORT_DIR/nist-csf-evidence-$ts.json"

jq -n \
  --arg framework "NIST Cybersecurity Framework (CSF) 2.0" \
  --argjson functions '["GV","ID","PR","DE","RS","RC"]' \
  --arg project "$PROJECT_ID" --arg region "$REGION" --arg zone "$ZONE" \
  --arg network "$NETWORK" --arg subnet "$SUBNET" --arg router "$ROUTER" --arg nat "$NAT" \
  --arg keyring "$KEYRING" --arg key "$KEY" --arg key_loc "$KEY_LOC" \
  --arg sa_email "$SA_EMAIL" --argjson vms "$(printf '%s\n' "${VMS[@]:-}" | jq -R . | jq -s .)" \
  --arg min_log_days "$MIN_LOG_RETENTION_DAYS" \
  --arg max_kms_rot_secs "$MAX_KMS_ROTATION_SECONDS" \
  --argjson pass "$(printf '%s\n' "${pass_list[@]}" | jq -R . | jq -s .)" \
  --argjson fail "$(printf '%s\n' "${fail_list[@]}" | jq -R . | jq -s .)" \
  --argjson manual "$(printf '%s\n' "${manual_list[@]}" | jq -R . | jq -s .)" \
  --argjson probes "[ $(IFS=,; echo "${probe_json[*]:-}") ]" \
  --arg timestamp "$ts" '
  {
    framework: $framework, functions: $functions,
    thresholds: { min_log_retention_days: ($min_log_days|tonumber), max_kms_rotation_seconds: ($max_kms_rot_secs|tonumber) },
    context: {
      project: $project, region: $region, zone: $zone,
      network: $network, subnet: $subnet, router: $router, nat: $nat,
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
  echo "NIST CSF automated checks FAILED for some controls."
  exit 2
fi
echo "NIST CSF automated checks PASSED for the technical safeguards tested."
