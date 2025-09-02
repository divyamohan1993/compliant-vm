#!/usr/bin/env bash
# iso27001.sh — ISO/IEC 27001:2022 technical signals checker (read-only, idempotent)
# Mirrors your autoconfig UX: sections, PASS/FAIL/MANUAL scoreboard, JSON evidence.
# Focus: Annex A 2022 (93 controls across A.5–A.8). Clauses 4–10 (ISMS) are MANUAL artifacts.
# Sources: ISO overview; Annex A structure; control guidance for logging/monitoring/cloud use. See README/citations.

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

# Optional tuning (does not mutate cloud config; only affects PASS/FAIL thresholds)
MIN_LOG_RETENTION_DAYS="${MIN_LOG_RETENTION_DAYS:-1}"    # ISO doesn’t mandate duration; assert >0 by default
MAX_KMS_ROTATION_SECONDS="${MAX_KMS_ROTATION_SECONDS:-31536000}" # 365d strong practice

SSH_KEY="${SSH_KEY:-}"   # optional: OS Login key path for SSH host probes
SSH_COMMON_BASE=(--tunnel-through-iap)
[[ -n "${SSH_KEY}" ]] && SSH_COMMON_BASE+=(--ssh-key-file="$SSH_KEY")

usage() {
  cat <<EOF
Usage: $0 [--project ID] [--region R] [--zone Z] [--network NET] [--subnet SUBNET]
          [--router R] [--nat N] [--keyring KR] [--key K] [--key-loc L]
          [--sa-email SA] [--vm NAME ...] [--report-dir DIR]
          [--min-log-retention DAYS] [--max-kms-rotation-seconds SECS] [--no-stamped]
Env fallbacks: PROJECT_ID, REGION, ZONE, NETWORK, SUBNET, ROUTER, NAT, KEYRING, KEY, KEY_LOC, SA_EMAIL,
               REPORT_DIR, MIN_LOG_RETENTION_DAYS, MAX_KMS_ROTATION_SECONDS, SSH_KEY
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
    --min-log-retention) MIN_LOG_RETENTION_DAYS="$2"; shift 2;;
    --max-kms-rotation-seconds) MAX_KMS_ROTATION_SECONDS="$2"; shift 2;;
    --no-stamped) STAMPED=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

# ---- Preflight ----------------------------------------------------------------
section "ISO/IEC 27001:2022 checker preflight"
need() { command -v "$1" >/div/null 2>&1 || { echo "Missing tool: $1" >&2; exit 3; }; }
need gcloud; need jq; need awk; need sed; need grep; need date || true  # shellcheck disable=SC2312

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
# ISMS Clauses 4–10 (Context, Leadership, Planning, Support, Operation, Performance, Improvement)
# Always MANUAL artifacts (policies, risk assessment, metrics, audits, mgmt reviews).
# ============================================================================
section "ISMS Clauses 4–10 — Management system evidence (always MANUAL)"
note "Provide: scope, risk assessment & treatment plan, Statement of Applicability, policies, competence & awareness, documented procedures, internal audits, management reviews, KPIs/objectives, corrective actions."

# ============================================================================
# Annex A — Organizational, People, Physical, Technological
# Below are automatable signals primarily under A.8 Technological + a few A.5 items.
# ============================================================================

# ---- A.8.20 Network security ---------------------------------------------------
section "A.8.20 Network security (no broad ingress, controlled admin access)"
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/iso_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK [A.8.20]" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/iso_fws.json >/dev/null'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/iso_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH (tcp:22 from 35.235.240.0/20) [A.8.20]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/iso_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH present [A.8.20]")
fi

# ---- A.8.9 Configuration management & A.8.10 Baseline (Shielded VM posture) ---
section "A.8.9 Configuration management & baseline hardening"
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project [A.8.23]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/iso_inst.json
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/iso_inst.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/iso_inst.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/iso_inst.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/iso_inst.json)"
    ext="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // empty' /tmp/iso_inst.json)"
    check "No public IP ($inst) [A.8.20]"                    bash -lc '[[ -z "'"$ext"'" ]]'
    check "Secure Boot enabled ($inst) [A.8.9]"              bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "vTPM enabled ($inst) [A.8.9]"                     bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Integrity monitoring enabled ($inst) [A.8.9]"     bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst) [A.8.9]"          bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# ---- A.8.23 Identity and access management / A.8.24 Privileged access ----------
section "A.8.23/.24 Identity & privileged access"
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/iso_iam.json
check "No human principals with roles/owner at project [A.8.23/.24]" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/iso_iam.json >/dev/null'

if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL [A.8.24]" test -z "$keys"
fi

# ---- A.8.28 Cryptography / A.8.29 Key management --------------------------------
section "A.8.28/.29 Cryptography & key management"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/iso_key.json || true
  check "CMEK rotation <= ${MAX_KMS_ROTATION_SECONDS}s (strong practice) [A.8.29]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= '"$MAX_KMS_ROTATION_SECONDS"'" /tmp/iso_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured (strong practice) [A.8.29]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst) [A.8.28/.29]" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# ---- A.8.15 Logging / A.8.16 Monitoring ---------------------------------------
section "A.8.15 Logging & A.8.16 Monitoring activities"
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/iso_iam_policy.json
check "Audit logs (DATA_READ/WRITE) enabled for allServices [A.8.15]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/iso_iam_policy.json >/dev/null'

gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/iso_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/iso_nat.json
check "VPC Flow Logs enabled on subnet [A.8.15/.16]"  bash -lc 'jq -e ".enableFlowLogs==true" /tmp/iso_subnet.json >/dev/null'
check "Cloud NAT logging = ALL [A.8.15/.16]"          bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/iso_nat.json >/dev/null'

# Retention policy (org-defined) — assert > MIN_LOG_RETENTION_DAYS
gcloud logging buckets describe _Default --location=global --format=json > /tmp/iso_logbucket.json || true
check "Cloud Logging retention >= ${MIN_LOG_RETENTION_DAYS} days [A.8.15]" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>='"$MIN_LOG_RETENTION_DAYS" /tmp/iso_logbucket.json >/dev/null'

gcloud monitoring alert-policies list --format=json > /tmp/iso_alerts.json || true
check "At least 1 Monitoring alert policy exists [A.8.16]" bash -lc 'jq -e "length>=1" /tmp/iso_alerts.json >/dev/null' || true

# ---- A.8.19 Backup -------------------------------------------------------------
section "A.8.19 Information backup (signals)"
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached [A.8.19]"; pass_list+=("Snapshot schedules attached [A.8.19]")
  else
    log "FAIL: Snapshot schedules attached [A.8.19]"; fail_list+=("Snapshot schedules attached [A.8.19]")
  fi
fi
note "Document backup scope, RPO/RTO, encryption of backups, and periodic restore testing with evidence [A.8.19 — MANUAL aspects]."

# ---- A.5.23 Information security for use of cloud services --------------------
section "A.5.23 Information security for use of cloud services"
note "Maintain policy/procedures for cloud service use (selection, onboarding, roles/responsibilities, shared responsibility, exit/transfer, monitoring, due diligence) — attach SoA and supplier reviews. [MANUAL]"

# ---- A.6 People / A.7 Physical (MANUAL placeholders) --------------------------
section "A.6 People controls (MANUAL)"
note "Background checks as applicable; awareness & training; disciplinary process; remote working policy; access provisioning/deprovisioning records."
section "A.7 Physical controls (MANUAL)"
note "Physical entry controls (DC/office), equipment siting, secure disposal, secure areas — typically covered by cloud provider & your facilities evidence."

# ---- Host probes (support A.8.15/.16 and A.8.23/.24) --------------------------
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
      fail_list+=("Auditd active on $inst [A.8.15]"); fail_list+=("Audit rules present on $inst [A.8.15]")
      fail_list+=("Ops Agent running on $inst [A.8.16]"); fail_list+=("SSH password auth disabled on $inst [A.8.23]")
      fail_list+=("SSH root login disabled on $inst [A.8.24]"); fail_list+=("AIDE installed on $inst [A.8.9]")
      fail_list+=("AIDE baseline present on $inst [A.8.9]");   fail_list+=("Unattended upgrades enabled on $inst [A.8.8]")
      fail_list+=("NTP sync enabled on $inst [A.8.15]");       fail_list+=("Auto logoff (TMOUT) set on $inst [A.8.23]")
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

    check "Auditd active on $inst [A.8.15]"                          bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [A.8.15]"                    bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [A.8.16]"                      bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [A.8.23]"             bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [A.8.24]"                bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst (FIM signal) [A.8.9]"             bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst [A.8.9]"                   bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst [A.8.8]"     bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst [A.8.15]"                bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst [A.8.23]"                bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

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

# ---- Scoreboard & JSON evidence ----------------------------------------------
section "ISO/IEC 27001:2022 Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/iso27001-evidence.json"
out_ts="$REPORT_DIR/iso27001-evidence-$ts.json"

jq -n \
  --arg standard "ISO/IEC 27001:2022" \
  --argjson domains '["A.5 Organizational","A.6 People","A.7 Physical","A.8 Technological"]' \
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
    standard: $standard, annexA_domains: $domains,
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
  echo "ISO/IEC 27001 automated checks FAILED for some controls."
  exit 2
fi
echo "ISO/IEC 27001 automated checks PASSED for the technical safeguards tested."
