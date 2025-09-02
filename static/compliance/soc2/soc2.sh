#!/usr/bin/env bash
# soc2.sh — SOC 2 (AICPA Trust Services Criteria) technical signals checker
# Read-only, idempotent. Mirrors your autoconfig UX (sections, PASS/FAIL, scoreboard).
# Maps checks to TSC families: Security (CC2/CC6/CC7/CC8/CC9), Availability (A1),
# Confidentiality (C1), Processing Integrity (PI1 — mostly MANUAL), Privacy (P — MANUAL).

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

SSH_KEY="${SSH_KEY:-}"   # optional: OS Login key path for SSH probes
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
section "SOC 2 checker preflight"
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
# CC1 — Control Environment, Risk Assessment, Info & Communication (MANUAL)
# ============================================================================
section "CC1.* Governance, Risk Assessment, Communication (MANUAL)"
note "Document risk assessment, control environment, roles/responsibilities, policies, and communication program (security awareness)."

# ============================================================================
# CC2/CC6 — Logical access, least privilege, authentication
# ============================================================================
section "CC2.x / CC6.x — Logical access, least privilege, auth"
# No 0.0.0.0/0 ingress; IAP-only SSH; OS Login; no public IPs on VMs; least-privilege IAM
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/soc2_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/soc2_fws.json >/dev/null'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/soc2_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/soc2_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)")
fi

proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/soc2_inst.json
    ext="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // empty' /tmp/soc2_inst.json)"
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/soc2_inst.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/soc2_inst.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/soc2_inst.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/soc2_inst.json)"
    check "No public IP ($inst)"                        bash -lc '[[ -z "'"$ext"'" ]]'
    check "Shielded VM secure boot ($inst)"             bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "Shielded VM vTPM ($inst)"                    bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Shielded VM integrity monitoring ($inst)"    bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst)"             bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# Human “Owner” role hygiene + SA user-managed keys
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/soc2_iam.json
check "No human users with roles/owner at project" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/soc2_iam.json >/dev/null'
if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL" test -z "$keys"
fi

# ============================================================================
# CC7 — System operations, security events monitoring, vulnerability mgt
# ============================================================================
section "CC7.x — System operations, security events monitoring"
# Subnet flow logs, NAT logging, audit logs enabled; monitoring alerts present
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/soc2_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/soc2_nat.json
check "VPC Flow Logs enabled on subnet"  bash -lc 'jq -e ".enableFlowLogs==true" /tmp/soc2_subnet.json >/dev/null'
check "Cloud NAT logging = ALL"          bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/soc2_nat.json >/dev/null'

gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/soc2_iam_policy.json
check "Project audit logs (DATA_READ/WRITE) enabled for allServices" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/soc2_iam_policy.json >/dev/null'

gcloud monitoring alert-policies list --format=json > /tmp/soc2_alerts.json || true
check "At least 1 Monitoring alert policy exists" bash -lc 'jq -e "length>=1" /tmp/soc2_alerts.json >/dev/null' || true

# Log retention finite (choose your policy; we assert >0 days, you can raise via env later)
gcloud logging buckets describe _Default --location=global --format=json > /tmp/soc2_logbucket.json || true
check "Cloud Logging retention is finite (>0 days)" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>0" /tmp/soc2_logbucket.json >/dev/null'

# ============================================================================
# A1 — Availability (backups/restore readiness)
# ============================================================================
section "A1.* — Availability (backup/restore signals)"
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached (restore capability signal)"; pass_list+=("Snapshot schedules attached")
  else
    log "FAIL: Snapshot schedules attached (restore capability signal)"; fail_list+=("Snapshot schedules attached")
  fi
fi
note "Document DR strategy, RPO/RTO, and periodic restore tests with evidence (MANUAL)."

# ============================================================================
# C1 — Confidentiality (encryption & key mgmt)
# ============================================================================
section "C1.* — Confidentiality (encryption & key management)"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/soc2_key.json || true
  check "CMEK rotation configured (<=365d) [strong practice]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 31536000" /tmp/soc2_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured (<=365d) [strong practice]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst)" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

note "Verify strong TLS for data in transit (modern SSL policies on LBs/apps) (MANUAL)."
note "Maintain data classification & DLP controls appropriate to sensitivity (MANUAL)."

# ============================================================================
# CC8/CC9 — Change management & risk mitigation (signals; mostly MANUAL)
# ============================================================================
section "CC8/CC9 — Change management & risk mitigation"
note "Maintain change approval workflow, peer review, testing, and SoD for production changes (MANUAL)."
note "Maintain vulnerability management program, scanning cadence, and remediation SLAs (MANUAL)."

# ============================================================================
# PI1 — Processing Integrity (design/change/test controls — MANUAL)
# ============================================================================
section "PI1.* — Processing integrity (MANUAL)"
note "Establish input/processing/output controls, reconciliations, and QA/rollback procedures with evidence (MANUAL)."

# ============================================================================
# P.* — Privacy (if in scope) — MANUAL
# ============================================================================
section "P.* — Privacy (MANUAL, if TSC Privacy is included)"
note "Publish privacy notices, consent/rights handling, data subject response SLAs, and retention/erasure procedures with evidence (MANUAL)."

# ============================================================================
# Host probes (support CC6/CC7 signals)
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
      fail_list+=("NTP sync enabled on $inst");   fail_list+=("Auto logoff (TMOUT) set on $inst")
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

    check "Auditd active on $inst"                          bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst"                    bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst"                      bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst"             bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst"                bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst (FIM signal)"            bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst"                  bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst"    bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst"                bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst"                bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

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
section "SOC 2 Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/soc2-evidence.json"
out_ts="$REPORT_DIR/soc2-evidence-$ts.json"

jq -n \
  --arg framework "SOC 2 — AICPA Trust Services Criteria" \
  --argjson categories '["Security(CC)","Availability(A)","Confidentiality(C)","Processing Integrity(PI)","Privacy(P)"]' \
  --arg project "$PROJECT_ID" --arg region "$REGION" --arg zone "$ZONE" \
  --arg network "$NETWORK" --arg subnet "$SUBNET" --arg router "$ROUTER" --arg nat "$NAT" \
  --arg keyring "$KEYRING" --arg key "$KEY" --arg key_loc "$KEY_LOC" \
  --arg sa_email "$SA_EMAIL" --argjson vms "$(printf '%s\n' "${VMS[@]:-}" | jq -R . | jq -s .)" \
  --argjson pass "$(printf '%s\n' "${pass_list[@]}" | jq -R . | jq -s .)" \
  --argjson fail "$(printf '%s\n' "${fail_list[@]}" | jq -R . | jq -s .)" \
  --argjson manual "$(printf '%s\n' "${manual_list[@]}" | jq -R . | jq -s .)" \
  --argjson probes "[ $(IFS=,; echo "${probe_json[*]:-}") ]" \
  --arg timestamp "$ts" '
  {
    framework: $framework, categories: $categories,
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
  echo "SOC 2 automated checks FAILED for some controls."
  exit 2
fi
echo "SOC 2 automated checks PASSED for the technical safeguards tested."
