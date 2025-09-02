#!/usr/bin/env bash
# sox.sh — SOX §404 ICFR: IT General Controls (read-only, idempotent)
# Maps technical signals to ICFR/ITGC areas: Access to Programs & Data, Change Mgmt (signals),
# Computer Ops, Evidence retention. Organizational items are flagged MANUAL.

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# ---- CLI / env (uniform across modules) --------------------------------------
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

SSH_KEY="${SSH_KEY:-}"   # optional OS Login key path for SSH (read-only probes)
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
section "SOX ICFR (ITGC) checker preflight"
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

# ---- ITGC Area 1: Access to Programs & Data -----------------------------------
section "Access to Programs & Data (least privilege, auth, exposure)"
# No 0.0.0.0/0 ingress; IAP-only SSH
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/sox_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/sox_fws.json >/dev/null'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/sox_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/sox_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)")
fi

# OS Login on the project; Shielded VM + serial console disabled
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/sox_inst.json
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/sox_inst.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/sox_inst.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/sox_inst.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/sox_inst.json)"
    ext="$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // empty' /tmp/sox_inst.json)"
    check "No public IP ($inst)"                          bash -lc '[[ -z "'"$ext"'" ]]'
    check "Shielded VM secure boot ($inst)"               bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "Shielded VM vTPM ($inst)"                      bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Shielded VM integrity monitoring ($inst)"      bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst)"               bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# Human “Owner” role check (SoD/least-privilege signal)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/sox_iam.json
check "No human users with roles/owner at project" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/sox_iam.json >/dev/null'

# Service account user-managed keys (should be zero)
if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL" test -z "$keys"
fi

# ---- ITGC Area 2: Change Management (signals only) ----------------------------
section "Change Management (signals — organizational controls are MANUAL)"
note "Maintain change tickets, approvals, testing evidence, and deployment records for in-scope apps (ICFR)."
note "Enforce code review + segregation for prod changes (no self-approval)."
note "Retain change evidence aligned to SOX retention policy."

# ---- ITGC Area 3: Computer Operations (logging, monitoring, backups) ----------
section "Computer Operations (logging, monitoring, continuity)"
# Subnet flow logs & NAT logging → traffic visibility
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/sox_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/sox_nat.json
check "VPC Flow Logs enabled on subnet"      bash -lc 'jq -e ".enableFlowLogs==true" /tmp/sox_subnet.json >/dev/null'
check "Cloud NAT logging = ALL"              bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/sox_nat.json >/dev/null'

# Project-level DATA_READ/WRITE logging → audit trail
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/sox_iam_policy.json
check "Audit logs (DATA_READ/WRITE) enabled for allServices" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/sox_iam_policy.json >/dev/null'

# Log retention & immutability (7 years; bucket locked)
gcloud logging buckets describe _Default --location=global --format=json > /tmp/sox_logbucket.json || true
check "Logging retention >= 2555 days (7 years) [evidence alignment]" \
  bash -lc 'jq -e ".retentionDays>=2555" /tmp/sox_logbucket.json >/dev/null'
check "Logging bucket locked (immutability signal)" \
  bash -lc 'jq -e ".locked==true" /tmp/sox_logbucket.json >/dev/null'

# Optional: CMEK protecting Cloud Logging
gcloud logging cmek-settings describe --project="$PROJECT_ID" --format=json > /tmp/sox_cmek.json || true
check "Cloud Logging protected with CMEK (optional but strong)" \
  bash -lc 'jq -r ".kmsKeyName // empty" /tmp/sox_cmek.json | grep -q "."'

# Availability/continuity evidence: snapshot schedules on VM boot disks
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached"; pass_list+=("Snapshot schedules attached")
  else
    log "FAIL: Snapshot schedules attached"; fail_list+=("Snapshot schedules attached")
  fi
fi

# Monitoring alerting presence
gcloud monitoring alert-policies list --format=json > /tmp/sox_alerts.json || true
check "At least 1 Monitoring alert policy exists" bash -lc 'jq -e "length>=1" /tmp/sox_alerts.json >/dev/null' || true

# ---- Encryption & key management (strong control) -----------------------------
section "Encryption & Key Management (strong control for ICFR)"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/sox_key.json || true
  check "CMEK rotation configured (<=90d) [best practice]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 7776000" /tmp/sox_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured (<=90d) [best practice]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst)" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# ---- Host probes (auth, integrity, ops) ---------------------------------------
section "Host probes (supports Access & Ops controls)"
read -r -d '' REMOTE <<"EOS" || true
set -Eeuo pipefail
echo "HOST=$(hostname)"
state_auditd="$(systemctl is-active auditd || true)"; echo "AUDITD=$state_auditd"
rules_cnt="$(auditctl -l 2>/dev/null | wc -l || true)"; echo "AUDIT_RULES=$rules_cnt"
ops_state="$(systemctl is-active google-cloud-ops-agent 2>/dev/null || true)"; echo "OPS_AGENT=$ops_state"
sshpw="$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}' || true)"; echo "SSH_PASSAUTH=${sshpw:-unknown}"
sshroot="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}' || true)"; echo "SSH_ROOTLOGIN=${sshroot:-unknown}"
ntp="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)"; echo "NTP_SYNC=$ntp"
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
      fail_list+=("SSH root login disabled on $inst"); fail_list+=("Time sync (NTP) enabled on $inst")
      continue
    fi

    echo "$out" | sed 's/^/  ['"$inst"'] /'
    auditd="$(grep '^AUDITD=' <<<"$out" | cut -d= -f2-)"
    rules="$(grep '^AUDIT_RULES=' <<<"$out" | cut -d= -f2-)"
    ops="$(grep '^OPS_AGENT=' <<<"$out" | cut -d= -f2-)"
    sshpw="$(grep '^SSH_PASSAUTH=' <<<"$out" | cut -d= -f2-)"
    sshroot="$(grep '^SSH_ROOTLOGIN=' <<<"$out" | cut -d= -f2-)"
    ntp="$(grep '^NTP_SYNC=' <<<"$out" | cut -d= -f2-)"

    check "Auditd active on $inst"                     bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst"               bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst"                 bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst"        bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst"           bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "Time sync (NTP) enabled on $inst"           bash -lc '[[ "'"$ntp"'" == "yes" ]]'

    probe_json+=("{
      \"instance\":\"$inst\",\"auditd\":\"$auditd\",\"audit_rules\":$rules,
      \"ops_agent\":\"$ops\",\"ssh_passwordauth\":\"$sshpw\",
      \"ssh_rootlogin\":\"$sshroot\",\"ntp_sync\":\"$ntp\"
    }")
  done
else
  log "Skipping host probes (no --vm provided)."
fi

# ---- Always-MANUAL organizational evidence ------------------------------------
section "Organizational ICFR evidence (always MANUAL)"
note "Management ICFR assessment & scoping (systems impacting financial reporting)."
note "Quarterly access reviews for in-scope apps & DBs; leaver offboarding SLAs; emergency access reviews."
note "Change management approvals/testing/segregation; release governance & prod access workflows."
note "End-to-end logging demonstrating who changed what, when, with authorization; tie to tickets."

# ---- Scoreboard & evidence file ----------------------------------------------
section "SOX ICFR (ITGC) Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/sox-evidence.json"
out_ts="$REPORT_DIR/sox-evidence-$ts.json"

jq -n \
  --arg framework "SOX §404 ICFR — ITGC (signals for AS 2201 audit)" \
  --argjson areas '["Access","Change Mgmt (signals)","Computer Ops","Retention","Encryption"]' \
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
    framework: $framework,
    areas: $areas,
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

# Non-zero exit if anything failed
if (( ${#fail_list[@]} > 0 )); then
  echo "SOX automated checks FAILED for some controls."
  exit 2
fi
echo "SOX automated checks PASSED for the technical safeguards tested."
