#!/usr/bin/env bash
# bsa.sh — Bank Secrecy Act (BSA/AML) technical signals checker (read-only, idempotent)
# Mirrors your autoconfig UX: sections + PASS/FAIL/MANUAL + JSON evidence.
# What it can prove on infra: audit/retention (≥5y), access control, encryption at rest, monitoring signals.
# What stays MANUAL: the AML program “five pillars”, CIP, CDD/Beneficial Ownership, SAR/CTR operations.

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

# BSA-specific knobs (affect PASS/FAIL; never mutate resources)
MIN_BSA_RETENTION_DAYS="${MIN_BSA_RETENTION_DAYS:-1825}" # 5 years per 31 CFR 1010.430
REQUIRE_CMEK_ON_SINKS="${REQUIRE_CMEK_ON_SINKS:-1}"      # 1=require CMEK on GCS/BQ sinks if present

SSH_KEY="${SSH_KEY:-}"   # optional OS Login key for SSH probes
SSH_COMMON_BASE=(--tunnel-through-iap)
[[ -n "${SSH_KEY}" ]] && SSH_COMMON_BASE+=(--ssh-key-file="$SSH_KEY")

usage() {
  cat <<EOF
Usage: $0 [--project ID] [--region R] [--zone Z]
          [--network NET] [--subnet SUBNET] [--router R] [--nat N]
          [--keyring KR] [--key K] [--key-loc L] [--sa-email SA]
          [--vm NAME ...] [--report-dir DIR]
          [--min-bsa-retention-days DAYS] [--require-cmek-on-sinks 0|1]
          [--no-stamped]
Env fallbacks: PROJECT_ID, REGION, ZONE, NETWORK, SUBNET, ROUTER, NAT, KEYRING, KEY, KEY_LOC, SA_EMAIL,
               REPORT_DIR, MIN_BSA_RETENTION_DAYS, REQUIRE_CMEK_ON_SINKS, SSH_KEY
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
    --min-bsa-retention-days) MIN_BSA_RETENTION_DAYS="$2"; shift 2;;
    --require-cmek-on-sinks) REQUIRE_CMEK_ON_SINKS="$2"; shift 2;;
    --no-stamped) STAMPED=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 3;;
  esac
done

# ---- Preflight ----------------------------------------------------------------
section "BSA/AML checker preflight"
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1" >&2; exit 3; }; }
need gcloud; need jq; need awk; need sed; need grep; need date
# Optional tools (only if available): bq CLI for BigQuery metadata
has_bq=0; command -v bq >/dev/null 2>&1 && has_bq=1

[[ -n "$PROJECT_ID" && -n "$REGION" && -n "$ZONE" ]] || { echo "Need --project/--region/--zone" >&2; exit 3; }
[[ -n "$NETWORK" && -n "$SUBNET" && -n "$ROUTER" && -n "$NAT" ]] || { echo "Need --network/--subnet/--router/--nat" >&2; exit 3; }
mkdir -p "$REPORT_DIR"

OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[?primary=true].username)' || true)"
[[ -z "$OS_LOGIN_USER" ]] && OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[0].username)' || true)"
SSH_COMMON=("${SSH_COMMON_BASE[@]}")
[[ -n "$OS_LOGIN_USER" ]] && SSH_COMMON+=(--ssh-flag="-l ${OS_LOGIN_USER}")

# ---- Helpers ------------------------------------------------------------------
pass_list=(); fail_list=(); manual_list=(); probe_json=(); sinks_json=()
check() { local name="$1"; shift; if "$@"; then log "PASS: $name"; pass_list+=("$name"); else log "FAIL: $name"; fail_list+=("$name"); fi; }
note()  { manual_list+=("$1"); log "MANUAL: $1"; }
dedup() { awk '!seen[$0]++'; }

# ============================================================================
# BSA/AML Program — the Five Pillars (MANUAL artifacts)
# 31 CFR 1020.210 + CIP 1020.220 + CDD 1010.230 (Beneficial Ownership)
# ============================================================================
section "BSA/AML Program — Five Pillars (MANUAL evidence)"
note "System of internal controls for ongoing BSA compliance (policies, procedures, transaction monitoring) — provide policy + runbooks. [MANUAL]"
note "Independent testing of BSA/AML (internal audit / external) — provide schedule & latest report. [MANUAL]"
note "BSA compliance officer (day-to-day oversight) — provide charter/appointment. [MANUAL]"
note "Training for appropriate personnel (role-based) — provide calendar/records. [MANUAL]"
note "Risk-based ongoing CDD including beneficial ownership (31 CFR 1010.230) — provide procedures, risk model & QA evidence. [MANUAL]"
note "Customer Identification Program (CIP, 31 CFR 1020.220) incl. notice, verification methods, TIN rules — provide procedures & samples. [MANUAL]"

# ============================================================================
# SAR / CTR obligations (operations/process) — MANUAL artifacts
# ============================================================================
section "SAR / CTR obligations (operations) — MANUAL evidence"
note "SAR: suspicious activity monitoring & filing (31 CFR 1020.320), continuing-activity review cadence, supporting documentation — provide queue/workflow evidence. [MANUAL]"
note "CTR: currency transactions > \$10,000 (31 CFR 1010.311) & exempt-person procedures — provide process & samples. [MANUAL]"
note "BSA Record retention ≥5 years for required records/reports (31 CFR 1010.430) — see technical retention checks below."

# ============================================================================
# Technical safeguards that support BSA: logging, retention (≥5y), access control, encryption, monitoring
# ============================================================================
section "Project audit logging & retention (≥ ${MIN_BSA_RETENTION_DAYS} days)"
# Require ADMIN_READ/DATA_READ/DATA_WRITE logging (org-defined scope support)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/bsa_iam_policy.json
check "Audit logs enabled (ADMIN_READ/DATA_READ/DATA_WRITE)" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]? | .logType]
            | (index("ADMIN_READ") != null and index("DATA_READ") != null and index("DATA_WRITE") != null)'\'' \
            /tmp/bsa_iam_policy.json >/dev/null'

# Cloud Logging default bucket retention (signal only — many orgs export via sinks)
gcloud logging buckets describe _Default --location=global --format=json > /tmp/bsa_logbucket.json || true
check "Cloud Logging _Default retention >= ${MIN_BSA_RETENTION_DAYS} days" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>='"$MIN_BSA_RETENTION_DAYS" /tmp/bsa_logbucket.json >/dev/null'

section "Long-term evidence sinks (GCS/BQ) with ≥5y retention + (optional) CMEK"
gcloud logging sinks list --format=json > /tmp/bsa_sinks.json || echo "[]" >/tmp/bsa_sinks.json
have_longterm=0; cmek_ok=1
jq -c '.[]?' /tmp/bsa_sinks.json | while read -r s; do
  name="$(jq -r '.name' <<<"$s")"
  dest="$(jq -r '.destination' <<<"$s")"
  # Normalize destination types
  if [[ "$dest" == storage.googleapis.com/* || "$dest" == //storage.googleapis.com/* || "$dest" == "storage.googleapis.com://"* ]]; then
    # GCS bucket
    bucket="${dest#*storage.googleapis.com/}"
    bucket="${bucket#//}"
    bucket="gs://${bucket%%/*}"
    # Describe bucket
    if gcloud storage buckets describe "$bucket" --format=json >/tmp/bsa_bucket.json 2>/dev/null; then
      rp="$(jq -r '.retentionPolicy.retentionPeriod // 0' /tmp/bsa_bucket.json)"
      kms="$(jq -r '.defaultKmsKeyName // empty' /tmp/bsa_bucket.json)"
      days=$(( rp/86400 ))
      if (( days >= MIN_BSA_RETENTION_DAYS )); then have_longterm=1; fi
      if [[ "${REQUIRE_CMEK_ON_SINKS}" == "1" && -z "$kms" ]]; then cmek_ok=0; fi
      sinks_json+=("$(jq -n --arg type "gcs" --arg name "$name" --arg bucket "$bucket" --argjson retention_days "$days" --arg cmek "${kms:-}" '{type:$type,name:$name,bucket:$bucket,retention_days:$retention_days,cmek:$cmek}')")
    fi
  elif [[ "$dest" == bigquery.googleapis.com/* ]]; then
    # BigQuery dataset
    ds="$(sed -E 's#^bigquery.googleapis.com/##' <<<"$dest")" # projects/PRJ/datasets/DS
    prj="$(cut -d/ -f2 <<<"$ds")"; dset="$(cut -d/ -f4 <<<"$ds")"
    if (( has_bq )); then
      if out="$(bq --project_id="$prj" show --format=json "$dset" 2>/dev/null)"; then
        exp="$(jq -r '.defaultTableExpirationMs // empty' <<<"$out")"
        kms="$(jq -r '.defaultEncryptionConfiguration.kmsKeyName // empty' <<<"$out")"
        # If no expiration, treat as indefinite (good)
        days=$(( ${exp:-0} / 86400000 ))
        if [[ -z "$exp" || $days -ge $MIN_BSA_RETENTION_DAYS ]]; then have_longterm=1; fi
        if [[ "${REQUIRE_CMEK_ON_SINKS}" == "1" && -z "$kms" ]]; then cmek_ok=0; fi
        sinks_json+=("$(jq -n --arg type "bigquery" --arg name "$name" --arg dataset "$dset" --arg project "$prj" --argjson retention_days "${days:-0}" --arg cmek "${kms:-}" '{type:$type,name:$name,project:$project,dataset:$dataset,retention_days:$retention_days,cmek:$cmek}')")
      fi
    else
      sinks_json+=("$(jq -n --arg type "bigquery" --arg name "$name" --arg dataset "$dset" '{type:$type,name:$name,dataset:$dataset,retention_days:null,cmek:null,note:"bq CLI not available"}')")
    fi
  else
    sinks_json+=("$(jq -n --arg type "other" --arg name "$name" --arg dest "$dest" '{type:$type,name:$name,destination:$dest}')")
  fi
done

# Evaluate sink signals
if (( have_longterm == 1 )); then
  log "PASS: At least one logging sink provides ≥${MIN_BSA_RETENTION_DAYS} days of retention"
  pass_list+=("Long-term logging sink ≥${MIN_BSA_RETENTION_DAYS}d")
else
  log "FAIL: No logging sink with ≥${MIN_BSA_RETENTION_DAYS} days retention found"
  fail_list+=("Long-term logging sink ≥${MIN_BSA_RETENTION_DAYS}d")
fi
if [[ "${REQUIRE_CMEK_ON_SINKS}" == "1" ]]; then
  if (( cmek_ok == 1 )); then
    log "PASS: Long-term sinks use CMEK (where checked)"
    pass_list+=("CMEK on long-term sinks")
  else
    log "FAIL: Long-term sinks missing CMEK on at least one destination"
    fail_list+=("CMEK on long-term sinks")
  fi
fi

section "Network & access control (IAP+OS Login; no broad ingress)"
gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json >/tmp/bsa_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/bsa_fws.json >/dev/null'

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/bsa_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH (tcp:22 from 35.235.240.0/20)" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/bsa_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH present")
fi

proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enforced at project" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

gcloud projects get-iam-policy "$PROJECT_ID" --format=json >/tmp/bsa_iam.json
check "No human principals with roles/owner" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/bsa_iam.json >/dev/null'

if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL" test -z "$keys"
fi

section "Encryption & key mgmt signals (CMEK + Shielded VM)"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/bsa_key.json || true
  rot="$(jq -r '.rotationPeriod|sub("s$";"")|tonumber // 0' /tmp/bsa_key.json)"
  check "CMEK key has rotation configured (>0)" bash -lc '[[ '"${rot:-0}"' -gt 0 ]]'
else
  fail_list+=("CMEK key rotation configured")
fi
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/bsa_vm.json
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/bsa_vm.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/bsa_vm.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/bsa_vm.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/bsa_vm.json)"
    disk="$(jq -r '.disks[0].source' /tmp/bsa_vm.json | awk -F/ '{print $NF}')"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "Shielded VM secure boot ($inst)"           bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "Shielded VM vTPM ($inst)"                  bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Shielded VM integrity monitoring ($inst)"  bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst)"           bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
    check "CMEK on boot disk ($inst)"                 bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

section "Network telemetry & monitoring signals"
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/bsa_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/bsa_nat.json
check "VPC Flow Logs enabled on subnet"  bash -lc 'jq -e ".enableFlowLogs==true" /tmp/bsa_subnet.json >/dev/null'
check "Cloud NAT logging = ALL"          bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/bsa_nat.json >/dev/null'
gcloud monitoring alert-policies list --format=json > /tmp/bsa_alerts.json || true
check "At least 1 Monitoring alert policy exists" bash -lc 'jq -e "length>=1" /tmp/bsa_alerts.json >/dev/null' || true

# ============================================================================
# Host probes (auditd/time sync/hardening) — supports evidence integrity
# ============================================================================
section "Host probes (audit/telemetry/time sync)"
read -r -d '' REMOTE <<"EOS" || true
set -Eeuo pipefail
echo "HOST=$(hostname)"
state_auditd="$(systemctl is-active auditd || true)"; echo "AUDITD=$state_auditd"
rules_cnt="$(auditctl -l 2>/dev/null | wc -l || true)"; echo "AUDIT_RULES=$rules_cnt"
ops_state="$(systemctl is-active google-cloud-ops-agent 2>/dev/null || true)"; echo "OPS_AGENT=$ops_state"
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
      fail_list+=("auditd active on $inst"); fail_list+=("audit rules present on $inst")
      fail_list+=("Ops Agent running on $inst"); fail_list+=("NTP sync enabled on $inst")
      continue
    fi
    echo "$out" | sed 's/^/  ['"$inst"'] /'
    auditd="$(grep '^AUDITD=' <<<"$out" | cut -d= -f2-)"
    rules="$(grep '^AUDIT_RULES=' <<<"$out" | cut -d= -f2-)"
    ops="$(grep '^OPS_AGENT=' <<<"$out" | cut -d= -f2-)"
    ntp="$(grep '^NTP_SYNC=' <<<"$out" | cut -d= -f2-)"

    check "auditd active on $inst"                   bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "audit rules present on $inst"             bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst"               bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "Time sync (NTP) enabled on $inst"         bash -lc '[[ "'"$ntp"'" == "yes" ]]'

    sinks_line="$(printf '%s' "${sinks_json[*]:-}" | jq -s .)"
    probe_json+=("{
      \"instance\":\"$inst\",\"auditd\":\"$auditd\",\"audit_rules\":$rules,
      \"ops_agent\":\"$ops\",\"ntp_sync\":\"$ntp\"
    }")
  done
else
  log "Skipping host probes (no --vm provided)."
fi

# ============================================================================
# Scoreboard & evidence JSON
# ============================================================================
section "BSA/AML Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/bsa-evidence.json"
out_ts="$REPORT_DIR/bsa-evidence-$ts.json"

jq -n \
  --arg framework "BSA/AML (31 CFR Chapter X)" \
  --arg project "$PROJECT_ID" --arg region "$REGION" --arg zone "$ZONE" \
  --arg network "$NETWORK" --arg subnet "$SUBNET" --arg router "$ROUTER" --arg nat "$NAT" \
  --arg keyring "$KEYRING" --arg key "$KEY" --arg key_loc "$KEY_LOC" \
  --arg sa_email "$SA_EMAIL" --argjson vms "$(printf '%s\n' "${VMS[@]:-}" | jq -R . | jq -s .)" \
  --arg min_ret_days "$MIN_BSA_RETENTION_DAYS" \
  --arg require_cmek "$REQUIRE_CMEK_ON_SINKS" \
  --argjson pass "$(printf '%s\n' "${pass_list[@]}" | jq -R . | jq -s .)" \
  --argjson fail "$(printf '%s\n' "${fail_list[@]}" | jq -R . | jq -s .)" \
  --argjson manual "$(printf '%s\n' "${manual_list[@]}" | jq -R . | jq -s .)" \
  --argjson probes "[ $(IFS=,; echo "${probe_json[*]:-}") ]" \
  --argjson sinks  "[ $(IFS=,; echo "${sinks_json[*]:-}") ]" \
  --arg timestamp "$ts" '
  {
    framework: $framework,
    context: {
      project: $project, region: $region, zone: $zone,
      network: $network, subnet: $subnet, router: $router, nat: $nat,
      keyring: $keyring, key: $key, key_loc: $key_loc, sa_email: $sa_email, vms: $vms
    },
    thresholds: { min_retention_days: ($min_ret_days|tonumber), require_cmek_on_sinks: ($require_cmek=="1") },
    results: { pass: $pass, fail: $fail, manual: $manual },
    vm_probes: $probes,
    sinks: $sinks,
    timestamp: $timestamp
  }' > "$out_base"

[[ "$STAMPED" == "1" ]] && cp -f "$out_base" "$out_ts"
log "Wrote evidence: $out_base"
[[ "$STAMPED" == "1" ]] && log "Wrote timestamped copy: $out_ts"

if (( ${#fail_list[@]} > 0 )); then
  echo "BSA automated checks FAILED for some technical safeguards."
  exit 2
fi
echo "BSA automated checks PASSED for the technical safeguards tested."
