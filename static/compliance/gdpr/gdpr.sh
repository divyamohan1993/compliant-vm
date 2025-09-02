#!/usr/bin/env bash
# gdpr.sh — GDPR (EU 2016/679) technical & evidence checks (read-only, idempotent)
# Focus: Automatable parts of Art. 5(2), 25, 30, 32, 33/34, 44–49 (evidence), with MANUAL flags for legal/organizational items.

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# ---- Defaults / CLI (align with hipaa.sh) ------------------------------------
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
SSH_KEY="${SSH_KEY:-}"   # optional for OS Login SSH
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
section "GDPR checker preflight"
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

# Simple region-classifier (EEA-ish heuristic): true if region starts with "europe-"
is_eea_region() { [[ "$REGION" == europe-* ]]; }

# ---- 1) Art. 32 — Security of processing (encryption, integrity, availability) ----
section "Art. 32 — Security of processing"

# Data Access audit logs enabled (evidence for audit controls/integrity)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/gdpr_iam_policy.json
check "Data Access logs enabled for allServices [Art. 32(1) audit controls]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/gdpr_iam_policy.json >/dev/null'

# Encryption at rest: CMEK + rotation
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/gdpr_key.json || true
  check "CMEK rotation configured (<=90d) [Art. 32(1)(a) encryption]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 7776000" /tmp/gdpr_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured (<=90d) [Art. 32(1)(a) encryption]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst) [Art. 32(1)(a) encryption]" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# Confidentiality in transit / exposure minimization
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    ext="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" \
          --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
    check "No public IP ($inst) [Art. 32(1)(b) confidentiality]" test -z "${ext}"
  done
fi

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/gdpr_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress [Art. 32(1)(b) confidentiality]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/gdpr_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress [Art. 32(1)(b) confidentiality]")
fi

gcloud compute firewall-rules list --project "$PROJECT_ID" \
  --filter="network=$NETWORK AND direction=INGRESS AND disabled=false" --format=json > /tmp/gdpr_fws.json
check "No 0.0.0.0/0 ingress on $NETWORK [Art. 25 & 32 privacy by default/confidentiality]" \
  bash -lc '! jq -e '\''.[]?|.sourceRanges[]? | select(.=="0.0.0.0/0")'\'' /tmp/gdpr_fws.json >/dev/null'

# Availability & resilience → snapshot policy as restoration evidence
snap_ok=1
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    policies="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)' || true)"
    [[ -z "$policies" ]] && snap_ok=0
  done
  if [[ "$snap_ok" == "1" ]]; then
    log "PASS: Snapshot schedules attached [Art. 32(1)(b)(c) availability/resilience]"; pass_list+=("Snapshot schedules attached [Art. 32]")
  else
    log "FAIL: Snapshot schedules attached [Art. 32(1)(b)(c)]"; fail_list+=("Snapshot schedules attached [Art. 32]")
  fi
fi

# ---- 2) Art. 25 — Privacy by design/default (exposure, least privilege) -------
section "Art. 25 — Data protection by design & by default"

# OS Login = unique IDs; block password auth/root on VMs (checked via probe)
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project [Art. 25/32 access control]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

# IAM sanity: detect broad Owner bindings to human principals (rough heuristic)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/gdpr_iam.json
check "No human users with roles/owner at project [Art. 25/32 least privilege]" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/gdpr_iam.json >/dev/null'

# ---- 3) Art. 33/34 — Breach notification readiness (signals) ------------------
section "Art. 33/34 — Breach detection & notification (signals/evidence)"
# We can’t prove your legal response, but we can check alerting exists.
gcloud monitoring alert-policies list --format=json > /tmp/gdpr_alerts.json || true
check "At least 1 Cloud Monitoring alert policy exists [Art. 33/34 operational readiness]" \
  bash -lc 'jq -e "length>=1" /tmp/gdpr_alerts.json >/dev/null' || true
note "Document incident response & breach notification procedures (who/when/how) [Art. 33, 34]"

# ---- 4) Art. 30 — Records of processing (organizational) ----------------------
section "Art. 30 — Records of processing (organizational)"
note "Maintain controller/processor Records of Processing Activities (RoPA) [Art. 30]"

# ---- 5) Art. 28 — Processor contracts (DPA/SCCs) ------------------------------
section "Art. 28 — Processor contracts"
note "Execute GDPR-compliant DPA with Google & relevant processors [Art. 28(3)]"
note "If sub-processors used, ensure contractual flow-down & transparency [Art. 28(2)]"

# ---- 6) Art. 44–49 — International transfers ---------------------------------
section "Art. 44–49 — International data transfers"
if is_eea_region; then
  log "INFO: Region '${REGION}' detected as EU/EEA-style; cross-border safeguards may still apply for multi-region services."
else
  note "Processing region '${REGION}' is outside EEA → ensure valid transfer mechanism (SCCs/adequacy + TIA) [Art. 44–49]"
fi

# ---- 7) VM OS probes (confidentiality/integrity defaults) ---------------------
section "VM OS probes (Art. 32(d) auth; 32 integrity; 25 defaults)"
read -r -d '' REMOTE_GDPR <<"EOS" || true
set -Eeuo pipefail
echo "HOST=$(hostname)"
state_auditd="$(systemctl is-active auditd || true)"; echo "AUDITD=$state_auditd"
rules_cnt="$(auditctl -l 2>/dev/null | wc -l || true)"; echo "AUDIT_RULES=$rules_cnt"
ops_state="$(systemctl is-active google-cloud-ops-agent 2>/dev/null || true)"; echo "OPS_AGENT=$ops_state"
aide_ver="$(dpkg -s aide 2>/dev/null | awk -F': ' '/Version/{print $2}' || true)"; echo "AIDE_VER=${aide_ver:-none}"
aide_db="$(ls -1 /var/lib/aide/aide.db* 2>/dev/null | head -n1 || true)"; echo "AIDE_DB=${aide_db:-none}"
sshpw="$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}' || true)"; echo "SSH_PASSAUTH=${sshpw:-unknown}"
sshroot="$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}' || true)"; echo "SSH_ROOTLOGIN=${sshroot:-unknown}"
EOS

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    set +e
    out="$(gcloud compute ssh "$inst" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "$REMOTE_GDPR" 2>/dev/null)"
    rc=$?
    set -e
    if (( rc != 0 )); then
      log "WARN: SSH probe failed on $inst (marking probe checks as FAIL)"
      fail_list+=("Auditd active on $inst [Art. 32]")
      fail_list+=("Audit rules present on $inst [Art. 32]")
      fail_list+=("Ops Agent running on $inst [Art. 32]")
      fail_list+=("SSH password auth disabled on $inst [Art. 32(d)]")
      fail_list+=("SSH root login disabled on $inst [Art. 32(d)]")
      continue
    fi

    echo "$out" | sed 's/^/  ['"$inst"'] /'
    auditd="$(grep '^AUDITD=' <<<"$out" | cut -d= -f2-)"
    rules="$(grep '^AUDIT_RULES=' <<<"$out" | cut -d= -f2-)"
    ops="$(grep '^OPS_AGENT=' <<<"$out" | cut -d= -f2-)"
    sshpw="$(grep '^SSH_PASSAUTH=' <<<"$out" | cut -d= -f2-)"
    sshroot="$(grep '^SSH_ROOTLOGIN=' <<<"$out" | cut -d= -f2-)"

    check "Auditd active on $inst [Art. 32]" bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [Art. 32]" bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [Art. 32]" bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [Art. 32(d) auth]" bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [Art. 32(d) auth]" bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'

    probe_json+=("{
      \"instance\":\"$inst\",\"auditd\":\"$auditd\",\"audit_rules\":$rules,
      \"ops_agent\":\"$ops\",\"ssh_passwordauth\":\"$sshpw\",\"ssh_rootlogin\":\"$sshroot\"
    }")
  done
else
  log "Skipping VM OS probes (no --vm provided)."
fi

# ---- 8) Art. 5 & retention (storage limitation/accountability) ----------------
section "Art. 5 — Principles: storage limitation & accountability"
# We can’t prove your business retention schedule, but we can check logs aren’t indefinite.
gcloud logging buckets describe _Default --location=global --format=json > /tmp/gdpr_logbucket.json || true
check "Cloud Logging retention configured (finite) [Art. 5(1)(e) storage limitation]" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>0" /tmp/gdpr_logbucket.json >/dev/null'
note "Verify your **data** (not just logs) retention schedules match purpose limitation [Art. 5(1)(b) & (e)]"

# ---- 9) Always-manual evidence (law/organizational) ---------------------------
section "Manual evidences (legal & organizational)"
note "DPA with Google + sub-processor transparency in place [Art. 28]"
note "Records of Processing Activities (controller/processor) maintained [Art. 30]"
note "DPIA conducted where high risk processing occurs [Art. 35]"
note "Breach response plan & notification procedures documented [Art. 33/34]"
if ! is_eea_region; then
  note "SCCs/adequacy + Transfer Impact Assessment for transfers outside EEA [Art. 44–49]"
fi
note "Data subject rights processes (access, erasure, portability) operational [Art. 15–22]"

# ---- Scoreboard & evidence file ----------------------------------------------
section "GDPR Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/gdpr-evidence.json"
out_ts="$REPORT_DIR/gdpr-evidence-$ts.json"

jq -n \
  --arg standard "EU GDPR (2016/679)" \
  --argjson articles '["Art.5","Art.25","Art.30","Art.32","Art.33","Art.34","Art.44-49"]' \
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
    standard: $standard,
    articles: $articles,
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

# Exit non-zero when FAILs exist
if (( ${#fail_list[@]} > 0 )); then
  echo "GDPR automated checks FAILED for some controls."
  exit 2
fi
echo "GDPR automated checks PASSED for the technical safeguards tested."
