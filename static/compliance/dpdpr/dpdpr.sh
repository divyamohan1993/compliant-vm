#!/usr/bin/env bash
# dpdpr.sh — India DPDP Act, 2023 + DPDP Rules (draft) technical checks (read-only)
# Style matches your autoconfig.sh/hipaa.sh/gdpr.sh modules.

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# ---- CLI / env (uniform with your other modules) ------------------------------
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

SSH_KEY="${SSH_KEY:-}"   # optional (OS Login key path if you want to force a specific key)
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
section "DPDPR checker preflight"
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

is_india_region() { [[ "$REGION" == "asia-south1" || "$REGION" == "asia-south2" ]]; }

# ---- §8(5)-(6): Security safeguards & breach intimation readiness -------------
section "DPDPA §8(5)-(6) — Security safeguards & breach intimation readiness"

# Project-level Data Access audit logs (read/write) → audit evidence
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/dpdp_iam_policy.json
check "Audit logs (DATA_READ/WRITE) enabled for allServices" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/dpdp_iam_policy.json >/dev/null'

# Exposure minimization: no public IPs; IAP-only SSH; no 0.0.0.0/0
if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    ext="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" \
          --format='get(networkInterfaces[0].accessConfigs[0].natIP)' || true)"
    check "No public IP ($inst)" test -z "${ext}"
  done
fi

if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/dpdp_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/dpdp_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress present (tcp:22 from 35.235.240.0/20)")
fi

# List all and filter locally; .network is a selfLink, so match by suffix.
gcloud compute firewall-rules list --project "$PROJECT_ID" --format=json > /tmp/dpdp_fws.json || echo "[]" > /tmp/dpdp_fws.json

check "No 0.0.0.0/0 ingress on VPC $NETWORK" \
  bash -lc 'jq -e --arg net "'"$NETWORK"'" '\''[
      .[]
      | select(.network|endswith("/" + $net))
      | select(.direction=="INGRESS")
      | select(.disabled!=true)
      | .sourceRanges[]?
    ] | index("0.0.0.0/0") == null'\'' /tmp/dpdp_fws.json >/dev/null'

# Network observability
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/dpdp_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/dpdp_nat.json
check "VPC Flow Logs enabled on subnet" bash -lc 'jq -e ".enableFlowLogs==true" /tmp/dpdp_subnet.json >/dev/null'
check "Cloud NAT logging enabled (ALL)"  bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/dpdp_nat.json >/dev/null'

# Breach detection signal: alerts + channels exist (readiness to notify Board & individuals)
ALERTS_JSON="/tmp/dpdp_alerts.json"
if ! (
  gcloud monitoring policies list --format=json > "$ALERTS_JSON" 2>/dev/null \
  || gcloud monitoring alert-policies list --format=json > "$ALERTS_JSON" 2>/dev/null \
  || gcloud beta  monitoring policies list --format=json > "$ALERTS_JSON" 2>/dev/null \
  || gcloud alpha monitoring policies list --format=json > "$ALERTS_JSON" 2>/dev/null
); then
  echo "[]" > "$ALERTS_JSON"
fi

# Channels: prefer GA; fallback to beta/alpha so older gclouds don't break
if ! (
  gcloud monitoring channels list --format=json > /tmp/dpdp_channels.json 2>/dev/null \
  || gcloud beta  monitoring channels list --format=json > /tmp/dpdp_channels.json 2>/dev/null \
  || gcloud alpha monitoring channels list --format=json > /tmp/dpdp_channels.json 2>/dev/null
); then
  echo "[]" > /tmp/dpdp_channels.json
fi


check "At least 1 Monitoring alert policy exists" bash -lc 'jq -e "length>=1" '"$ALERTS_JSON"' >/dev/null'
check "At least 1 Notification channel exists"   bash -lc 'jq -e "length>=1" /tmp/dpdp_channels.json >/dev/null'


# ---- Strong control for §8(5): encryption at rest (CMEK) ---------------------
section "DPDPA §8(5) — Encryption at rest (strong control)"
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/dpdp_key.json || true
  # Rotation ≤90d is a best-practice bar (law is principles-based)
  check "CMEK rotation configured (<=90d) [best practice]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 7776000" /tmp/dpdp_key.json >/dev/null'
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

# ---- §8(7)-(10): Erasure/retention, DPO contact, grievance redressal ----------
section "DPDPA §8(7)-(10) — Retention/erasure & contact/grievance"
# We can’t introspect your product data-retention logic; we do verify logs aren’t indefinite.
gcloud logging buckets describe _Default --location=global --format=json > /tmp/dpdp_logbucket.json || true
check "Cloud Logging retention set to a finite value" \
  bash -lc 'jq -e ".retentionDays and .retentionDays>0" /tmp/dpdp_logbucket.json >/dev/null'
note "Verify your **business** data-retention and erasure flows (withdrawal of consent/purpose complete)."

note "Publish business contact (DPO/Contact) & provide effective grievance mechanism."

# ---- §9: Children’s data (verifiable consent; no tracking/targeted ads) -------
section "DPDPA §9 — Children’s data"
note "Implement verifiable parental/guardian consent for <18; avoid tracking/targeted ads to children; document exemptions if notified."

# ---- §10: Significant Data Fiduciary (SDF) obligations ------------------------
section "DPDPA §10 — Significant Data Fiduciary obligations"
note "If designated SDF: appoint India-based DPO, independent data auditor; conduct periodic DPIA & audits; maintain additional measures."

# ---- §16: Cross-border transfers (negative list regime) -----------------------
section "DPDPA §16 — Cross-border transfer posture"
if is_india_region; then
  log "INFO: Primary region '${REGION}' is in India (Mumbai/Delhi). Review any multi-region services/replicas."
else
  note "Region '${REGION}' is outside India — ensure transfers are not to any **restricted** countries (if/when notified)."
fi

# ---- VM OS probes (auth/integrity/telemetry) ----------------------------------
section "Host probes (auth/integrity/telemetry)"
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
    # Refresh OS Login key TTL if a key was provided (prevents occasional SSH rc=1)
    if [[ -n "$SSH_KEY" && -f "$SSH_KEY.pub" ]]; then
      gcloud compute os-login ssh-keys add --project "$PROJECT_ID" --key-file="$SSH_KEY.pub" --ttl=24h || true
    fi

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
    check "AIDE installed on $inst"                         bash -lc '[[ "'"$aidev"'" != "none" ]]'
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
  log "Skipping VM OS probes (no --vm provided)."
fi

# ---- Scoreboard & evidence file ----------------------------------------------
section "DPDPR Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/dpdpr-evidence.json"
out_ts="$REPORT_DIR/dpdpr-evidence-$ts.json"

jq -n \
  --arg standard "India DPDP Act, 2023 + DPDP Rules (draft)" \
  --argjson sections '["§6","§8","§9","§10","§16"]' \
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
    standard: $standard, sections: $sections,
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
  echo "DPDPR automated checks FAILED for some controls."
  exit 2
fi
echo "DPDPR automated checks PASSED for the technical safeguards tested."
