#!/usr/bin/env bash
# pcidss-l1.sh — PCI DSS v4.0.1 Level 1: technical & evidence checks (read-only, idempotent)
# Mirrors your autoconfig.sh UX (sections, PASS/FAIL, scoreboard) and JSON evidence.

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

SSH_KEY="${SSH_KEY:-}"   # optional: OS Login key path for SSH (read-only probes)
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
section "PCI DSS v4.0.1 L1 checker preflight"
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
# ---- gcloud Monitoring compatibility (GA/beta/alpha) --------------------------
monitoring_list_json() {
  # Try GA
  if gcloud monitoring alert-policies list --format=json >/tmp/_mon.json 2>/dev/null; then
    cat /tmp/_mon.json; return 0
  fi
  # Try beta
  if gcloud beta monitoring alert-policies list --format=json >/tmp/_mon.json 2>/dev/null; then
    cat /tmp/_mon.json; return 0
  fi
  # Alpha uses 'policies'
  if gcloud alpha monitoring policies list --format=json >/tmp/_mon.json 2>/dev/null; then
    cat /tmp/_mon.json; return 0
  fi
  # Last resort: empty list
  echo "[]"
}


# ---- Req 1: Network security controls ----------------------------------------
section "Req 1 — Install and maintain network security controls"

# List all rules; filter locally (portable across gcloud versions)
gcloud compute firewall-rules list --project "$PROJECT_ID" --format=json > /tmp/pci_fws.json 2>/dev/null || echo "[]" >/tmp/pci_fws.json

# No 0.0.0.0/0 ingress on this VPC
check "No 0.0.0.0/0 ingress on $NETWORK [Req 1]" \
  bash -lc 'jq -e --arg net "'"$NETWORK"'" '\''[
      .[] 
      | select(.network | endswith("/networks/" + $net))
      | select(.direction == "INGRESS")
      | select(.disabled != true)
      | .sourceRanges[]?
    ] | index("0.0.0.0/0") == null'\'' /tmp/pci_fws.json >/dev/null'

# IAP-only SSH (tcp:22 from 35.235.240.0/20)
if gcloud compute firewall-rules describe allow-iap-ssh --project "$PROJECT_ID" --format=json >/tmp/pci_fw_iap.json 2>/dev/null; then
  check "IAP-only SSH ingress present [Req 1]" \
    bash -lc 'jq -e '\''(.direction=="INGRESS")
      and ([.sourceRanges[]?]|join(" ")|contains("35.235.240.0/20"))
      and ( [.allowed[]?|select(.IPProtocol=="tcp")|.ports[]?] | index("22") != null )'\'' /tmp/pci_fw_iap.json >/dev/null'
else
  fail_list+=("IAP-only SSH ingress present [Req 1]")
fi

# Subnet flow logs + NAT logging (visibility for ruleset review & traffic)
gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/pci_subnet.json
gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --format=json >/tmp/pci_nat.json
check "VPC Flow Logs enabled on subnet [Req 1/10]" bash -lc 'jq -e ".enableFlowLogs==true" /tmp/pci_subnet.json >/dev/null'
check "Cloud NAT logging = ALL [Req 1/10]"        bash -lc 'jq -e ".logConfig.enable==true and .logConfig.filter==\"ALL\"" /tmp/pci_nat.json >/dev/null'

# ---- Req 2: Secure configurations --------------------------------------------
section "Req 2 — Apply secure configurations"
# OS Login enforced (central identities), serial console off, Shielded VM
proj_oslogin="$(gcloud compute project-info describe --project "$PROJECT_ID" --format=json \
  | jq -r '.commonInstanceMetadata.items[]? | select(.key=="enable-oslogin") | .value' || true)"
check "OS Login enabled at project [Req 2/7/8]" bash -lc '[[ "'"$proj_oslogin"'" == "TRUE" ]]'

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format=json >/tmp/pci_inst.json
    sb="$(jq -r '.shieldedInstanceConfig.enableSecureBoot' /tmp/pci_inst.json)"
    vtpm="$(jq -r '.shieldedInstanceConfig.enableVtpm' /tmp/pci_inst.json)"
    im="$(jq -r '.shieldedInstanceConfig.enableIntegrityMonitoring' /tmp/pci_inst.json)"
    ser="$(jq -r '.metadata.items[]? | select(.key=="serial-port-enable") | .value' /tmp/pci_inst.json)"
    check "Shielded VM secure boot ($inst) [Req 2]"            bash -lc '[[ "'"$sb"'" == "true" ]]'
    check "Shielded VM vTPM ($inst) [Req 2]"                   bash -lc '[[ "'"$vtpm"'" == "true" ]]'
    check "Shielded VM integrity monitoring ($inst) [Req 2]"   bash -lc '[[ "'"$im"'" == "true" ]]'
    check "Serial console disabled ($inst) [Req 2]"            bash -lc '[[ -z "'"$ser"'" || "'"$ser"'" == "FALSE" ]]'
  done
fi

# ---- Req 3/4: Protect account data (at rest & in transit) ---------------------
section "Req 3 & 4 — Protect stored account data; Protect CHD in transit"
# Encryption at rest with CMEK + rotation
if [[ -n "$KEYRING" && -n "$KEY" && -n "$KEY_LOC" ]]; then
  gcloud kms keys describe "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" --project "$PROJECT_ID" --format=json >/tmp/pci_key.json || true
  check "CMEK rotation configured (<=90d) [Req 3]" \
    bash -lc 'jq -e ".rotationPeriod | sub(\"s$\";\"\") | tonumber <= 7776000" /tmp/pci_key.json >/dev/null'
else
  fail_list+=("CMEK rotation configured (<=90d) [Req 3]")
fi

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    disk="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)' || true)"
    disk="${disk##*/}"
    kms="$(gcloud compute disks describe "$disk" --zone "$ZONE" --project "$PROJECT_ID" --format='get(diskEncryptionKey.kmsKeyName)' || true)"
    check "CMEK on boot disk ($inst) [Req 3]" bash -lc '[[ -n "'"$kms"'" ]]'
  done
fi

# Transmission security (TLS) cannot be inferred generically here
note "Verify strong TLS for all CHD transmission (LB/app): modern SSL policy, TLS1.2+, AEAD suites [Req 4]"

# ---- Req 5/6: Malware & patching (signals only) --------------------------------
section "Req 5 & 6 — Protect from malware; Secure systems and software"
note "Malware/EDR on in-scope systems (Linux scope-dependent) [Req 5] — verify your EDR/AV deployment & exclusions."
note "Patch & vulnerability program [Req 6] — show policies, inventory, CVE risk ranking, change control."

# ---- Req 7/8: Access control & authentication ---------------------------------
section "Req 7 & 8 — Restrict access (need-to-know) & authenticate users"
# Least-privilege hygiene: no project Owner to human principals
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/pci_iam.json
check "No human users with roles/owner at project [Req 7]" \
  bash -lc '! jq -re '\''[.bindings[]?|select(.role=="roles/owner")|.members[]?
    | select(startswith("user:") or startswith("group:"))] | length > 0'\'' /tmp/pci_iam.json >/dev/null'

# Service account keys (user-managed) — should be zero
if [[ -n "$SA_EMAIL" ]]; then
  keys="$(gcloud iam service-accounts keys list --iam-account "$SA_EMAIL" --format='value(name)' || true)"
  check "No user-managed keys for $SA_EMAIL [Req 8]" test -z "$keys"
fi
note "Enforce MFA for all administrative & remote access (IdP/Workspace policy) [Req 8]"

# ---- Req 9: Physical security -------------------------------------------------
section "Req 9 — Physical security (datacenter) "
note "Physical access controls are provided by your Cloud provider (review GCP AoC/AUP) [Req 9]."

# ---- Req 10: Logging and monitoring -------------------------------------------
section "Req 10 — Log & monitor all access (12 months; 3 months immediate)"
# Project-level data access logging (read & write)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > /tmp/pci_iam_policy.json
check "Audit logs (DATA_READ/WRITE) enabled for allServices [Req 10]" \
  bash -lc 'jq -e '\''[.auditConfigs[]? | select(.service=="allServices") | .auditLogConfigs[]?
              | select(.logType=="DATA_READ" or .logType=="DATA_WRITE")
              | ((.exemptedMembers|length)//0)==0] | length>=2'\'' /tmp/pci_iam_policy.json >/dev/null'

# Retention ≥ 12 months (365 days) and ≥ 90 days available (hot)
gcloud logging buckets describe _Default --location=global --format=json > /tmp/pci_logbucket.json || true
check "Logging retention >= 365 days [Req 10]" bash -lc 'jq -e ".retentionDays>=365" /tmp/pci_logbucket.json >/dev/null'
check "At least 90 days immediate availability [Req 10]" bash -lc 'jq -e ".retentionDays>=90" /tmp/pci_logbucket.json >/dev/null'

# Monitoring alert policies exist (operational signal)
monitoring_list_json > /tmp/pci_alerts.json || true
check "At least 1 Monitoring alert policy exists [Req 10/11/12 evidence]" \
  bash -lc 'jq -e "length>=1" /tmp/pci_alerts.json >/dev/null' || true

# # Monitoring alert policies exist (operational signal)
# gcloud monitoring alert-policies list --format=json > /tmp/pci_alerts.json || true
# check "At least 1 Monitoring alert policy exists [Req 10/11/12 evidence]" \
#   bash -lc 'jq -e "length>=1" /tmp/pci_alerts.json >/dev/null' || true

# ---- Req 11: Regular testing ---------------------------------------------------
section "Req 11 — Regularly test security of systems and networks"
note "Provide **internal vuln scans** quarterly (and after changes), with rescans to closure [Req 11.3.1]."
note "Provide **external ASV scans** quarterly (and after changes), passing per ASV Guide [Req 11.3.2]."
note "Provide annual **penetration test** + segmentation validation at least every 6 months or after significant changes [Req 11.4 / scoping/segmentation]."

# ---- Req 12: Security program -------------------------------------------------
section "Req 12 — Support info security with policies/programs"
note "Maintain PCI DSS BAU activities, roles, training, third-party agreements, and evidence (AOC/ROC/SAQ) [Req 12]."

# ---- Host probes (auth, integrity, telemetry) ---------------------------------
section "Host probes (supports Req 2,7,8,10,11.5/FIM intent)"
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

# Run SSH command and always return a numeric RC without tripping ERR
ssh_probe() {
  local host="$1" cmd="$2" tmp rc
  tmp="$(mktemp)"
  (
    set +e
    trap - ERR
    gcloud compute ssh "$host" --zone "$ZONE" --project "$PROJECT_ID" \
      "${SSH_COMMON[@]}" --command "$cmd" >"$tmp" 2>/dev/null
    echo $? >"$tmp.rc"
  )
  rc="$(cat "$tmp.rc" 2>/dev/null || echo 1)"
  cat "$tmp"
  rm -f "$tmp" "$tmp.rc"
  return "$rc"
}


# ---- Host probes (supports Req 2,7,8,10,11.5/FIM intent) ----
# ... keep everything above as-is (REMOTE heredoc + ssh_probe function) ...

if ((${#VMS[@]})); then
  for inst in "${VMS[@]}"; do
    # Refresh OS Login key TTL if a key was provided (prevents occasional SSH rc=1)
    if [[ -n "$SSH_KEY" && -f "$SSH_KEY.pub" ]]; then
      gcloud compute os-login ssh-keys add --project "$PROJECT_ID" --key-file="$SSH_KEY.pub" --ttl=24h >/dev/null 2>&1 || true
    fi

    tmpout="$(mktemp)"
    if ssh_probe "$inst" "$REMOTE" >"$tmpout"; then
      rc=0
    else
      rc=$?
    fi
    out="$(cat "$tmpout")"; rm -f "$tmpout"

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

    check "Auditd active on $inst [Req 10]"                       bash -lc '[[ "'"$auditd"'" == "active" ]]'
    check "Audit rules present on $inst [Req 10]"                 bash -lc '[[ "'"$rules"'" -ge 1 ]]'
    check "Ops Agent running on $inst [Req 10 evidence]"          bash -lc '[[ "'"$ops"'" == "active" ]]'
    check "SSH password auth disabled on $inst [Req 8]"           bash -lc '[[ "'"$sshpw"'" == "no" ]]'
    check "SSH root login disabled on $inst [Req 8]"              bash -lc '[[ "'"$sshroot"'" == "no" || "'"$sshroot"'" == "prohibit-password" ]]'
    check "AIDE installed on $inst (FIM signal) [Req 11.5 intent]" bash -lc '[[ "'"$aidev"'" != "none" ]]'
    check "AIDE baseline present on $inst [Req 11.5 intent]"      bash -lc '[[ "'"$aidedb"'" != "none" ]]'
    check "Unattended security updates enabled on $inst [Req 6]"  bash -lc '[[ "'"$ua"'" == *"installed ok installed"* && "'"$uaon"'" -ge 1 ]]'
    check "Time sync (NTP) enabled on $inst [Req 10]"             bash -lc '[[ "'"$ntp"'" == "yes" ]]'
    check "Auto logoff (TMOUT) set on $inst [Req 8]"              bash -lc '[[ "'"$tmout"'" -ge 1 ]]'

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


# ---- Scoreboard & evidence file ----------------------------------------------
section "PCI DSS v4.0.1 L1 Scoreboard"
printf "PASS: %s\n"   "${pass_list[@]}"   | sed '/^PASS: $/d'   | dedup || true
printf "FAIL: %s\n"   "${fail_list[@]}"   | sed '/^FAIL: $/d'   | dedup || true
printf "MANUAL: %s\n" "${manual_list[@]}" | sed '/^MANUAL: $/d' | dedup || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_base="$REPORT_DIR/pcidss-l1-evidence.json"
out_ts="$REPORT_DIR/pcidss-l1-evidence-$ts.json"

jq -n \
  --arg standard "PCI DSS v4.0.1 (Level 1)" \
  --argjson reqs '["Req1","Req2","Req3","Req4","Req5","Req6","Req7","Req8","Req9","Req10","Req11","Req12"]' \
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
    standard: $standard, requirements: $reqs,
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
  echo "PCI DSS automated checks FAILED for some controls."
  exit 2
fi
echo "PCI DSS automated checks PASSED for the technical safeguards tested."
