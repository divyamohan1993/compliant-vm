#!/usr/bin/env bash
# Idempotent, auditable bring-up of two compliant VMs with continuous encrypted sync.
# Re-runnable: only creates what doesn't exist; updates where needed.

set -Eeuo pipefail
shopt -s inherit_errexit

# ---- Logging / diagnostics ----------------------------------------------------
export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()      { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section()  { echo; echo "==== $* ===="; }
on_err()   { local rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc; }
trap on_err ERR

# Toggle very verbose tracing via VERBOSE=1 ./autoconfig.sh
if [[ "${VERBOSE:-0}" == "1" ]]; then set -x; fi

# ---- Config -------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-unified-icon-469918-s7}"
REGION="${REGION:-asia-south1}"
ZONE="${ZONE:-asia-south1-a}"

NETWORK="${NETWORK:-vm-privacy-net}"
SUBNET="${SUBNET:-vm-privacy-subnet}"
SUBNET_RANGE="${SUBNET_RANGE:-10.20.0.0/24}"

KEYRING="${KEYRING:-vm-xfer-kr}"
KEY="${KEY:-vm-xfer-key}"
KEY_LOC="${KEY_LOC:-asia-south1}"

SA_NAME="${SA_NAME:-vm-transfer-sa}"
SA_EMAIL="${SA_EMAIL:-${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com}"

VM1="${VM1:-vm-a}"
VM2="${VM2:-vm-b}"
MACHINE="${MACHINE:-e2-standard-2}"
IMG_FAMILY="${IMG_FAMILY:-ubuntu-2204-lts}"
IMG_PROJECT="${IMG_PROJECT:-ubuntu-os-cloud}"

# ---- Helpers ------------------------------------------------------------------
retry() { # retry <tries> <sleep> -- <cmd...>
  local tries=$1; shift
  local sleep_s=$1; shift
  local i
  for ((i=1;i<=tries;i++)); do
    if "$@"; then return 0; fi
    log "retry $i/${tries} failed for: $*"
    sleep "${sleep_s}"
  done
  "$@"
}

exists_network()  { gcloud compute networks describe "$NETWORK" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_subnet()   { gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_fw()       { gcloud compute firewall-rules describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_keyring()  { gcloud kms keyrings describe "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_key()      { gcloud kms keys describe "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_sa()       { gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_vm()       { gcloud compute instances describe "$1" --zone "$ZONE" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_router() { gcloud compute routers describe "$ROUTER" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_nat()    { gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }


enable_api() {
  local svc="$1"
  if ! gcloud services list --enabled --project "$PROJECT_ID" --format="value(config.name)" | grep -qx "$svc"; then
    gcloud services enable "$svc" --project "$PROJECT_ID"
  fi
}

iam_bind_if_missing() { # iam_bind_if_missing <member> <role> (project)
  local member="$1" role="$2"
  local policy tmp
  tmp="$(mktemp)"
  gcloud projects get-iam-policy "$PROJECT_ID" --format=json > "$tmp"
  if ! jq -e --arg m "$member" --arg r "$role" '.bindings[]? | select(.role==$r) | .members[]? | select(.==$m)' "$tmp" >/dev/null; then
    gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="$member" --role="$role" >/dev/null
  fi
  rm -f "$tmp"
}

# ---- 0) Enable required APIs ---------------------------------------------------
section "0) Enabling APIs (idempotent)"
for svc in compute.googleapis.com iam.googleapis.com cloudkms.googleapis.com \
           oslogin.googleapis.com osconfig.googleapis.com iap.googleapis.com \
           logging.googleapis.com monitoring.googleapis.com; do
  enable_api "$svc"
done

# ---- 1) Network / Subnet / Firewalls ------------------------------------------
section "1) Network & Firewall (no public exposure + IAP SSH)"
if ! exists_network; then
  gcloud compute networks create "$NETWORK" --project "$PROJECT_ID" --subnet-mode=custom
else
  log "Network $NETWORK exists - skipping"
fi

if ! exists_subnet; then
  gcloud compute networks subnets create "$SUBNET" \
    --project "$PROJECT_ID" --network "$NETWORK" --region "$REGION" \
    --range "$SUBNET_RANGE" --enable-private-ip-google-access --enable-flow-logs
else
  # ensure flow logs stay enabled (safe to re-run)
  gcloud compute networks subnets update "$SUBNET" --project "$PROJECT_ID" --region "$REGION" --enable-flow-logs
  log "Subnet $SUBNET exists - ensured flow logs on"
fi

if ! exists_fw "allow-iap-ssh"; then
  gcloud compute firewall-rules create allow-iap-ssh \
    --project "$PROJECT_ID" --network "$NETWORK" \
    --allow tcp:22 --source-ranges=35.235.240.0/20 --direction=INGRESS \
    --description="Allow SSH from IAP only"
else
  log "Firewall allow-iap-ssh exists - skipping"
fi

if ! exists_fw "allow-internal"; then
  gcloud compute firewall-rules create allow-internal \
    --project "$PROJECT_ID" --network "$NETWORK" \
    --allow tcp,udp,icmp --source-ranges="$SUBNET_RANGE" --direction=INGRESS \
    --description="Allow internal traffic within subnet"
else
  log "Firewall allow-internal exists - skipping"
fi

# ---- 1b) Cloud Router + Cloud NAT for egress (apt/security updates) ----
ROUTER="${NETWORK}-router"
NAT="${NETWORK}-nat"

if ! exists_router; then
  gcloud compute routers create "$ROUTER" \
    --network "$NETWORK" --region "$REGION" --project "$PROJECT_ID"
else
  log "Router $ROUTER exists - skipping"
fi

if ! exists_nat; then
  gcloud compute routers nats create "$NAT" \
    --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" \
    --nat-all-subnet-ip-ranges \
    --auto-allocate-nat-external-ips \
    --enable-logging --log-filter=ALL
else
  # ensure logging stays enabled for auditability
  gcloud compute routers nats update "$NAT" \
    --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" \
    --enable-logging --log-filter=ALL
  log "NAT $NAT exists - ensured logging"
fi

# ---- 1c) Enforce OS Login on project + (only if VM already exists) ----
ACCOUNT="$(gcloud config get-value account)"

# Roles required for OS Login over IAP (idempotent)
iam_bind_if_missing "user:${ACCOUNT}" "roles/compute.osAdminLogin"
iam_bind_if_missing "user:${ACCOUNT}" "roles/iap.tunnelResourceAccessor"
iam_bind_if_missing "user:${ACCOUNT}" "roles/compute.viewer"

# Project-wide OS Login (safe & idempotent)
gcloud compute project-info add-metadata --project "$PROJECT_ID" \
  --metadata enable-oslogin=TRUE

# Only touch instance metadata if the VM already exists (skip otherwise)
for inst in "$VM1" "$VM2"; do
  if exists_vm "$inst"; then
    gcloud compute instances add-metadata "$inst" \
      --zone "$ZONE" --project "$PROJECT_ID" \
      --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE
  else
    log "Instance $inst not found yet; OS Login will be set at create time"
  fi
done

# Create (if needed) and register a dedicated OS Login key (24h TTL)
SSH_KEY="${SSH_KEY:-$HOME/.ssh/gce_oslogin}"
if [[ ! -f "$SSH_KEY.pub" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "$ACCOUNT"
fi
# Always refresh TTL so subsequent SSH in this run never expires
gcloud compute os-login ssh-keys add --project "$PROJECT_ID" \
  --key-file="$SSH_KEY.pub" --ttl=24h || true

# Resolve OS Login Linux username and pin it for SSH
OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
  --format='value(posixAccounts[?primary=true].username)')"
if [[ -z "$OS_LOGIN_USER" ]]; then
  OS_LOGIN_USER="$(gcloud compute os-login describe-profile --project "$PROJECT_ID" \
    --format='value(posixAccounts[0].username)')"
fi

# Use IAP + pinned key + correct Linux user for all SSH calls in this script
SSH_COMMON=(--tunnel-through-iap --ssh-key-file="$SSH_KEY" --ssh-flag="-l ${OS_LOGIN_USER}")

sleep 5

# ---- 2) KMS (CMEK) -------------------------------------------------------------
section "2) KMS (CMEK) with rotation schedule"
if ! exists_keyring; then
  gcloud kms keyrings create "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID"
else
  log "Keyring $KEYRING exists - skipping"
fi

NEXT_ROTATION="$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ || date -u -v+30d +%Y-%m-%dT%H:%M:%SZ)"
if ! exists_key; then
  gcloud kms keys create "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" \
    --purpose=encryption --default-algorithm="google-symmetric-encryption" \
    --rotation-period="30d" --next-rotation-time="$NEXT_ROTATION" --project "$PROJECT_ID"
else
  # ensure rotation is configured (safe update)
  gcloud kms keys update "$KEY" --location "$KEY_LOC" --keyring "$KEYRING" \
    --rotation-period="30d" --next-rotation-time="$NEXT_ROTATION" --project "$PROJECT_ID" || true
  log "Key $KEY exists - rotation ensured"
fi

BOOT_KMS="projects/${PROJECT_ID}/locations/${KEY_LOC}/keyRings/${KEYRING}/cryptoKeys/${KEY}"

# ---- 3) Service Account + IAM (with eventual-consistency retry) ---------------
section "3) Service Account & IAM"
if ! exists_sa; then
  gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT_ID"
  # wait until SA actually visible
  retry 10 2 exists_sa
else
  log "Service account $SA_EMAIL exists - skipping create"
fi

# Bind minimal roles (idempotent)
iam_bind_if_missing "serviceAccount:${SA_EMAIL}" "roles/logging.logWriter"
iam_bind_if_missing "serviceAccount:${SA_EMAIL}" "roles/monitoring.metricWriter"

# Allow SA to use the CMEK
if ! gcloud kms keys get-iam-policy "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" \
  --format=json | jq -e --arg m "serviceAccount:${SA_EMAIL}" '.bindings[]? | select(.role=="roles/cloudkms.cryptoKeyEncrypterDecrypter") | .members[]? | select(.==$m)' >/dev/null; then
  gcloud kms keys add-iam-policy-binding "$KEY" \
    --location "$KEY_LOC" --keyring "$KEYRING" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" --project "$PROJECT_ID"
else
  log "CMEK binding exists for $SA_EMAIL - skipping"
fi

# Also allow the Compute Engine **Service Agent** to use the CMEK (required for boot-disk CMEK).
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
CE_AGENT="service-${PROJECT_NUMBER}@compute-system.iam.gserviceaccount.com"

if ! gcloud kms keys get-iam-policy "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" \
  --format=json | jq -e --arg m "serviceAccount:${CE_AGENT}" \
  '.bindings[]? | select(.role=="roles/cloudkms.cryptoKeyEncrypterDecrypter") | .members[]? | select(.==$m)' >/dev/null; then
  gcloud kms keys add-iam-policy-binding "$KEY" \
    --location "$KEY_LOC" --keyring "$KEYRING" \
    --member="serviceAccount:${CE_AGENT}" \
    --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
    --project "$PROJECT_ID"
else
  log "CMEK binding exists for Compute Engine service agent - skipping"
fi

# ---- 4) Shielded VMs (no public IPs) ------------------------------------------
section "4) Compute instances"
COMMON_FLAGS=(--project "$PROJECT_ID" --zone "$ZONE" --no-address \
  --machine-type "$MACHINE" --network "$NETWORK" --subnet "$SUBNET" \
  --service-account "$SA_EMAIL" --scopes "https://www.googleapis.com/auth/cloud-platform" \
  --image-family "$IMG_FAMILY" --image-project "$IMG_PROJECT" \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE,serial-port-enable=FALSE \
  --boot-disk-kms-key "$BOOT_KMS" --boot-disk-size "20GB" \
  --tags "sync")


if ! exists_vm "$VM1"; then
  gcloud compute instances create "$VM1" "${COMMON_FLAGS[@]}"
else
  log "VM $VM1 exists - skipping"
fi
if ! exists_vm "$VM2"; then
  gcloud compute instances create "$VM2" "${COMMON_FLAGS[@]}"
else
  log "VM $VM2 exists - skipping"
fi

IP1="$(gcloud compute instances describe "$VM1" --zone "$ZONE" --format='get(networkInterfaces[0].networkIP)' --project "$PROJECT_ID")"
IP2="$(gcloud compute instances describe "$VM2" --zone "$ZONE" --format='get(networkInterfaces[0].networkIP)' --project "$PROJECT_ID")"
log "$VM1 @ $IP1"
log "$VM2 @ $IP2"

# Enforce OS Login + block project keys on instances now that they exist
# (covers first-run create and any older instances missing these bits)
for inst in "$VM1" "$VM2"; do
  gcloud compute instances add-metadata "$inst" --zone "$ZONE" --project "$PROJECT_ID" \
    --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE || true
done

# Refresh OS Login key TTL again right before SSH phases (belt-and-suspenders)
gcloud compute os-login ssh-keys add --project "$PROJECT_ID" \
  --key-file="$SSH_KEY.pub" --ttl=24h || true


# ---- 5) Bootstrap packages / audit on both VMs --------------------------------
section "5) Bootstrap auditd + Ops Agent + rsync + inotify"
read -r -d '' REMOTE_BOOTSTRAP <<'EOF' || true
set -Eeuo pipefail

# Non-interactive apt to avoid debconf prompts
export DEBIAN_FRONTEND=noninteractive

# Make apt resilient + IPv4-only (avoids IPv6 reachability issues)
sudo mkdir -p /etc/apt/apt.conf.d
echo 'Acquire::ForceIPv4 "true"; Acquire::Retries "5";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 >/dev/null

# Update with retries
for i in {1..5}; do
  if sudo apt-get update -y; then break; fi
  sleep 5
done

# Add Ops Agent repo (idempotent, correct key source) + resilient fallback
sudo install -d -m 0755 /usr/share/keyrings
# Correct URL and non-interactive dearmor
curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
  | sudo gpg --dearmor --yes --batch -o /usr/share/keyrings/google-cloud-ops-agent.gpg || true

echo "deb [signed-by=/usr/share/keyrings/google-cloud-ops-agent.gpg] https://packages.cloud.google.com/apt google-cloud-ops-agent-jammy-all main" \
  | sudo tee /etc/apt/sources.list.d/google-cloud-ops-agent.list >/dev/null

# Update with retries; if signature error persists, fall back to vendor script
sig_ok=0
for i in {1..3}; do
  if sudo apt-get update -y 2>&1 | tee /tmp/apt_update.log; then
    if ! grep -q 'NO_PUBKEY' /tmp/apt_update.log; then
      sig_ok=1; break
    fi
  fi
  # fallback registers repo/key the "old" way (still supported by Google)
  curl -sS https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh | sudo bash || true
  sleep 3
done

# Install packages (retry-once pattern)
if ! sudo apt-get install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      google-cloud-ops-agent auditd inotify-tools rsync; then
  sudo apt-get update -y || true
  sudo apt-get install -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      google-cloud-ops-agent auditd inotify-tools rsync
fi

sudo systemctl enable --now auditd

# Minimal audit rules for /data
echo '-w /data -p rwa -k data_changes' | sudo tee /etc/audit/rules.d/99-data.rules >/dev/null
sudo augenrules --load

# Dedicated sync user & /data (ensure group exists, then user uses that group)
if ! getent group sync >/dev/null 2>&1; then
  sudo groupadd --system sync
fi
if ! id -u sync >/dev/null 2>&1; then
  sudo useradd -m -g sync -s /usr/sbin/nologin sync
fi

## Ensure canonical home for sync (fix prior bad states like /bin)
HOME_DIR="$(getent passwd sync | cut -d: -f6 || true)"
if [[ "$HOME_DIR" != "/home/sync" ]]; then
  if [[ "$HOME_DIR" == /home/* ]]; then
    # Safe to move if old home was under /home
    sudo usermod -d /home/sync -m sync
  else
    # Don't try to move system dirs like /bin; just set + prepare the new home
    sudo mkdir -p /home/sync
    sudo chown sync:sync /home/sync
    sudo usermod -d /home/sync sync
  fi
fi

# Ensure .ssh exists with correct ownership
sudo install -d -m 700 -o sync -g sync /home/sync/.ssh

sudo mkdir -p /data
sudo chown -R sync:sync /data

# Ops Agent: ingest auditd
sudo tee /etc/google-cloud-ops-agent/config.yaml >/dev/null <<'YAML'
logging:
  receivers:
    auditd:
      type: files
      include_paths: [/var/log/audit/audit.log]
  service:
    pipelines:
      default_pipeline:
        receivers: [auditd]
YAML

sudo systemctl restart google-cloud-ops-agent
EOF


gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "$REMOTE_BOOTSTRAP"
gcloud compute ssh "$VM2" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "$REMOTE_BOOTSTRAP"

# ---- 6) SSH trust (keypair + host key pinning) --------------------------------
section "6) SSH trust for sync user with host key pinning"

# Generate key on VM1 if missing
gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command \
  "sudo -u sync bash -lc 'H=/home/sync; test -f \$H/.ssh/id_ed25519 || (install -d -m 700 -o sync -g sync \$H/.ssh && ssh-keygen -t ed25519 -N \"\" -f \$H/.ssh/id_ed25519)'"
 
PUBKEY="$(gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "sudo -u sync bash -lc 'cat /home/sync/.ssh/id_ed25519.pub'")"

# Create known_hosts on VM1 for IP2 (host key pin)
HOSTKEY="$(gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command "ssh-keyscan -t ed25519 $IP2" 2>/dev/null || true)"
if [[ -n "$HOSTKEY" ]]; then
  gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command \
    "sudo -u sync bash -lc 'H=/home/sync; install -d -m 700 -o sync -g sync \$H/.ssh; grep -q \"${IP2}\" \$H/.ssh/known_hosts 2>/dev/null || echo \"$HOSTKEY\" >> \$H/.ssh/known_hosts; chmod 600 \$H/.ssh/known_hosts'"
fi

# Push authorized key to VM2 for sync user (restrict source by IP1)
gcloud compute ssh "$VM2" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command \
  "sudo -u sync bash -lc 'H=/home/sync; install -d -m 700 -o sync -g sync \$H/.ssh; grep -q \"${PUBKEY}\" \$H/.ssh/authorized_keys 2>/dev/null || echo \"from=${IP1} ${PUBKEY}\" >> \$H/.ssh/authorized_keys; chmod 600 \$H/.ssh/authorized_keys'"

# ---- 7) Continuous rsync service (idempotent) ---------------------------------
section "7) Continuous encrypted sync service (VM1 -> VM2)"
read -r -d '' SYNC_SCRIPT <<EOF || true
#!/usr/bin/env bash
set -Eeuo pipefail
DEST_USER="sync"
DEST_HOST="${IP2}"
SRC_DIR="/data/"
DEST_DIR="/data/"
SSH_OPTS="-o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -i /home/sync/.ssh/id_ed25519"
rsync -az --delete -e "ssh \$SSH_OPTS" "\$SRC_DIR" "\${DEST_USER}@\${DEST_HOST}:\${DEST_DIR}"
inotifywait -m -r -e modify,create,delete,move "\$SRC_DIR" | while read -r _; do
  rsync -az --delete -e "ssh \$SSH_OPTS" "\$SRC_DIR" "\${DEST_USER}@\${DEST_HOST}:\${DEST_DIR}"
done
EOF

read -r -d '' SYNC_SERVICE <<'EOF' || true
[Unit]
Description=Continuous encrypted sync of /data to peer
After=network-online.target
Wants=network-online.target

[Service]
User=sync
Group=sync
ExecStart=/usr/local/bin/continuous-sync.sh
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

# Install/update script + service atomically
gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command \
  "echo '${SYNC_SCRIPT}' | sudo tee /usr/local/bin/continuous-sync.sh >/dev/null && sudo chmod 755 /usr/local/bin/continuous-sync.sh"

# Only (re)write unit if missing or content differs
gcloud compute ssh "$VM1" --zone "$ZONE" --project "$PROJECT_ID" "${SSH_COMMON[@]}" --command \
  "sudo bash -lc 'UNIT=/etc/systemd/system/continuous-sync.service; TMP=\$(mktemp); echo \"${SYNC_SERVICE}\" > \$TMP; if ! cmp -s \$TMP \$UNIT; then sudo cp \$TMP \$UNIT; fi; sudo systemctl daemon-reload; sudo systemctl enable --now continuous-sync; systemctl is-active continuous-sync; sudo journalctl -u continuous-sync -n 20 --no-pager'"

# ---- 8) Summary / Verification hints ------------------------------------------
section "8) Summary & verification"
cat <<OUT
VMs:
 - ${VM1} @ ${IP1}
 - ${VM2} @ ${IP2}

Run these to verify controls:
  gcloud compute instances describe ${VM1} --zone ${ZONE} | grep -A5 shieldedInstanceConfig
  gcloud compute disks describe ${VM1} --zone ${ZONE} | grep kmsKeyName
  gcloud kms keys describe ${KEY} --keyring ${KEYRING} --location ${KEY_LOC} | egrep 'rotation|nextRotationTime'
  gcloud compute instances list --project ${PROJECT_ID} --filter="name~'${VM1}|${VM2}'" --format="table(name,networkInterfaces[].accessConfigs)"
  gcloud compute firewall-rules list --project ${PROJECT_ID} --filter="name=allow-iap-ssh OR name=allow-internal"
  gcloud compute routers describe ${NETWORK}-router --region ${REGION} --project ${PROJECT_ID} | sed -n '1,80p'
  gcloud compute routers nats describe ${NETWORK}-nat --router ${NETWORK}-router --region ${REGION} --project ${PROJECT_ID} | sed -n '1,80p'

  # On VM1:
  #   sudo systemctl status continuous-sync
  #   logger -p authpriv.info "audit-test"; sudo tail -n 50 /var/log/audit/audit.log

Compliance notes (manual + policy):
 - Accept GDPR DP Addendum + HIPAA BAA (if applicable) in IAM & Admin > Legal & Compliance.
 - Store CIS/OpenSCAP reports and SCC findings export as audit evidence.
OUT

# ---------------------- Compliance Checker Callers -------------------------
COMPLIANCE_DIR="${COMPLIANCE_DIR:-./compliance}"
mkdir -p "$COMPLIANCE_DIR"
mkdir -p ./compliance-reports

section "Enable APIs needed for compliance ops (idempotent)"
enable_api logging.googleapis.com
enable_api cloudkms.googleapis.com
enable_api iam.googleapis.com

section "Pre-HIPAA: ensure OS Login + IAP SSH prerequisites"

ACCOUNT="$(gcloud config get-value account)"
# Grant minimal roles (idempotent)
iam_bind_if_missing "user:${ACCOUNT}" "roles/compute.osAdminLogin"
iam_bind_if_missing "user:${ACCOUNT}" "roles/iap.tunnelResourceAccessor"
iam_bind_if_missing "user:${ACCOUNT}" "roles/compute.viewer"

# Project-wide OS Login
gcloud compute project-info add-metadata --project "$PROJECT_ID" \
  --metadata enable-oslogin=TRUE

# Instance metadata (if VMs exist)
for inst in "$VM1" "$VM2"; do
  if exists_vm "$inst"; then
    gcloud compute instances add-metadata "$inst" --zone "$ZONE" --project "$PROJECT_ID" \
      --metadata enable-oslogin=TRUE,block-project-ssh-keys=TRUE,serial-port-enable=FALSE || true
  fi
done

# Add a fresh OS Login SSH key (24h TTL) and export for hipaa.sh to use
SSH_KEY="${SSH_KEY:-$HOME/.ssh/gce_oslogin}"
if [[ ! -f "$SSH_KEY.pub" ]]; then
  ssh-keygen -t ed25519 -N "" -f "$SSH_KEY" -C "$ACCOUNT"
fi
gcloud compute os-login ssh-keys add --project "$PROJECT_ID" --key-file="$SSH_KEY.pub" --ttl=24h || true
export SSH_KEY


section "Pre-HIPAA hardening: audit logs + retention+lock + Logging CMEK"
# 1) Data Access logs (READ/WRITE) on allServices
POL=$(mktemp); NEW=$(mktemp)
gcloud projects get-iam-policy "$PROJECT_ID" --format=json > "$POL"
jq '(.auditConfigs //= []) as $ac
  | ($ac | map(select(.service!="allServices"))) as $others
  | ($ac | map(select(.service=="allServices") | .auditLogConfigs[]?)) as $existing
  | .auditConfigs = ($others + [
      { service:"allServices",
        auditLogConfigs: ( ($existing + [{logType:"DATA_READ"},{logType:"DATA_WRITE"}]) | unique_by(.logType) )
      }
    ])' "$POL" > "$NEW"
gcloud projects set-iam-policy "$PROJECT_ID" "$NEW" >/dev/null

# 2) Logging bucket retention & lock (lock is irreversible)
gcloud logging buckets update _Default --location=global --retention-days=2190 || true
gcloud logging buckets update _Default --location=global --locked || true

# 3) Logging CMEK
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
LOG_SA="service-${PROJECT_NUMBER}@gcp-sa-logging.iam.gserviceaccount.com"
gcloud kms keys add-iam-policy-binding "$KEY" \
  --keyring "$KEYRING" --location "$KEY_LOC" \
  --member "serviceAccount:${LOG_SA}" \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter || true
gcloud logging cmek-settings update --project="$PROJECT_ID" \
  --kms-key-name "projects/${PROJECT_ID}/locations/${KEY_LOC}/keyRings/${KEYRING}/cryptoKeys/${KEY}" || true

section "Pre-HIPAA: remove USER_MANAGED keys from SA (idempotent)"
UM_KEYS=$(gcloud iam service-accounts keys list \
  --iam-account "$SA_EMAIL" \
  --format='value(name, keyType)' | awk '$2=="USER_MANAGED"{print $1}')
for k in $UM_KEYS; do
  gcloud iam service-accounts keys delete "$k" --iam-account "$SA_EMAIL" -q || true
done

run_checker() { # run_checker "NAME" <cmd ...>
  local name="$1"; shift
  if ! "$@"; then
    rc=$?
    log "Non-fatal: $name exited with rc=$rc"
  fi
}

section "Pre-HIPAA: ensure snapshot schedule attached to VM boot disks"
POLICY="daily-snapshots-7d"
if ! gcloud compute resource-policies describe "$POLICY" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud compute resource-policies create snapshot-schedule "$POLICY" \
    --region "$REGION" \
    --max-retention-days=7 \
    --daily-schedule \
    --start-time=01:30 \
    --on-source-disk-delete=apply-retention-policy \
    --project "$PROJECT_ID"
fi
for inst in "$VM1" "$VM2"; do
  if exists_vm "$inst"; then
    DISK="$(gcloud compute instances describe "$inst" --zone "$ZONE" --project "$PROJECT_ID" --format='get(disks[0].source)')"
    DISK="${DISK##*/}"
    HAVE="$(gcloud compute disks describe "$DISK" --zone "$ZONE" --project "$PROJECT_ID" --format='get(resourcePolicies)')"
    if [[ -z "$HAVE" || "$HAVE" != *"$POLICY"* ]]; then
      gcloud compute disks add-resource-policies "$DISK" \
        --zone "$ZONE" --resource-policies "$POLICY" --project "$PROJECT_ID" || true
    fi
  fi
done



# ---- HIPAA checker fetch & run -------------------------------------------------
section "Fetch & run HIPAA checker (modular)"

# Pin to a specific version/branch/commit if you like:
HIPAA_URL="${HIPAA_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/hipaa/hipaa.sh}"

# Always re-download latest unless pinned via HIPAA_PIN=1
if [[ "${HIPAA_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/hipaa.sh" "$HIPAA_URL" 
  chmod +x "$COMPLIANCE_DIR/hipaa.sh"
else
  [[ -x "$COMPLIANCE_DIR/hipaa.sh" ]] || { echo "Pinned hipaa.sh missing/executable bit"; exit 1; }
fi

# Run read-only compliance (safe to call every autoconfig.sh run)
run_checker "HIPAA" "$COMPLIANCE_DIR/hipaa.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"


# If you want the autoconfig to fail pipeline on HIPAA fails, just forward exit code.

# ---- GDPR checker fetch & run --------------------------------------------------
section "Fetch & run GDPR checker (modular)"

GDPR_URL="${GDPR_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/gdpr/gdpr.sh}"

if [[ "${GDPR_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/gdpr.sh" "$GDPR_URL"
  chmod +x "$COMPLIANCE_DIR/gdpr.sh"
else
  [[ -x "$COMPLIANCE_DIR/gdpr.sh" ]] || { echo "Pinned gdpr.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/gdpr.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- DPDPR checker fetch & run -------------------------------------------------
section "Fetch & run DPDPR checker (modular)"

DPDPR_URL="${DPDPR_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/dpdpr/dpdpr.sh}"

# Always refresh unless pinned
if [[ "${DPDPR_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/dpdpr.sh" "$DPDPR_URL"
  chmod +x "$COMPLIANCE_DIR/dpdpr.sh"
else
  [[ -x "$COMPLIANCE_DIR/dpdpr.sh" ]] || { echo "Pinned dpdpr.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/dpdpr.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- PCI DSS L1 checker fetch & run -------------------------------------------
section "Fetch & run PCI DSS v4.0.1 Level 1 checker (modular)"

PCIDSS_URL="${PCIDSS_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/pcidss-l1/pcidss-l1.sh}"

# Always refresh unless pinned for reproducibility
if [[ "${PCIDSS_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/pcidss-l1.sh" "$PCIDSS_URL"
  chmod +x "$COMPLIANCE_DIR/pcidss-l1.sh"
else
  [[ -x "$COMPLIANCE_DIR/pcidss-l1.sh" ]] || { echo "Pinned pcidss-l1.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/pcidss-l1.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- SOX ICFR checker fetch & run ---------------------------------------------
section "Fetch & run SOX §404 ICFR (ITGC) checker (modular)"

SOX_URL="${SOX_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/sox/sox.sh}"

if [[ "${SOX_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/sox.sh" "$SOX_URL"
  chmod +x "$COMPLIANCE_DIR/sox.sh"
else
  [[ -x "$COMPLIANCE_DIR/sox.sh" ]] || { echo "Pinned sox.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/sox.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- GLBA / FTC Safeguards Rule checker fetch & run ---------------------------
section "Fetch & run GLBA (FTC Safeguards Rule) checker (modular)"

GLBA_URL="${GLBA_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/glba/glba.sh}"

# Always refresh unless pinned
if [[ "${GLBA_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/glba.sh" "$GLBA_URL"
  chmod +x "$COMPLIANCE_DIR/glba.sh"
else
  [[ -x "$COMPLIANCE_DIR/glba.sh" ]] || { echo "Pinned glba.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/glba.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- SOC 2 checker fetch & run -------------------------------------------------
section "Fetch & run SOC 2 checker (modular)"

SOC2_URL="${SOC2_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/soc2/soc2.sh}"

if [[ "${SOC2_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/soc2.sh" "$SOC2_URL"
  chmod +x "$COMPLIANCE_DIR/soc2.sh"
else
  [[ -x "$COMPLIANCE_DIR/soc2.sh" ]] || { echo "Pinned soc2.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/soc2.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- ISO/IEC 27001:2022 checker fetch & run -----------------------------------
section "Fetch & run ISO/IEC 27001:2022 checker (modular)"

ISO27001_URL="${ISO27001_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/iso27001/iso27001.sh}"

if [[ "${ISO27001_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/iso27001.sh" "$ISO27001_URL"
  chmod +x "$COMPLIANCE_DIR/iso27001.sh"
else
  [[ -x "$COMPLIANCE_DIR/iso27001.sh" ]] || { echo "Pinned iso27001.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/iso27001.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- ISO/IEC 27017 checker fetch & run ----------------------------------------
section "Fetch & run ISO/IEC 27017 checker (modular)"

ISO27017_URL="${ISO27017_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/iso27017/iso27017.sh}"

if [[ "${ISO27017_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/iso27017.sh" "$ISO27017_URL"
  chmod +x "$COMPLIANCE_DIR/iso27017.sh"
else
  [[ -x "$COMPLIANCE_DIR/iso27017.sh" ]] || { echo "Pinned iso27017.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/iso27017.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --subnet-range "$SUBNET_RANGE" \
  --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- NIST SP 800-53 Rev. 5 checker fetch & run --------------------------------
section "Fetch & run NIST SP 800-53 Rev.5 checker (modular)"

NIST80053_URL="${NIST80053_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/nist80053/nist80053.sh}"

if [[ "${NIST80053_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/nist80053.sh" "$NIST80053_URL"
  chmod +x "$COMPLIANCE_DIR/nist80053.sh"
else
  [[ -x "$COMPLIANCE_DIR/nist80053.sh" ]] || { echo "Pinned nist80053.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/nist80053.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- NIST CSF 2.0 checker fetch & run -----------------------------------------
section "Fetch & run NIST CSF 2.0 checker (modular)"

NIST_CSF_URL="${NIST_CSF_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/nistcsf/nistcsf.sh}"

if [[ "${NIST_CSF_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/nistcsf.sh" "$NIST_CSF_URL"
  chmod +x "$COMPLIANCE_DIR/nistcsf.sh"
else
  [[ -x "$COMPLIANCE_DIR/nistcsf.sh" ]] || { echo "Pinned nistcsf.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/nistcsf.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports"

# ---- BSA/AML checker fetch & run ----------------------------------------------
section "Fetch & run BSA/AML checker (modular)"

BSA_URL="${BSA_URL:-https://raw.githubusercontent.com/divyamohan1993/compliant-vm/refs/heads/main/static/compliance/bsa/bsa.sh}"

if [[ "${BSA_PIN:-0}" == "0" ]]; then
  wget -qO "$COMPLIANCE_DIR/bsa.sh" "$BSA_URL"
  chmod +x "$COMPLIANCE_DIR/bsa.sh"
else
  [[ -x "$COMPLIANCE_DIR/bsa.sh" ]] || { echo "Pinned bsa.sh missing/executable bit"; exit 1; }
fi

"$COMPLIANCE_DIR/bsa.sh" \
  --project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" \
  --network "$NETWORK" --subnet "$SUBNET" --router "${NETWORK}-router" --nat "${NETWORK}-nat" \
  --keyring "$KEYRING" --key "$KEY" --key-loc "$KEY_LOC" \
  --sa-email "$SA_EMAIL" \
  --vm "$VM1" --vm "$VM2" \
  --report-dir "./compliance-reports" \
  --min-bsa-retention-days 1825 \
  --require-cmek-on-sinks 1
