#!/usr/bin/env bash
set -euo pipefail

### === CONFIG ===
PROJECT_ID="unified-icon-469918-s7"
BILLING_NOTE="Set legal toggles for GDPR/CDPA & HIPAA BAA in IAM&Admin > Legal & Compliance (manual step)."
REGION="asia-south1"
ZONE="asia-south1-a"
NETWORK="vm-privacy-net"
SUBNET="vm-privacy-subnet"
SUBNET_RANGE="10.20.0.0/24"
KEYRING="vm-xfer-kr"
KEY="vm-xfer-key"
KEY_LOC="asia-south1"
SA_NAME="vm-transfer-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
VM1="vm-a"
VM2="vm-b"
MACHINE="e2-standard-2"
IMG_FAMILY="ubuntu-2204-lts"
IMG_PROJECT="ubuntu-os-cloud"

### === ENABLE APIS ===
gcloud services enable \
  compute.googleapis.com iam.googleapis.com cloudkms.googleapis.com \
  oslogin.googleapis.com osconfig.googleapis.com iap.googleapis.com \
  logging.googleapis.com monitoring.googleapis.com --project "${PROJECT_ID}"

### === NETWORK ===
gcloud compute networks create "${NETWORK}" --project "${PROJECT_ID}" --subnet-mode=custom
gcloud compute networks subnets create "${SUBNET}" \
  --project "${PROJECT_ID}" --network "${NETWORK}" --region "${REGION}" \
  --range "${SUBNET_RANGE}" --enable-private-ip-google-access \
  --enable-flow-logs

# IAP SSH ingress only (35.235.240.0/20). Internal east-west allowed.
gcloud compute firewall-rules create allow-iap-ssh \
  --project "${PROJECT_ID}" --network "${NETWORK}" \
  --allow tcp:22 --source-ranges=35.235.240.0/20 --direction=INGRESS \
  --description="Allow SSH from IAP only"
gcloud compute firewall-rules create allow-internal \
  --project "${PROJECT_ID}" --network "${NETWORK}" \
  --allow tcp,udp,icmp --source-ranges="${SUBNET_RANGE}" --direction=INGRESS \
  --description="Allow internal traffic within subnet"

### === KMS (CMEK) ===
gcloud kms keyrings create "${KEYRING}" --location "${KEY_LOC}" --project "${PROJECT_ID}" || true
gcloud kms keys create "${KEY}" --location "${KEY_LOC}" --keyring "${KEYRING}" \
  --purpose=encryption --default-algorithm="google-symmetric-encryption" \
  --rotation-period="30d" --project "${PROJECT_ID}" || true

# SA for VMs (least privilege for logging/metrics + decrypt/encrypt with the key)
gcloud iam service-accounts create "${SA_NAME}" --project "${PROJECT_ID}" || true
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/logging.logWriter"
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/monitoring.metricWriter"
gcloud kms keys add-iam-policy-binding "${KEY}" \
  --location "${KEY_LOC}" --keyring "${KEYRING}" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" --project "${PROJECT_ID}"

### === CREATE SHIELDED VMs (NO PUBLIC IP, CMEK) ===
BOOT_KMS="projects/${PROJECT_ID}/locations/${KEY_LOC}/keyRings/${KEYRING}/cryptoKeys/${KEY}"
COMMON_FLAGS=(--project "${PROJECT_ID}" --zone "${ZONE}" --no-address \
  --machine-type "${MACHINE}" --network "${NETWORK}" --subnet "${SUBNET}" \
  --service-account "${SA_EMAIL}" --scopes "https://www.googleapis.com/auth/cloud-platform" \
  --image-family "${IMG_FAMILY}" --image-project "${IMG_PROJECT}" \
  --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
  --metadata enable-oslogin=TRUE,serial-port-enable=FALSE \
  --boot-disk-kms-key "${BOOT_KMS}" --boot-disk-size "20GB" \
  --tags "sync")

gcloud compute instances create "${VM1}" "${COMMON_FLAGS[@]}"
gcloud compute instances create "${VM2}" "${COMMON_FLAGS[@]}"

# Get internal IPs
IP1=$(gcloud compute instances describe "${VM1}" --zone "${ZONE}" --format='get(networkInterfaces[0].networkIP)')
IP2=$(gcloud compute instances describe "${VM2}" --zone "${ZONE}" --format='get(networkInterfaces[0].networkIP)')

### === BOOTSTRAP BOTH VMs: ops agent, auditd, rsync, inotify, /data ===
read -r -d '' REMOTE_BOOTSTRAP <<'EOF'
set -euo pipefail
sudo apt-get update -y
# Ops Agent (logs+metrics)
curl -sS https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh | sudo bash
sudo apt-get install -y google-cloud-ops-agent
# Audit + tools
sudo apt-get install -y auditd rsync inotify-tools
sudo systemctl enable --now auditd

# Minimal audit rules focusing on /data (append-safe)
echo '-w /data -p rwa -k data_changes' | sudo tee /etc/audit/rules.d/99-data.rules >/dev/null
sudo augenrules --load

# Create dedicated sync user & data dir
sudo useradd -m -s /usr/sbin/nologin sync || true
sudo mkdir -p /data
sudo chown -R sync:sync /data

# Ops Agent: collect auditd logs
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

gcloud compute ssh "${VM1}" --zone "${ZONE}" --tunnel-through-iap --command "${REMOTE_BOOTSTRAP}"
gcloud compute ssh "${VM2}" --zone "${ZONE}" --tunnel-through-iap --command "${REMOTE_BOOTSTRAP}"

### === SSH key: generate on VM1 for user "sync", push to VM2 with restriction ===
gcloud compute ssh "${VM1}" --zone "${ZONE}" --tunnel-through-iap --command \
  "sudo -u sync bash -lc 'test -f ~/.ssh/id_ed25519 || (mkdir -p ~/.ssh && chmod 700 ~/.ssh && ssh-keygen -t ed25519 -N \"\" -f ~/.ssh/id_ed25519)'"

PUBKEY=$(gcloud compute ssh "${VM1}" --zone "${ZONE}" --tunnel-through-iap --command "sudo -u sync cat ~/.ssh/id_ed25519.pub")
gcloud compute ssh "${VM2}" --zone "${ZONE}" --tunnel-through-iap --command \
  "sudo -u sync bash -lc 'mkdir -p ~/.ssh && chmod 700 ~/.ssh; echo \"from=${IP1} ${PUBKEY}\" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys'"

### === Continuous rsync service from VM1:/data -> VM2:/data (internal IP only) ===
read -r -d '' SYNC_SCRIPT <<EOF
#!/usr/bin/env bash
set -euo pipefail
DEST_USER="sync"
DEST_HOST="${IP2}"
SRC_DIR="/data/"
DEST_DIR="/data/"
SSH_OPTS="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/dev/null"
# First full sync, then watch & sync fast
rsync -az --delete -e "ssh \$SSH_OPTS" "\$SRC_DIR" "\${DEST_USER}@\${DEST_HOST}:\${DEST_DIR}"
inotifywait -m -r -e modify,create,delete,move "\$SRC_DIR" | while read -r _; do
  rsync -az --delete -e "ssh \$SSH_OPTS" "\$SRC_DIR" "\${DEST_USER}@\${DEST_HOST}:\${DEST_DIR}"
done
EOF

read -r -d '' SYNC_SERVICE <<'EOF'
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

gcloud compute ssh "${VM1}" --zone "${ZONE}" --tunnel-through-iap --command \
  "echo '${SYNC_SCRIPT}' | sudo tee /usr/local/bin/continuous-sync.sh >/dev/null && sudo chmod 755 /usr/local/bin/continuous-sync.sh && echo '${SYNC_SERVICE}' | sudo tee /etc/systemd/system/continuous-sync.service >/dev/null && sudo systemctl daemon-reload && sudo systemctl enable --now continuous-sync && systemctl is-active continuous-sync && sudo journalctl -u continuous-sync -n 20 --no-pager"

### === Print summary ===
cat <<OUT

Deployment done.

VMs:
 - ${VM1} @ ${IP1}
 - ${VM2} @ ${IP2}

Key checks:
  gcloud compute instances describe ${VM1} --zone ${ZONE} | grep shieldedInstanceConfig -A5
  gcloud compute disks describe ${VM1} --zone ${ZONE} | grep kmsKeyName
  gcloud kms keys describe ${KEY} --keyring ${KEYRING} --location ${KEY_LOC}

Reminder:
 - Accept GDPR CDPA & HIPAA BAA (if applicable) in IAM & Admin > Legal & Compliance.
 - Store CIS/OpenSCAP reports and SCC export as audit evidence.
OUT
