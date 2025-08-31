#!/usr/bin/env bash
# Deletes all resources created by autoconfig.sh
# Safe to re-run; skips anything already gone.

set -Eeuo pipefail
shopt -s inherit_errexit

export PS4='+ [${EPOCHREALTIME}] [${BASH_SOURCE##*/}:${LINENO}] '
exec 3>&1
log()     { printf -- "[%(%Y-%m-%dT%H:%M:%SZ)T] %s\n" -1 "$*" >&3; }
section() { echo; echo "==== $* ===="; }
trap 'rc=$?; echo "[ERROR] rc=$rc line=${BASH_LINENO[0]} cmd: ${BASH_COMMAND}" >&2; exit $rc' ERR

# ---- Config (keep in sync with autoconfig.sh) ---------------------------------
PROJECT_ID="${PROJECT_ID:-unified-icon-469918-s7}"
REGION="${REGION:-asia-south1}"
ZONE="${ZONE:-asia-south1-a}"

NETWORK="${NETWORK:-vm-privacy-net}"
SUBNET="${SUBNET:-vm-privacy-subnet}"

KEYRING="${KEYRING:-vm-xfer-kr}"
KEY="${KEY:-vm-xfer-key}"
KEY_LOC="${KEY_LOC:-asia-south1}"

SA_NAME="${SA_NAME:-vm-transfer-sa}"
SA_EMAIL="${SA_EMAIL:-${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com}"

VM1="${VM1:-vm-a}"
VM2="${VM2:-vm-b}"

ROUTER="${ROUTER:-${NETWORK}-router}"
NAT="${NAT:-${NETWORK}-nat}"

ACCOUNT="$(gcloud config get-value account 2>/dev/null || echo "")"
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
CE_AGENT="service-${PROJECT_NUMBER}@compute-system.iam.gserviceaccount.com"

# Feature toggles
REMOVE_USER_ROLES="${REMOVE_USER_ROLES:-0}"   # also remove your user role grants
REMOVE_OSLOGIN_KEY="${REMOVE_OSLOGIN_KEY:-0}" # unregister ~/.ssh/gce_oslogin.pub if present
DISABLE_APIS="${DISABLE_APIS:-0}"             # disable APIs enabled by autoconfig

# ---- Helpers ------------------------------------------------------------------
exists_inst()    { gcloud compute instances describe "$1" --zone "$ZONE" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_disk()    { gcloud compute disks describe "$1" --zone "$ZONE" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_fw()      { gcloud compute firewall-rules describe "$1" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_subnet()  { gcloud compute networks subnets describe "$SUBNET" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_network() { gcloud compute networks describe "$NETWORK" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_router()  { gcloud compute routers describe "$ROUTER" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_nat()     { gcloud compute routers nats describe "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_sa()      { gcloud iam service-accounts describe "$SA_EMAIL" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_keyring() { gcloud kms keyrings describe "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" >/dev/null 2>&1; }
exists_key()     { gcloud kms keys describe "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" >/dev/null 2>&1; }

del_if() { # del_if "<desc>" <cmd...>
  local desc="$1"; shift
  if "$@"; then :; fi
}

# ---- 0) Context ----------------------------------------------------------------
section "0) Context"
log "Project: $PROJECT_ID | Zone: $ZONE | Region: $REGION"
log "Account: ${ACCOUNT:-unknown}"

# ---- 1) Instances (and any leftover disks) ------------------------------------
section "1) Delete VMs"

for INST in "$VM1" "$VM2"; do
  if exists_inst "$INST"; then
    # record attached disks (URLs) before deletion
    DISKS=$(gcloud compute instances describe "$INST" --zone "$ZONE" --project "$PROJECT_ID" \
      --format="value(disks[].source)")
    log "Deleting instance: $INST"
    gcloud compute instances delete "$INST" --zone "$ZONE" --project "$PROJECT_ID" --quiet || true

    # delete any leftover disks (in case auto-delete was off)
    if [[ -n "${DISKS:-}" ]]; then
      for DURL in $DISKS; do
        DNAME="${DURL##*/}"
        if exists_disk "$DNAME"; then
          log "Deleting leftover disk: $DNAME"
          gcloud compute disks delete "$DNAME" --zone "$ZONE" --project "$PROJECT_ID" --quiet || true
        fi
      done
    fi
  else
    log "Instance $INST already gone"
  fi
done

# ---- 2) Firewall rules ---------------------------------------------------------
section "2) Firewall rules"
for FW in allow-iap-ssh allow-internal; do
  if exists_fw "$FW"; then
    log "Deleting firewall rule: $FW"
    gcloud compute firewall-rules delete "$FW" --project "$PROJECT_ID" --quiet || true
  else
    log "Firewall $FW already gone"
  fi
done

# ---- 3) Cloud NAT + Router -----------------------------------------------------
section "3) Cloud NAT + Router"
if exists_nat; then
  log "Deleting NAT: $NAT"
  gcloud compute routers nats delete "$NAT" --router "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --quiet || true
else
  log "NAT $NAT already gone"
fi

if exists_router; then
  log "Deleting Router: $ROUTER"
  gcloud compute routers delete "$ROUTER" --region "$REGION" --project "$PROJECT_ID" --quiet || true
else
  log "Router $ROUTER already gone"
fi

# ---- 4) Subnet + Network -------------------------------------------------------
section "4) Subnet + Network"
if exists_subnet; then
  log "Deleting Subnet: $SUBNET"
  gcloud compute networks subnets delete "$SUBNET" --region "$REGION" --project "$PROJECT_ID" --quiet || true
else
  log "Subnet $SUBNET already gone"
fi

if exists_network; then
  log "Deleting Network: $NETWORK"
  gcloud compute networks delete "$NETWORK" --project "$PROJECT_ID" --quiet || true
else
  log "Network $NETWORK already gone"
fi

# ---- 5) KMS (destroy versions; attempt key/keyring cleanup) --------------------
section "5) KMS cleanup"
if exists_key; then
  # Remove IAM bindings first (service account + CE agent)
  log "Removing KMS IAM bindings"
  gcloud kms keys remove-iam-policy-binding "$KEY" \
    --keyring "$KEYRING" --location "$KEY_LOC" \
    --member "serviceAccount:${SA_EMAIL}" \
    --role "roles/cloudkms.cryptoKeyEncrypterDecrypter" \
    --project "$PROJECT_ID" || true

  gcloud kms keys remove-iam-policy-binding "$KEY" \
    --keyring "$KEYRING" --location "$KEY_LOC" \
    --member "serviceAccount:${CE_AGENT}" \
    --role "roles/cloudkms.cryptoKeyEncrypterDecrypter" \
    --project "$PROJECT_ID" || true

  # Destroy all key versions
  log "Destroying all crypto key versions for $KEY"
  VERS=$(gcloud kms keys versions list --key "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" --format='value(name)' || true)
  if [[ -n "${VERS:-}" ]]; then
    while read -r V; do
      [[ -z "$V" ]] && continue
      VID="${V##*/}"
      log "Destroy version: $VID"
      gcloud kms keys versions destroy "$VID" \
        --key "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" --quiet || true
    done <<< "$VERS"
  fi

  # Try to delete the key (will no-op or fail harmlessly on some org policies)
  log "Attempting to delete KMS key $KEY"
  gcloud kms keys delete "$KEY" --keyring "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" --quiet || true
else
  log "KMS key $KEY already absent"
fi

if exists_keyring; then
  log "Attempting to delete keyring $KEYRING"
  gcloud kms keyrings delete "$KEYRING" --location "$KEY_LOC" --project "$PROJECT_ID" --quiet || true
else
  log "Keyring $KEYRING already absent"
fi

# ---- 6) Service Account + project-level bindings ------------------------------
section "6) Service Account + IAM bindings"
# Remove project roles from the SA (then delete SA)
for ROLE in roles/logging.logWriter roles/monitoring.metricWriter; do
  log "Removing project role $ROLE from $SA_EMAIL"
  gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" --role="$ROLE" >/dev/null 2>&1 || true
done

if exists_sa; then
  log "Deleting service account $SA_EMAIL"
  gcloud iam service-accounts delete "$SA_EMAIL" --project "$PROJECT_ID" --quiet || true
else
  log "Service account already gone"
fi

# ---- 7) OS Login: project metadata + optional key unregister -------------------
section "7) OS Login cleanup"
# Remove the project-level enable-oslogin metadata key (safe if not present)
log "Removing project metadata enable-oslogin"
gcloud compute project-info remove-metadata --project "$PROJECT_ID" --keys=enable-oslogin >/dev/null 2>&1 || true

# Optionally unregister the dedicated OS Login key we added (~/.ssh/gce_oslogin.pub)
if [[ "${REMOVE_OSLOGIN_KEY}" == "1" ]]; then
  OSK="$HOME/.ssh/gce_oslogin.pub"
  if [[ -f "$OSK" ]]; then
    log "Unregistering OS Login key from $OSK"
    # gcloud expects the full key text
    gcloud compute os-login ssh-keys remove --project "$PROJECT_ID" --key="$(cat "$OSK")" >/dev/null 2>&1 || true
  else
    log "No OS Login key file at $OSK; skipping"
  fi
fi

# ---- 8) Optional: remove your user role grants --------------------------------
section "8) Optional user role cleanup"
if [[ "${REMOVE_USER_ROLES}" == "1" && -n "${ACCOUNT}" ]]; then
  for ROLE in roles/compute.osAdminLogin roles/iap.tunnelResourceAccessor roles/compute.viewer; do
    log "Removing $ROLE from user:${ACCOUNT}"
    gcloud projects remove-iam-policy-binding "$PROJECT_ID" \
      --member="user:${ACCOUNT}" --role="$ROLE" >/dev/null 2>&1 || true
  done
else
  log "Skipping removal of your user role grants (set REMOVE_USER_ROLES=1 to enable)"
fi

# ---- 9) Optional: disable APIs -------------------------------------------------
section "9) Optional API disable"
if [[ "${DISABLE_APIS}" == "1" ]]; then
  for SVC in compute.googleapis.com iam.googleapis.com cloudkms.googleapis.com \
             oslogin.googleapis.com osconfig.googleapis.com iap.googleapis.com \
             logging.googleapis.com monitoring.googleapis.com; do
    log "Disabling API: $SVC"
    gcloud services disable "$SVC" --project "$PROJECT_ID" --quiet || true
  done
else
  log "Skipping API disable (set DISABLE_APIS=1 to enable)"
fi

section "Done"
log "Teardown completed."
