# **PCI DSS v4.0.1 Level 1**

## What this actually verifies (mapped to PCI DSS v4.0.1)

* **Req 1 – Network security controls**: No `0.0.0.0/0` ingress, IAP-only SSH, subnet flow logs, Cloud NAT logging (ALL). These support required ruleset reviews and scoping/segmentation posture. ([Middlebury][1])
* **Req 2 – Secure configurations**: OS Login at project; Shielded VM secure boot/vTPM/integrity; serial console disabled. (Hardening evidence for “secure configs.”) ([Middlebury][1])
* **Req 3 – Protect stored account data**: CMEK on boot disks and CMEK rotation policy (≤90 days here as a strong control; PCI requires appropriate key management and strong cryptography). ([Middlebury][1])
* **Req 4 – Protect CHD in transit**: Marked **MANUAL** for TLS policy/cipher verification at LB/app; your infra must meet “strong cryptography during transmission.” ([Middlebury][1])
* **Req 5 – Anti-malware**: **MANUAL** (platform/role-based); Linux hosts often require EDR/AV if “commonly affected by malware”. ([Middlebury][1])
* **Req 6 – Secure systems & software**: Script surfaces unattended upgrades (signal). Full vulnerability management remains **MANUAL** (risk ranking, change control). ([Middlebury][1])
* **Req 7 – Need-to-know**: Detects human principals with `roles/owner` at project (should be none). ([Middlebury][1])
* **Req 8 – Identify & authenticate**: OS Login; host checks ensure SSH password auth off and root login disabled; SA user-managed keys = none; MFA enforcement is **MANUAL** via IdP. ([Middlebury][1])
* **Req 9 – Physical**: **MANUAL**; covered by provider AoC (review Google Cloud PCI DSS page/AoC). ([Google Cloud][2], [Google Services][3])
* **Req 10 – Logging & monitoring**:
  * Data Access logging enabled at project, and **retention ≥ 12 months** with the most recent **3 months immediately available** (the script checks bucket `retentionDays` ≥ 365 and ≥ 90 respectively). These map to **Req 10.5.1**. ([Middlebury][1])
  * Host probes confirm auditd active and time sync.
* **Req 11 – Regular testing**: **MANUAL** evidence for **quarterly internal** scans, **quarterly external ASV** scans, and **annual pen-test**; ASV/scan cadence text comes directly from Req 11.3.1 and 11.3.2. Segmentation validation is required regularly. ([Middlebury][1])
* **Req 12 – Program**: **MANUAL** (policies, roles, BAU/continuous validation). ([Middlebury][1])

For cloud-specific scoping/segmentation & shared responsibility, keep these handy during assessment: Google Cloud **PCI DSS on GCP** guide and the **GCP PCI DSS v4.x Shared Responsibility Matrix**. ([Google Cloud][4], [Google Services][3])

**Log retention source (explicit):** PCI DSS v4.0.1 **Req 10.5.1** requires **12 months** of audit log history with the most recent **three months immediately available**. The script checks Cloud Logging bucket `retentionDays` to evidence both. ([Middlebury][1])

**Quarterly scans source (explicit):** Internal scans at least **every three months** (with rescans), and external scans **by an ASV** at least **every three months** (with rescans to passing). ([Middlebury][1])

---

[1]: https://www.middlebury.edu/sites/default/files/2025-01/PCI-DSS-v4_0_1.pdf?fv=AKHVQBp6 "Payment Card Industry Data Security Standard"
[2]: https://cloud.google.com/security/compliance/pci-dss?utm_source=chatgpt.com "PCI DSS - Compliance"
[3]: https://services.google.com/fh/files/misc/gcp_pci_dss_v4_responsibility_matrix.pdf?utm_source=chatgpt.com "GCP: PCI DSS v4.0.1 Shared Responsibility Matrix"
[4]: https://cloud.google.com/architecture/pci-dss-compliance-in-gcp?utm_source=chatgpt.com "PCI Data Security Standard compliance"
