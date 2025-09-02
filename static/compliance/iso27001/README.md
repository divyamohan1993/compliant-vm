# **ISO/IEC 27001:2022**
Validates strong, automatable signals aligned to **Annex A (2022)** — which contains **93 controls** grouped under **Organizational (A.5), People (A.6), Physical (A.7), Technological (A.8)** — and flags management-system items (Clauses **4–10**) as **MANUAL** artifacts you’ll attach to your evidence pack. ([ISO][1], [IT Governance][2], [Secureframe][3])

## What this validates (and why)

* **Annex A structure & scope** — ISO/IEC 27001:2022 Annex A has **93 controls** across **A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological** (2013’s 114 controls were consolidated/updated). The module targets **A.8** signals you can reliably automate in GCP/Ubuntu; the rest are marked MANUAL. ([IT Governance][2], [Secureframe][3])
* **A.8.20 Network security** — Blocks broad ingress, enforces **IAP-only SSH**; disallows VM public IPs. ([IT Governance][2])
* **A.8.9 Configuration mgmt / baseline** — Verifies **Shielded VM** (secure boot, vTPM, integrity monitor), **serial console off**.
* **A.8.23 / A.8.24 IAM & privileged access** — **OS Login** on project; checks for human **Owner** grants; forbids user-managed SA keys; host SSH password auth **off** and root login **disabled**.
* **A.8.28/.29 Cryptography & key mgmt** — **CMEK on disks** with key rotation (≤365d as a strong practice you can tune).
* **A.8.15 Logging / A.8.16 Monitoring** — **Audit logs** for all services (DATA\_READ/WRITE), **VPC Flow Logs**, **Cloud NAT** logging (ALL), **Monitoring alerts** present; **Cloud Logging retention** is **finite and ≥ your threshold**. (ISO doesn’t prescribe a number — you set it via risk/requirements; default is >0). ([ISMS.online][4])
* **A.8.19 Backups** — Snapshot schedules detected (plus MANUAL reminders for scope/RPO/RTO/restore tests).
* **A.5.23 Cloud services** — The standard expects policy/controls over **use of cloud services**; script flags this as **MANUAL** (supplier due-diligence, shared-responsibility, onboarding/exit). ([ISMS.online][5], [DQS Global][6])

> Notes:
>
> * ISO clauses 4–10 (ISMS) are **management-system** requirements (context, risk treatment, policies, internal audits, mgmt review, continual improvement) — the script **intentionally** leaves them **MANUAL** so you attach your ISMS artifacts. ([ISO][1])
> * The checker is **idempotent**: it never mutates resources and only overwrites `iso27001-evidence.json` (+ timestamped copy). Re-running alongside `autoconfig.sh` won’t create duplicates.
> * You can raise thresholds (e.g., `MIN_LOG_RETENTION_DAYS=365`) without editing the script.

[1]: https://www.iso.org/standard/27001?utm_source=chatgpt.com "ISO/IEC 27001:2022 - Information security management ..."
[2]: https://www.itgovernance.co.uk/blog/iso-27001-the-14-control-sets-of-annex-a-explained?utm_source=chatgpt.com "ISO 27001:2022 Annex A Controls - A Complete Guide"
[3]: https://secureframe.com/hub/iso-27001/controls?utm_source=chatgpt.com "ISO 27001 Controls Explained: A Guide to Annex A"
[4]: https://www.isms.online/iso-27001/annex-a/8-15-logging-2022/?utm_source=chatgpt.com "ISO 27001:2022 Annex A 8.15 – Logging"
[5]: https://www.isms.online/iso-27001/annex-a/5-23-information-security-use-of-cloud-services-2022/?utm_source=chatgpt.com "ISO 27001:2022 Annex A Control 5.23 Explained - ISMS.online"
[6]: https://www.dqsglobal.com/en-us/learn/blog/cloud-security-with-iso-27001-2022?utm_source=chatgpt.com "Security in the Cloud with ISO/IEC 27001:2022"
