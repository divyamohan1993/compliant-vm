# **NIST SP 800-53 Rev. 5**
Maps strong, automatable signals to key **control families** (AC, AU, CM, CP, IA, IR, SC, SI, etc.), and clearly flags **MANUAL** items that require policy/process artifacts. ([NIST Computer Security Resource Center][1], [NIST Publications][2], [CSF Tools][3])

## Why these checks map to NIST 800-53 Rev.5

* **Control families & scope** — Rev.5 catalogs **security & privacy controls** across families like **AC, AU, CM, CP, IA, IR, SC, SI** (and more). This module automates strong technical signals for those, while organizational families remain **MANUAL** evidence. ([NIST Computer Security Resource Center][1], [CSF Tools][3])
* **AC/IA** — Boundary & remote access (**no 0.0.0.0/0**, **IAP-only SSH**) align with **AC-4/SC-7** and **AC-17**; **OS Login** (central identity), **no human Owner grants** (**AC-6 least privilege**), and **no user-managed SA keys** (**IA-5**). ([CSF Tools][4])
* **AU** — **Project audit logs** enabled for **ADMIN\_READ/DATA\_READ/DATA\_WRITE** (AU-2/AU-12), **finite retention** (AU-11), plus **Flow Logs** and **NAT logging** to support monitoring/analysis. ([CSF Tools][5])
* **SC (crypto)** — **CMEK on disks** → **SC-28 (information at rest)**; **key rotation** threshold aligns with **SC-12 (key management)** (tunable). ([CSF Tools][6])
* **CP** — **Snapshot schedules** reflect **CP-9 (system backup)**; **restore tests/RPO/RTO** are flagged **MANUAL** for **CP-10**. ([CSF Tools][7])

> Notes:
>
> * **Baselines** (LOW/MODERATE/HIGH) live in **SP 800-53B**; this checker is baseline-agnostic and surfaces objective technical signals you can reuse in overlays. ([NIST Publications][2])
> * Thresholds like `MIN_LOG_RETENTION_DAYS` and `MAX_KMS_ROTATION_SECONDS` are knobs you can set per system risk/tailoring.
> * Script is **idempotent & read-only**, so bundling with `autoconfig.sh` won’t create duplicates and will always generate fresh evidence.

[1]: https://csrc.nist.gov/pubs/sp/800/53/r5/final?utm_source=chatgpt.com "SP 800-53 Rev. 5, Security and Privacy Controls for ..."
[2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf?utm_source=chatgpt.com "NIST.SP.800-53r5.pdf"
[3]: https://csf.tools/reference/nist-sp-800-53/r5/?utm_source=chatgpt.com "NIST SP 800-53, Revision 5"
[4]: https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-17/?utm_source=chatgpt.com "AC-17: Remote Access"
[5]: https://csf.tools/reference/nist-sp-800-53/r5/au/?utm_source=chatgpt.com "AU: Audit and Accountability"
[6]: https://csf.tools/reference/nist-sp-800-53/r5/sc/sc-28/?utm_source=chatgpt.com "SC-28: Protection of Information at Rest"
[7]: https://csf.tools/reference/nist-sp-800-53/r5/cp/cp-9/?utm_source=chatgpt.com "CP-9: System Backup"
