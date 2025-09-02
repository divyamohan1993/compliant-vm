# **SOC 2 (AICPA Trust Services Criteria)**
Surfaces strong, automatable signals aligned to the TSC (Security is baseline; Availability/Confidentiality optional; Processing Integrity/Privacy mainly MANUAL artifacts).

---

## Notes on scope & use

* **SOC 2 isn’t a prescriptive checklist**: auditors assess the **design & operating effectiveness** of controls over a **period**. This module provides objective **signals** that strongly support TSC areas (e.g., network exposure, logging/monitoring, encryption, host hardening).
* Keep the **MANUAL** items (governance, risk, change mgmt, DR tests, data classification, privacy program) in your evidence packet — those are policy/process artifacts auditors must review.
* You can tune thresholds (e.g., require `retentionDays>=365`) by adding flags later; script structure already mirrors your other modules for easy extension.
