# **NIST CSF 2.0** 
Maps strong, automatable signals to CSF 2.0 **Functions & Categories** (notably the new **Govern (GV)** function alongside **Identify, Protect, Detect, Respond, Recover**), and marks policy/process items as **MANUAL**. ([NIST Publications][1], [CSF Tools][2])

## Why these checks map cleanly to **CSF 2.0**

* **Functions**: CSF 2.0 has **six** functions—**Govern, Identify, Protect, Detect, Respond, Recover**—with the **Govern (GV)** function added in 2.0; categories like **GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC** live there. These are mainly program/policy artifacts (hence **MANUAL**). ([NIST Publications][1], [CSF Tools][3])
* **Protect (PR)**: We validate **PR.AA** (identity/access: OS Login, IAP-only SSH, least privilege, no user-managed SA keys), **PR.PS** (platform security: Shielded VM, serial console off, OS baseline signals), and **PR.DS** (encryption-at-rest via CMEK with rotation). **PR.AA** naming is the CSF 2.0 category update. ([CSF Tools][2])
* **Detect (DE)**: **DE.CM** (continuous monitoring) is evidenced by **project audit logs** (ADMIN/DATA read/write), **VPC Flow Logs**, **Cloud NAT logging (ALL)**, **host auditd + ops agent**, **alert policies**, and **finite log retention**. ([NIST Publications][1])
* **Respond/Recover**: These are mostly **MANUAL** (plans, comms, improvements). We add a technical signal for **RC** via attached **snapshot schedules** and leave **restore testing** as **MANUAL** evidence (playbooks & test reports). ([NIST Publications][1])

[1]: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf?utm_source=chatgpt.com "The NIST Cybersecurity Framework (CSF) 2.0"
[2]: https://csf.tools/reference/nist-cybersecurity-framework/v2-0/pr/pr-aa/?utm_source=chatgpt.com "PR.AA: Identity Management, Authentication, And Access ..."
[3]: https://csf.tools/reference/nist-cybersecurity-framework/v2-0/gv/?utm_source=chatgpt.com "GV: Govern"
