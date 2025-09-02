# **GLBA (FTC Safeguards Rule, 16 CFR Part 314)**
Maps checks directly to **§314.4(a)–(j)** and flags org-process items as **MANUAL**.

## What this checks (and why)

* **Encryption (§314.4(c)(3))** — Encrypt customer info **in transit over external networks and at rest**, or apply QI-approved compensating controls. The script validates **CMEK on boot disks** and (as a strong practice) **key rotation**; you still need to ensure strong TLS for all data in transit. ([eCFR][1])
* **Access controls (§314.4(c)(1))** — No `0.0.0.0/0` ingress, **IAP-only SSH**, **OS Login**, no public IPs, no human project **Owner** role, and no user-managed SA keys. ([eCFR][1])
* **Monitoring & logging (§314.4(c)(8), §314.4(d))** — Subnet **VPC Flow Logs**, **Cloud NAT** logging (ALL), **DATA\_READ/WRITE** audit logs for all services, host **auditd**, and Ops Agent. Pen-testing / vuln assessments cadence remains **MANUAL** (you must do continuous monitoring or annual pen test + vuln assessments at least every 6 months and after material changes). ([eCFR][1])
* **Training & staffing (§314.4(e))**, **service provider oversight (§314.4(f))**, **IR plan (§314.4(h))**, **QI board reporting (§314.4(i))** — flagged **MANUAL** (org artifacts). ([eCFR][1])
* **FTC breach notification (§314.4(j))** — For breaches involving **≥500 consumers’ unencrypted information**, notify the FTC **as soon as possible and no later than 30 days after discovery** (effective **May 13, 2024**). Script checks presence of alert policies/channels (readiness signal). ([eCFR][1], [Federal Trade Commission][2])
* **Scope/exemptions (§314.6)** — Institutions maintaining customer information for **< 5,000 consumers** are exempt from **§314.4(b)(1), (d)(2), (h), (i)** only (risk assessment “written” criteria, pen-test cadence clause, IR plan, and board report). Your scale suggests **not exempt**. ([eCFR][1])

**Primary sources**: the current **eCFR text of 16 CFR Part 314** (§314.3–§314.6) and the **FTC’s guidance/blog** on the 30-day breach notice (≥500 consumers) that took effect **May 13, 2024**. ([eCFR][1], [Federal Trade Commission][2])

---

[1]: https://www.ecfr.gov/current/title-16/chapter-I/subchapter-C/part-314 "
    eCFR :: 16 CFR Part 314 -- Standards for Safeguarding Customer Information
  "
[2]: https://www.ftc.gov/business-guidance/blog/2024/05/safeguards-rule-notification-requirement-now-effect?utm_source=chatgpt.com "Safeguards Rule notification requirement now in effect"
