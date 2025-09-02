# **SOX module**
Focuses on **IT General Controls (ITGC)** that support SOX §404 ICFR assertions

## What this verifies & how it maps to SOX (with sources)

* **SOX §404 (ICFR) and PCAOB AS 2201**: Auditors opine on the **effectiveness of Internal Control over Financial Reporting**; robust ITGCs (access control, change mgmt, computer operations) are foundational for ICFR. The module surfaces objective, automatable signals that support ICFR assertions. ([Default][1], [Moss Adams][2])

* **Evidence retention**: SEC **Rule 2-06 of Regulation S-X (17 CFR 210.2-06)** requires **seven years** retention of records relevant to audits/reviews (e.g., workpapers, electronic records). While this rule is aimed at **accountants/auditors**, many SOX programs align supporting **IT evidences** (including logs that substantiate ICFR) to **7-year** retention. The script checks Cloud Logging retention **≥ 2555 days** and that the bucket is **locked** (immutability signal). ([SEC][3], [Legal Information Institute][4], [GovInfo][5])

* **Access controls & SoD signals**: No broad `roles/owner` assigned to human principals; OS Login enforced; SSH password auth disabled; root login disabled; no public IP exposure; IAP-only SSH; Shielded VM and serial console off. These reduce risk around unauthorized changes and support ICFR reliability. ([KPMG][6])

* **Computer operations**: Project **DATA\_READ/WRITE** audit logging enabled; **VPC Flow Logs** and **Cloud NAT** logging; host **auditd** and **time sync**; at least one **Monitoring alert**. These support ongoing monitoring and traceability that auditors expect for ICFR. ([KPMG][6])

* **Encryption & key management**: CMEK on disks + rotation (≤90d as a strong control). SOX doesn’t prescribe crypto specifics, but encryption and managed keys are common ICFR risk mitigations. (General ICFR/ITGC practice; see Big-4 ICFR handbooks for principles.) ([KPMG][6])

* **Change management**: Ticketing, approvals, testing, SoD, and deployment evidence are inherently **organizational** and remain **MANUAL**; the script flags them for your packet. (Audited under AS 2201 as part of ICFR.) ([Default][1])

---

### Notes / options

* If you later adopt org policies (e.g., **disable SA key creation**, **deny external IPs**) you can extend the checker to read **Organization Policy** state for even stronger automated evidence.
* If you operate Cloud SQL/Load Balancers in scope, you can add targeted checks (e.g., LB SSL policies, SQL public IP prohibition).

[1]: https://pcaobus.org/oversight/standards/auditing-standards/details/AS2201?utm_source=chatgpt.com "AS 2201: An Audit of Internal Control Over Financial ..."
[2]: https://www.mossadams.com/articles/2024/08/improve-sox-404-compliance-strategies?utm_source=chatgpt.com "SOX 404 Compliance Strategies"
[3]: https://www.sec.gov/rules-regulations/2003/01/retention-records-relevant-audits-reviews?utm_source=chatgpt.com "Retention of Records Relevant to Audits and Reviews"
[4]: https://www.law.cornell.edu/cfr/text/17/210.2-06?utm_source=chatgpt.com "17 CFR § 210.2-06 - Retention of audit and review records."
[5]: https://www.govinfo.gov/content/pkg/CFR-2012-title17-vol2/pdf/CFR-2012-title17-vol2-sec210-2-06.pdf?utm_source=chatgpt.com "Securities and Exchange Commission § 210.2–06"
[6]: https://kpmg.com/kpmg-us/content/dam/kpmg/frv/pdf/2023/handbook-internal-controls-over-financial-reporting.pdf?utm_source=chatgpt.com "handbook-internal-controls-over-financial-reporting. ..."
