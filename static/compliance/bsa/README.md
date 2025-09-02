# **BSA (Bank Secrecy Act / AML)** 
Focuses on the technical signals your GCP/Ubuntu stack can actually prove (logging, retention ≥5 years, access controls, encryption, monitoring), and cleanly flags the **programmatic “five pillars”** (internal controls, independent testing, BSA officer, training, risk-based CDD/CIP) plus **SAR/CTR** obligations as **MANUAL** artifacts you’ll supply from policy & operations.


## Why this aligns with **BSA/AML** (and what’s automatable vs. manual)

* **BSA AML Program (“five pillars”)** — banks must maintain internal controls, independent testing, a BSA officer, training, and risk-based **CDD** (now explicitly including ongoing monitoring). That’s in **31 CFR 1020.210**. These are organizational artifacts → **MANUAL** evidence. ([eCFR][1], [Legal Information Institute][2])
* **CIP** rules (identify/verify customers, notice, TIN rules, risk-based verification) are at **31 CFR 1020.220**; **CDD/Beneficial Ownership** for legal entities is **31 CFR 1010.230**. Both are program/process requirements your script can’t “discover” from VMs → **MANUAL** evidence. ([eCFR][3], [GovInfo][4], [Legal Information Institute][5], [FFIEC BSA/AML][6])
* **SAR** filing requirement is **31 CFR 1020.320**; **CTR** threshold is **>\$10,000** at **31 CFR 1010.311** (with exempt person provisions). These are operational compliance obligations → **MANUAL** artifacts (cases, filings, procedures). ([eCFR][7], [Legal Information Institute][8], [FFIEC BSA/AML][9])
* **Record retention**: required BSA records/reports must be kept **≥5 years** (**31 CFR 1010.430**; FFIEC Appendix P summarizes). The module verifies **Cloud Logging retention** and looks for **export sinks** to **GCS**/**BigQuery** with **≥5-year retention** and (optionally) **CMEK**, which are appropriate technical controls to satisfy the recordkeeping aspect at scale. ([eCFR][10], [FFIEC BSA/AML][11])
* **Protecting BSA records**: we assert **OS Login + IAP-only SSH, least privilege (no human Owner), no user-managed SA keys**, **Shielded VMs** and **CMEK on disks**—good practice to safeguard sensitive BSA data/logs. (While not line-item BSA regs, they underpin confidentiality/integrity for your evidence & monitoring stacks.) ([eCFR][12])
* **Monitoring signals**: **VPC Flow Logs**, **Cloud NAT logging (ALL)**, audit logs, and **alert policies** provide technical detection support; host **auditd** and **NTP** help ensure evidentiary quality (complete, time-synchronized logs). FFIEC manual emphasizes effective monitoring and timely SAR decisions; our checks surface the infrastructure signals that support those workflows. ([FFIEC BSA/AML][13])

> Tuning tips
> • If you export logs to **GCS**, set a bucket **retention policy** ≥ 5 years; the script reads it and flags if shorter.
> • For **BigQuery**, either leave default table expiration **unset** (indefinite) or set ≥ 5 years; the script checks with `bq` when available.
> • Keep `MIN_BSA_RETENTION_DAYS` at **1825** unless counsel specifies longer.


[1]: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1020/subpart-B/section-1020.210?utm_source=chatgpt.com "31 CFR 1020.210 -- Anti-money laundering program ..."
[2]: https://www.law.cornell.edu/cfr/text/31/1020.210?utm_source=chatgpt.com "31 CFR § 1020.210 - Anti-money laundering program ..."
[3]: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1020/subpart-B/section-1020.220?utm_source=chatgpt.com "31 CFR 1020.220 - Customer Identification Program"
[4]: https://www.govinfo.gov/link/cfr/31/1020?link-type=pdf&sectionnum=220&year=mostrecent&utm_source=chatgpt.com "31 CFR Ch. X (7–1–24 Edition) § 1020.220"
[5]: https://www.law.cornell.edu/cfr/text/31/1010.230?utm_source=chatgpt.com "31 CFR § 1010.230 - Beneficial ownership requirements for ..."
[6]: https://bsaaml.ffiec.gov/manual/AssessingComplianceWithBSARegulatoryRequirements/03?utm_source=chatgpt.com "Beneficial Ownership Requirements for Legal Entity ..."
[7]: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1020/subpart-C/section-1020.320?utm_source=chatgpt.com "31 CFR 1020.320 -- Reports by banks of suspicious ..."
[8]: https://www.law.cornell.edu/cfr/text/31/1020.320?utm_source=chatgpt.com "31 CFR § 1020.(ID31614358) - § 1020.320 Reports by banks ..."
[9]: https://bsaaml.ffiec.gov/manual/AssessingComplianceWithBSARegulatoryRequirements/05?utm_source=chatgpt.com "Currency Transaction Reporting - BSA/AML Manual"
[10]: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1010/subpart-D/section-1010.430?utm_source=chatgpt.com "31 CFR 1010.430 -- Nature of records and retention period."
[11]: https://bsaaml.ffiec.gov/manual/Appendices/17?utm_source=chatgpt.com "Appendix P – BSA Record Retention Requirements"
[12]: https://www.ecfr.gov/current/title-31/subtitle-B/chapter-X/part-1020?utm_source=chatgpt.com "31 CFR Part 1020 -- Rules for Banks"
[13]: https://bsaaml.ffiec.gov/manual/AssessingComplianceWithBSARegulatoryRequirements/04?utm_source=chatgpt.com "Suspicious Activity Reporting - BSA/AML Manual"
