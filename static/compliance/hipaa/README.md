# **HIPAA**. 

### What HIPAA demands (the bits we can test vs. must document)

**Security Rule (45 CFR Part 164 Subpart C):**

* **Technical safeguards (§164.312)**: access control (unique IDs, emergency access, auto logoff, encryption), audit controls, integrity, person/entity authentication, transmission security (integrity + encryption “addressable”). ([eCFR][1], [Legal Information Institute][2], [GovInfo][3])
* **Administrative safeguards (§164.308)**: risk analysis/management, sanction policy, information system activity review, contingency plan (backup/DR), incident response, workforce training. (We can collect *evidence of* logging, retention, backups, etc., but most are programmatic/organizational.) ([HHS.gov][4], [NIST Cybersecurity Framework][5])
* **Policies, procedures & documentation (§164.316)**: keep required docs **6 years**; make them available to responsible personnel. (Common practice = retain audit logs the same 6 years to support investigations.) ([eCFR][6], [Legal Information Institute][7], [The HIPAA Journal][8])
* **Business Associate Agreement (BAA)** with cloud provider before handling PHI on covered services (GCP has a HIPAA BAA you must accept). ([Google Cloud][9], [admin.google.com][10])

**Best-practice guidance to *implement* HIPAA:**

* **NIST SP 800-66 Rev.2** gives concrete activities & mappings (useful to justify each control we check). HHS links to it as official guidance. ([NIST Publications][11], [HHS.gov][12])

> Heads-up: HHS proposed strengthening rules (e.g., **mandatory MFA**). Not final yet—useful for “future-ready,” but we shouldn’t fail you on proposals. ([Reuters][13])

---

### What we’ll auto-verify in your environment

The checker validates (and maps each to CFR/NIST):

**Project/GCP plane**

* No public IPs; IAP-only SSH; least-exposed firewall; VPC flow logs; NAT logging. *(164.312(e): transmission security; 164.312(a): access control; 164.312(b): audit controls)*
* CMEK on boot disks + **rotation**; logging bucket **retention ≥ 6 years** and **locked**; **Data Access** audit logs enabled for **allServices** (Compute/IAM/KMS at minimum); Ops Agent shipping auditd logs. *(164.312(b), 164.316)*
* **No service-account keys** (keyless) for your workload SA. *(164.312(d))*
* Snapshot schedules on disks (backup evidence for contingency). *(164.308(a)(7))*

**VM/OS plane (Ubuntu 22.04)**

* **auditd active & rules loaded**; **AIDE** present & baseline created (integrity); **SSH hardened** (no root login, no password auth); **automatic updates**; **time sync**; **auto-logoff (TMOUT)**. *(164.312(b),(c),(d),(a)(2)(iii))*

Everything gets a **PASS/FAIL with the CFR reference**; anything inherently organizational (e.g., BAA, risk analysis, training) is flagged **MANUAL** with the exact citation.


### Why these checks = HIPAA-aligned (quick map)

* **Audit controls** (log what happened): Cloud **Data Access** logs + **Ops Agent** + **auditd** = evidence for §164.312(b). ([eCFR][1], [Legal Information Institute][2])
* **Transmission security**: No public IPs + IAP-only SSH + VPC/NAT logging line up with §164.312(e). ([GovInfo][3])
* **Access control / person–entity auth**: OS Login (unique IDs) + SSH hardening → §164.312(a),(d). ([Legal Information Institute][2])
* **Encryption**: CMEK for disks + rotation → §164.312(a)(2)(iv); logging CMEK helps both audit and data protection. ([eCFR][1])
* **Integrity**: AIDE baseline and Shielded VM integrity monitoring support §164.312(c)(1). ([eCFR][1])
* **Documentation & retention**: 6-year retention requirement → we enforce/verify long log retention & lock as supporting evidence for §164.316(b). ([eCFR][6], [Legal Information Institute][7])
* **Programmatic glue**: NIST **800-66r2** lists typical activities that our checks operationalize (log review, encryption, key management, backup evidence, config mgmt). ([NIST Publications][11])
* **Contractual**: **BAA** with Google must be in place before handling PHI on covered services. (*Checker flags MANUAL*). ([Google Cloud][9])

[1]: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312?utm_source=chatgpt.com "45 CFR 164.312 -- Technical safeguards."
[2]: https://www.law.cornell.edu/cfr/text/45/164.312?utm_source=chatgpt.com "45 CFR § 164.312 - Technical safeguards."
[3]: https://www.govinfo.gov/content/pkg/CFR-2004-title45-vol1/pdf/CFR-2004-title45-vol1-sec164-312.pdf?utm_source=chatgpt.com "Department of Health and Human Services § 164.312"
[4]: https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html?utm_source=chatgpt.com "Summary of the HIPAA Security Rule"
[5]: https://csrc.nist.gov/pubs/sp/800/66/r2/final?utm_source=chatgpt.com "SP 800-66 Rev. 2, Implementing the Health Insurance ..."
[6]: https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.316?utm_source=chatgpt.com "45 CFR 164.316 -- Policies and procedures ..."
[7]: https://www.law.cornell.edu/cfr/text/45/164.316?utm_source=chatgpt.com "45 CFR § 164.316 - Policies and procedures and ..."
[8]: https://www.hipaajournal.com/hipaa-retention-requirements/?utm_source=chatgpt.com "HIPAA Retention Requirements - 2025 Update"
[9]: https://cloud.google.com/security/compliance/hipaa?utm_source=chatgpt.com "HIPAA Compliance on Google Cloud | GCP Security"
[10]: https://admin.google.com/terms/cloud_identity/3/7/en/hipaa_baa.html?utm_source=chatgpt.com "HIPAA Business Associate Addendum"
[11]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf?utm_source=chatgpt.com "NIST.SP.800-66r2.pdf"
[12]: https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html?utm_source=chatgpt.com "Security Rule Guidance Material"
[13]: https://www.reuters.com/legal/litigation/top-10-takeaways-new-hipaa-security-rule-nprm-2025-03-14/?utm_source=chatgpt.com "Top 10 takeaways from the new HIPAA security rule NPRM"
