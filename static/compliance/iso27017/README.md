#v **ISO/IEC 27017**
Maps checks to the **7 cloud-specific “CLD” controls** (e.g., **CLD.6.3.1, CLD.8.1.5, CLD.9.5.1, CLD.9.5.2, CLD.12.1.5, CLD.12.4.5, CLD.13.1.4**) and surfaces automatable signals for each; org/contract items are marked **MANUAL**. (ISO/IEC 27017 extends ISO/IEC 27002 with cloud guidance on 37 controls and adds these 7 new cloud controls. ([Google Cloud][1], [Microsoft Learn][2], [IT Governance][3]))

## Why these checks map to ISO/IEC 27017

* **ISO/IEC 27017 extends 27002 with cloud guidance on 37 controls and adds seven new cloud controls**; these include **roles & responsibilities (CLD.6.3.1), asset return/removal (CLD.8.1.5), segregation in virtual environments (CLD.9.5.1), VM hardening (CLD.9.5.2), admin operational security (CLD.12.1.5), monitoring of cloud services (CLD.12.4.5), and alignment of virtual/physical network security (CLD.13.1.4)**. The module validates each with strong GCP/host signals and flags contractual/process items as **MANUAL**. ([Google Cloud][1], [Microsoft Learn][2], [IT Governance][3], [BSI][4])
* **Segregation & VM hardening** — no broad ingress, internal allow scoped to your CIDR, no VM public IPs, Shielded VM secure-boot/vTPM/integrity, serial console off. (Matches **CLD.9.5.1/.9.5.2**.) ([IT Governance][3], [BSI][4])
* **Admin operational security & monitoring** — OS Login + IAP-only SSH, least privilege (no human Owner; no user-managed SA keys), project audit logs (**ADMIN\_READ/DATA\_READ/DATA\_WRITE**), VPC Flow Logs + NAT logging, alert policies. (Matches **CLD.12.1.5, CLD.12.4.5**.) ([Microsoft Learn][2], [IT Governance][3])
* **Virtual vs physical network alignment** — verifies **Private Google Access** and logging signals; documentation of CSP underlay mapping is **MANUAL** (per shared-responsibility intent of **CLD.13.1.4**). ([Google Cloud][1])

> Handy references: Google’s ISO/IEC 27017 overview (lists the **seven cloud controls**), Microsoft’s 27017 note (37 controls + 7 new), IT Governance (explicit **CLD** numbers), and BSI’s whitepaper mapping (examples for **CLD.9.5.1/.9.5.2/.12.1.5**). ([Google Cloud][1], [Microsoft Learn][2], [IT Governance][3], [BSI][4])

[1]: https://cloud.google.com/security/compliance/iso-27017?utm_source=chatgpt.com "ISO/IEC 27017 - Compliance"
[2]: https://learn.microsoft.com/en-us/compliance/regulatory/offering-iso-27017?utm_source=chatgpt.com "ISO/IEC 27017:2015 Code of Practice for Information ..."
[3]: https://www.itgovernance.co.uk/blog/what-are-iso-27017-and-iso-27018-and-what-are-their-controls?utm_source=chatgpt.com "What Are ISO 27017 and ISO 27018, and What Are Their ..."
[4]: https://www.bsigroup.com/LocalFiles/en-IN/Resources/ISO-27017-overview-Whitepaper.pdf?utm_source=chatgpt.com "ISO/IEC 27017 Extending ISO/IEC 27001 into the Cloud"
