# **Digital Personal Data Protection Act, 2023 + Draft DPDP Rules (2025)**

## What the checker maps to (with sources)

* **Security safeguards & breach notification**: DPDP §8(5) requires “reasonable security safeguards” and **§8(6)** requires intimation of personal data breaches to the **Data Protection Board of India** and each affected data principal “in the form and manner as may be prescribed.” The script verifies logging, hardened ingress, encryption-at-rest (strong control), monitoring alerts & channels to evidence readiness.&#x20;

* **Consent & Consent Managers**: Consent standards + Consent Manager registration are set in §6; the module flags these as **MANUAL** evidences (notice text, withdrawal parity, using a registered Consent Manager).&#x20;

* **Children’s data**: §9 mandates verifiable parental consent and bans tracking/targeted ads directed at children (unless exempted by notification). Marked **MANUAL** due to app-level logic.&#x20;

* **Significant Data Fiduciary (SDF)**: §10 defines SDF designation and extra obligations (DPO in India, independent audit, periodic DPIA). The script reminds/flags these as **MANUAL** because SDF status is by government notification.&#x20;

* **Cross-border transfers**: **§16** authorizes a **negative list** approach (transfers generally allowed except to restricted countries notified by the Central Government). The script notes your region and flags the need to check the restricted list when notified.&#x20;
  (Background analysis on the negative-list model and draft Rules context: ([ITIF][1], [Securiti][2]))

* **Rules status / timelines**: MeitY has released **Draft DPDP Rules 2025** for consultation (Feb 2025). Some commentary expects **72-hour** breach-reporting steps in the Rules; treat timelines as **draft** until finalized. ([MeitY][3], [IAPP][4], [Sai Krishna Associates][5])

> Primary text of the **DPDP Act, 2023** (official PDF) used to map the automated checks and the manual evidences.&#x20;

---

[1]: https://itif.org/publications/2025/06/09/india-cross-border-data-transfer-regulation/?utm_source=chatgpt.com "India's Cross-Border Data Transfer Regulation"
[2]: https://securiti.ai/cross-border-data-transfer-requirements-under-india-dpdpa/?utm_source=chatgpt.com "Cross-Border Data Transfer Requirements Under India ..."
[3]: https://www.meity.gov.in/documents/act-and-policies?utm_source=chatgpt.com "Act and Policies"
[4]: https://iapp.org/news/a/decoding-india-s-draft-dpdpa-rules-for-the-world?utm_source=chatgpt.com "Decoding India's draft DPDPA rules for the world"
[5]: https://www.saikrishnaassociates.com/intimation-of-personal-data-breach-under-the-draft-digital-personal-data-protection-rules-2025/?utm_source=chatgpt.com "Intimation of Personal Data Breach under the Draft Digital ..."
