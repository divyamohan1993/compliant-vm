# **GDPR checker**

### What the script verifies (and why)

* **Art. 32 – Security of processing**: encryption at rest with **CMEK** + rotation, minimal exposure (no public IPs; IAP-only SSH), audit controls (Data Access logs), availability/resilience evidence (snapshot policy). ([EUR-Lex][1], [GDPR Text][2])
* **Art. 25 – Data protection by design/default**: OS Login (unique IDs), no 0.0.0.0/0 ingress, Owner-role hygiene. ([EUR-Lex][1])
* **Art. 33/34 – Breach notification**: presence of monitoring alerts as *operational readiness signal* (legal notification remains **manual**). ([GDPR][3])
* **Art. 30 – Records of processing activities (RoPA)**: flagged **MANUAL**—must exist, but not testable by cloud APIs. ([GDPR][4], [GDPR Text][5], [Legislation.gov.uk][6])
* **Art. 28 – Processor contracts (DPA/SCC 2021/915)**: flagged **MANUAL**—you must have a DPA with Google (and SCCs where applicable). ([GDPR][7], [EUR-Lex][8])
* **Art. 44–49 – International transfers**: if your region isn’t obviously EU/EEA (your default is `asia-south1`), the checker reminds you to ensure SCCs/adequacy + TIA. ([EUR-Lex][1])
* **Art. 5 – Principles (storage limitation & accountability)**: verifies that **logging** retention is finite (not indefinite). Your actual **data** retention schedules still need **manual** review. ([GDPR][9], [GDPR Text][10], [dataprotection.ie][11])


[1]: https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng?utm_source=chatgpt.com "Regulation - 2016/679 - EN - gdpr - EUR-Lex - European Union"
[2]: https://gdpr-text.com/en/read/article-32/?utm_source=chatgpt.com "Article 32 📖 GDPR. Security of processing"
[3]: https://gdpr-info.eu/?utm_source=chatgpt.com "General Data Protection Regulation (GDPR) – Legal Text"
[4]: https://gdpr-info.eu/art-30-gdpr/?utm_source=chatgpt.com "Art. 30 GDPR – Records of processing activities"
[5]: https://gdpr-text.com/en/read/article-30/?utm_source=chatgpt.com "Article 30 📖 GDPR. Records of processing activities"
[6]: https://www.legislation.gov.uk/eur/2016/679/article/30?utm_source=chatgpt.com "Regulation (EU) 2016/679 of the European Parliament and ..."
[7]: https://gdpr-info.eu/art-28-gdpr/?utm_source=chatgpt.com "Art. 28 GDPR – Processor - General Data Protection ..."
[8]: https://eur-lex.europa.eu/eli/dec_impl/2021/915/oj/eng?utm_source=chatgpt.com "Implementing decision - 2021/915 - EN - EUR-Lex"
[9]: https://gdpr-info.eu/art-5-gdpr/?utm_source=chatgpt.com "Art. 5 GDPR – Principles relating to processing of personal ..."
[10]: https://gdpr-text.com/en/read/article-5/?utm_source=chatgpt.com "Article 5 📖 GDPR. Principles relating to processing of ..."
[11]: https://www.dataprotection.ie/en/individuals/data-protection-basics/principles-data-protection?utm_source=chatgpt.com "Principles of Data Protection"
