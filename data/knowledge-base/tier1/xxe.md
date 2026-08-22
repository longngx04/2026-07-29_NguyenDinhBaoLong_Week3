---
tier: 1
id: xxe
title: XML External Entity XXE
tags: [example, xxe, xml, cwe-611]
---

# XXE — XML External Entity

Parser XML xử lý external entity → đọc file local hoặc SSRF. Disable DTD/external entities trên parser (Java: `XMLConstants.FEATURE_SECURE_PROCESSING`).
