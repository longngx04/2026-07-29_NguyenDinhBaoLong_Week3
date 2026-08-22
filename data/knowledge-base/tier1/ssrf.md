---
tier: 1
id: ssrf
title: Server-Side Request Forgery SSRF
tags: [example, ssrf, owasp-a10, request-forgery]
---

# SSRF — Server-Side Request Forgery

Server gọi URL do user cung cấp, có thể đụng metadata cloud (`169.254.169.254`) hoặc dịch vụ nội bộ.

Mitigation: allowlist scheme/host; chặn IP private; không follow redirect tùy tiện.
