---
tier: 1
id: vulnerable-components
title: Vulnerable and Outdated Components
tags: [example, components, cve, a06, dependencies]
---

# Vulnerable Components

Dùng thư viện có CVE đã công bố (log4j, cũ Spring, …). SCA/tool dependency giúp phát hiện; SAST pattern không thay thế được việc patch.

Mitigation: inventory dependency, cập nhật, theo dõi advisory.
