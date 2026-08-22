---
tier: 1
id: insecure-deserialization
title: Insecure Deserialization
tags: [example, deserialization, cwe-502, a08, java]
---

# Insecure Deserialization

`ObjectInputStream.readObject()` trên dữ liệu attacker-controlled có thể dẫn tới RCE (gadget chains). OpenGrep rule `java-unsafe-deserialization` gắn CWE-502 / OWASP A08.

Mitigation: tránh Java native serialization; dùng JSON với schema; allowlist class nếu bắt buộc.
