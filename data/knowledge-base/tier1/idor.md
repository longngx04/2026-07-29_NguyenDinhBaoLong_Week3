---
tier: 1
id: idor
title: Insecure Direct Object Reference IDOR
tags: [example, idor, access-control, broken-access-control, a01]
---

# IDOR — Insecure Direct Object Reference

Đổi `userId=123` thành `124` xem dữ liệu người khác vì thiếu kiểm tra ownership.

Thuộc Broken Access Control (OWASP A01). Fix: authorize trên mọi object ID phía server.
