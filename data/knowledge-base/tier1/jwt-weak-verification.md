---
tier: 1
id: jwt-weak-verification
title: JWT weak verification
tags: [example, jwt, authentication, integrity]
---

# JWT — weak verification

Chấp nhận `alg=none`, dùng secret yếu, hoặc tin `kid`/`jku` từ header mà không validate → privilege escalation.

Mitigation: pin algorithm, secret mạnh, không lấy khóa từ input người dùng.
