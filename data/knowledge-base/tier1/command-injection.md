---
tier: 1
id: command-injection
title: OS Command Injection via Runtime.exec
tags: [example, command-injection, cmdi, cwe-78, injection, java]
---

# Command Injection — Runtime.exec

```java
Runtime.getRuntime().exec(userControlled);
```

Nếu `userControlled` chứa `; rm -rf /` hoặc pipe, attacker chạy lệnh OS. OpenGrep rule `java-command-execution` bắt pattern này. Fix: tránh shell; dùng ProcessBuilder với allowlist argument; không nối chuỗi lệnh.
