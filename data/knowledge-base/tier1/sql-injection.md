---
tier: 1
id: sql-injection
title: SQL Injection
cwe: [CWE-89]
owasp: [A03:2021]
tags: [example, sql-injection, sqli, cwe-89, injection, java]
---

# SQL Injection

Dữ liệu người dùng đi vào câu lệnh SQL mà không qua tham số hoá, cho phép kẻ tấn
công đổi ngữ nghĩa truy vấn.

## Biến thể: nối chuỗi trực tiếp

Vulnerable pattern:

```java
String q = "SELECT * FROM users WHERE name = '" + userInput + "'";
statement.executeQuery(q);
```

Attacker input ' OR '1'='1 thay đổi logic query. Mitigation: dùng `PreparedStatement` với placeholder `?`.

## Biến thể: trên form đăng nhập

Query kiểu `SELECT * FROM users WHERE user='...' AND pass='...'` ghép chuỗi cho phép bypass đăng nhập bằng `' OR '1'='1' --`.

Dấu hiệu: SQL Injection / CWE-89 trên form login. Fix: parameterized query + hash mật khẩu, không so sánh plaintext trong SQL động.

## Khắc phục chung

Dùng `PreparedStatement` với placeholder `?`. Không nối chuỗi vào SQL động.
