---
tier: 2
id: java-sql-statement-execute
canonical_category: SQL Injection
cwe: [CWE-89]
tier1_parent: sql-injection
language: java
sink_signatures:
  - java.sql.Statement.execute
  - java.sql.Statement.executeQuery
  - java.sql.Statement.executeUpdate
matches_rule_ids:
  - java-sql-statement-execution
safe_alternative: "java.sql.PreparedStatement với placeholder `?` và setString/setInt"
exploitable_when: >
  chuỗi truy vấn được dựng bằng nối chuỗi hoặc String.format với giá trị mà
  caller kiểm soát, và giá trị đó không đi qua allowlist ký tự
not_exploitable_when: >
  truy vấn là hằng biên dịch không có nội suy, hoặc mọi giá trị nội suy đều lấy
  từ một allowlist cố định trong mã, hoặc giá trị đã qua PreparedStatement.setXxx
---

# `Statement.execute*` — SQL Injection

`java.sql.Statement` nhận nguyên một chuỗi SQL và gửi thẳng tới driver. Driver
không phân biệt được phần nào là lệnh, phần nào là dữ liệu.

`PreparedStatement` khác về bản chất: câu lệnh được biên dịch trước với placeholder,
giá trị gửi sau theo kênh riêng, nên dữ liệu không bao giờ được đọc như cú pháp.

## Vì sao `not_exploitable_when` quan trọng ở đây

`SET SCHEMA "` + name + `"` nhìn giống lỗ hổng, nhưng nếu `name` chỉ nhận giá trị
từ một enum cố định thì kẻ tấn công không chèn được gì. Báo nó là lỗ hổng thật là
dương tính giả — và đó là loại sai mà bộ đo ghi vào over-claim rate.

## Nguồn

- Java SE API: `java.sql.Statement`, `java.sql.PreparedStatement`
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
