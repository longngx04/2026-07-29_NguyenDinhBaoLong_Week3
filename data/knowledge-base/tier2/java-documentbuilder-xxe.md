---
tier: 2
id: java-documentbuilder-xxe
canonical_category: XXE
cwe: [CWE-611]
tier1_parent: xxe
language: java
sink_signatures:
  - javax.xml.parsers.DocumentBuilderFactory.newInstance
no_rule_yet: true
safe_alternative: "Tắt DTD ngoài và thực thể ngoài qua setFeature(FEATURE_SECURE_PROCESSING, true) và disallow-doctype-decl"
exploitable_when: >
  parser XML phân tích cú pháp tài liệu từ người dùng gửi lên mà chưa tắt tính năng
  nạp thực thể ngoài (External Entities) và DTD
not_exploitable_when: >
  DocumentBuilderFactory đã được cấu hình disallow-doctype-decl=true hoặc đã vô hiệu hoá
  toàn bộ external-general-entities và external-parameter-entities
---

# `DocumentBuilderFactory.newInstance` — XML External Entity (XXE) Injection

Mặc định, nhiều bộ phân tích cú pháp XML trong Java cho phép tham chiếu tới các thực thể DTD bên ngoài.
Kẻ tấn công có thể chèn các thực thể `SYSTEM` trỏ tới tệp tin cục bộ (`file:///etc/passwd`) hoặc gọi dịch vụ
nội bộ (SSRF) qua luồng XML tải lên.

Cần cấu hình các feature bảo mật cho `DocumentBuilderFactory` như `http://apache.org/xml/features/disallow-doctype-decl`
thành `true` trước khi khởi tạo `DocumentBuilder`.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu nhà phát triển đã gọi `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
hoặc ứng dụng chỉ đọc XML từ tài nguyên đóng gói sẵn trong tệp JAR của hệ thống, XXE không thể bị khai thác.

## Nguồn

- OWASP Cheat Sheet Series: XML External Entity Prevention Cheat Sheet
- Java XML API: `javax.xml.parsers.DocumentBuilderFactory`
- CWE-611: Improper Restriction of XML External Entity Reference
