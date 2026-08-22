---
tier: 2
id: java-thymeleaf-unescaped-output
canonical_category: XSS
cwe: [CWE-79]
tier1_parent: xss
language: java
sink_signatures:
  - th:utext
no_rule_yet: true
safe_alternative: "Dùng thuộc tính thoát chuỗi mặc định `th:text` thay vì `th:utext`"
exploitable_when: >
  biểu thức `th:utext` hiển thị chuỗi chứa ký tự HTML do người dùng điều khiển
  mà không qua bộ lọc HTML sanitization
not_exploitable_when: >
  giá trị truyền vào `th:utext` là chuỗi tĩnh từ tài nguyên nội bộ đã được kiểm duyệt
  hoặc đã qua pipeline HTML sanitizer nghiêm ngặt
---

# `th:utext` — Unescaped Output in Thymeleaf (XSS)

Thymeleaf mặc định mã hoá HTML khi dùng `th:text`. Thuộc tính `th:utext` (unescaped text)
bỏ qua cơ chế bảo vệ này và chèn thẳng HTML thô vào trang giao diện.

Nên sử dụng `th:text` cho mọi dữ liệu động; chỉ dùng `th:utext` khi thực sự cần render HTML
và đã vệ sinh dữ liệu qua OWASP Java HTML Sanitizer.

## Vì sao `not_exploitable_when` quan trọng ở đây

Khi dữ liệu hiển thị bằng `th:utext` là chuỗi bản địa hoá cố định (i18n message) được nạp
từ file bundle nội bộ chứ không nhận từ input người dùng, không có rủi ro XSS.

## Nguồn

- Thymeleaf Documentation: Standard Dialect Reference (`th:utext`, `th:text`)
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
