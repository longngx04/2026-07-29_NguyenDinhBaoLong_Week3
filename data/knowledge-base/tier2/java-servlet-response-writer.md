---
tier: 2
id: java-servlet-response-writer
canonical_category: XSS
cwe: [CWE-79]
tier1_parent: xss
language: java
sink_signatures:
  - javax.servlet.http.HttpServletResponse.getWriter
  - java.io.PrintWriter.print
no_rule_yet: true
safe_alternative: "Mã hoá HTML context-aware qua OWASP Java HTML Sanitizer hoặc dùng template engine tự động escape"
exploitable_when: >
  dữ liệu caller chưa được mã hoá ký tự HTML đặc biệt (`<`, `>`, `"`, `'`, `&`)
  được ghi trực tiếp vào phản hồi HTTP có content-type là text/html
not_exploitable_when: >
  nội dung ghi ra là hằng số, phản hồi có Content-Type an toàn như application/json,
  hoặc dữ liệu đã được mã hoá context-aware (HTML entity encode)
---

# `HttpServletResponse.getWriter` / `PrintWriter.print` — Cross-Site Scripting (XSS)

Ghi trực tiếp tham số người dùng ra luồng phản hồi của Servlet mà không mã hoá ký tự
đặc biệt cho phép trình duyệt của nạn nhân thực thi mã JavaScript độc hại.

Giải pháp là sử dụng các thư viện mã hoá ngữ cảnh (context-aware encoding) như OWASP Java Encoder
hoặc cấu hình kiểu dữ liệu trả về `application/json` khi chỉ truyền tải dữ liệu thuần.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu Servlet phục vụ API REST trả về `Content-Type: application/json` hoặc `text/plain`,
trình duyệt sẽ không phân tích cú pháp HTML/JS, do đó không thể kích hoạt XSS.

## Nguồn

- Java Servlet API: `javax.servlet.http.HttpServletResponse`, `java.io.PrintWriter`
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
