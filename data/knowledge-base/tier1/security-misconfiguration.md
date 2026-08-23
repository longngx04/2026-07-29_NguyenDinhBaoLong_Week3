---
tier: 1
id: security-misconfiguration
title: Security Misconfiguration
cwe: [CWE-16, CWE-209, CWE-942]
owasp: [A05:2021]
tags: [example, misconfiguration, a05, defaults, cwe-16, hardening, security-headers]
references:
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/16.html
---

# Security Misconfiguration

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Security Misconfiguration (Cấu hình bảo mật sai sót - OWASP A05:2021 / CWE-16) là lớp lỗ hổng phổ biến xảy ra khi các thành phần của hệ thống phần mềm (máy chủ web, máy chủ ứng dụng, cơ sở dữ liệu, framework, cloud container hoặc dịch vụ mạng) được cài đặt và vận hành với các thiết lập bảo mật thiếu an toàn, giữ cấu hình mặc định (default credentials/settings), hoặc bật các tính năng gỡ lỗi không cần thiết.

Tác động của Security Misconfiguration:
- **Lộ lọt thông tin cấu trúc nội bộ (Information Disclosure):** Stacktrace ra production tiết lộ phiên bản framework, cấu trúc bảng CSDL, đường dẫn tệp tin mã nguồn và biến môi trường.
- **Truy cập trái phép vào trang quản trị:** Kẻ tấn công truy cập trực tiếp vào các console quản trị, Swagger UI, Spring Boot Actuator không có xác thực để kiểm soát hệ thống.
- **Leo thang xâm nhập và khai thác liên tầng:** Cấu hình CORS quá lỏng lẻo (`Access-Control-Allow-Origin: *` kèm credentials) cho phép trang web bên ngoài đánh cắp dữ liệu người dùng.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Lộ Stacktrace và Thông báo Lỗi chi tiết trên Production (Verbose Errors)

Khi ứng dụng gặp lỗi ngoại lệ (500 Internal Server Error), thay vì trả về trang lỗi thân thiện, hệ thống in nguyên stacktrace chi tiết chứa thông tin truy vấn SQL, tên thư viện và đường dẫn file hệ thống ra giao diện cho người dùng xem.

### 2.2. Bật tính năng Duyệt Thư mục (Directory Listing Enabled)

Máy chủ web (Nginx, Apache, Tomcat) được cấu hình cho phép duyệt danh mục khi không có file `index.html`, cho phép kẻ tấn công tải về các tệp sao lưu (`.bak`, `.zip`), file cấu hình hoặc mã nguồn bị bỏ quên.

### 2.3. Cổng quản trị và Endpoint giám sát mở tự do (Unprotected Admin/Actuator Endpoints)

Các endpoint như `/actuator/heapdump`, `/actuator/env`, `/swagger-ui.html`, `/admin` không yêu cầu xác thực hoặc chỉ ẩn URL mà không phân quyền, cho phép kẻ tấn công tải bộ nhớ RAM máy chủ về giải mã mật khẩu hoặc thông tin thẻ.

### 2.4. Thiếu các HTTP Security Headers

Hệ thống phản hồi thiếu các header bảo vệ quan trọng như `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, hoặc `Strict-Transport-Security` (HSTS), khiến ứng dụng dễ bị tấn công Clickjacking, MIME-sniffing hoặc hạ cấp giao thức HTTP.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống Security Misconfiguration bao gồm:

1. **Lớp 1 — Quy trình Hardening hệ thống chuẩn hóa (Security Hardening Checklist):**
   Xây dựng và tuân thủ danh mục kiểm tra an toàn hệ thống (CIS Benchmarks, OWASP Hardening Guide); tự động hóa triển khai hạ tầng bằng Infrastructure as Code (IaC - Terraform, Ansible, Dockerfile) với cấu hình tối giản (minimal footprint).
2. **Lớp 2 — Tắt chế độ Debug & Xử lý lỗi tập trung:**
   Vô hiệu hóa toàn bộ cờ debug (`debug=false`), thay thế stacktrace bằng các trang thông báo lỗi chung (Generic Error Pages) kết hợp mã theo dõi lỗi (Correlation ID) để lưu vết nội bộ.
3. **Lớp 3 — Cấu hình đầy đủ HTTP Security Headers:**
   Kích hoạt toàn bộ các tiêu đề bảo mật HTTP tiêu chuẩn (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Permissions-Policy`, `Referrer-Policy`).
4. **Lớp 4 — Quét cấu hình định kỳ & Kiểm soát đặc quyền:**
   Chạy công cụ quét cấu hình tự động (SCA, CSPM, CI Linting) trong pipeline CI/CD để phát hiện sớm các thay đổi cấu hình nguy hiểm. Áp dụng phân quyền tối thiểu (least privilege) cho mọi service account.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
