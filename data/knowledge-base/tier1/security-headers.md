---
tier: 1
id: security-headers
title: Security Headers
cwe: [CWE-693, CWE-1021]
owasp: [A05:2021]
tags: [security-headers, csp, x-content-type-options, x-frame-options, cwe-693, cwe-1021]
references:
  - https://owasp.org/www-project-secure-headers/
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/693.html
---

# Security Headers

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Security Headers (Các tiêu đề phản hồi an toàn HTTP - OWASP A05:2021 / CWE-693, CWE-1021) là các chỉ thị cấu hình được máy chủ gửi về cho trình duyệt (user-agent) nhằm kích hoạt hoặc siết chặt các cơ chế phòng vệ tích hợp sẵn trong trình duyệt.

Khi ứng dụng web phản hồi thiếu các tiêu đề bảo mật chuẩn mực:
- **Tấn công Clickjacking (CWE-1021):** Kẻ tấn công nhúng giao diện trang web vào một khung ẩn (`<iframe>`) trên website độc hại để lừa người dùng nhấp chuột ngoài ý muốn vào các nút thao tác nhạy cảm (chuyển tiền, thay đổi cài đặt bảo mật).
- **Tấn công MIME-Sniffing (CWE-693):** Trình duyệt tự động đoán sai loại nội dung (MIME type sniffing) và thực thi các tệp dữ liệu tĩnh không tin cậy (ảnh, văn bản tải lên) như mã nguồn JavaScript độc hại.
- **Tấn công Cross-Site Scripting (XSS) & Data Exfiltration:** Thiếu Content-Security-Policy (CSP) khiến trình duyệt cho phép thực thi mã kịch bản nội tuyến (inline script) và gửi dữ liệu phiên/token ra máy chủ của bên thứ ba.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Thiếu hoặc cấu hình CSP quá lỏng lẻo (Missing/Weak Content-Security-Policy)

Máy chủ phản hồi không có tiêu đề `Content-Security-Policy` hoặc cấu hình chứa các chỉ thị nguy hiểm như `'unsafe-inline'`, `'unsafe-eval'`, `data:`, `*`. Điều này vô hiệu hóa ranh giới cô lập nguồn tài nguyên, cho phép kẻ tấn công chèn mã khai thác XSS thành công.

### 2.2. Thiếu tiêu đề chống MIME-Sniffing (Missing X-Content-Type-Options)

Không có tiêu đề `X-Content-Type-Options: nosniff`. Khi người dùng tải lên tệp tin văn bản hoặc hình ảnh chứa mã HTML/JavaScript độc hại, trình duyệt cũ hoặc một số trình duyệt hiện đại có thể diễn giải sai định dạng và thực thi mã script.

### 2.3. Thiếu tiêu đề chống nhúng khung (Missing X-Frame-Options / CSP frame-ancestors)

Thiếu `X-Frame-Options: DENY` hoặc `X-Frame-Options: SAMEORIGIN` (hoặc CSP `frame-ancestors 'self'`), cho phép mọi website bên ngoài nhúng trang đích vào thẻ `<iframe>` để thực hiện tấn công UI Redressing / Clickjacking.

### 2.4. Thiếu bảo vệ chuyển giao HTTPS (Missing Strict-Transport-Security)

Thiếu tiêu đề `Strict-Transport-Security` (HSTS), khiến người dùng có nguy cơ bị tấn công hạ cấp giao thức (SSL Stripping) hoặc trung gian (Man-in-the-Middle) trong lần kết nối đầu tiên.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược triển khai Security Headers toàn diện:

1. **Lớp 1 — Áp dụng bộ tiêu đề bảo vệ cơ bản tại Gateway / Reverse Proxy:**
   Cấu hình Nginx, Envoy hoặc API Gateway tự động bổ sung các tiêu đề bảo mật cho toàn bộ phản hồi HTTP:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY` (hoặc `SAMEORIGIN` nếu cần nhúng nội bộ)
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
2. **Lớp 2 — Xây dựng chính sách Content-Security-Policy (CSP) chặt chẽ:**
   Xác định rõ ràng nguồn nạp kịch bản (`script-src`), kiểu dáng (`style-src`), hình ảnh (`img-src`), và giới hạn nguồn nhúng khung (`frame-ancestors 'none'`). Sử dụng nonce hoặc SHA-256 hash cho các script hợp lệ thay vì mở `'unsafe-inline'`.
3. **Lớp 3 — Kích hoạt HSTS với cờ preload:**
   Thiết lập `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` để đảm bảo 100% lưu lượng truy cập đều qua HTTPS.
4. **Lớp 4 — Kiểm thử tự động DAST và Audit định kỳ:**
   Tích hợp công cụ quét tự động (OWASP ZAP, Mozilla Observatory) trong CI/CD pipeline để phát hiện sớm các endpoint bị sót header bảo mật.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
