---
tier: 2
id: http-missing-permissions-policy
canonical_category: Security Misconfiguration
cwe: [CWE-693]
tier1_parent: security-headers
language: http
sink_signatures:
  - Permissions-Policy
matches_rule_ids:
  - "10063"
safe_alternative: "Khai báo tiêu đề Permissions-Policy (Feature-Policy cũ) giới hạn các API trình duyệt nhạy cảm như geolocation, camera, microphone"
exploitable_when: >
  trang web tải mã script của bên thứ ba, tiện ích mở rộng hoặc cho phép nhúng iframe
  từ các nguồn khác mà không giới hạn quyền truy cập phần cứng và API nhạy cảm của trình duyệt.
not_exploitable_when: >
  ứng dụng không sử dụng bất kỳ API phần cứng/thiết bị nhạy cảm nào và không
  nhúng mã nguồn hay iframe của bên thứ ba, hoặc đã đặt Permissions-Policy ở tầng reverse proxy / Gateway.
references:
  - https://owasp.org/www-project-secure-headers/
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
  - https://cwe.mitre.org/data/definitions/693.html
---

# `Permissions-Policy` — Missing Permissions Policy Header

## 1. Cơ chế rủi ro (Risk Mechanism)

Tiêu đề HTTP `Permissions-Policy` (trước đây là `Feature-Policy`) cho phép quản trị viên web kiểm soát rõ ràng các tính năng và API nhạy cảm của trình duyệt (như Geolocation, Camera, Microphone, Payment, FLoC, USB, v.v.) được phép kích hoạt trên trang hiện tại hoặc trong các iframe được nhúng.

Khi máy chủ không gửi tiêu đề `Permissions-Policy`:
- Các iframe hoặc mã script của bên thứ ba (như thư viện quảng cáo, analytics) có thể tự động gọi các API quyền riêng tư nếu người dùng vô tình cấp quyền cho trang chính.
- Tăng bề mặt tấn công khi có lỗ hổng XSS xảy ra trên trang web.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP từ máy chủ không chứa tiêu đề `Permissions-Policy`:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1024

<!DOCTYPE html>
<html>
  <head><title>Web Application</title></head>
  <body><iframe src="https://third-party-widget.example.com"></iframe></body>
</html>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Máy chủ phản hồi với tiêu đề `Permissions-Policy` vô hiệu hóa các API không cần thiết:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
Content-Length: 1024

<!DOCTYPE html>
<html>
  <head><title>Web Application</title></head>
  <body><iframe src="https://third-party-widget.example.com"></iframe></body>
</html>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

1. **Lớp 1 — Khai báo chính sách Permissions-Policy tối thiểu:**
   Chỉ định rõ các tính năng nhạy cảm bị vô hiệu hóa hoàn toàn bằng cú pháp `feature=()` hoặc chỉ cho phép same-origin `feature=(self)`:
   ```http
   Permissions-Policy: camera=(), microphone=(), geolocation=(self), payment=()
   ```
2. **Lớp 2 — Cấu hình tập trung tại Reverse Proxy / API Gateway:**
   - Trên Nginx: `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;`
   - Trong Spring Security: Khai báo cấu hình custom headers qua `http.headers(headers -> headers.addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", "camera=(), microphone=()")))`.
3. **Lớp 3 — Giới hạn thuộc tính `allow` trên các thẻ `<iframe>`:**
   Nếu bắt buộc nhúng iframe bên thứ ba, không cấp thêm quyền trong thuộc tính `allow` trừ khi thực sự cần thiết.

## 4. Tài liệu tham khảo (References)

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Docs: Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
