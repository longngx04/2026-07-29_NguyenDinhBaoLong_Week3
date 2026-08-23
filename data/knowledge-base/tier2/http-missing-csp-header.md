---
tier: 2
id: http-missing-csp-header
canonical_category: Security Misconfiguration
cwe: [CWE-693]
tier1_parent: security-headers
language: http
sink_signatures:
  - Content-Security-Policy
matches_rule_ids:
  - "10038"
safe_alternative: "Cấu hình tiêu đề Content-Security-Policy (CSP) chặt chẽ hạn chế nguồn tài nguyên thực thi"
exploitable_when: >
  ứng dụng web chứa các lỗ hổng chèn mã (XSS/HTML Injection) hoặc nạp tài nguyên động từ bên thứ ba
  mà không có chính sách kiểm soát nguồn gốc
not_exploitable_when: >
  tài nguyên là tệp tĩnh thuần túy không chứa mã thực thi và không nhận dữ liệu đầu vào người dùng,
  hoặc ứng dụng đã áp dụng CSP tập trung ở tầng reverse proxy / API Gateway.
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  - https://cwe.mitre.org/data/definitions/693.html
---

# `Content-Security-Policy` — Missing Content Security Policy Header

## 1. Cơ chế rủi ro (Risk Mechanism)

Content Security Policy (CSP) là lớp bảo vệ bổ sung giúp phát hiện và giảm thiểu nhiều loại tấn công, đặc biệt là Cross-Site Scripting (XSS) và data injection. Khi máy chủ phản hồi các trang HTML mà không gửi kèm tiêu đề `Content-Security-Policy` (ZAP Rule 10038 / CWE-693), trình duyệt sẽ áp dụng chính sách mở mặc định: cho phép nạp và thực thi mã script, style, image, font từ bất kỳ nguồn gốc (origin) nào, đồng thời cho phép chạy các đoạn script nội tuyến (`inline script`) và hàm `eval()`.

Nếu ứng dụng xuất hiện bất kỳ điểm yếu chèn dữ liệu người dùng chưa được lọc (Reflected/Stored/DOM XSS), kẻ tấn công có thể dễ dàng thực thi mã kịch bản độc hại, đánh cắp cookie/phiên làm việc, đọc nội dung DOM nhạy cảm và chuyển hướng nạn nhân sang các máy chủ giả mạo.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP trả về nội dung HTML nhưng hoàn toàn thiếu tiêu đề `Content-Security-Policy`:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1024
Connection: keep-alive

<!DOCTYPE html>
<html>
<head><title>WebGoat Portal</title></head>
<body>
  <h1>Chào mừng người dùng</h1>
</body>
</html>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Phản hồi HTTP bổ sung tiêu đề `Content-Security-Policy` với các chỉ thị giới hạn nghiêm ngặt nguồn tài nguyên:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1024
Connection: keep-alive
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

<!DOCTYPE html>
<html>
<head><title>WebGoat Portal</title></head>
<body>
  <h1>Chào mừng người dùng</h1>
</body>
</html>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Triển khai Content Security Policy an toàn và hiệu quả:

1. **Lớp 1 — Thiết lập chính sách CSP tối thiểu an toàn (Strict Baseline CSP):**
   Cấu hình `default-src 'self'` để mặc định chỉ nạp tài nguyên từ cùng origin. Chặn hoàn toàn việc nhúng đối tượng nguy hiểm bằng `object-src 'none'` và chặn clickjacking bằng `frame-ancestors 'none'`.
2. **Lớp 2 — Sử dụng Nonce hoặc Hash cho Inline Scripts:**
   Tránh sử dụng `'unsafe-inline'`. Nếu bắt buộc phải dùng inline script, tạo nonce ngẫu nhiên theo từng request (ví dụ: `script-src 'self' 'nonce-rAnd0m123'`) và gắn thuộc tính `nonce` vào thẻ `<script>`.
3. **Lớp 3 — Chế độ Báo cáo thử nghiệm (Report-Only Mode):**
   Trong quá trình triển khai ban đầu, sử dụng tiêu đề `Content-Security-Policy-Report-Only` kết hợp chỉ thị `report-uri` hoặc `report-to` để thu thập và tinh chỉnh các vi phạm chính sách trước khi kích hoạt chặn thực sự.
4. **Lớp 4 — Cấu hình tập trung tại Reverse Proxy / Gateway:**
   Khai báo chỉ thị CSP trên Nginx (`add_header Content-Security-Policy "..." always;`) hoặc cấu hình Spring Security `http.headers(headers -> headers.contentSecurityPolicy(csp -> csp.policyDirectives("...")))`.

## 4. Tài liệu tham khảo (References)

- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [MDN Web Docs: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
