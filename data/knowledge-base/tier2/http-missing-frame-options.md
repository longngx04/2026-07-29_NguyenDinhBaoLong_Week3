---
tier: 2
id: http-missing-frame-options
canonical_category: Security Misconfiguration
cwe: [CWE-1021]
tier1_parent: security-headers
language: http
sink_signatures:
  - X-Frame-Options
matches_rule_ids:
  - "10020"
safe_alternative: "Cấu hình tiêu đề X-Frame-Options: DENY hoặc SAMEORIGIN, hoặc chỉ thị CSP frame-ancestors"
exploitable_when: >
  ứng dụng chứa các chức năng hoặc biểu mẫu nhạy cảm (giao dịch, đổi mật khẩu) và cho phép bị nhúng vào thẻ <iframe> trên trang web bên thứ ba
not_exploitable_when: >
  trang web được thiết kế công khai không có chức năng nhạy cảm hoặc thao tác xác thực, hoặc đã dùng chỉ thị CSP frame-ancestors 'none' thay thế.
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
  - https://cwe.mitre.org/data/definitions/1021.html
---

# `X-Frame-Options` — Missing Anti-Clickjacking Header

## 1. Cơ chế rủi ro (Risk Mechanism)

Clickjacking (hay UI Redressing - CWE-1021 / ZAP Rule 10020) là kỹ thuật tấn công trong đó kẻ tấn công tạo một trang web độc hại và nhúng giao diện trang web đích vào bên trong một khung nhìn vô hình hoặc trong suốt (`<iframe style="opacity: 0;">`). Kẻ tấn công bố trí các nút bấm, trò chơi hoặc liên kết giả mạo phía trên giao diện ẩn để dẫn dụ nạn nhân (đang đăng nhập) nhấp chuột vào đúng vị trí của các nút hành động nhạy cảm trên trang đích (như "Chuyển tiền", "Xóa tài khoản", "Cấp quyền OAuth").

Khi phản hồi HTTP của ứng dụng không chứa tiêu đề `X-Frame-Options` (hoặc chỉ thị CSP `frame-ancestors`), trình duyệt sẽ cho phép bất kỳ trang web của bên thứ ba nào nhúng trang vào thẻ `<iframe>`, khiến toàn bộ các chức năng và biểu mẫu tương tác của ứng dụng đứng trước nguy cơ bị thao túng qua Clickjacking.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP của trang web chứa thao tác tài khoản nhưng không có bất kỳ cơ chế kiểm soát nhúng khung:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1536
Connection: keep-alive

<!DOCTYPE html>
<html>
<head><title>Quản lý tài khoản</title></head>
<body>
  <form action="/account/delete" method="POST">
    <button type="submit">Xóa vĩnh viễn tài khoản</button>
  </form>
</body>
</html>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Phản hồi HTTP bổ sung tiêu đề `X-Frame-Options: DENY` (hoặc `SAMEORIGIN`) kết hợp chỉ thị CSP `frame-ancestors`:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1536
Connection: keep-alive
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'

<!DOCTYPE html>
<html>
<head><title>Quản lý tài khoản</title></head>
<body>
  <form action="/account/delete" method="POST">
    <button type="submit">Xóa vĩnh viễn tài khoản</button>
  </form>
</body>
</html>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Phòng chống tấn công Clickjacking toàn diện:

1. **Lớp 1 — Thiết lập `X-Frame-Options: DENY` làm mặc định:**
   Cấu hình máy chủ web trả về `X-Frame-Options: DENY` để cấm hoàn toàn việc nhúng trang trong bất kỳ iframe nào. Nếu cần nhúng giữa các trang cùng một domain, sử dụng `X-Frame-Options: SAMEORIGIN`.
2. **Lớp 2 — Sử dụng chỉ thị hiện đại `Content-Security-Policy: frame-ancestors`:**
   Chỉ thị `frame-ancestors 'none'` hoặc `frame-ancestors 'self'` là giải pháp kế thừa chuẩn hóa (CSP Level 2/3) có độ ưu tiên cao hơn `X-Frame-Options` trên các trình duyệt hiện đại và hỗ trợ danh sách nhiều domain nguồn.
3. **Lớp 3 — Cấu hình Reverse Proxy / Nginx:**
   ```nginx
   add_header X-Frame-Options "DENY" always;
   add_header Content-Security-Policy "frame-ancestors 'none'" always;
   ```
4. **Lớp 4 — Cấu hình Spring Security:**
   Spring Security tự động cấu hình `X-Frame-Options: DENY`. Cần đảm bảo không tắt header writer trong filter chain.

## 4. Tài liệu tham khảo (References)

- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [MDN Web Docs: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [CWE-1021: Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)
