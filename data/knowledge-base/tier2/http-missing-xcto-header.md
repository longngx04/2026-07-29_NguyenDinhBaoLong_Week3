---
tier: 2
id: http-missing-xcto-header
canonical_category: Security Misconfiguration
cwe: [CWE-693]
tier1_parent: security-headers
language: http
sink_signatures:
  - X-Content-Type-Options
matches_rule_ids:
  - "10021"
safe_alternative: "Thêm tiêu đề X-Content-Type-Options: nosniff trong mọi phản hồi HTTP"
exploitable_when: >
  máy chủ phục vụ tệp tin do người dùng tải lên hoặc không khai báo Content-Type rõ ràng,
  dẫn đến việc trình duyệt tự suy đoán MIME type (MIME sniffing)
not_exploitable_when: >
  mọi phản hồi đều khai báo Content-Type chính xác và máy chủ không phục vụ bất kỳ tệp tin tải lên nào do người dùng kiểm soát.
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
  - https://cwe.mitre.org/data/definitions/693.html
---

# `X-Content-Type-Options` — Missing X-Content-Type-Options Header

## 1. Cơ chế rủi ro (Risk Mechanism)

Khi trình duyệt nhận được một phản hồi HTTP thiếu tiêu đề `X-Content-Type-Options` (ZAP Rule 10021 / CWE-693), một số trình duyệt (đặc biệt khi xử lý các tài nguyên không rõ ràng hoặc kiểu MIME không chuẩn) sẽ tự động kích hoạt tính năng "MIME type sniffing" (tự động suy đoán định dạng tệp tin dựa trên nội dung byte thực tế thay vì tin tưởng tiêu đề `Content-Type` do máy chủ cung cấp).

Cơ chế này tạo ra rủi ro nghiêm trọng khi ứng dụng cho phép người dùng tải lên các tệp tin tưởng chừng vô hại (như ảnh `.png`, `.jpg`, hoặc tệp văn bản `.txt`, `.csv`) nhưng chứa mã HTML/JavaScript độc hại ở đầu tệp (Polyglot files). Khi trình duyệt tải tệp này và suy đoán sai thành `text/html`, mã JavaScript độc hại sẽ được thực thi trong ngữ cảnh của ứng dụng, dẫn đến tấn công Cross-Site Scripting (XSS).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP trả về tài nguyên người dùng tải lên nhưng không có tiêu đề `X-Content-Type-Options`:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/plain; charset=UTF-8
Content-Length: 256
Connection: keep-alive

<script>alert(document.domain)</script>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Phản hồi HTTP bổ sung tiêu đề `X-Content-Type-Options: nosniff` để vô hiệu hóa tính năng MIME sniffing của trình duyệt:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Content-Type: text/plain; charset=UTF-8
Content-Length: 256
Connection: keep-alive
X-Content-Type-Options: nosniff

<script>alert(document.domain)</script>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Khắc phục triệt để lỗ hổng thiếu `X-Content-Type-Options`:

1. **Lớp 1 — Luôn gửi kèm tiêu đề `X-Content-Type-Options: nosniff`:**
   Cấu hình máy chủ web / API Gateway bổ sung tiêu đề `X-Content-Type-Options: nosniff` vào 100% các phản hồi HTTP (cả phản hồi thành công 2xx lẫn phản hồi lỗi 4xx/5xx).
2. **Lớp 2 — Khai báo chính xác tiêu đề `Content-Type` kèm bảng mã `charset`:**
   Đảm bảo mọi phản hồi HTTP đều chỉ định đúng MIME type tương ứng với dữ liệu (ví dụ: `application/json; charset=UTF-8`, `image/png`, `text/html; charset=UTF-8`).
3. **Lớp 3 — Cấu hình Nginx / Web Server:**
   Thêm chỉ thị trong khối cấu hình `server` hoặc `http`:
   ```nginx
   add_header X-Content-Type-Options "nosniff" always;
   ```
4. **Lớp 4 — Cấu hình Spring Security:**
   Trong Spring Security, cờ này được kích hoạt mặc định trong bộ lọc `HeaderWriterFilter`. Đảm bảo không gọi lệnh tắt headers.

## 4. Tài liệu tham khảo (References)

- [OWASP HTTP Headers Cheat Sheet — X-Content-Type-Options](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN Web Docs: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)
