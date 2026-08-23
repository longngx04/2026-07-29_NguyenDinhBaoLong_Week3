---
tier: 1
id: caching-policy
title: Insecure Caching Policy
cwe: [CWE-524, CWE-525]
owasp: [A05:2021]
tags: [caching, cache-control, cwe-524]
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/524.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
---

# Insecure Caching Policy

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Insecure Caching Policy (Chính sách lưu đệm thiếu an toàn - OWASP A05:2021 / CWE-524, CWE-525) xảy ra khi máy chủ phản hồi các tài nguyên chứa dữ liệu nhạy cảm (thông tin cá nhân, báo cáo tài chính, mã phiên, dữ liệu giao dịch) nhưng không thiết lập hoặc thiết lập sai các chỉ thị điều khiển lưu đệm HTTP (HTTP Cache-Control Headers).

Tác động của Insecure Caching Policy:
- **Rò rỉ dữ liệu qua bộ nhớ tạm trình duyệt (Browser Cache Exposure - CWE-524):** Khi người dùng sử dụng máy tính công cộng (shared computer) hoặc máy tính dùng chung trong doanh nghiệp, người dùng tiếp theo có thể nhấn nút Back trên trình duyệt hoặc truy cập thư mục cache cục bộ để xem toàn bộ thông tin nhạy cảm của người dùng trước đó.
- **Lưu trữ dữ liệu nhạy cảm trên Proxy trung gian (Shared / Intermediate Proxy Cache - CWE-525):** Nếu không có chỉ thị `private`, các máy chủ proxy trung gian hoặc CDN có thể lưu bản sao phản hồi chứa dữ liệu cá nhân của một người dùng và phục vụ lại cho người dùng khác.
- **Vi phạm quy định bảo vệ dữ liệu (Compliance Violations):** Lưu đệm không kiểm soát các dữ liệu thẻ thanh toán (PCI-DSS) hoặc thông tin sức khỏe/định danh (GDPR/HIPAA) trên đĩa cứng cục bộ.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Thiếu tiêu đề Cache-Control trên các Endpoint nhạy cảm (Missing Cache-Control Headers)

Máy chủ phục vụ các trang thông tin tài khoản hoặc báo cáo cá nhân nhưng không gửi kèm bất kỳ chỉ thị cache nào, khiến trình duyệt tự áp dụng cơ chế heuristic caching và lưu trang vào bộ nhớ tạm.

### 2.2. Sử dụng chỉ thị lỏng lẻo cho dữ liệu riêng tư (Public Caching of Private Data)

Sử dụng `Cache-Control: public, max-age=3600` cho các API trả về dữ liệu người dùng đã đăng nhập, cho phép các proxy chia sẻ và bộ định tuyến biên lưu đệm nội dung riêng tư.

### 2.3. Thiếu chỉ thị tương thích ngược HTTP/1.0 (Missing Pragma / Expires Headers)

Chỉ cấu hình `Cache-Control` mà quên các tiêu đề tương thích cho các client hoặc proxy HTTP/1.0 cũ (`Pragma: no-cache`, `Expires: 0`).

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược thiết lập chính sách lưu đệm an toàn:

1. **Lớp 1 — Áp dụng chỉ thị cấm lưu đệm nghiêm ngặt cho toàn bộ tài nguyên nhạy cảm:**
   Mọi phản hồi HTTP chứa dữ liệu cá nhân, trạng thái phiên, hoặc kết quả xác thực phải đính kèm đầy đủ bộ ba tiêu đề:
   ```http
   Cache-Control: no-store, no-cache, must-revalidate, max-age=0
   Pragma: no-cache
   Expires: 0
   ```
2. **Lớp 2 — Phân biệt rõ ràng giữa tài nguyên tĩnh và dữ liệu động:**
   - **Tài nguyên tĩnh (CSS, JS, Fonts, Ảnh công khai):** Thiết lập `Cache-Control: public, max-age=31536000, immutable` kết hợp phiên bản hóa (cache busting) để tối ưu hiệu năng.
   - **Dữ liệu động / API cá nhân:** Luôn mặc định cấu hình `no-store` hoặc `private, no-cache`.
3. **Lớp 3 — Cấu hình tập trung tại Gateway / Web Server:**
   Đảm bảo Reverse Proxy / API Gateway tự động bổ sung tiêu đề chống lưu đệm cho các đường dẫn nhạy cảm (`/api/*`, `/user/*`, `/admin/*`, `/account/*`).
4. **Lớp 4 — Kiểm thử tự động DAST:**
   Sử dụng công cụ kiểm thử tự động quét xác minh toàn bộ các endpoint sau xác thực có phản hồi đầy đủ chỉ thị `Cache-Control: no-store`.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Session Management Cheat Sheet — Caching](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-524: Use of Cache-Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)
- [MDN Web Docs: Cache-Control HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
