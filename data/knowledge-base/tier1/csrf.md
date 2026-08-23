---
tier: 1
id: csrf
title: Cross-Site Request Forgery (CSRF)
cwe: [CWE-352]
owasp: [A01:2021]
tags: [example, csrf, session, cwe-352, a01, broken-access-control, request-forgery]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/352.html
---

# CSRF — Cross-Site Request Forgery

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Cross-Site Request Forgery (CSRF hay XSRF) là lỗ hổng bảo mật phía web cho phép kẻ tấn công đánh lừa trình duyệt của nạn nhân (người dùng đã đăng nhập hợp lệ) gửi các yêu cầu thay đổi trạng thái không mong muốn (state-changing requests) tới ứng dụng mục tiêu mà nạn nhân không hề hay biết.

Do trình duyệt tự động đính kèm thông tin xác thực phiên (như Session Cookies, HTTP Basic Auth credentials) trong mọi yêu cầu gửi tới domain mục tiêu, máy chủ ứng dụng sẽ lầm tưởng yêu cầu đó xuất phát từ hành vi tự nguyện của người dùng.

Tác động chính của CSRF:
- **Thực hiện giao dịch trái phép:** Chuyển tiền, mua hàng, thay đổi thông tin đơn hàng trên các hệ thống tài chính/thương mại điện tử.
- **Chiếm đoạt tài khoản:** Thay đổi địa chỉ email liên kết, đổi mật khẩu tài khoản hoặc thêm khóa API/SSH key của kẻ tấn công.
- **Thay đổi cấu hình hệ thống:** Kích hoạt/vô hiệu hóa các tính năng bảo mật hoặc thay đổi cấu hình thiết bị mạng (Router/Modem).

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. GET-based CSRF qua Thẻ HTML đơn giản

Khi ứng dụng thực hiện các hành động nhạy cảm hoặc thay đổi trạng thái thông qua phương thức HTTP GET (vi phạm nguyên tắc REST):

```html
<!-- Kẻ tấn công nhúng vào trang web độc hại hoặc diễn đàn -->
<img src="https://bank.example.com/transfer?toAccount=attacker&amount=10000" width="0" height="0" />
```

Trình duyệt của nạn nhân khi tải thẻ `<img>` sẽ tự động gửi request kèm cookie phiên đăng nhập và kích hoạt lệnh chuyển tiền.

### 2.2. POST-based CSRF qua Form tự động gửi (Auto-submitting HTML Form)

Khi ứng dụng yêu cầu HTTP POST, kẻ tấn công tạo một trang web độc hại chứa form ẩn và dùng JavaScript tự động submit khi nạn nhân truy cập:

```html
<form id="csrfForm" action="https://app.example.com/api/user/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>
    document.getElementById("csrfForm").submit();
</script>
```

### 2.3. CSRF trên Single Page Application (SPA) & Tắt bảo vệ Framework

Nhiều ứng dụng phân phối qua REST API hoặc SPA vô tình vô hiệu hóa tính năng bảo vệ CSRF mặc định của framework (ví dụ `http.csrf().disable()` trong Spring Security) khi cho rằng chỉ xác thực qua cookie hoặc CORS là đủ, tạo điều kiện cho các request fetch độc hại qua trình duyệt.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống CSRF hiệu quả bao gồm:

1. **Lớp 1 — Anti-CSRF Synchronizer Tokens (CSRF Token):**
   Mỗi phiên làm việc hoặc mỗi request thay đổi trạng thái phải được gán một token bí mật, ngẫu nhiên và khó đoán do server sinh ra. Token này được truyền qua trường ẩn trong form (`_csrf`) hoặc request header (ví dụ `X-XSRF-TOKEN`). Server bắt buộc phải đối chiếu tính hợp lệ của token trước khi xử lý nghiệp vụ.
2. **Lớp 2 — Cấu hình Thuộc tính SameSite cho Cookie:**
   Thiết lập thuộc tính `SameSite=Lax` hoặc `SameSite=Strict` cho tất cả các cookie phiên. `SameSite=Strict` ngăn chặn hoàn toàn việc trình duyệt gửi kèm cookie trong các request xuất phát từ trang web bên ngoài.
3. **Lớp 3 — Custom Request Headers cho REST API:**
   Sử dụng các header tùy chỉnh (như `X-Requested-With: XMLHttpRequest` hoặc custom header riêng) cho các API AJAX/Fetch. Trình duyệt không cho phép trang web cross-origin gửi custom header nếu không có sự đồng thuận rõ ràng từ chính sách CORS (Preflight request).
4. **Lớp 4 — Xác thực lại đối với hành động nhạy cảm (Re-authentication / Step-up Auth):**
   Yêu cầu người dùng nhập lại mật khẩu hiện tại hoặc mã xác thực OTP (MFA) trước khi hoàn tất các thao tác rủi ro cao như đổi mật khẩu, thay đổi email hoặc chuyển tiền.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
