---
tier: 1
id: html-tampering
title: HTML Tampering & Client-Side Security Trust
cwe: [CWE-602, CWE-565]
owasp: [A04:2021]
tags: [example, html-tampering, client-side, validation, cwe-602, a04, insecure-design]
references:
  - https://owasp.org/Top10/A04_2021-Insecure_Design/
  - https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/602.html
---

# HTML Tampering — Client-Side Security Trust

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

HTML Tampering (CWE-602: Client-Side Enforcement of Server-Side Security / Insecure Design - OWASP A04:2021) là lớp lỗ hổng thiết kế xảy ra khi hệ thống đặt niềm tin mù quáng vào các cơ chế kiểm soát dữ liệu hoặc logic nghiệp vụ chỉ được thực thi ở phía client (trình duyệt người dùng).

Do toàn bộ môi trường trình duyệt, mã HTML, CSS, JavaScript và dữ liệu HTTP Request đều nằm dưới quyền kiểm soát tuyệt đối của người dùng, kẻ tấn công có thể dễ dàng can thiệp, chỉnh sửa DOM hoặc dùng công cụ HTTP proxy (Burp Suite, curl, Postman) để thay đổi dữ liệu trước khi gửi lên máy chủ.

Tác động chính của HTML Tampering:
- **Gian lận thương mại & Thao túng giá:** Chỉnh sửa đơn giá sản phẩm, tỷ lệ giảm giá hoặc phí vận chuyển thành giá trị nhỏ hoặc âm.
- **Leo thang quyền hạn:** Sửa đổi các trường vai trò ẩn (`<input type="hidden" name="role" value="user">`) thành `admin`.
- **Vượt qua quy trình kiểm duyệt:** Bỏ qua các bước xác thực tuần tự (Workflow Bypass) hoặc gửi dữ liệu vi phạm ràng buộc định dạng của hệ thống.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Thao túng trường ẩn & Trường vô hiệu hóa (Hidden & Disabled Field Tampering)

Ứng dụng hiển thị thông tin giá tiền hoặc quyền hạn trong các thẻ form HTML ẩn hoặc bị khóa:

```html
<!-- Form mua hàng hiển thị giá sản phẩm -->
<form action="/checkout" method="POST">
  <input type="hidden" name="productId" value="P102" />
  <input type="hidden" name="unitPrice" value="500000" />
  <input type="text" name="discount" value="0" disabled />
  <button type="submit">Thanh toán</button>
</form>
```

Kẻ tấn công sửa `unitPrice` thành `1` hoặc xóa thuộc tính `disabled` trên trường `discount` để nhập `100%`, sau đó gửi request về máy chủ.

### 2.2. Vượt qua kiểm tra JavaScript phía Client (Bypassing Client-Side Validation)

Chỉ validate giá trị trên HTML/JS (ví dụ độ dài mật khẩu, định dạng số, kiểm tra trường bắt buộc). Kẻ tấn công chỉ cần tắt JavaScript trong trình duyệt hoặc sử dụng API client để gửi trực tiếp payload vi phạm lên server.

### 2.3. Sửa đổi tham số Cookie & LocalStorage không có chữ ký

Ứng dụng lưu trữ giỏ hàng, thông tin tài khoản hoặc số dư điểm thưởng trực tiếp trong Cookie hoặc Web Storage không được ký số/mã hóa. Kẻ tấn công chỉnh sửa giá trị trực tiếp trên DevTools để hưởng lợi bất chính.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống HTML Tampering căn bản:

1. **Lớp 1 — Mọi kiểm soát nghiệp vụ và tính giá phải ở Server (Server-Side Business Logic Enforcement):**
   Mọi dữ liệu nhạy cảm (đơn giá, quyền hạn, chiết khấu, trạng thái đơn hàng) bắt buộc phải được truy vấn và tính toán trực tiếp từ cơ sở dữ liệu ở phía server. Server chỉ nhận định danh sản phẩm (`productId`) và số lượng (`quantity`) từ client.
2. **Lớp 2 — Coi Validation phía Client chỉ phục vụ trải nghiệm người dùng (UX Only):**
   Kiểm tra tính hợp lệ của dữ liệu ở phía client (JavaScript/HTML5 constraints) chỉ nhằm mục đích cung cấp phản hồi nhanh cho người dùng, không bao giờ được coi là một biện pháp bảo mật thay thế cho server-side validation.
3. **Lớp 3 — Bảo vệ tính toàn vẹn của dữ liệu trạng thái (State Integrity Verification):**
   Nếu bắt buộc phải lưu trạng thái ở client, sử dụng chữ ký điện tử HMAC (ví dụ qua Signed Session Cookies) với khóa bí mật lưu an toàn ở server để phát hiện ngay lập tức mọi hành vi sửa đổi dữ liệu.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A04: Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
