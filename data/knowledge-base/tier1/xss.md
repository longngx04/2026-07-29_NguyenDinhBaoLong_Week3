---
tier: 1
id: xss
title: Cross-Site Scripting (XSS)
cwe: [CWE-79]
owasp: [A03:2021]
tags: [example, xss, cross-site-scripting, cwe-79, injection, a03, client-side]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/79.html
---

# Cross-Site Scripting (XSS)

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Cross-Site Scripting (XSS) là lỗ hổng bảo mật phía client xảy ra khi ứng dụng web nhúng dữ liệu đầu vào không tin cậy từ người dùng vào trang HTML trả về mà không thực hiện mã hóa theo ngữ cảnh (context-aware output encoding) hoặc kiểm duyệt (sanitization) hợp lệ. Điều này cho phép kẻ tấn công chèn mã JavaScript độc hại và thực thi trong trình duyệt của nạn nhân dưới quyền của phiên đăng nhập hiện tại.

Tác động chính của Cross-Site Scripting bao gồm:
- **Đánh cắp phiên làm việc (Session Hijacking):** Đọc cookie phiên không có cờ `HttpOnly` (`document.cookie`) và gửi về máy chủ kẻ tấn công.
- **Mạo danh người dùng (User Impersonation):** Thực hiện các hành vi trái phép trên ứng dụng nhân danh người dùng (thay đổi thông tin cá nhân, gửi tin nhắn, chuyển tiền).
- **Thao túng giao diện (DOM Defacement & Phishing):** Chèn form đăng nhập giả mạo trực tiếp vào giao diện web hợp pháp để thu thập thông tin xác thực của người dùng.
- **Cài đặt mã độc & Keylogging:** Ghi lại thao tác bàn phím của nạn nhân hoặc chuyển hướng nạn nhân tới trang web độc hại.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Reflected XSS (Non-Persistent XSS)

Ứng dụng phản chiếu trực tiếp dữ liệu đầu vào từ HTTP Request (tham số URL, form tìm kiếm, thông báo lỗi) vào trang phản hồi mà không qua bộ mã hóa. Kẻ tấn công thường lừa nạn nhân nhấp vào liên kết độc hại chứa payload:

```html
<!-- Ví dụ URL: https://example.com/search?q=<script>alert(1)</script> -->
<p>Kết quả tìm kiếm cho: <script>alert(1)</script></p>
```

Tìm kiếm “XSS” hoặc “cross site scripting” phản chiếu input (search, error message) vào HTML mà không encode là dấu hiệu đặc trưng của biến thể này.

### 2.2. Stored XSS (Persistent XSS)

Payload mã độc JavaScript được lưu trữ vĩnh viễn trong cơ sở dữ liệu của ứng dụng (bình luận, thông tin hồ sơ người dùng, bài viết diễn đàn, thông báo nội bộ). Mỗi khi bất kỳ người dùng nào truy cập vào trang hiển thị dữ liệu đó, đoạn mã độc sẽ tự động thực thi.

Biến thể Stored XSS có mức độ nguy hiểm và phạm vi ảnh hưởng rộng hơn Reflected XSS vì nó không phụ thuộc vào việc lừa người dùng nhấp vào link cụ thể.

### 2.3. DOM-based XSS (Client-Side XSS)

Lỗ hổng xảy ra hoàn toàn ở tầng xử lý JavaScript phía client trong trình duyệt mà không nhất thiết phải có phản hồi chứa script từ máy chủ. JavaScript phía client lấy dữ liệu từ một nguồn không tin cậy (Source như `location.hash`, `location.search`, `document.referrer`) rồi đưa trực tiếp vào một điểm thực thi nguy hiểm (Sink như `element.innerHTML`, `document.write()`, `eval()`):

```javascript
// LỖ HỔNG: Nhận hash từ URL và gán trực tiếp vào innerHTML
var customName = location.hash.substring(1);
document.getElementById("greeting").innerHTML = "Xin chào " + customName;
```

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Phòng thủ Cross-Site Scripting đòi hỏi phối hợp đa lớp từ mã hóa đầu ra, bảo vệ cookie đến chính sách bảo mật trình duyệt:

1. **Lớp 1 — Mã hóa đầu ra theo đúng ngữ cảnh (Context-Aware Output Encoding):**
   Mã hóa toàn bộ dữ liệu không tin cậy trước khi hiển thị dựa trên vị trí xuất hiện:
   - Trong HTML Body: Chuyển đổi các ký tự đặc biệt (`&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;`).
   - Trong HTML Attributes, JavaScript Variables, CSS, hoặc URL parameters: Sử dụng các hàm mã hóa chuyên biệt tương ứng.
   - Ưu tiên sử dụng các Template Engine tự động escape an toàn (Thymeleaf với `th:text`, React JSX, Angular).
2. **Lớp 2 — Chính sách bảo mật nội dung (Content-Security-Policy - CSP):**
   Triển khai HTTP Header `Content-Security-Policy` chặt chẽ, vô hiệu hóa việc thực thi inline script (`'unsafe-inline'`), chặn hàm `eval()`, và chỉ cho phép tải script từ các domain danh sách trắng có gắn nonce/hash.
3. **Lớp 3 — Bảo vệ Cookie phiên (HttpOnly & Secure Flags):**
   Thiết lập thuộc tính `HttpOnly` cho tất cả các cookie chứa Session ID hoặc JWT để ngăn chặn mã JavaScript độc hại truy cập thông qua `document.cookie`.
4. **Lớp 4 — Kiểm duyệt HTML an toàn (HTML Sanitization) & Tránh Sink nguy hiểm:**
   Khi ứng dụng bắt buộc phải nhận HTML định dạng phong phú từ người dùng (Rich Text Editor), sử dụng thư viện kiểm duyệt chuẩn như OWASP Java HTML Sanitizer hoặc DOMPurify. Phía client, thay thế `innerHTML` bằng các thuộc tính an toàn như `textContent` hoặc `innerText`.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
