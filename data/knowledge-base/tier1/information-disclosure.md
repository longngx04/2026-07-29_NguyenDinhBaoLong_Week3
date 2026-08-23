---
tier: 1
id: information-disclosure
title: Information Disclosure
cwe: [CWE-497, CWE-598, CWE-615, CWE-200]
owasp: [A01:2021, A05:2021]
tags: [information-disclosure, server-leak, cwe-497, cwe-200]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cwe.mitre.org/data/definitions/497.html
  - https://cwe.mitre.org/data/definitions/200.html
---

# Information Disclosure

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Information Disclosure (Lộ lọt thông tin nhạy cảm - OWASP A01:2021, A05:2021 / CWE-497, CWE-200) xảy ra khi ứng dụng hoặc máy chủ vô tình để lộ các dữ liệu kỹ thuật nội bộ, thông tin định danh phiên bản, cấu trúc hệ thống hoặc dữ liệu người dùng cho các đối tượng không được phân quyền.

Tác động của Information Disclosure:
- **Thăm dò và lập hồ sơ tấn công chính xác (Targeted Fingerprinting):** Việc để lộ tên và phiên bản chính xác của Web Server (Apache, Nginx, Tomcat, IIS) hoặc Application Framework giúp kẻ tấn công nhanh chóng tra cứu cơ sở dữ liệu lỗ hổng (CVE/NVD) để sử dụng các khai thác công khai (Public Exploit / 1-day).
- **Lộ lọt cấu trúc mạng nội bộ & Tệp mã nguồn (Internal Architecture Leak):** Thông tin rò rỉ qua comment HTML, tệp tin cấu hình, debug endpoint hỗ trợ kẻ tấn công leo thang đặc quyền hoặc xâm nhập mạng nội bộ.
- **Rò rỉ dữ liệu nhạy cảm qua URL hoặc Response:** Dữ liệu cá nhân (PII), token xác thực hoặc tham số mật gửi qua GET query string có thể bị lưu lại trong lịch sử duyệt web, log proxy và tiêu đề Referer.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Lộ phiên bản phần mềm máy chủ qua HTTP Headers (Server Version Leaks - CWE-497)

Máy chủ phản hồi trả về các tiêu đề `Server`, `X-Powered-By`, `X-AspNet-Version` chứa thông tin chi tiết như `Apache/2.4.41 (Ubuntu)`, `Tomcat/9.0.31`, `PHP/7.4.3`, tạo điều kiện cho kẻ tấn công xác định chính xác các điểm yếu chưa được vá.

### 2.2. Nhúng dữ liệu nhạy cảm trong URL Query String (Sensitive Data in GET - CWE-598)

Truyền mật khẩu, mã OTP, hoặc API Token trên thanh địa chỉ URL (`/api/login?token=xyz`). Các thông tin này bị lưu vết vĩnh viễn trên nhật ký truy cập máy chủ proxy trung gian và lịch sử trình duyệt.

### 2.3. Chú thích mã nguồn chứa thông tin nhạy cảm (Comments in Source Code - CWE-615)

Lập trình viên để quên các chú thích nội bộ (`<!-- TODO: fix admin pass: 123456 -->`, ghi chú API key, logic hệ thống) trong mã HTML, JavaScript hoặc CSS trả về cho client.

### 2.4. Thông báo lỗi chi tiết & Stacktrace (Verbose Error Messages - CWE-200)

Khi gặp sự cố, máy chủ trả về toàn bộ thông tin ngoại lệ (exception stacktrace, đường dẫn file, truy vấn CSDL), cho phép kẻ tấn công hiểu rõ kiến trúc backend và cấu trúc dữ liệu.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống rò rỉ thông tin:

1. **Lớp 1 — Ẩn và chuẩn hóa tiêu đề máy chủ (Server Header Hardening):**
   Vô hiệu hóa hoặc ghi đè các tiêu đề tiết lộ phiên bản tại reverse proxy / web server:
   - Nginx: `server_tokens off;`
   - Apache: `ServerTokens Prod`, `ServerSignature Off`
   - Loại bỏ tiêu đề `X-Powered-By`, `X-Runtime`, `X-Version`.
2. **Lớp 2 — Quản lý phương thức truyền dữ liệu an toàn:**
   Tuyệt đối không truyền thông tin nhạy cảm (mật khẩu, token) qua phương thức GET hoặc query string; luôn sử dụng POST/PUT với thân yêu cầu (request body) được mã hóa TLS.
3. **Lớp 3 — Xử lý lỗi tập trung & Loại bỏ ghi chú nhạy cảm:**
   Cấu hình trang báo lỗi chung (custom generic error page) cho toàn bộ mã phản hồi lỗi 4xx/5xx. Tích hợp công cụ minification và linter để xóa bỏ chú thích trước khi đóng gói production.
4. **Lớp 4 — Kiểm thử rò rỉ dữ liệu tự động (DAST Fingerprint Scans):**
   Chạy công cụ kiểm thử tự động quét banner máy chủ và kiểm tra rò rỉ thông tin trong các gói phản hồi HTTP.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-497: Exposure of System Data to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
