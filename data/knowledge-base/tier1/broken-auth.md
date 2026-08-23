---
tier: 1
id: broken-auth
title: Broken Authentication & Identification Failures
cwe: [CWE-287, CWE-384, CWE-798]
owasp: [A07:2021]
tags: [example, authentication, session, a07, credential, cwe-287, broken-authentication, login]
references:
  - https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/287.html
---

# Broken Authentication — Identification and Authentication Failures

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Broken Authentication (Các sai sót trong nhận dạng và xác thực - OWASP A07:2021 / CWE-287) là nhóm lỗ hổng xảy ra khi các hàm liên quan đến xác thực người dùng và quản lý phiên (Session Management) bị thiết kế hoặc triển khai thiếu an toàn. Điều này cho phép kẻ tấn công thỏa hiệp mật khẩu, khóa bí mật hoặc token phiên để giả mạo danh tính của người dùng hợp pháp một cách tạm thời hoặc vĩnh viễn.

Tác động chính của Broken Authentication:
- **Chiếm đoạt tài khoản (Account Takeover):** Chiếm quyền tài khoản người dùng hoặc tài khoản quản trị hệ thống.
- **Rò rỉ dữ liệu nhạy cảm:** Tiếp cận thông tin định danh, tài chính và bí mật nghiệp vụ của nạn nhân.
- **Gian lận và phá hoại hệ thống:** Thực hiện các giao dịch gian lận hoặc thay đổi cấu hình bảo mật dưới danh nghĩa nạn nhân.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Tấn công Vét cạn & Credential Stuffing

Xảy ra khi ứng dụng không có cơ chế giới hạn số lần thử đăng nhập (Rate Limiting / Account Lockout) trên các endpoint đăng nhập hoặc quên mật khẩu:
- **Brute-Force:** Thử lần lượt các mật khẩu phổ biến đối với một tài khoản.
- **Credential Stuffing:** Sử dụng danh sách cặp username/password bị rò rỉ từ các vụ xâm phạm dữ liệu khác để tự động đăng nhập hàng loạt.

### 2.2. Quản lý Phiên yếu & Cố định Phiên (Session Fixation & Weak Session ID)

Session ID có thể bị tấn công nếu:
- Session ID đoán được hoặc có entropy thấp.
- Không tạo mới Session ID sau khi người dùng đăng nhập thành công (Session Fixation), cho phép kẻ tấn công gán trước Session ID cho nạn nhân.
- Token phiên không hết hạn (thiếu Idle Timeout và Absolute Timeout), hoặc không bị hủy khi người dùng nhấn Logout.
- Session ID bị lộ qua URL query parameter (`?jsessionid=...`) hoặc lưu trong log máy chủ.

### 2.3. Thông tin xác thực mặc định hoặc Hardcoded trong mã nguồn (Hardcoded Credentials)

Hệ thống sử dụng tài khoản quản trị mặc định (như `admin/admin`, `root/root`) hoặc lập trình viên lưu cứng chuỗi mật khẩu/khóa API trong mã nguồn (CWE-798) dẫn đến việc bị khai thác tự động.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống Broken Authentication đòi hỏi các biện pháp bảo mật chặt chẽ:

1. **Lớp 1 — Bắt buộc Xác thực đa yếu tố (Multi-Factor Authentication - MFA):**
   Triển khai MFA (TOTP, FIDO2/WebAuthn, SMS/Email OTP) cho toàn bộ tài khoản đặc quyền, quản trị viên và khuyến khích áp dụng cho người dùng thông thường để triệt tiêu nguy cơ từ mật khẩu bị lộ.
2. **Lớp 2 — Kiểm soát tốc độ truy cập & Khóa tài khoản tạm thời (Rate Limiting):**
   Áp dụng giới hạn tốc độ truy cập theo địa chỉ IP và tài khoản trên các endpoint nhạy cảm (đăng nhập, reset password, OTP). Bật CAPTCHA hoặc khóa tạm thời khi có dấu hiệu dò quét bất thường.
3. **Lớp 3 — Quản lý phiên an toàn và tiêu chuẩn:**
   - Luôn tạo Session ID mới ngẫu nhiên (sử dụng `SecureRandom` với tối thiểu 128-bit entropy) ngay sau khi xác thực thành công.
   - Thiết lập thời gian hết hạn phiên làm việc (Idle Timeout ngắn hạn, Absolute Timeout dài hạn).
   - Đặt cờ bảo mật cho Cookie phiên (`HttpOnly`, `Secure`, `SameSite=Strict`).
4. **Lớp 4 — Lưu trữ mật khẩu an toàn & Chính sách mật khẩu mạnh:**
   Băm mật khẩu bằng các thuật toán băm chậm, có salt và chống tăng tốc phần cứng (Argon2id, PBKDF2, BCrypt). Thiết lập chính sách mật khẩu tối thiểu 8-12 ký tự và kiểm tra danh sách mật khẩu yếu phổ biến.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A07: Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
