---
tier: 1
id: jwt-weak-verification
title: JWT Weak Verification & Signature Bypass
cwe: [CWE-347]
owasp: [A02:2021, A07:2021]
tags: [example, jwt, authentication, integrity, cwe-347, cryptographic-failures, broken-auth]
references:
  - https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/347.html
---

# JWT — Weak Verification & Signature Bypass

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

JSON Web Token (JWT) là chuẩn mở (RFC 7519) được sử dụng phổ biến để truyền tải thông tin định danh và ủy quyền giữa client và server. Lỗ hổng JWT Weak Verification (CWE-347: Improper Verification of Cryptographic Signature) xảy ra khi ứng dụng xác thực chữ ký của token không đúng cách, cho phép giải mã payload mà không kiểm tra tính toàn vẹn, hoặc sử dụng cơ chế bảo mật lỏng lẻo.

Điều này cho phép kẻ tấn công tự do chỉnh sửa các trường dữ liệu (claims như `sub`, `roles`, `userId`, `permissions`) trong token mà không bị phát hiện.

Hậu quả chính của việc xác thực JWT yếu:
- **Leo thang đặc quyền (Privilege Escalation):** Sửa đổi quyền hạn từ người dùng thông thường (`role: "USER"`) thành quản trị viên tối cao (`role: "ADMIN"`).
- **Mạo danh bất kỳ người dùng nào (Account Takeover):** Tự sinh token với định danh `sub` của nạn nhân để vượt qua toàn bộ lớp xác thực.
- **Vượt qua kiểm soát truy cập (Authentication Bypass):** Truy cập trái phép vào các API nội bộ nhạy cảm.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Tấn công Giải thuật "None" (`alg=none`)

Kẻ tấn công sửa đổi phần Header của JWT thành `{"alg": "none", "typ": "JWT"}` và xóa bỏ hoàn toàn phần chữ ký (Signature). Nếu thư viện JWT ở server được cấu hình chấp nhận giải thuật `none`, nó sẽ coi token là hợp lệ mà không thực hiện xác thực chữ ký.

### 2.2. Khóa ký yếu (Weak HMAC Secret Key Brute-Force)

Khi sử dụng giải thuật HMAC (như `HS256`), nếu khóa bí mật (Secret Key) quá ngắn hoặc là từ điển phổ biến (ví dụ: `secret`, `123456`, `password`), kẻ tấn công có thể trích xuất token và thực hiện tấn công vét cạn (offline brute-force) bằng các công cụ như `jwt-cracker` hoặc `hashcat` để tìm ra khóa bí mật, sau đó tự ký các token giả mạo tùy ý.

### 2.3. Lỗ hổng nhầm lẫn giải thuật (Key Confusion / RS256 to HS256)

Ứng dụng dự kiến sử dụng cặp khóa bất đối xứng RSA (`RS256`), trong đó server ký bằng Private Key và các dịch vụ khác xác thực bằng Public Key. Kẻ tấn công sửa `alg` thành `HS256` (đối xứng) và dùng chính Public Key công khai của server làm khóa ký HMAC. Nếu hàm xác thực của server dùng chung một hàm nhận key mà không kiểm tra chặt chẽ giải thuật, nó sẽ dùng Public Key để xác thực chữ ký HMAC và chấp nhận token giả mạo.

### 2.4. Header Injection (`kid`, `jku`, `x5u`)

Chấp nhận hoặc tin cậy các tham số trong JWT Header như `kid` (Key ID), `jku` (JWK Set URL) từ phía client mà không kiểm tra có thể dẫn tới lỗ hổng Path Traversal (chỉ định `kid=/dev/null` với khóa rỗng), SQLi hoặc SSRF.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống xác thực JWT yếu bao gồm:

1. **Lớp 1 — Cố định giải thuật ký (Strict Algorithm Pinning):**
   Cố định rõ ràng giải thuật ký mong muốn trong cấu hình xác thực (ví dụ: chỉ chấp nhận `HS256` hoặc `RS256`). Từ chối triệt để giải thuật `none` hoặc các giải thuật không nằm trong danh sách trắng.
2. **Lớp 2 — Luôn xác thực chữ ký bằng thư viện chuẩn (Enforce Signature Verification):**
   Luôn gọi phương thức kiểm tra chữ ký (như `parseClaimsJws()` thay vì `parseClaimsJwt()` trong thư viện Java JJWT). Không bao giờ chỉ giải mã Base64 URL payload để lấy thông tin người dùng mà bỏ qua bước xác thực chữ ký.
3. **Lớp 3 — Độ dài khóa bí mật đạt chuẩn mật mã học:**
   Đối với HMAC, khóa bí mật đối xứng phải có độ dài tối thiểu 256 bits (32 bytes ngẫu nhiên mạnh về mặt mật mã). Đối với RSA/ECDSA, sử dụng độ dài khóa tối thiểu 2048 bits (RSA) hoặc đường cong P-256 / secp256r1.
4. **Lớp 4 — Xác thực nghiêm ngặt các Claims tiêu chuẩn:**
   Bắt buộc kiểm tra `exp` (thời gian hết hạn - nên đặt thời gian ngắn kết hợp Refresh Token), `nbf` (không hợp lệ trước thời điểm), `iss` (đúng nhà phát hành token) và `aud` (đúng ứng dụng đối tượng). Không lấy khóa từ input người dùng.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
