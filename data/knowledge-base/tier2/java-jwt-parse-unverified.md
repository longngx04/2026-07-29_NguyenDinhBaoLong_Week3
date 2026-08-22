---
tier: 2
id: java-jwt-parse-unverified
canonical_category: JWT Weak Verification
cwe: [CWE-347]
tier1_parent: jwt-weak-verification
language: java
sink_signatures:
  - io.jsonwebtoken.Jwts.parser
  - io.jsonwebtoken.JwtParser.parseClaimsJwt
no_rule_yet: true
safe_alternative: "Dùng setSigningKey() kèm parseClaimsJws() để bắt buộc xác thực chữ ký"
exploitable_when: >
  parser giải mã phần payload của JWT mà không thiết lập khoá ký và thuật toán mong đợi,
  cho phép kẻ tấn công sửa đổi claims hoặc dùng thuật toán `none`
not_exploitable_when: >
  parser luôn cấu hình khoá ký tường minh qua setSigningKey()/verifyWith() và kiểm tra
  chữ ký với parseClaimsJws() trước khi đọc claims
---

# `Jwts.parser` / `parseClaimsJwt` — JWT Weak Verification

Sử dụng `parseClaimsJwt()` thay vì `parseClaimsJws()` sẽ phân tích chuỗi JWT không có chữ ký
(unsigned JWT), cho phép kẻ tấn công sửa đổi thông tin người dùng (như username, role) và mạo danh
mà không cần biết khoá bí mật.

Cần sử dụng `parseClaimsJws()` kết hợp với việc cài đặt khoá ký xác thực hợp lệ qua `setSigningKey()`.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu parser được cấu hình bắt buộc xác thực chữ ký số HMAC/RSA và từ chối thuật toán `none`,
mọi token bị giả mạo sẽ bị từ chối ngay tại tầng kiểm tra tính toàn vẹn mật mã.

## Nguồn

- JJWT Documentation: Parsing JSON Web Signatures (JWS)
- CWE-347: Improper Verification of Cryptographic Signature
