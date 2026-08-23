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
safe_alternative: "Dùng setSigningKey() / verifyWith() kết hợp parseClaimsJws() để bắt buộc xác thực chữ ký số"
exploitable_when: >
  parser giải mã phần payload của JWT mà không thiết lập khoá ký và thuật toán mong đợi,
  cho phép kẻ tấn công sửa đổi claims hoặc dùng thuật toán `none`
not_exploitable_when: >
  parser luôn cấu hình khoá ký tường minh qua setSigningKey()/verifyWith() và kiểm tra
  chữ ký với parseClaimsJws() trước khi đọc claims
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
  - https://github.com/jwtk/jjwt
  - https://cwe.mitre.org/data/definitions/347.html
---

# `Jwts.parser` / `parseClaimsJwt` — JWT Weak Verification

## 1. Cơ chế rủi ro (Risk Mechanism)

JSON Web Token (JWT) là định dạng truyền tải thông tin định danh gồm 3 phần: Header, Payload (Claims), và Signature. Khi ứng dụng Java sử dụng thư viện JJWT và gọi phương thức `parseClaimsJwt(jwt)` hoặc khởi tạo `Jwts.parser()` mà không cấu hình khoá ký bí mật (`setSigningKey()`), bộ parser sẽ xử lý chuỗi JWT dưới dạng không có chữ ký (Unsecured / Plaintext JWT hoặc thuật toán `alg: none`).

Lỗ hổng này cho phép kẻ tấn công chỉnh sửa tự do phần Payload của token (ví dụ: thay đổi `sub` thành tài khoản quản trị viên, chèn role `ROLE_ADMIN`, thay đổi thời hạn `exp`), sau đó gửi lên máy chủ mà không cần biết khóa bí mật. Khi máy chủ giải mã token mà không xác minh tính toàn vẹn mật mã qua chữ ký số, kẻ tấn công có thể giả mạo danh tính hoàn toàn (Authentication Bypass) và leo thang đặc quyền trái phép (Privilege Escalation).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phân tích cú pháp JWT bằng `parseClaimsJwt` mà không cấu hình khoá ký mật mã:

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public Claims getClaimsFromToken(String jwtToken) {
    // NGUY HIỂM: parseClaimsJwt chỉ giải mã chuỗi unsigned JWT, hoàn toàn bỏ qua việc xác thực chữ ký
    Claims claims = Jwts.parser()
                        .parseClaimsJwt(jwtToken)
                        .getBody();
    return claims;
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng `setSigningKey()` và bắt buộc xác thực chữ ký số bằng `parseClaimsJws()`:

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import java.security.Key;

public Claims getVerifiedClaims(String jwtToken, Key signingKey) {
    try {
        // AN TOÀN: Bắt buộc cấu hình khoá ký và xác thực toàn vẹn chữ ký mật mã qua parseClaimsJws
        return Jwts.parserBuilder()
                   .setSigningKey(signingKey)
                   .build()
                   .parseClaimsJws(jwtToken)
                   .getBody();
    } catch (JwtException ex) {
        // Token không hợp lệ, chữ ký sai, hoặc đã hết hạn
        throw new SecurityException("Xác thực JWT thất bại: Chữ ký không hợp lệ hoặc token đã bị sửa đổi", ex);
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Chiến lược bảo mật JWT toàn diện bao gồm 3 lớp phòng vệ:

1. **Lớp 1 — Bắt buộc xác thực chữ ký mật mã với khoá bảo mật mạnh (Signature Verification & Strong Keys):**
   Luôn sử dụng phương thức `parseClaimsJws()` (cho Signed JWTs / JWS) thay vì `parseClaimsJwt()`. Cấu hình khóa ký tường minh (`setSigningKey(key)` hoặc `verifyWith(key)` trong các phiên bản JJWT mới). Sử dụng thuật toán ký mạnh với độ dài khóa an toàn (HMAC-SHA256 với khoá bí mật tối thiểu 256-bit / 32 bytes ngẫu nhiên, hoặc bất đối xứng RSA/ECDSA 2048-bit trở lên).
2. **Lớp 2 — Kiểm tra thuật toán và xác thực Claims chuẩn (Algorithm & Claims Validation):**
   Chỉ chấp nhận các thuật toán ký đã được chỉ định trước (chặn hoàn toàn thuật toán `none`). Luôn kiểm tra các trường claims chuẩn: thời gian hết hạn (`exp`), thời gian hiệu lực (`nbf`), người phát hành (`iss`) và đối tượng sử dụng (`aud`).
3. **Lớp 3 — Quản lý khoá ký an toàn và xoay vòng khoá định kỳ (Key Management & Rotation):**
   Tuyệt đối không lưu trữ khóa bí mật trực tiếp trong mã nguồn. Sử dụng dịch vụ quản lý khóa chuyên dụng (AWS KMS, HashiCorp Vault, Spring Cloud Config Server với mã hóa) và thiết lập cơ chế hỗ trợ nhiều khóa (Key ID `kid`) để thực hiện xoay vòng khóa không gián đoạn dịch vụ.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu bộ parser đã được cấu hình khoá ký bí mật thông qua `setSigningKey()` hoặc `verifyWith()` và phân tích token qua phương thức `parseClaimsJws()`, mọi nỗ lực thay đổi nội dung payload hoặc sử dụng token giả mạo thuật toán `none` đều sẽ bị thư viện JJWT từ chối ngay lập tức với ngoại lệ `SignatureException` hoặc `MalformedJwtException`. Việc cảnh báo mọi thao tác khởi tạo `Jwts.parser()` mà không đối chiếu việc cấu hình khoá ký và phương thức `parseClaimsJws()` sẽ dẫn đến dương tính giả (false positive).

## 4. Tài liệu tham khảo (References)

- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html)
- [JJWT Documentation: Reading a JWS](https://github.com/jwtk/jjwt)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
