---
tier: 2
id: java-insecure-random
canonical_category: Insecure Randomness
cwe: [CWE-338]
tier1_parent: security-misconfiguration
language: java
sink_signatures:
  - java.util.Random.nextInt
  - java.lang.Math.random
no_rule_yet: true
safe_alternative: "Sử dụng java.security.SecureRandom (hoặc SecureRandom.getInstanceStrong()) cho mọi mục đích liên quan đến an ninh và mật mã"
exploitable_when: >
  giá trị ngẫu nhiên tuyến tính dự đoán được từ java.util.Random hoặc Math.random() được dùng làm token xác thực,
  mã OTP, session ID, mật khẩu tạm thời hoặc khoá mật mã
not_exploitable_when: >
  giá trị sinh ra chỉ dùng cho mục đích không bảo mật như jitter thời gian,
  xáo trộn hiển thị giao diện, hoặc dữ liệu thử nghiệm giả lập — không dùng làm token, mã khôi phục, hay khoá phiên
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html
  - https://cwe.mitre.org/data/definitions/338.html
---

# `Random.nextInt` / `Math.random` — Insecure Randomness

## 1. Cơ chế rủi ro (Risk Mechanism)

Các hàm sinh số ngẫu nhiên tiêu chuẩn trong Java như `java.util.Random` và `java.lang.Math.random()` sử dụng thuật toán Linear Congruential Generator (LCG) với kích thước seed chỉ 48-bit. Thuật toán LCG có tính tất định toán học cao và không phải là bộ sinh số ngẫu nhiên an toàn mật mã (Cryptographically Secure Pseudo-Random Number Generator - CSPRNG).

Kẻ tấn công sau khi quan sát một vài giá trị ngẫu nhiên liên tiếp (ví dụ 2 giá trị 32-bit từ `nextInt()`) có thể dễ dàng giải phương trình toán học để khôi phục trạng thái hạt giống (seed) ban đầu trong vòng vài phần nghìn giây. Khi các giá trị này được ứng dụng dùng làm mã xác thực một lần (OTP), token đặt lại mật khẩu (password reset tokens), định danh phiên làm việc (Session IDs), mã kích hoạt tài khoản hoặc muối mật mã (cryptographic salts/IVs), kẻ tấn công có thể tính toán trước token của nạn nhân và chiếm đoạt tài khoản trái phép.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Sử dụng `java.util.Random` hoặc `Math.random` để tạo mã OTP và token đặt lại mật khẩu:

```java
import java.util.Random;

public class PasswordResetService {
    private final Random random = new Random();

    public String generatePasswordResetToken() {
        // NGUY HIỂM: Random sử dụng thuật toán LCG 48-bit, kẻ tấn công có thể dự đoán toàn bộ chuỗi token
        int token = 100000 + random.nextInt(900000);
        return String.valueOf(token);
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng `java.security.SecureRandom` với nguồn entropy hệ điều hành để sinh token an toàn mật mã:

```java
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SafePasswordResetService {
    private final SecureRandom secureRandom;

    public SafePasswordResetService() {
        try {
            // AN TOÀN: Sử dụng bộ sinh số ngẫu nhiên an toàn mật mã từ hệ điều hành (/dev/urandom)
            this.secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Không tìm thấy thuật toán CSPRNG an toàn", e);
        }
    }

    public String generateSafeResetToken() {
        byte[] tokenBytes = new byte[32]; // 256 bits entropy
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Chiến lược sinh số ngẫu nhiên bảo mật tuân theo 3 lớp phòng vệ:

1. **Lớp 1 — Chuyển đổi bắt buộc sang CSPRNG an toàn mật mã (Cryptographically Secure PRNG):**
   Thay thế toàn bộ `java.util.Random` và `Math.random()` bằng `java.security.SecureRandom` (hoặc `SecureRandom.getInstanceStrong()`) cho tất cả các tác vụ liên quan đến an ninh (sinh token, OTP, nonce, initialization vector IV, session ID, API keys). `SecureRandom` lấy nguồn entropy trực tiếp từ hệ điều hành (như `/dev/urandom` trên Linux hoặc CryptoAPI trên Windows) đảm bảo tính không thể đoán trước (unpredictability).
2. **Lớp 2 — Đảm bảo đủ độ dài entropy và định dạng an toàn (Entropy Size & Safe Encoding):**
   Sử dụng kích thước entropy tối thiểu 128-bit (16 bytes) cho token ngắn hạn hoặc 256-bit (32 bytes) cho token bảo mật cao, mã hóa kết quả bằng Base64URL hoặc Hex để tránh lỗi phân tích cú pháp khi truyền tải qua URL hoặc HTTP Header.
3. **Lớp 3 — Giới hạn vòng đời và vô hiệu hóa sau một lần sử dụng (Token Expiration & Single-Use):**
   Thiết lập thời gian hết hạn ngắn cho mã OTP / Reset Token (ví dụ 5–10 phút), thu hồi token ngay sau khi xác thực thành công và giới hạn tần suất yêu cầu (rate limiting) trên các API xác thực token để chống tấn công brute-force.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu `java.util.Random` chỉ được sử dụng cho các mục đích tính toán phi bảo mật như xáo trộn hiển thị danh sách (UI element shuffling), tính toán độ trễ ngẫu nhiên (exponential backoff jitter) trong các tác vụ gọi lại mạng, hoặc sinh dữ liệu giả lập (mock data generator), tính chất dễ đoán của thuật toán LCG không gây ra bất kỳ rủi ro bảo mật nào. Cần phân biệt rõ ngữ cảnh bảo mật với ngữ cảnh phi an ninh để tránh các cảnh báo dương tính giả.

## 4. Tài liệu tham khảo (References)

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Oracle Java SE 17: java.security.SecureRandom API](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandom.html)
- [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
