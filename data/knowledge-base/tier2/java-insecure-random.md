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
safe_alternative: "Sử dụng java.security.SecureRandom cho mọi mục đích liên quan đến an ninh và mã hoá"
exploitable_when: >
  giá trị ngẫu nhiên tuyến tính dự đoán được từ java.util.Random được dùng làm token xác thực,
  mã OTP, session ID hoặc khoá mật mã
not_exploitable_when: >
  giá trị sinh ra chỉ dùng cho mục đích không bảo mật như jitter thời gian,
  xáo trộn hiển thị, hoặc dữ liệu thử nghiệm — không dùng làm token, mã khôi phục, hay khoá phiên
---

# `Random.nextInt` / `Math.random` — Insecure Randomness

`java.util.Random` sử dụng thuật toán Linear Congruential Generator (LCG) có tính tất định cao.
Kẻ tấn công sau khi quan sát một vài giá trị ngẫu nhiên có thể tính toán được trạng thái seed ban đầu
và dự đoán các giá trị tiếp theo.

Đối với các bài toán bảo mật (mã OTP, reset token, khoá phiên), bắt buộc phải sử dụng `java.security.SecureRandom`
với nguồn entropy từ hệ điều hành.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu `Random` chỉ được dùng để chọn vị trí hiển thị hình ảnh ngẫu nhiên hoặc tính toán thời gian chờ jitter
trong thuật toán retry, tính dễ đoán không gây tổn hại đến cơ chế bảo mật của ứng dụng.

## Nguồn

- Java SE API: `java.util.Random`, `java.security.SecureRandom`
- CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
