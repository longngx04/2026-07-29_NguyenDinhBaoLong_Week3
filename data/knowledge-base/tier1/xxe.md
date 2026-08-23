---
tier: 1
id: xxe
title: XML External Entity (XXE) Injection
cwe: [CWE-611, CWE-776]
owasp: [A05:2021]
tags: [example, xxe, xml, cwe-611, injection, cwe-776, a05]
references:
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/611.html
---

# XXE — XML External Entity Injection

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

XML External Entity (XXE Injection - CWE-611 / OWASP A05:2021) là lỗ hổng bảo mật nghiêm trọng xảy ra khi trình phân tích cú pháp XML (XML Parser) xử lý tài liệu XML chứa định nghĩa thực thể ngoài (External Entity) từ nguồn dữ liệu không tin cậy mà không vô hiệu hóa tính năng DTD (Document Type Definition).

Chuẩn XML cho phép định nghĩa các thực thể có thể tham chiếu tới tài nguyên bên ngoài (URI/URL hoặc tệp tin cục bộ). Khi phân tích cú pháp, parser sẽ tự động thay thế thực thể bằng nội dung của tài nguyên đó.

Tác động chính của XXE:
- **Đọc trộm tệp tin hệ thống cục bộ (Local File Disclosure):** Đọc nội dung các file nhạy cảm như `/etc/passwd`, file cấu hình, khóa riêng tư.
- **Tấn công Server-Side Request Forgery (SSRF via XXE):** Ép parser gửi HTTP request tới các dịch vụ nội bộ hoặc endpoint Cloud Metadata (`169.254.169.254`).
- **Từ chối dịch vụ (Denial of Service - Billion Laughs Attack):** Làm cạn kiệt bộ nhớ RAM máy chủ thông qua tấn công phóng đại thực thể đệ quy (XML Bomb / CWE-776).

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Khai thác File Disclosure qua SYSTEM Entity

Kẻ tấn công định nghĩa một thực thể ngoài trỏ tới tệp tin cục bộ trong phần DTD và nhúng thực thể đó vào trường dữ liệu XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <user>&xxe;</user>
</data>
```

Khi máy chủ phân tích cú pháp và hiển thị lại giá trị `<user>`, nội dung tệp `/etc/passwd` sẽ bị rò rỉ trực tiếp trên phản hồi.

### 2.2. SSRF qua XXE

Thực thể ngoài trỏ tới địa chỉ URL mạng nội bộ:

```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<order><id>&xxe;</id></order>
```

### 2.3. Blind XXE / Out-of-Band (OOB) XXE

Khi máy chủ không trả về nội dung XML đã parse, kẻ tấn công sử dụng Parameter Entity (`%`) để tải file DTD độc hại từ máy chủ ngoài của mình, sau đó gửi nội dung file máy chủ nạn nhân ra ngoài thông qua URL request (ví dụ: `http://attacker.com/?data=...`).

### 2.4. XML Entity Expansion / Billion Laughs (DoS)

Sử dụng chuỗi thực thể lồng nhau cấp số nhân (ví dụ: 10 thực thể lồng nhau tạo ra hàng triệu bản sao trong bộ nhớ) gây treo hoặc tràn bộ nhớ JVM (OutOfMemoryError).

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống XXE triệt để:

1. **Lớp 1 — Vô hiệu hóa hoàn toàn DTD trên mọi Parser XML (Disallow DTD):**
   Cấu hình parser vô hiệu hóa hoàn toàn khai báo DOCTYPE. Trong Java:
   ```java
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   ```
2. **Lớp 2 — Tắt tính năng nạp External Entities:**
   Nếu bắt buộc phải sử dụng DTD vì yêu cầu nghiệp vụ, bắt buộc phải tắt các tính năng nạp thực thể ngoài:
   ```java
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
   ```
3. **Lớp 3 — Bật chế độ Xử lý An toàn (FEATURE_SECURE_PROCESSING):**
   Kích hoạt cờ `XMLConstants.FEATURE_SECURE_PROCESSING` để giới hạn số lượng thực thể mở rộng và ngăn chặn tấn công từ chối dịch vụ XML Bomb.
4. **Lớp 4 — Ưu tiên sử dụng định dạng JSON:**
   Chuyển đổi giao tiếp API sang định dạng JSON nếu không cần các tính năng đặc thù của XML.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
