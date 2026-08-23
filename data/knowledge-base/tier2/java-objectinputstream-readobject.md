---
tier: 2
id: java-objectinputstream-readobject
canonical_category: Insecure Deserialization
cwe: [CWE-502]
tier1_parent: insecure-deserialization
language: java
sink_signatures:
  - java.io.ObjectInputStream.readObject
matches_rule_ids:
  - java-unsafe-deserialization
safe_alternative: "định dạng dữ liệu thuần như JSON kèm schema validation, hoặc ObjectInputFilter allowlist"
exploitable_when: >
  luồng byte đầu vào nhận dữ liệu nhị phân tuần tự hoá từ caller không tin cậy
  và classpath chứa gadget chain (như Commons Collections, Spring)
not_exploitable_when: >
  luồng đọc từ nguồn trong tin cậy hoàn toàn, hoặc đã cài ObjectInputFilter chỉ cho phép
  một allowlist lớp, hoặc dữ liệu đã được ký và chữ ký được kiểm trước khi deserialize
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/502.html
  - https://docs.oracle.com/en/java/javase/17/core/serialization-filtering1.html
---

# `java.io.ObjectInputStream.readObject` — Insecure Deserialization

## 1. Cơ chế rủi ro (Risk Mechanism)

Java Native Serialization (`ObjectInputStream`) tự động giải mã luồng byte nhị phân thành đối tượng trong bộ nhớ. Trong quá trình này, các phương thức khởi tạo vòng đời đặc biệt (như `readObject()`, `readResolve()`, `validateObject()`) của các lớp có trong classpath sẽ được JVM tự động gọi thực thi trước khi mã ứng dụng kịp kiểm tra kiểu dữ liệu của đối tượng trả về.

Nếu classpath của ứng dụng chứa các thư viện có sẵn "gadget chains" (ví dụ: Apache Commons Collections, Spring Beans, Groovy, các lớp trung gian của JDK), kẻ tấn công có thể chế tạo một chuỗi byte độc hại để kích hoạt việc thực thi mã từ xa (RCE), tạo tệp tin tùy ý hoặc gây tấn công từ chối dịch vụ (DoS) ngay khi phương thức `readObject()` được gọi.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Đọc trực tiếp đối tượng từ luồng dữ liệu nhị phân không tin cậy mà không có bất kỳ bộ lọc lớp nào:

```java
public Object deserializePayload(InputStream untrustedStream) throws IOException, ClassNotFoundException {
    // NGUY HIỂM: readObject() thực thi tự động các gadget chains trong classpath trước khi ép kiểu
    try (ObjectInputStream ois = new ObjectInputStream(untrustedStream)) {
        return ois.readObject();
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Cách 1: Thay thế bằng định dạng dữ liệu có cấu trúc an toàn (JSON) dùng Jackson `ObjectMapper`:

```java
public UserDTO deserializeJsonPayload(String jsonPayload) throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    // AN TOÀN: Không dùng Java native serialization, giải mã dữ liệu thuần theo schema DTO cố định
    return mapper.readValue(jsonPayload, UserDTO.class);
}
```

Cách 2: Nếu bắt buộc phải dùng `ObjectInputStream`, cấu hình `ObjectInputFilter` theo allowlist lớp nghiêm ngặt (JEP 290):

```java
public Object deserializeWithFilter(InputStream untrustedStream) throws IOException, ClassNotFoundException {
    try (ObjectInputStream ois = new ObjectInputStream(untrustedStream)) {
        // AN TOÀN: Chỉ cho phép các lớp DTO cụ thể được deserialize, từ chối mọi lớp khác (!*)
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
            "com.example.dto.UserDTO;java.lang.String;!*"
        );
        ois.setObjectInputFilter(filter);
        return ois.readObject();
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

1. **Lớp 1 — Tránh sử dụng Java Native Serialization:**
   Thay thế cơ chế tuần tự hóa nhị phân mặc định của Java bằng các định dạng dữ liệu trung lập, an toàn hơn như JSON (Jackson/Gson với cấu hình an toàn, tắt polymorphic deserialization mặc định), Protocol Buffers hoặc FlatBuffers.
2. **Lớp 2 — Áp dụng Serialization Filtering (JEP 290 / `ObjectInputFilter`):**
   Khi không thể thay thế `ObjectInputStream`, bắt buộc phải cấu hình `ObjectInputFilter` với chính sách allowlist nghiêm ngặt (`com.example.model.*;!*`). Từ chối mọi lớp không nằm trong danh sách cần thiết để vô hiệu hóa các chuỗi gadget phổ biến.
3. **Lớp 3 — Xác thực toàn vẹn & Ký số (HMAC / Cryptographic Signatures):**
   Nếu đối tượng tuần tự hóa phải truyền qua mạng hoặc lưu trữ bên ngoài, hãy mã hóa và ký số luồng byte bằng thuật toán mật mã mạnh. Kiểm tra tính hợp lệ của chữ ký trước khi chuyển luồng vào `ObjectInputStream`.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu luồng dữ liệu đến từ một kênh nội bộ hoàn toàn cô lập hoặc ứng dụng đã cấu hình `ObjectInputFilter` chặn mọi lớp ngoài danh sách DTO an toàn, việc deserialize không thể kích hoạt gadget chain độc hại. Phân biệt rõ các điều kiện bảo vệ này giúp SAST pipeline đánh giá đúng mức độ nghiêm trọng và không báo động giả.

## 4. Tài liệu tham khảo (References)

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Oracle Java SE 17: Core Libraries - Serialization Filtering Guide](https://docs.oracle.com/en/java/javase/17/core/serialization-filtering1.html)
