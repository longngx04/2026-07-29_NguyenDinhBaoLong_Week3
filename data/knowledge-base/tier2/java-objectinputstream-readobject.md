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
---

# `ObjectInputStream.readObject` — Insecure Deserialization

Java Native Serialization tự động khởi tạo đối tượng và gọi các phương thức vòng đời
(như `readObject()`) của các lớp trong classpath. Khi classpath chứa các thư viện có
gadget chains, kẻ tấn công có thể thực thi mã từ xa (RCE).

Khắc phục an toàn bằng cách chuyển sang các định dạng không thực thi như JSON/Protocol Buffers,
hoặc thiết lập bộ lọc `ObjectInputFilter` nghiêm ngặt theo allowlist.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu luồng dữ liệu đến từ một kênh nội bộ hoàn toàn cô lập hoặc ứng dụng đã cấu hình
`ObjectInputFilter` chặn mọi lớp ngoài danh sách DTO an toàn, việc deserialize không thể kích hoạt
gadget chain độc hại.

## Nguồn

- Java SE API: `java.io.ObjectInputStream`, `java.io.ObjectInputFilter`
- CWE-502: Deserialization of Untrusted Data
