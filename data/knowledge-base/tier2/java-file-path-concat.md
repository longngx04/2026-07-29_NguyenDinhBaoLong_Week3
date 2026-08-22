---
tier: 2
id: java-file-path-concat
canonical_category: Path Traversal
cwe: [CWE-22]
tier1_parent: path-traversal
language: java
sink_signatures:
  - java.io.File.<init>
  - java.nio.file.Paths.get
no_rule_yet: true
safe_alternative: "Chuẩn hoá đường dẫn bằng Path.normalize() và kiểm tra Path.startsWith(baseDir)"
exploitable_when: >
  tên file hoặc đường dẫn con từ caller chứa chuỗi traversal (`../` hoặc `..\`)
  được nối trực tiếp vào thư mục gốc mà không kiểm tra giới hạn
not_exploitable_when: >
  đường dẫn đã được chuẩn hoá qua Path.toRealPath() hoặc normalize() và xác thực
  nằm hoàn toàn bên trong thư mục gốc cho phép (base directory check)
---

# `File.<init>` / `Paths.get` — Path Traversal

Nối chuỗi trực tiếp từ dữ liệu người dùng để tạo đường dẫn tệp tin cho phép kẻ tấn công
sử dụng các chuỗi `../` để thoát khỏi thư mục dự kiến và đọc hoặc ghi đè các tệp nhạy cảm
trên hệ thống.

Biện pháp khắc phục là phân giải đường dẫn tuyệt đối, gọi `normalize()` và kiểm tra phương thức
`startsWith()` so với thư mục gốc được chỉ định.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu ứng dụng trích xuất chỉ lấy tên tệp bằng `FilenameUtils.getName()` hoặc kiểm tra
`canonicalPath.startsWith(baseDir)`, kẻ tấn công không thể đọc file ngoài phạm vi.

## Nguồn

- Java NIO API: `java.nio.file.Path`, `java.io.File`
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
