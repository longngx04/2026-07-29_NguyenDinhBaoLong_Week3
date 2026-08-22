---
tier: 2
id: java-hardcoded-credential
canonical_category: Hardcoded Credentials
cwe: [CWE-798]
tier1_parent: broken-auth
language: java
sink_signatures:
  - java.sql.DriverManager.getConnection
no_rule_yet: true
safe_alternative: "Đọc thông tin xác thực từ biến môi trường, tệp cấu hình bảo mật bên ngoài hoặc Secret Manager"
exploitable_when: >
  mật khẩu hoặc token bí mật được viết cứng dạng chuỗi ký tự trong mã nguồn
  và người có quyền đọc mã nguồn có thể dùng chúng truy cập tài nguyên
not_exploitable_when: >
  chuỗi là thông tin kết nối môi trường phát triển cục bộ giả lập (dummy test credential)
  không có giá trị trên môi trường thực tế
---

# `DriverManager.getConnection` — Hardcoded Credentials

Lưu trữ chuỗi kết nối cơ sở dữ liệu kèm username/password trực tiếp trong mã nguồn
khiến các bí mật bị lộ khi mã được đưa vào hệ thống quản lý phiên bản hoặc phân phối.

Cần chuyển các thông tin bí mật sang biến môi trường (`System.getenv()`), tệp cấu hình
ngoài không commit vào git, hoặc các dịch vụ quản lý bí mật như HashiCorp Vault.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu thông tin đăng nhập chỉ là tài khoản kiểm thử cục bộ trong H2/HSQLDB in-memory database
hoặc container thử nghiệm ngắn hạn (testcontainer), việc hardcode không tạo ra lỗ hổng an ninh trên production.

## Nguồn

- Java SE API: `java.sql.DriverManager`
- CWE-798: Use of Hard-coded Credentials
