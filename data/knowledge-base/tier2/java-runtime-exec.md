---
tier: 2
id: java-runtime-exec
canonical_category: Command Injection
cwe: [CWE-78]
tier1_parent: command-injection
language: java
sink_signatures:
  - java.lang.Runtime.exec
  - java.lang.ProcessBuilder.start
matches_rule_ids:
  - java-command-execution
safe_alternative: "ProcessBuilder với danh sách tham số tách rời, không qua shell"
exploitable_when: >
  chuỗi lệnh hệ thống được nối từ dữ liệu người dùng truyền vào mà không được kiểm tra,
  cho phép chèn ký tự điều khiển shell như `;`, `|`, `&`
not_exploitable_when: >
  lệnh là hằng không nội suy, hoặc mọi phần nội suy đến từ allowlist cố định,
  hoặc lệnh được truyền dạng mảng tham số nên shell không diễn giải
---

# `Runtime.exec` / `ProcessBuilder.start` — Command Injection

Việc truyền trực tiếp chuỗi chứa dữ liệu người dùng vào `Runtime.exec()` hoặc shell
có thể khiến kẻ tấn công nối các lệnh tuỳ ý trên hệ điều hành của máy chủ.

Sử dụng `ProcessBuilder` truyền mảng tham số riêng biệt giúp tách bạch lời gọi nhị phân
và danh sách đối số, ngăn chặn shell diễn giải các ký tự điều khiển lệnh.

## Vì sao `not_exploitable_when` quan trọng ở đây

Nếu lệnh thực thi là một mảng tham số cố định và dữ liệu người dùng chỉ được chuyển
vào vị trí một đối số độc lập (không gọi qua `sh -c` hay `cmd.exe /c`), shell không can thiệp
và command injection không thể xảy ra.

## Nguồn

- Java SE API: `java.lang.Runtime`, `java.lang.ProcessBuilder`
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
