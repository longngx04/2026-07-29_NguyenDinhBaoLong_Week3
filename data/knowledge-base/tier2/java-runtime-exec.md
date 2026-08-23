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
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/78.html
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ProcessBuilder.html
---

# `Runtime.exec` / `ProcessBuilder.start` — Command Injection

## 1. Cơ chế rủi ro (Risk Mechanism)

Khi ứng dụng gọi `Runtime.getRuntime().exec(cmdString)` với một chuỗi đơn lẻ, hoặc gọi lệnh qua shell (`/bin/sh -c`, `cmd.exe /c`) mà nội suy trực tiếp dữ liệu từ bên ngoài, trình thông dịch shell hoặc bộ chia từ của tiến trình sẽ diễn giải các siêu ký tự điều khiển shell (như `;`, `&`, `|`, `` ` ``, `$()`, `>`, `<`).

Kẻ tấn công có thể chèn các lệnh bổ sung vào chuỗi tham số để buộc hệ điều hành máy chủ thực thi các chương trình độc hại ngoài ý muốn với quyền hạn của người dùng đang chạy tiến trình Java, dẫn tới chiếm quyền điều khiển máy chủ (Remote Code Execution - RCE).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Nối chuỗi tham số người dùng vào lệnh thực thi qua `Runtime.getRuntime().exec()` hoặc gọi qua shell:

```java
public void pingHost(String host) throws IOException {
    // NGUY HIỂM: Kẻ tấn công có thể truyền host = "127.0.0.1; cat /etc/passwd" để thực thi lệnh thứ hai
    String command = "ping -c 4 " + host;
    Process process = Runtime.getRuntime().exec(command);
    // ...
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng `ProcessBuilder` với danh sách tham số mảng hoặc `List<String>` tách rời hoàn toàn, không thông qua shell:

```java
public void pingHost(String host) throws IOException, InterruptedException {
    // AN TOÀN: Các đối số được truyền dưới dạng mảng độc lập, hệ điều hành không kích hoạt shell để diễn giải cú pháp
    List<String> commandList = Arrays.asList("ping", "-c", "4", host);
    ProcessBuilder processBuilder = new ProcessBuilder(commandList);
    processBuilder.redirectErrorStream(true);
    Process process = processBuilder.start();
    int exitCode = process.waitFor();
    // ...
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

1. **Lớp 1 — Sử dụng API Java gốc thay vì gọi lệnh OS:**
   Ưu tiên sử dụng các thư viện chuẩn của Java (như `java.nio.file` để thao tác tệp, `java.net.InetAddress` để kiểm tra mạng, thư viện Zip/Tar) thay vì gọi các công cụ dòng lệnh của hệ điều hành.
2. **Lớp 2 — Tách rời đối số bằng `ProcessBuilder`:**
   Nếu bắt buộc phải gọi chương trình ngoài, luôn truyền tên tệp thực thi và các đối số dưới dạng danh sách `List<String>` hoặc mảng `String[]` thông qua `ProcessBuilder`. Tuyệt đối không bọc lệnh bằng `sh -c` hoặc `cmd.exe /c` khi có tham số người dùng.
3. **Lớp 3 — Kiểm thực dữ liệu đầu vào (Allowlist Validation) & Giới hạn quyền:**
   Kiểm tra tính hợp lệ của mọi đối số (ví dụ chỉ cho phép ký tự chữ, số, dấu chấm hợp lệ của IP/Hostname qua Regex). Chạy tiến trình Java dưới tài khoản người dùng không có quyền quản trị (non-root user), áp dụng cơ chế sandbox / containerization hạn chế quyền gọi OS binaries.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu lệnh thực thi là một mảng tham số cố định và dữ liệu người dùng chỉ được chuyển vào vị trí một đối số độc lập (không gọi qua `sh -c` hay `cmd.exe /c`), shell không can thiệp và command injection không thể xảy ra. Đánh dấu một đoạn mã an toàn như vậy là lỗ hổng sẽ gây nhiễu kết quả quét.

## 4. Tài liệu tham khảo (References)

- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)
- [Oracle Java SE 17: java.lang.ProcessBuilder API Documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/ProcessBuilder.html)
