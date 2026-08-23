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
safe_alternative: "Chuẩn hoá đường dẫn bằng Path.normalize() và kiểm tra targetPath.startsWith(baseDir)"
exploitable_when: >
  tên file hoặc đường dẫn con từ caller chứa chuỗi traversal (`../` hoặc `..\`)
  được nối trực tiếp vào thư mục gốc mà không kiểm tra giới hạn
not_exploitable_when: >
  đường dẫn đã được chuẩn hoá qua Path.toRealPath() hoặc normalize() và xác thực
  nằm hoàn toàn bên trong thư mục gốc cho phép (base directory check)
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/22.html
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Path.html
---

# `File.<init>` / `Paths.get` — Path Traversal

## 1. Cơ chế rủi ro (Risk Mechanism)

Khi ứng dụng Java tạo đối tượng tệp tin (`java.io.File` hoặc `java.nio.file.Path`) bằng cách ghép nối trực tiếp tên tệp do người dùng cung cấp vào đường dẫn thư mục gốc (`new File(uploadDir, userInput)` hoặc `Paths.get(uploadDir, userInput)`), trình xử lý hệ thống tệp sẽ phân giải các chuỗi điều hướng đặc biệt (`../`, `..\`, `%2e%2e%2f`).

Kẻ tấn công có thể chèn các chuỗi điều hướng này để thoát khỏi phạm vi thư mục lưu trữ dự kiến (sandbox escape). Hậu quả là kẻ tấn công có thể đọc trái phép các tệp tin nhạy cảm của hệ thống và ứng dụng (như `/etc/passwd`, tệp `.env`, mã nguồn, cấu hình chứng chỉ) hoặc ghi đè/tạo tệp tùy ý dẫn đến chiếm quyền điều khiển máy chủ (Remote Code Execution qua web shell hoặc SSH keys).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Khởi tạo đối tượng `File` bằng cách nối trực tiếp chuỗi tên tệp từ tham số đầu vào mà không kiểm tra tính hợp lệ của đường dẫn:

```java
public File getUploadedFile(File uploadDir, String userInputFilename) {
    // NGUY HIỂM: Người dùng có thể truyền "../../etc/passwd" để đọc tệp ngoài phạm vi uploadDir
    File targetFile = new File(uploadDir, userInputFilename);
    return targetFile;
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng `java.nio.file.Path` để chuẩn hóa đường dẫn và xác thực ranh giới thư mục gốc bằng `startsWith()`:

```java
public Path getSafeFilePath(Path baseDir, String userInputFilename) throws SecurityException {
    // AN TOÀN: Chuẩn hóa đường dẫn tuyệt đối và kiểm tra ranh giới thư mục gốc
    Path target = baseDir.resolve(userInputFilename).normalize().toAbsolutePath();
    Path base = baseDir.toAbsolutePath().normalize();

    if (!target.startsWith(base)) {
        throw new SecurityException("Phát hiện hành vi Path Traversal bất hợp pháp: " + userInputFilename);
    }
    return target;
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Chiến lược phòng chống Path Traversal hiệu quả bao gồm 3 lớp bảo vệ:

1. **Lớp 1 — Chuẩn hóa đường dẫn và kiểm tra ranh giới (Path Normalization & Boundary Check):**
   Luôn sử dụng `Path.resolve(filename).normalize().toAbsolutePath()` và kiểm tra phương thức `target.startsWith(baseDir)`. Thao tác `normalize()` sẽ triệt tiêu các chuỗi `.` và `..`, giúp việc so sánh tiền tố thư mục gốc đạt độ chính xác tuyệt đối.
2. **Lớp 2 — Làm sạch tên tệp và loại bỏ ký tự phân cách (Filename Sanitization):**
   Chỉ lấy phần tên tệp cơ bản (basename) thông qua `FilenameUtils.getName(userInput)` hoặc `Path.getFileName()`, loại bỏ hoàn toàn các ký tự phân tách đường dẫn (`/`, `\`). Ưu tiên áp dụng danh sách trắng (allowlist) ký tự cho tên tệp (ví dụ regex `^[a-zA-Z0-9._-]+$`).
3. **Lớp 3 — Phân quyền hệ thống tệp tối thiểu (Filesystem Least Privilege):**
   Chạy ứng dụng với tài khoản dịch vụ không có quyền quản trị (non-root user), cấu hình quyền đọc/ghi chặt chẽ chỉ trên các thư mục cần thiết và thiết lập chroot/container isolation nếu có thể.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu ứng dụng trích xuất chỉ lấy tên tệp bằng `FilenameUtils.getName()` hoặc đã kiểm tra `target.startsWith(baseDir)` sau khi chuẩn hóa bằng `normalize()`, kẻ tấn công không thể đọc tệp ngoài phạm vi cho phép dù chuỗi đầu vào có chứa `../`. Việc cảnh báo mọi phép nối chuỗi đường dẫn mà không kiểm tra bước chuẩn hóa sẽ làm tăng tỷ lệ dương tính giả (false positive).

## 4. Tài liệu tham khảo (References)

- [OWASP File Path Traversal Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Path_Traversal_Cheat_Sheet.html)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [Oracle Java SE 17: java.nio.file.Path API Documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/nio/file/Path.html)

