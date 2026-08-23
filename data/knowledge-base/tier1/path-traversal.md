---
tier: 1
id: path-traversal
title: Path Traversal (Directory Traversal)
cwe: [CWE-22]
owasp: [A01:2021]
tags: [example, path-traversal, lfi, cwe-22, directory-traversal, a01, file-handling]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://owasp.org/www-community/attacks/Path_Traversal
  - https://cwe.mitre.org/data/definitions/22.html
---

# Path Traversal (Directory Traversal)

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Path Traversal (hay Directory Traversal / Local File Inclusion - LFI) là lỗ hổng bảo mật thuộc nhóm Broken Access Control (CWE-22 / OWASP A01) xảy ra khi ứng dụng sử dụng dữ liệu đầu vào không tin cậy từ người dùng để xây dựng đường dẫn tệp tin mà không thực hiện chuẩn hóa đường dẫn chính tắc (canonicalization) và kiểm tra ranh giới thư mục an toàn.

Điều này cho phép kẻ tấn công sử dụng các chuỗi ký tự chuyển hướng thư mục cha (`../` trên Linux/Unix hoặc `..\` trên Windows) để truy cập ra ngoài thư mục gốc được cấp phép (base directory).

Tác động chính của Path Traversal:
- **Đọc trộm tệp tin nhạy cảm của hệ điều hành:** Đọc các tệp như `/etc/passwd`, `/etc/shadow`, `C:\Windows\win.ini`, các file mã nguồn và cấu hình máy chủ.
- **Rò rỉ thông tin bí mật ứng dụng:** Đọc các file biến môi trường (`.env`), file cấu hình cơ sở dữ liệu (`application.properties`), khóa bí mật RSA / SSH private keys.
- **Ghi đè file nguy hiểm dẫn đến RCE (Arbitrary File Write):** Ghi đè file cấu hình cron job, web shell vào webroot hoặc thư mục nạp thư viện động.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Chuỗi Dot-Dot-Slash cơ bản (`../` & `..\`)

Thường gặp nhất trong các tính năng tải file (download), xem ảnh hoặc nạp tệp tin:

```http
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: example.com
```

Ứng dụng ghép chuỗi `"/var/www/uploads/" + file` sẽ tạo ra đường dẫn `/var/www/uploads/../../../../etc/passwd`, tương đương với `/etc/passwd`.

### 2.2. Mã hóa URL & Double Encoding Bypass

Kẻ tấn công vượt qua các bộ lọc chuỗi ngây thơ (chỉ chặn chuỗi `../` thô) bằng cách mã hóa ký tự:
- **URL Encoding:** `%2e%2e%2f` (`../`), `%2e%2e%5c` (`..\`).
- **Double URL Encoding:** `%252e%252e%252f`.
- **Non-standard UTF-8 Overlong Encoding:** `%c0%af`, `%e0%80%af`.

### 2.3. Path Traversal trong Giải nén File (Zip Slip)

Khi ứng dụng giải nén tệp tin archive (ZIP, TAR, GZ), nếu tên file bên trong archive chứa đường dẫn `../../evil.sh`, quá trình trích xuất file nếu không kiểm tra sẽ ghi đè file ra ngoài thư mục đích giải nén.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống Path Traversal bao gồm các lớp bảo vệ:

1. **Lớp 1 — Chuẩn hóa đường dẫn chính tắc (Path Canonicalization & Verification):**
   Luôn chuyển đổi đường dẫn thành đường dẫn tuyệt đối chuẩn hóa trước khi đọc/ghi file và kiểm tra xem nó có nằm trong thư mục gốc cho phép hay không:
   - Trong Java: Sử dụng `Path.toRealPath()` hoặc `File.getCanonicalPath()` và kiểm tra `targetPath.startsWith(baseDir)`.
2. **Lớp 2 — Sử dụng Định danh ánh xạ thay vì tên file thô:**
   Lưu trữ file trên đĩa dưới tên ngẫu nhiên (UUID) hoặc số định danh trong CSDL; người dùng chỉ yêu cầu tải file qua `fileId` gián tiếp.
3. **Lớp 3 — Danh sách trắng (Allowlist) tên file và phần mở rộng:**
   Nếu bắt buộc nhận tên file, chỉ cho phép ký tự chữ và số (`[a-zA-Z0-9_-]`), từ chối mọi ký tự phân tách đường dẫn (`/`, `\`), ký tự null byte (`%00`) và dấu chấm (`.`).
4. **Lớp 4 — Phân quyền hệ thống tệp tối thiểu (Least Privilege File System):**
   Chạy ứng dụng dưới user hệ thống bị giới hạn, không có quyền đọc các thư mục nhạy cảm (`/etc`, `/var/log`, `/root`) và cấu hình container/chroot jail cô lập.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Path Traversal Attack Guide](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
