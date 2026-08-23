---
tier: 1
id: ssrf
title: Server-Side Request Forgery (SSRF)
cwe: [CWE-918]
owasp: [A10:2021]
tags: [example, ssrf, owasp-a10, request-forgery, cwe-918, a10, network-security]
references:
  - https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/918.html
---

# SSRF — Server-Side Request Forgery

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Server-Side Request Forgery (SSRF - CWE-918 / OWASP A10:2021) là lỗ hổng bảo mật xảy ra khi ứng dụng web máy chủ thực hiện gửi yêu cầu HTTP hoặc kết nối mạng tới một URL/địa chỉ tài nguyên do người dùng cung cấp mà không kiểm tra giới hạn phạm vi đích đến.

Kẻ tấn công có thể lợi dụng sự tin cậy và vị trí mạng của máy chủ để gửi yêu cầu tới các hệ thống nội bộ mà từ mạng Internet bên ngoài không thể truy cập trực tiếp.

Hậu quả nghiêm trọng của SSRF:
- **Truy cập dịch vụ Instance Metadata trên Cloud:** Đọc dữ liệu metadata tại địa chỉ `http://169.254.169.254` (trên AWS, GCP, Azure, DigitalOcean) để trích xuất khóa truy cập tạm thời (IAM Role credentials / API tokens).
- **Quét cổng và tấn công dịch vụ mạng nội bộ (Internal Port Scanning & Pivot):** Tương tác với các dịch vụ nội bộ không yêu cầu xác thực hoặc bảo vệ yếu (như Redis, Memcached, Elasticsearch, Admin consoles).
- **Đọc tệp tin cục bộ qua Protocol Schemas:** Sử dụng các scheme nguy hiểm như `file:///etc/passwd`, `gopher://`, `dict://`.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Basic SSRF tới Cloud Metadata & Loopback

Ứng dụng nhận URL tải ảnh đại diện hoặc webhook:

```http
POST /api/fetch-avatar HTTP/1.1
Host: example.com
Content-Type: application/json

{"avatarUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

Nếu server không kiểm tra IP đích, nó sẽ tải nội dung metadata của cloud provider và trả về cho kẻ tấn công. Tương tự, gọi tới `http://127.0.0.1:8080/admin` hoặc `http://localhost:6379` để can thiệp dịch vụ nội bộ.

### 2.2. SSRF qua Chuyển hướng HTTP (Open Redirect SSRF Bypass)

Kẻ tấn công cung cấp một URL hợp lệ thuộc danh sách trắng bên ngoài, nhưng URL đó phản hồi mã chuyển hướng `302 Found` trỏ về IP mạng nội bộ (`Location: http://192.168.1.50/secret`). Nếu thư viện HTTP client tự động chuyển hướng (Follow Redirects), nó sẽ bị chuyển hướng sang mục tiêu nội bộ.

### 2.3. DNS Rebinding SSRF

Kẻ tấn công đăng ký một tên miền (ví dụ: `attacker-domain.com`) được cấu hình trả về IP công khai hợp lệ khi server kiểm tra lần đầu (TTL ngắn), nhưng ngay sau đó trả về IP nội bộ `127.0.0.1` khi thư viện HTTP thực hiện kết nối thực tế.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Chiến lược phòng chống SSRF hiệu quả bao gồm:

1. **Lớp 1 — Danh sách trắng Domain & Scheme nghiêm ngặt (Strict Allowlist):**
   Chỉ cho phép kết nối tới các tên miền tin cậy cụ thể trong danh sách trắng; chỉ hỗ trợ giao thức `http` và `https`, vô hiệu hóa tuyệt đối các giao thức khác (`file`, `gopher`, `ftp`, `dict`).
2. **Lớp 2 — Kiểm tra và Chặn toàn bộ Dải IP Nội bộ sau khi phân giải DNS (DNS Resolution Check):**
   Thực hiện phân giải DNS trước khi gửi request và kiểm tra xem IP trả về có thuộc các dải mạng riêng tư/loopback hay không:
   - Dải Loopback: `127.0.0.0/8`, `::1`
   - Dải Private (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Dải Link-Local & Cloud Metadata: `169.254.0.0/16`
   - Nếu IP nằm trong các dải trên, từ chối kết nối ngay lập tức.
3. **Lớp 3 — Vô hiệu hóa tính năng tự động chuyển hướng (Disable Auto-Redirect):**
   Tắt chế độ tự động follow redirect trong HTTP client hoặc thực hiện kiểm tra an toàn lại từ đầu đối với URL mới sau mỗi bước redirect.
4. **Lớp 4 — Phân đoạn mạng & IMDSv2:**
   Cấu hình tường lửa máy chủ (Egress Firewall / Network Security Groups) chặn mọi kết nối từ ứng dụng ra mạng nội bộ hoặc dải `169.254.169.254`. Bắt buộc nâng cấp lên AWS IMDSv2 (yêu cầu session token qua PUT header).

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A10: Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
