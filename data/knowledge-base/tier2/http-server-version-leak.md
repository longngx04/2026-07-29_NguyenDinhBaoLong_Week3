---
tier: 2
id: http-server-version-leak
canonical_category: Information Disclosure
cwe: [CWE-497]
tier1_parent: information-disclosure
language: http
sink_signatures:
  - Server
matches_rule_ids:
  - "10009"
  - "10036"
safe_alternative: "Ẩn hoặc chuẩn hóa tiêu đề Server và X-Powered-By trên máy chủ web / reverse proxy"
exploitable_when: >
  máy chủ trả về tên và phiên bản chi tiết của phần mềm hệ thống (Apache/Nginx/Tomcat) đang tồn tại các lỗ hổng bảo mật đã công bố
not_exploitable_when: >
  phiên bản máy chủ công khai đã được cập nhật bản vá bảo mật mới nhất và không chứa lỗ hổng 1-day/0-day đã biết.
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/497.html
  - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
---

# `Server` — Server Version Information Leak

## 1. Cơ chế rủi ro (Risk Mechanism)

Khi máy chủ web hoặc ứng dụng phản hồi các yêu cầu HTTP với tiêu đề `Server` (ZAP Rule 10009/10036 / CWE-497) hoặc `X-Powered-By` chứa chuỗi định danh phiên bản cụ thể (ví dụ: `Apache/2.4.41 (Ubuntu)`, `nginx/1.18.0`, `Apache-Coyote/1.1`), hệ thống đã vô tình tiết lộ chi tiết ngăn xếp công nghệ (technology stack) cho bất kỳ ai truy cập.

Hành vi rò rỉ này tạo thuận lợi lớn cho kẻ tấn công trong giai đoạn trinh sát (reconnaissance):
- Thay vì phải dò quét ngẫu nhiên, kẻ tấn công có thể tra cứu trực tiếp các cơ sở dữ liệu lỗ hổng bảo mật (NVD, Exploit-DB, GitHub Security Advisories) theo đúng số phiên bản máy chủ để tìm các bản vá còn thiếu.
- Nếu hệ thống đang vận hành phiên bản cũ có lỗ hổng thực thi mã từ xa (RCE) hoặc vượt qua xác thực đã biết (1-day exploit), kẻ tấn công có thể vũ khí hóa và khai thác ngay lập tức mà không cần tốn thời gian phân tích sâu.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Phản hồi HTTP chứa tiêu đề `Server` và `X-Powered-By` tiết lộ chi tiết phiên bản phần mềm máy chủ và framework:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Server: Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41 OpenSSL/1.1.1f
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
Content-Length: 512
Connection: keep-alive

<!DOCTYPE html>
<html><body><h1>Portal</h1></body></html>
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Phản hồi HTTP đã được ẩn thông tin phiên bản hoặc loại bỏ hoàn toàn các tiêu đề định danh công nghệ:

```http
HTTP/1.1 200 OK
Date: Wed, 20 Aug 2026 10:00:00 GMT
Server: SentinelGateway
Content-Type: text/html; charset=UTF-8
Content-Length: 512
Connection: keep-alive

<!DOCTYPE html>
<html><body><h1>Portal</h1></body></html>
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Khắc phục rò rỉ phiên bản máy chủ trên các tầng hạ tầng:

1. **Lớp 1 — Vô hiệu hóa banner phiên bản trên Nginx:**
   Trong file `nginx.conf`, thêm chỉ thị:
   ```nginx
   server_tokens off;
   # Hoặc thay thế tên Server qua module headers-more:
   more_set_headers 'Server: SentinelGateway';
   ```
2. **Lớp 2 — Cấu hình Apache HTTP Server:**
   Trong file `httpd.conf` hoặc `apache2.conf`:
   ```apache
   ServerTokens Prod
   ServerSignature Off
   ```
3. **Lớp 3 — Loại bỏ tiêu đề `X-Powered-By`:**
   - Trong PHP: Thiết lập `expose_php = Off` trong `php.ini`.
   - Trong Express.js: Gọi `app.disable('x-powered-by');`.
   - Trong Spring Boot / Tomcat: Cấu hình `server.server-header=""` trong `application.properties`.
4. **Lớp 4 — Chuẩn hóa tiêu đề tại API Gateway / Reverse Proxy:**
   Sử dụng API Gateway làm lá chắn trung tâm để ghi đè hoặc loại bỏ mọi tiêu đề rò rỉ thông tin trước khi chuyển tiếp gói tin ra Internet.

## 4. Tài liệu tham khảo (References)

- [OWASP HTTP Headers Cheat Sheet — Server](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [CWE-497: Exposure of System Data to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)
- [OWASP Top 10:2021 — A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
