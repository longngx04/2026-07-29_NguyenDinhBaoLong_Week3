---
tier: 1
id: idor
title: Insecure Direct Object Reference (IDOR / Broken Access Control)
cwe: [CWE-639]
owasp: [A01:2021]
tags: [example, idor, access-control, broken-access-control, a01, cwe-639, authorization]
references:
  - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/639.html
---

# IDOR — Insecure Direct Object Reference (Broken Access Control)

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

Insecure Direct Object Reference (IDOR) là một dạng lỗ hổng kiểm soát truy cập (Broken Access Control - OWASP A01) xảy ra khi ứng dụng cho phép người dùng truy cập trực tiếp tới các đối tượng hoặc tài nguyên nội bộ thông qua định danh (như `userId`, `accountId`, `invoiceId`, số thứ tự trong CSDL) do người dùng cung cấp mà không xác thực quyền sở hữu (ownership authorization) của người dùng đối với đối tượng đó ở phía server.

Tác động của IDOR:
- **Rò rỉ dữ liệu cá nhân hàng loạt (Mass PII Exfiltration):** Kẻ tấn công có thể quét duyệt qua toàn bộ dải ID (ví dụ: đổi `userId=123` thành `124`, `125`...) để xem dữ liệu nhạy cảm của người dùng khác.
- **Sửa đổi hoặc xóa tài nguyên trái phép:** Thay đổi thông tin cá nhân, sửa đơn hàng, xóa file tài liệu của nạn nhân.
- **Leo thang đặc quyền (Privilege Escalation):** Chiếm quyền tài khoản quản trị viên nếu các thao tác quản trị dùng tham số ID thiếu phân quyền.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Thao túng tham số trên URL (URL Parameter Tampering)

Thay đổi định danh trực tiếp trong đường dẫn RESTful API hoặc query parameter:

```http
GET /api/documents/1094 HTTP/1.1
Host: example.com
Cookie: session=user_A_cookie
```

Nếu server chỉ kiểm tra người dùng `User A` đã đăng nhập mà không kiểm tra tài liệu `1094` có thuộc sở hữu của `User A` hay không, kẻ tấn công dễ dàng đổi thành `GET /api/documents/1095` để đọc tài liệu của `User B`.

### 2.2. Thao túng tham số trong Request Body / JSON Payload

IDOR xuất hiện trong các API nhận JSON body cho các hành động cập nhật thông tin:

```json
{
  "accountId": "ACC-99882",
  "email": "attacker@evil.com"
}
```
Kẻ tấn công truyền `accountId` của nạn nhân vào request của chính mình để thay đổi dữ liệu của nạn nhân.

### 2.3. IDOR trong chức năng tải file / xuất báo cáo (File & Export IDOR)

Ứng dụng cho phép tải file qua tham số định danh như `filename=invoice_1001.pdf` hoặc `reportId=8842` mà không kiểm tra quyền của người gửi yêu cầu đối với file/báo cáo đó.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Phòng chống IDOR đòi hỏi cơ chế kiểm soát truy cập nghiêm ngặt ở tầng backend:

1. **Lớp 1 — Kiểm tra quyền sở hữu đối tượng ở tầng Server (Object-Level Authorization):**
   Mọi truy vấn lấy, sửa đổi hoặc xóa dữ liệu đều phải ràng buộc với định danh người dùng hiện tại lấy từ phiên làm việc tin cậy (`WHERE resource_id = :id AND user_id = :currentUser.id`), không bao giờ chỉ dựa vào ID do client truyền lên.
2. **Lớp 2 — Sử dụng Định danh ngẫu nhiên khó đoán (Random / Non-sequential IDs):**
   Sử dụng UUID v4, CUID hoặc mã băm ngẫu nhiên có độ dài đủ lớn (ví dụ: `uuid-v4`) thay vì các số nguyên tự tăng tuần tự (Auto-increment integers). Điều này ngăn chặn kẻ tấn công tự động quét duyệt (enumeration) toàn bộ tài nguyên.
3. **Lớp 3 — Kiểm soát truy cập dựa trên chính sách (Policy-Based / Attribute-Based Access Control):**
   Triển khai khung kiểm soát truy cập tập trung (như Spring Security `@PreAuthorize("@documentSecurity.isOwner(authentication, #id)")`) để đảm bảo logic phân quyền được thực thi đồng nhất trên toàn bộ hệ thống.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
