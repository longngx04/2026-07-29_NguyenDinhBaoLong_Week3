---
tier: 1
id: sql-injection
title: SQL Injection (SQLi)
cwe: [CWE-89]
owasp: [A03:2021]
tags: [example, sql-injection, sqli, cwe-89, injection, java, database, a03]
references:
  - https://owasp.org/Top10/A03_2021-Injection/
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/89.html
---

# SQL Injection (SQLi)

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)

SQL Injection (SQLi) là lớp lỗ hổng bảo mật xảy ra khi dữ liệu đầu vào không tin cậy từ người dùng được đưa trực tiếp vào câu lệnh truy vấn SQL mà không qua cơ chế tham số hóa (parameterization) hoặc lọc dữ liệu hợp lệ. Điều này cho phép kẻ tấn công can thiệp vào cấu trúc cú pháp của lệnh SQL và thay đổi luồng thực thi dự kiến của ứng dụng trên cơ sở dữ liệu.

Tác động của SQL Injection rất nghiêm trọng, bao gồm:
- **Rò rỉ dữ liệu nhạy cảm:** Đọc trích xuất toàn bộ bảng dữ liệu người dùng, thông tin thẻ thanh toán, mật khẩu và dữ liệu bí mật kinh doanh.
- **Vượt qua cơ chế xác thực:** Đăng nhập vào tài khoản người dùng hoặc quản trị viên mà không cần biết mật khẩu hợp lệ.
- **Mất tính toàn vẹn dữ liệu:** Sửa đổi, chèn thêm hoặc xóa sạch các bản ghi quan trọng trong cơ sở dữ liệu.
- **Thực thi mã từ xa (RCE):** Trong nhiều môi trường cơ sở dữ liệu (như Microsoft SQL Server với `xp_cmdshell` hoặc MySQL/PostgreSQL qua User-Defined Functions), kẻ tấn công có thể leo thang chiếm quyền điều khiển hệ điều hành máy chủ.

## 2. Các biến thể phổ biến (Common Attack Variants)

### 2.1. Nối chuỗi trực tiếp (Direct String Concatenation)

Biến thể cơ bản nhất xuất hiện khi mã nguồn sử dụng phép toán cộng chuỗi (`+`) hoặc hàm định dạng (`String.format()`) để tạo chuỗi SQL động:

```java
// LỖ HỔNG: Nối chuỗi biến userInput vào câu lệnh SQL
String q = "SELECT * FROM users WHERE name = '" + userInput + "'";
statement.executeQuery(q);
```

Khi kẻ tấn công truyền vào chuỗi payload `' OR '1'='1`, câu lệnh trở thành:
```sql
SELECT * FROM users WHERE name = '' OR '1'='1'
```
Điều này khiến mệnh đề `WHERE` luôn thỏa mãn và trả về toàn bộ bản ghi trong cơ sở dữ liệu.

### 2.2. Vượt qua xác thực trên Form đăng nhập (Authentication Bypass)

Truy vấn xác thực tài khoản dạng `SELECT * FROM users WHERE username = '...' AND password = '...'` nếu được ghép chuỗi động sẽ cho phép kẻ tấn công bypass đăng nhập bằng `' OR '1'='1' --`:

```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
```
Ký tự comment `--` (hoặc `#` trong MySQL) vô hiệu hóa toàn bộ phần kiểm tra mật khẩu phía sau.

### 2.3. Blind SQL Injection (Inference SQLi) & Time-based SQLi

Khi ứng dụng không trả về dữ liệu hay thông báo lỗi SQL trực tiếp trên giao diện:
- **Boolean-based Blind:** Kẻ tấn công suy đoán từng ký tự của dữ liệu dựa trên sự khác biệt về phản hồi HTTP (nội dung trang, mã trạng thái HTTP).
- **Time-based Blind:** Kẻ tấn công chèn các hàm gây trễ thời gian thực thi (như `pg_sleep(5)` trên PostgreSQL, `WAITFOR DELAY '0:0:5'` trên SQL Server, hoặc `sleep(5)` trên MySQL) và đo thời gian máy chủ phản hồi để suy luận dữ liệu.

### 2.4. Second-Order SQL Injection (Stored SQLi)

Dữ liệu đầu vào độc hại được lưu trữ trong cơ sở dữ liệu ở bước đầu, nhưng sau đó được một quy trình xử lý nền hoặc truy vấn nội bộ khác đọc ra và ghép vào một câu lệnh SQL động mà không kiểm soát.

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)

Để phòng chống SQL Injection triệt để, hệ thống cần áp dụng chiến lược phòng thủ theo chiều sâu:

1. **Lớp 1 — Tham số hóa truy vấn bắt buộc (Parameterized Queries / PreparedStatement):**
   Luôn sử dụng `PreparedStatement` với placeholder `?` trong Java (hoặc các thư viện ORM như Spring Data JPA, Hibernate). Khi sử dụng tham số hóa, hệ quản trị cơ sở dữ liệu sẽ biên dịch cú pháp truy vấn trước khi gán dữ liệu người dùng, biến dữ liệu thành literal value đơn thuần và triệt tiêu hoàn toàn khả năng can thiệp cú pháp. Không nối chuỗi vào SQL động.
2. **Lớp 2 — Danh sách trắng (Allowlist) cho các thành phần động:**
   Đối với các thành phần của câu lệnh SQL không thể tham số hóa qua JDBC (như tên bảng, tên cột trong mệnh đề `ORDER BY`, thứ tự sắp xếp `ASC`/`DESC`), bắt buộc phải đối chiếu đầu vào với một tập hợp giá trị danh sách trắng (enum/allowlist) cố định trong mã nguồn.
3. **Lớp 3 — Phân quyền cơ sở dữ liệu tối thiểu (Principle of Least Privilege):**
   Tài khoản kết nối cơ sở dữ liệu của ứng dụng chỉ được cấp quyền thao tác trên các bảng cần thiết (`SELECT`, `INSERT`, `UPDATE`), thu hồi các quyền quản trị phá hoại (`DROP`, `ALTER`, `GRANT`) và cô lập quyền truy cập bảng hệ thống.
4. **Lớp 4 — Lưu trữ mật khẩu an toàn & WAF:**
   Không bao giờ so sánh mật khẩu dạng văn bản thuần (plaintext) trong câu lệnh SQL; luôn băm mật khẩu bằng thuật toán an toàn (BCrypt, Argon2id). Sử dụng Web Application Firewall (WAF) để hỗ trợ phát hiện và ngăn chặn sớm các chuỗi tấn công phổ biến.

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)

- [OWASP Top 10:2021 — A03: Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
