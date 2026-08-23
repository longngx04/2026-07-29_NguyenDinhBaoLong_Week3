---
tier: 2
id: java-sql-statement-execute
canonical_category: SQL Injection
cwe: [CWE-89]
tier1_parent: sql-injection
language: java
sink_signatures:
  - java.sql.Statement.execute
  - java.sql.Statement.executeQuery
  - java.sql.Statement.executeUpdate
matches_rule_ids:
  - java-sql-statement-execution
safe_alternative: "java.sql.PreparedStatement với placeholder `?` và setString/setInt"
exploitable_when: >
  chuỗi truy vấn được dựng bằng nối chuỗi hoặc String.format với giá trị mà
  caller kiểm soát, và giá trị đó không đi qua allowlist ký tự
not_exploitable_when: >
  truy vấn là hằng biên dịch không có nội suy, hoặc mọi giá trị nội suy đều lấy
  từ một allowlist cố định trong mã, hoặc giá trị đã qua PreparedStatement.setXxx
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/89.html
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/PreparedStatement.html
---

# `java.sql.Statement.execute*` — SQL Injection

## 1. Cơ chế rủi ro (Risk Mechanism)

`java.sql.Statement` nhận nguyên một chuỗi SQL thô và chuyển trực tiếp tới cơ sở dữ liệu để phân tích cú pháp và thực thi. Trình phân tích cú pháp SQL (SQL parser) không thể phân biệt được ranh giới giữa cú pháp lệnh SQL định sẵn và dữ liệu người dùng truyền vào khi chuỗi được ghép bằng phép nối chuỗi (`+`) hoặc định dạng chuỗi (`String.format()`).

Kẻ tấn công có thể chèn các ký tự điều khiển cú pháp SQL (như dấu nháy đơn `'`, dấu chấm phẩy `;`, toán tử `--`, `OR 1=1`) để thay đổi cấu trúc truy vấn, vượt qua xác thực, đọc trích xuất dữ liệu trái phép hoặc thực thi các lệnh quản trị phá hoại cơ sở dữ liệu.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Ghép trực tiếp biến đầu vào không tin cậy `username` vào câu lệnh SQL thông qua `Statement`:

```java
public User findUser(Connection conn, String username) throws SQLException {
    Statement stmt = conn.createStatement();
    // NGUY HIỂM: Nối chuỗi trực tiếp khiến đầu vào người dùng trở thành một phần cú pháp SQL
    String sql = "SELECT id, name, role FROM users WHERE username = '" + username + "'";
    ResultSet rs = stmt.executeQuery(sql);
    if (rs.next()) {
        return new User(rs.getLong("id"), rs.getString("name"), rs.getString("role"));
    }
    return null;
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng `PreparedStatement` với tham số hóa (parameterized query) thông qua placeholder `?`:

```java
public User findUser(Connection conn, String username) throws SQLException {
    String sql = "SELECT id, name, role FROM users WHERE username = ?";
    // AN TOÀN: Truy vấn được biên dịch trước, giá trị tham số được truyền qua kênh dữ liệu riêng biệt
    try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, username);
        try (ResultSet rs = pstmt.executeQuery()) {
            if (rs.next()) {
                return new User(rs.getLong("id"), rs.getString("name"), rs.getString("role"));
            }
        }
    }
    return null;
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Phòng thủ SQL Injection đòi hỏi mô hình phòng thủ theo chiều sâu (Defense-in-Depth) với 3 lớp:

1. **Lớp 1 — Tham số hóa truy vấn (Parameterized Queries / PreparedStatement):**
   Luôn sử dụng `PreparedStatement` với placeholder `?` hoặc các thư viện ORM an toàn (JPA, Hibernate, Spring Data JPA). Database engine sẽ biên dịch khung câu lệnh trước, dữ liệu người dùng chỉ được coi là giá trị đơn thuần (literal value), triệt tiêu hoàn toàn khả năng can thiệp cú pháp.
2. **Lớp 2 — Allowlist danh sách trắng cho các định danh động (Dynamic Identifiers):**
   Với các trường hợp bắt buộc phải động mà JDBC không hỗ trợ placeholder `?` (như tên bảng, tên cột trong mệnh đề `ORDER BY`, chiều sắp xếp `ASC`/`DESC`), phải đối chiếu biến với một danh sách giá trị an toàn (enum/allowlist) cố định trong mã nguồn trước khi ghép chuỗi.
3. **Lớp 3 — Phân quyền cơ sở dữ liệu tối thiểu (Principle of Least Privilege):**
   Tài khoản kết nối CSDL của ứng dụng chỉ được cấp quyền tối thiểu cần thiết (`SELECT`, `INSERT`, `UPDATE` trên bảng nhất định), thu hồi quyền `DROP`, `ALTER`, `GRANT` và ngắt quyền truy cập vào các bảng hệ thống để hạn chế thiệt hại tối đa nếu xảy ra lỗ hổng.

### Vì sao `not_exploitable_when` quan trọng ở đây

`SET SCHEMA "` + name + `"` nhìn giống một điểm nối chuỗi nguy hiểm, nhưng nếu `name` được lấy từ một `enum` cố định hoặc danh sách schema đã được xác thực qua allowlist thì kẻ tấn công không thể chèn ký tự điều khiển. Việc báo cáo mọi lệnh `Statement` là lỗ hổng mà không kiểm tra nguồn gốc biến sẽ làm tăng tỷ lệ dương tính giả (false positive / over-claim rate).

## 4. Tài liệu tham khảo (References)

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)
- [Oracle Java SE 17: java.sql.PreparedStatement API Documentation](https://docs.oracle.com/en/java/javase/17/docs/api/java.sql/java/sql/PreparedStatement.html)
