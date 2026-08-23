---
tier: 2
id: java-hardcoded-credential
canonical_category: Hardcoded Credentials
cwe: [CWE-798]
tier1_parent: broken-auth
language: java
sink_signatures:
  - java.sql.DriverManager.getConnection
no_rule_yet: true
safe_alternative: "Đọc thông tin xác thực từ biến môi trường, tệp cấu hình bảo mật bên ngoài hoặc Secret Management Service"
exploitable_when: >
  mật khẩu, khóa bí mật hoặc token xác thực được viết cứng dạng chuỗi ký tự trong mã nguồn
  và người có quyền đọc mã nguồn hoặc reverse-engineering có thể trích xuất để truy cập trái phép
not_exploitable_when: >
  chuỗi là thông tin kết nối môi trường phát triển cục bộ giả lập (dummy test credential/in-memory testcontainer)
  không có giá trị trên môi trường thực tế
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config
  - https://cwe.mitre.org/data/definitions/798.html
---

# `DriverManager.getConnection` — Hardcoded Credentials

## 1. Cơ chế rủi ro (Risk Mechanism)

Lỗ hổng Hardcoded Credentials (CWE-798) xảy ra khi lập trình viên nhúng trực tiếp mật khẩu cơ sở dữ liệu, khóa API (API keys), secret token hoặc chứng chỉ bảo mật vào mã nguồn Java dưới dạng chuỗi ký tự cố định (ví dụ gọi `DriverManager.getConnection(url, "admin", "P@ssw0rd123!")`).

Khi mã nguồn được commit vào hệ thống quản lý phiên bản (Git), đóng gói thành các tệp nhị phân phân phối (JAR, WAR, Docker image), hoặc xuất hiện trong nhật ký biên dịch (CI/CD build logs), bất kỳ ai có quyền truy cập vào kho lưu trữ, artifact hoặc thực hiện kỹ thuật dịch ngược (decompilation/reverse engineering) đều có thể trích xuất nguyên vẹn các thông tin bí mật này. Kẻ tấn công có thể sử dụng thông tin bí mật bị lộ để truy cập trực tiếp vào cơ sở dữ liệu sản xuất, đánh cắp dữ liệu nhạy cảm hoặc chiếm quyền kiểm soát hạ tầng máy chủ.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Viết cứng tên đăng nhập và mật khẩu quản trị cơ sở dữ liệu trong mã nguồn Java:

```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseService {
    public Connection getConnection() throws SQLException {
        String url = "jdbc:mysql://db.production.internal:3306/customer_db";
        // NGUY HIỂM: Mật khẩu quản trị được viết cứng trực tiếp trong mã nguồn
        return DriverManager.getConnection(url, "admin", "P@ssw0rd123!");
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Tách biệt mật khẩu sang cấu hình môi trường hoặc nạp động từ Spring Boot Externalized Configuration:

```java
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class SafeDatabaseService {

    @Value("${spring.datasource.url}")
    private String dbUrl;

    @Value("${spring.datasource.username}")
    private String dbUser;

    @Value("${spring.datasource.password}")
    private String dbPassword;

    public Connection getSafeConnection() throws SQLException {
        // AN TOÀN: Nạp thông tin kết nối từ biến môi trường/Vault thông qua cấu hình Spring Boot
        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Quy trình quản lý bí mật an toàn tuân theo 3 lớp phòng vệ:

1. **Lớp 1 — Tách biệt cấu hình mật mã ra ngoài mã nguồn (Externalized Configuration):**
   Sử dụng cơ chế Externalized Configuration của Spring Boot (`application.yml` / `@Value("${spring.datasource.password}")`) hoặc đọc trực tiếp từ biến môi trường hệ điều hành (`System.getenv("DB_PASSWORD")`). Thêm toàn bộ các tệp cấu hình chứa thông tin nhạy cảm cục bộ (`.env`, `application-local.yml`, `secrets.properties`) vào `.gitignore`.
2. **Lớp 2 — Sử dụng dịch vụ quản trị bí mật tập trung (Centralized Secrets Management):**
   Tích hợp các giải pháp quản lý bí mật doanh nghiệp như HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, hoặc GCP Secret Manager. Các hệ thống này cung cấp khả năng cấp phát thông tin đăng nhập tạm thời (dynamic credentials), mã hóa dữ liệu khi lưu trữ/truyền tải và tự động xoay vòng mật khẩu (automated secret rotation) mà không yêu cầu khởi động lại ứng dụng.
3. **Lớp 3 — Quét bí mật tự động và giám sát rò rỉ mã nguồn (Secret Scanning & Pre-commit Hooks):**
   Triển khai công cụ quét tĩnh (Secret Scanners như Gitleaks, TruffleHog, OpenGrep) tại pre-commit hooks và CI/CD pipeline để tự động phát hiện và chặn các commit vô tình chứa mật khẩu, private key hoặc API token trước khi được đẩy lên máy chủ mã nguồn.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu chuỗi tài khoản và mật khẩu chỉ được sử dụng cho môi trường kiểm thử cục bộ cô lập (ví dụ kết nối cơ sở dữ liệu H2 in-memory `jdbc:h2:mem:testdb;USER=sa;PASSWORD=` hoặc testcontainers trong unit test không thể kết nối ra môi trường sản xuất), việc viết chuỗi giả lập (dummy credentials) không tạo ra nguy cơ rò rỉ dữ liệu thực tế. Nhận diện chính xác ngữ cảnh kiểm thử giúp giảm thiểu các cảnh báo sai gây nhiễu cho đội ngũ phát triển.

## 4. Tài liệu tham khảo (References)

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Spring Boot Reference: Externalized Configuration](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
