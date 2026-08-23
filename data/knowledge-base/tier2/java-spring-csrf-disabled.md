---
tier: 2
id: java-spring-csrf-disabled
canonical_category: CSRF
cwe: [CWE-352]
tier1_parent: csrf
language: java
sink_signatures:
  - org.springframework.security.config.annotation.web.builders.HttpSecurity.csrf().disable
no_rule_yet: true
safe_alternative: "Giữ bảo vệ CSRF bật mặc định của Spring Security hoặc cấu hình CookieCsrfTokenRepository.withHttpOnlyFalse() cho Single Page Application (SPA)"
exploitable_when: >
  ứng dụng web dùng xác thực dựa trên Cookie phiên duyệt (Session Cookie) cho các thao tác
  thay đổi trạng thái (POST/PUT/DELETE) nhưng tắt bảo vệ CSRF
not_exploitable_when: >
  ứng dụng là API hoàn toàn stateless sử dụng Bearer Token trong header Authorization
  hoặc mọi cookie đều cấu hình SameSite=Strict
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
  - https://cwe.mitre.org/data/definitions/352.html
---

# `HttpSecurity.csrf().disable` — Disabled CSRF Protection

## 1. Cơ chế rủi ro (Risk Mechanism)

Cross-Site Request Forgery (CSRF) là dạng tấn công lợi dụng việc trình duyệt web tự động gửi kèm thông tin xác thực phiên làm việc (Session Cookie, `JSESSIONID`) của người dùng khi gửi yêu cầu tới ứng dụng đích từ một trang web của bên thứ ba (Cross-Origin Request).

Khi cấu hình bảo mật Spring Security gọi `http.csrf().disable()` (hoặc `csrf.disable()` trong lambda DSL), toàn bộ cơ chế xác thực Synchronizer Token bị vô hiệu hóa. Kẻ tấn công có thể lừa nạn nhân (đang đăng nhập) truy cập vào một trang web độc hại chứa mã JavaScript hoặc biểu mẫu ẩn tự động gửi yêu cầu thay đổi trạng thái (`POST`, `PUT`, `DELETE`) tới máy chủ đích. Máy chủ sẽ thực thi các hành động nhạy cảm (chuyển tiền, thay đổi mật khẩu, đổi địa chỉ email tài khoản) dưới danh nghĩa nạn nhân mà người dùng hoàn toàn không hay biết.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Vô hiệu hóa hoàn toàn cơ chế bảo vệ CSRF trên ứng dụng sử dụng xác thực dựa trên Cookie phiên:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // NGUY HIỂM: Tắt toàn bộ bảo vệ CSRF, tạo điều kiện cho tấn công CSRF qua Session Cookie
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Duy trì cơ chế bảo vệ CSRF mặc định hoặc cấu hình `CookieCsrfTokenRepository` cho ứng dụng Single Page Application (SPA như Angular, React, Vue):

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // AN TOÀN: Cấu hình CookieCsrfTokenRepository hỗ trợ ứng dụng SPA đọc token qua XSRF-TOKEN
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Phòng chống tấn công CSRF đòi hỏi thực thi các biện pháp phòng vệ đồng bộ:

1. **Lớp 1 — Giữ nguyên cơ chế bảo vệ CSRF mặc định của Spring Security:**
   Spring Security tự động kích hoạt bảo vệ CSRF cho toàn bộ các phương thức thay đổi trạng thái (`POST`, `PUT`, `DELETE`, `PATCH`). Tuyệt đối không gọi `csrf().disable()` trên các ứng dụng web phục vụ người dùng qua trình duyệt.
2. **Lớp 2 — Cấu hình CookieCsrfTokenRepository cho Single Page Application (SPA):**
   Với các ứng dụng SPA frontend kết nối qua AJAX/Fetch, sử dụng `CookieCsrfTokenRepository.withHttpOnlyFalse()`. Frontend sẽ đọc giá trị token từ cookie `XSRF-TOKEN` và gửi lại máy chủ trong header `X-XSRF-TOKEN` ở mỗi request thay đổi trạng thái.
3. **Lớp 3 — Thiết lập thuộc tính Cookie SameSite:**
   Cấu hình Session Cookie với cờ `SameSite=Lax` hoặc `SameSite=Strict` để ngăn trình duyệt tự động đính kèm cookie trong các yêu cầu cross-origin từ các trang web bên ngoài.

### Vì sao `not_exploitable_when` quan trọng ở đây

Trong kiến trúc REST API thuần túy (Stateless) xác thực qua header `Authorization: Bearer <JWT>` và không sử dụng Cookie phiên để duy trì trạng thái đăng nhập, trình duyệt không tự động gửi Bearer token qua các cross-origin requests, do đó không bị ảnh hưởng bởi CSRF. Việc phân biệt rõ ràng giữa ứng dụng Stateful (dùng Cookie) và Stateless (dùng Bearer Token) là yếu tố quyết định để tránh tạo ra các cảnh báo dương tính giả (false positive).

## 4. Tài liệu tham khảo (References)

- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Spring Security Reference: CSRF Protection](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

