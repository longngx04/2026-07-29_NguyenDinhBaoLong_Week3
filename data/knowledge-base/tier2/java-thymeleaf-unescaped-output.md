---
tier: 2
id: java-thymeleaf-unescaped-output
canonical_category: XSS
cwe: [CWE-79]
tier1_parent: xss
language: java
sink_signatures:
  - th:utext
no_rule_yet: true
safe_alternative: "Dùng thuộc tính thoát chuỗi mặc định `th:text` thay vì `th:utext`"
exploitable_when: >
  biểu thức `th:utext` hiển thị chuỗi chứa ký tự HTML do người dùng điều khiển
  mà không qua bộ lọc HTML sanitization
not_exploitable_when: >
  giá trị truyền vào `th:utext` là chuỗi tĩnh từ tài nguyên nội bộ đã được kiểm duyệt
  hoặc đã qua pipeline HTML sanitizer nghiêm ngặt
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#unescaped-text
  - https://cwe.mitre.org/data/definitions/79.html
---

# `th:utext` — Unescaped Output in Thymeleaf (XSS)

## 1. Cơ chế rủi ro (Risk Mechanism)

Thymeleaf cung cấp hai thuộc tính chính để chèn văn bản động vào tài liệu HTML: `th:text` (mặc định tự động mã hóa và thoát các ký tự HTML đặc biệt như `<`, `>`, `&`, `"`, `'`) và `th:utext` (Unescaped Text — render trực tiếp chuỗi HTML thô mà không áp dụng bất kỳ cơ chế thoát chuỗi nào).

Khi ứng dụng sử dụng `th:utext` để hiển thị dữ liệu có nguồn gốc từ người dùng (`@RequestParam`, `@PathVariable`, form input) hoặc từ bên thứ ba mà không lọc sạch trước, kẻ tấn công có thể chèn các thẻ HTML độc hại hoặc mã script (`<script>`, `<img src=x onerror=...>`, `<svg/onload=...>`). Trình duyệt người xem sẽ phân tích và thực thi trực tiếp các thẻ này, dẫn đến lỗ hổng Cross-Site Scripting (XSS), cho phép chiếm phiên làm việc (Session Hijacking), trích xuất dữ liệu nhạy cảm hoặc tấn công mạo danh người dùng.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Sử dụng thuộc tính `th:utext` để render nội dung do người dùng nhập vào mà không lọc mã độc:

```html
<!-- View template (user-profile.html) -->
<div class="bio-container">
    <!-- NGUY HIỂM: th:utext chèn HTML thô trực tiếp vào DOM, cho phép thực thi script từ userBio -->
    <h3>Tiểu sử cá nhân:</h3>
    <div th:utext="${userBio}">Nội dung tiểu sử mặc định</div>
</div>
```

```java
// Spring MVC Controller
@GetMapping("/profile")
public String showProfile(@RequestParam String bio, Model model) {
    // Truyền trực tiếp dữ liệu chưa lọc vào model
    model.addAttribute("userBio", bio);
    return "user-profile";
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Sử dụng thuộc tính `th:text` để Thymeleaf tự động mã hóa thực thể HTML, hoặc lọc sạch qua bộ lọc HTML allowlist nếu bắt buộc phải hỗ trợ văn bản định dạng phong phú (Rich Text):

```html
<!-- View template (user-profile.html) -->
<div class="bio-container">
    <!-- AN TOÀN: th:text tự động chuyển đổi các ký tự <, >, &, ", ' thành các thực thể HTML an toàn -->
    <h3>Tiểu sử cá nhân:</h3>
    <div th:text="${userBio}">Nội dung tiểu sử mặc định</div>
</div>
```

```java
// Trường hợp bắt buộc hiển thị Rich Text HTML: Lọc qua OWASP Java HTML Sanitizer
@GetMapping("/profile")
public String showProfileSafe(@RequestParam String bio, Model model) {
    // AN TOÀN: Chỉ cho phép các thẻ HTML an toàn như <b>, <i>, <p>, loại bỏ hoàn toàn script và sự kiện DOM
    PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
    String sanitizedBio = policy.sanitize(bio);
    model.addAttribute("userBio", sanitizedBio);
    return "user-profile";
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Chiến lược phòng vệ chuẩn chống XSS trong các ứng dụng sử dụng Thymeleaf:

1. **Lớp 1 — Luôn ưu tiên `th:text` theo nguyên tắc an toàn mặc định (Secure by Default):**
   Mặc định áp dụng `th:text` cho tất cả các vị trí hiển thị dữ liệu động. Tuyệt đối không sử dụng `th:utext` trừ khi có yêu cầu nghiệp vụ bắt buộc phải kết xuất các thẻ HTML định dạng.
2. **Lớp 2 — Làm sạch HTML bằng danh sách trắng (HTML Sanitization with Allowlist):**
   Trong trường hợp bắt buộc phải render nội dung Rich Text/HTML từ người dùng qua `th:utext`, bắt buộc phải đưa dữ liệu qua một thư viện lọc HTML chuyên dụng và tin cậy như `OWASP Java HTML Sanitizer` trước khi đưa vào Model.
3. **Lớp 3 — Triển khai Content Security Policy (CSP):**
   Cấu hình HTTP header `Content-Security-Policy: default-src 'self'; script-src 'self'` để vô hiệu hóa việc thực thi inline script trong trường hợp có sơ sót ở tầng mã nguồn giao diện.

### Vì sao `not_exploitable_when` quan trọng ở đây

Khi dữ liệu hiển thị bằng `th:utext` là chuỗi tĩnh từ tài nguyên nội bộ đã được kiểm duyệt (như thông báo đa ngôn ngữ nạp từ file `messages.properties` thông qua cú pháp `#{...}`) hoặc các hằng số cấu hình do nhà phát triển kiểm soát, không hề tồn tại rủi ro XSS. Báo cáo mọi vị trí `th:utext` mà không xác minh nguồn gốc dữ liệu (data provenance/taint flow) sẽ gây ra tỷ lệ cảnh báo giả (false positive) không cần thiết.

## 4. Tài liệu tham khảo (References)

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Thymeleaf Official Documentation: Unescaped Text](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#unescaped-text)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

