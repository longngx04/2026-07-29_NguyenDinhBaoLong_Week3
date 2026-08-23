---
tier: 2
id: java-servlet-response-writer
canonical_category: XSS
cwe: [CWE-79]
tier1_parent: xss
language: java
sink_signatures:
  - javax.servlet.http.HttpServletResponse.getWriter
  - java.io.PrintWriter.print
no_rule_yet: true
safe_alternative: "Mã hoá HTML context-aware qua HtmlUtils.htmlEscape() hoặc cấu hình Content-Type an toàn application/json"
exploitable_when: >
  dữ liệu caller chưa được mã hoá ký tự HTML đặc biệt (`<`, `>`, `"`, `'`, `&`)
  được ghi trực tiếp vào phản hồi HTTP có content-type là text/html
not_exploitable_when: >
  nội dung ghi ra là hằng số, phản hồi có Content-Type an toàn như application/json,
  hoặc dữ liệu đã được mã hoá context-aware (HTML entity encode)
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/79.html
  - https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletResponse.html
---

# `HttpServletResponse.getWriter` / `PrintWriter.print` — Cross-Site Scripting (XSS)

## 1. Cơ chế rủi ro (Risk Mechanism)

Khi một Java Servlet sử dụng `HttpServletResponse.getWriter()` để lấy luồng xuất ký tự `PrintWriter` và ghi dữ liệu do người dùng kiểm soát (`request.getParameter(...)`, header, cookie) trực tiếp vào phản hồi HTTP mà không qua bước mã hóa thực thể HTML (HTML entity encoding), trình duyệt nạn nhân sẽ phân tích chuỗi này thành cấu trúc DOM của trang web.

Nếu phản hồi trả về có kiểu MIME là `text/html` (hoặc không khai báo Content-Type rõ ràng khiến trình duyệt tự suy đoán qua MIME-sniffing), kẻ tấn công có thể chèn các đoạn mã JavaScript độc hại (`<script>`, `<img onerror=...>`, `<svg onload=...>`). Khi người dùng truy cập trang, mã độc sẽ tự động thực thi trong ngữ cảnh phiên duyệt của nạn nhân, dẫn đến đánh cắp session cookie, mạo danh thao tác người dùng (session hijacking), hoặc thay đổi giao diện trang web (DOM defacement).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Ghi trực tiếp tham số đầu vào không tin cậy `username` ra luồng phản hồi HTML thông qua `PrintWriter.println()`:

```java
public class UserServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        // NGUY HIỂM: Nối chuỗi dữ liệu người dùng trực tiếp vào tài liệu HTML mà không escape
        out.println("<html><body>");
        out.println("<h1>Xin chào: " + username + "</h1>");
        out.println("</body></html>");
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Mã hóa ngữ cảnh HTML trước khi ghi ra luồng hoặc chuyển sang trả về định dạng dữ liệu an toàn `application/json`:

```java
public class UserServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String username = request.getParameter("username");

        // CÁCH 1: Mã hóa HTML context-aware nếu bắt buộc phải trả về trang HTML
        String safeUsername = org.springframework.web.util.HtmlUtils.htmlEscape(username);
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Xin chào: " + safeUsername + "</h1>");
        out.println("</body></html>");

        // CÁCH 2 (KHUYẾN NGHỊ): Trả về JSON thuần túy để tách biệt dữ liệu và giao diện
        // response.setContentType("application/json;charset=UTF-8");
        // response.getWriter().write(new ObjectMapper().writeValueAsString(Map.of("username", username)));
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Phòng ngừa XSS tại tầng phản hồi Servlet đòi hỏi chiến lược phòng thủ đa lớp:

1. **Lớp 1 — Mã hóa dữ liệu theo ngữ cảnh (Context-Aware Output Encoding):**
   Trước khi chèn bất kỳ biến động nào vào tài liệu HTML, bắt buộc phải mã hóa các ký tự điều khiển HTML (`<`, `>`, `&`, `"`, `'`) thành các thực thể tương ứng (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). Sử dụng thư viện chuẩn như `org.springframework.web.util.HtmlUtils.htmlEscape()` hoặc `org.owasp.encoder.Encode`.
2. **Lớp 2 — Tách bạch tầng dữ liệu với Content-Type an toàn:**
   Xây dựng API RESTful và cấu hình rõ ràng `response.setContentType("application/json;charset=UTF-8")` hoặc `text/plain`. Khi Content-Type là JSON hoặc Plaintext, trình duyệt sẽ phân tích cú pháp dạng dữ liệu thô và từ chối thực thi bất kỳ thẻ HTML hay mã script nào.
3. **Lớp 3 — Thiết lập tiêu đề bảo mật HTTP (Security Headers & CSP):**
   Cấu hình `Content-Security-Policy` (CSP) với chỉ thị `default-src 'self'` để hạn chế thực thi script không tin cậy. Đặt cờ `X-Content-Type-Options: nosniff` để ngăn trình duyệt tự ý đoán định kiểu MIME của phản hồi.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu Servlet phục vụ API REST trả về `Content-Type: application/json` hoặc `text/plain`, trình duyệt sẽ không phân tích cú pháp HTML/JavaScript từ nội dung phản hồi, do đó hoàn toàn không thể kích hoạt XSS. Việc chỉ phát hiện gọi `response.getWriter()` mà không kiểm tra kiểu nội dung Content-Type được thiết lập sẽ tạo ra tỷ lệ dương tính giả (false positive) rất cao trong các REST controller.

## 4. Tài liệu tham khảo (References)

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [Java EE 7: HttpServletResponse API Documentation](https://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpServletResponse.html)

