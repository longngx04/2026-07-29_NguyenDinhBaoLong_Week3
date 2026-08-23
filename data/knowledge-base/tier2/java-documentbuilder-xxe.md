---
tier: 2
id: java-documentbuilder-xxe
canonical_category: XXE
cwe: [CWE-611]
tier1_parent: xxe
language: java
sink_signatures:
  - javax.xml.parsers.DocumentBuilderFactory.newInstance
no_rule_yet: true
safe_alternative: "Tắt DTD ngoài và thực thể ngoài qua setFeature(disallow-doctype-decl, true) hoặc setFeature(FEATURE_SECURE_PROCESSING, true)"
exploitable_when: >
  parser XML phân tích cú pháp tài liệu từ người dùng gửi lên mà chưa tắt tính năng nạp thực thể ngoài (External Entities) và DTD,
  cho phép đọc file hệ thống hoặc kích hoạt SSRF
not_exploitable_when: >
  DocumentBuilderFactory đã được cấu hình disallow-doctype-decl=true hoặc đã vô hiệu hoá toàn bộ external-general-entities và external-parameter-entities
references:
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
  - https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html
  - https://cwe.mitre.org/data/definitions/611.html
---

# `DocumentBuilderFactory.newInstance` — XML External Entity (XXE) Injection

## 1. Cơ chế rủi ro (Risk Mechanism)

Lỗ hổng XML External Entity (XXE) Injection (CWE-611) xuất hiện khi ứng dụng Java sử dụng `DocumentBuilderFactory` để phân tích tài liệu XML từ người dùng mà không vô hiệu hóa tính năng xử lý Document Type Definition (DTD) và thực thể ngoài (External Entities). Theo mặc định ở nhiều cấu hình parser XML của Java, trình phân giải thực thể (Entity Resolver) sẽ tự động nạp và thay thế nội dung của các thực thể bên ngoài được định nghĩa trong thẻ `<!ENTITY ... SYSTEM "URI">`.

Kẻ tấn công có thể gửi tệp XML chứa thực thể độc hại trỏ đến tệp tin cục bộ trên máy chủ (`file:///etc/passwd` hoặc `file:///c:/boot.ini`) để đọc trộm dữ liệu nhạy cảm (Arbitrary File Read), trỏ đến các tài nguyên mạng nội bộ (`http://169.254.169.254/` hoặc máy chủ nội bộ) để thực hiện tấn công giả mạo yêu cầu phía máy chủ (SSRF), hoặc sử dụng các thực thể lồng nhau dạng đệ quy (Billion Laughs Attack / XML Bomb) để làm cạn kiệt bộ nhớ và gây tê liệt dịch vụ (Denial of Service).

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)

Khởi tạo `DocumentBuilderFactory` và phân tích XML trực tiếp với cấu hình mặc định:

```java
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XmlParserService {
    public Document parseXml(InputStream xmlInput) throws Exception {
        // NGUY HIỂM: Cấu hình mặc định cho phép nạp thực thể DTD bên ngoài dẫn đến XXE
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(xmlInput);
    }
}
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)

Vô hiệu hóa hoàn toàn khai báo DOCTYPE và thực thể ngoài trên `DocumentBuilderFactory`:

```java
import java.io.InputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class SafeXmlParserService {
    public Document parseSafeXml(InputStream xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // AN TOÀN: Vô hiệu hóa hoàn toàn DOCTYPE declaration (biện pháp triệt để nhất chống XXE)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // Cấu hình phòng thủ theo chiều sâu tắt các thực thể ngoài và DTD tải ngoài
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(xmlInput);
    }
}
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)

Chiến lược phòng chống XXE chuẩn hóa bao gồm 3 lớp phòng vệ:

1. **Lớp 1 — Vô hiệu hóa hoàn toàn DOCTYPE (Disallow DOCTYPE Declaration):**
   Thiết lập thuộc tính `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`. Đây là biện pháp phòng thủ mạnh mẽ và khuyến nghị hàng đầu của OWASP, loại bỏ hoàn toàn khả năng ứng dụng bị chèn ép các thực thể độc hại thông qua DTD.
2. **Lớp 2 — Tắt External Entities và kích hoạt Secure Processing (Disable External Entities & FSP):**
   Trong trường hợp bắt buộc phải hỗ trợ DTD nội bộ, cấu hình tắt `external-general-entities`, `external-parameter-entities`, `load-external-dtd` và bật `XMLConstants.FEATURE_SECURE_PROCESSING` để giới hạn tài nguyên tính toán của parser, chống tấn công XML Entity Expansion (Billion Laughs DoS).
3. **Lớp 3 — Chuyển đổi định dạng dữ liệu hiện đại (Modern Format Migration):**
   Chuyển đổi giao thức truyền tải dữ liệu sang định dạng JSON hoặc Protocol Buffers kết hợp các parser an toàn, hạn chế tối đa việc sử dụng XML khi không có yêu cầu bắt buộc về cấu trúc tài liệu phức tạp.

### Vì sao `not_exploitable_when` quan trọng ở đây

Nếu nhà phát triển đã cấu hình `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` hoặc đã tắt toàn bộ các cờ nạp thực thể ngoài trước khi gọi `dbf.newDocumentBuilder()`, hoặc ứng dụng chỉ phân tích các tệp tin XML tĩnh đóng gói sẵn trong tệp `.jar` nội bộ từ nguồn tin cậy, ứng dụng hoàn toàn miễn nhiễm với XXE. Cảnh báo mọi lệnh gọi `DocumentBuilderFactory.newInstance()` mà không xem xét cấu hình bảo mật sẽ dẫn đến dương tính giả.

## 4. Tài liệu tham khảo (References)

- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Oracle Java SE 17: javax.xml.parsers.DocumentBuilderFactory API](https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/javax/xml/parsers/DocumentBuilderFactory.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
