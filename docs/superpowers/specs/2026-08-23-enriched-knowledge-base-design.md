# Đặc tả Thiết kế: Mở rộng và Làm phong phú Kho tri thức (Enriched Two-Tier KB)

**Ngày:** 2026-08-23 · **Trạng thái:** Approved · **Tác giả:** Antigravity & User  
**Tài liệu liên quan:** [`docs/superpowers/specs/2026-08-23-knowledge-base-two-tier-design.md`](2026-08-23-knowledge-base-two-tier-design.md)

---

## 1. Tóm tắt mục tiêu (Understanding Summary)

* **Mục tiêu:** Mở rộng và chuẩn hóa chất lượng nội dung của toàn bộ 25 tài liệu trong Kho tri thức Project Sentinel (14 tài liệu Tier 1 và 11 tài liệu Tier 2), nâng cấp từ dạng tóm tắt kỹ thuật cơ bản thành nguồn tri thức bảo mật chuyên sâu.
* **Nội dung bổ sung:**
  - Bổ sung cấu trúc chuẩn hóa 5 phần cho toàn bộ các tài liệu.
  - Tích hợp trích dẫn chính thức từ **OWASP Cheat Sheet Series**, **MITRE CWE**, và **Oracle Java / Spring Security Reference Documentation**.
  - Bổ sung các khối mã nguồn Java đối chứng cụ thể (**Vulnerable Pattern vs. Remediated Pattern**).
  - Khai báo trường `references` trong frontmatter để hỗ trợ kiểm thử và hiển thị tự động.
* **Phục vụ:**
  - **LLM Agent:** Nhận các căn cứ điều kiện an toàn (`not_exploitable_when`) và giải pháp thay thế (`safe_alternative`) súc tích, chính xác hơn.
  - **Web UI & Security Analyst:** Hiển thị hướng dẫn khắc phục chi tiết, mã nguồn mẫu và đường dẫn tra cứu trực tiếp khi xem báo cáo finding.

---

## 2. Các giả định & Ràng buộc cốt lõi (Assumptions & Constraints)

1. **Hoàn toàn ngoại tuyến (Offline & Version-Controlled):** Mọi tài liệu và ví dụ mã nguồn đều nằm trong repository (`data/knowledge-base/`), không gọi live API ra ngoài Internet trong runtime.
2. **Tối ưu Token & Context Window:** Quá trình phân tích của LLM vẫn áp dụng giới hạn ký tự (`max_snippet_chars`), chỉ nạp tóm tắt cốt lõi vào prompt để tránh làm phình context. Toàn bộ mã nguồn chi tiết và Cheat Sheet đầy đủ được dùng để hiển thị trên Web UI.
3. **Bảo toàn Schema & Provenance:** Không thay đổi JSON Schema của `SecurityAnalysisRecord` hay quy tắc tính điểm provenance.
4. **Kiểm thử chống trôi (Anti-Drift):** Tự động hóa kiểm thử để đảm bảo mọi tài liệu đều tuân thủ cấu trúc 5 phần, có mã nguồn mẫu và các liên kết URL hợp lệ.

---

## 3. Nhật ký quyết định (Decision Log)

| # | Quyết định | Các phương án đã cân nhắc | Lý do lựa chọn |
|---|---|---|---|
| **D1** | Chuẩn hóa toàn bộ 25 tài liệu theo **Bộ khung 5 phần thống nhất** | Mở rộng tự do (Free-form) vs. Bộ khung 5 phần chuẩn | Giữ tính kỷ luật cao cho dữ liệu, cho phép viết test tự động và render UI dễ dàng |
| **D2** | Bổ sung trường `references` vào frontmatter YAML | Chỉ để link trong body vs. Khai báo trong YAML frontmatter | Giúp parser Python trích xuất link URL chuẩn cho UI badge mà không cần parse Markdown body |
| **D3** | Tách bạch dữ liệu Prompt vs. Dữ liệu Web UI | Đưa toàn bộ tài liệu vào prompt vs. Tách bạch | Tiết kiệm chi phí token và tránh quá tải context cho mô hình ngôn ngữ |
| **D4** | Bổ sung kiểm thử tính toàn vẹn 5 phần trong `test_kb_integrity.py` | Kiểm tra thủ công vs. Test tự động | Chống trôi (anti-drift) cấu trúc tài liệu qua các lần cập nhật |

---

## 4. Cấu trúc chi tiết của các tài liệu tri thức

### 4.1. Cấu trúc chuẩn của một tài liệu Tier 2 (`data/knowledge-base/tier2/<id>.md`)

```markdown
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
safe_alternative: "java.sql.PreparedStatement với placeholder `?` và các setter kiểu dữ liệu"
exploitable_when: >
  chuỗi truy vấn SQL được dựng bằng phép cộng chuỗi, String.format hoặc StringBuilder
  với dữ liệu đầu vào từ người dùng mà không qua cơ chế tham số hoá.
not_exploitable_when: >
  truy vấn là hằng chuỗi tĩnh hoàn toàn, hoặc mọi tham số nội suy đều được lấy từ một
  allowlist cố định trong mã nguồn (ví dụ: tên bảng/cột từ Enum), hoặc đã qua PreparedStatement.
references:
  - "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
  - "https://cwe.mitre.org/data/definitions/89.html"
  - "https://docs.oracle.com/javase/8/docs/api/java/sql/PreparedStatement.html"
---

# `Statement.execute*` — SQL Injection

## 1. Cơ chế rủi ro (Risk Mechanism)
Mô tả chi tiết nguyên nhân kỹ thuật ở mức API và Runtime khiến sink này trở nên nguy hiểm.

## 2. Mã nguồn minh họa (Code Examples)

### ❌ Không an toàn (Vulnerable Pattern)
```java
// Đoạn mã mẫu minh hoạ cách lập trình viên vô tình gọi sink không an toàn
```

### ✅ Đã khắc phục an toàn (Remediated Pattern)
```java
// Đoạn mã mẫu minh hoạ cách khắc phục chuẩn theo best practice
```

## 3. Biện pháp khắc phục chuẩn (Remediation Guide)
Các bước cụ thể theo thứ tự ưu tiên (Primary Fix, Defense-in-depth, Configuration).

## 4. Tài liệu tham khảo (References)
- Liên kết Markdown tới OWASP Cheat Sheet, MITRE CWE, Oracle Java SE / Spring Docs.
```

### 4.2. Cấu trúc chuẩn của một tài liệu Tier 1 (`data/knowledge-base/tier1/<id>.md`)

```markdown
---
tier: 1
id: sql-injection
title: SQL Injection
cwe: [CWE-89]
owasp: [A03:2021]
tags: [sql-injection, sqli, cwe-89, owasp-a03, injection, database]
references:
  - "https://owasp.org/Top10/A03_2021-Injection/"
  - "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
---

# SQL Injection

## 1. Khái niệm & Mối đe dọa (Overview & Threat Impact)
Tổng quan phân loại lỗ hổng, hậu quả an ninh đối với hệ thống.

## 2. Các biến thể phổ biến (Common Attack Variants)
Mô tả các biến thể tấn công chính (ví dụ: nối chuỗi trực tiếp, form đăng nhập, blind/time-based).

## 3. Nguyên tắc phòng thủ đa lớp (Defense-in-Depth Strategy)
Các trụ cột bảo vệ tổng thể (Tham số hóa, Kiểm duyệt đầu vào, Phân quyền cơ sở dữ liệu).

## 4. Tài liệu tham khảo thẩm quyền (Authoritative References)
Danh sách liên kết chính thức OWASP Top 10, OWASP Cheat Sheets, MITRE CWE.
```

---

## 5. Kế hoạch xác minh & Kiểm thử (Verification Strategy)

1. **Schema Validation (`test_kb_schema.py`):**
   - Đảm bảo `kb_schema.py` hỗ trợ parse trường `references: tuple[str, ...]`.
   - Kiểm tra mọi URL trong `references` đều bắt đầu bằng `http://` hoặc `https://`.
2. **Integrity & Quality Gates (`test_kb_integrity.py`):**
   - Kiểm tra 100% 14 file Tier 1 và 11 file Tier 2 chứa đủ các đề mục bắt buộc.
   - Kiểm tra 100% 11 file Tier 2 chứa ít nhất 1 code block Vulnerable và 1 code block Remediated có cú pháp Java hợp lệ.
3. **Pipeline & Quality Suite:**
   - Chạy `make quality` đảm bảo 100% xanh.
   - Chạy `make kb-coverage` và `make search` kiểm tra tính tương thích ngược hoàn hảo.
