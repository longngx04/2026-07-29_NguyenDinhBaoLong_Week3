# Worklog — Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm A: XSS, Path Traversal, CSRF)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · **Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](../docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 3`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Task này đã mở rộng và chuẩn hóa toàn diện 4 tài liệu tri thức Tier 2 chưa có OpenGrep rule trực tiếp thuộc Nhóm A (gồm XSS qua Servlet Response Writer, XSS qua Thymeleaf unescaped output, Path Traversal qua File path concatenation và CSRF qua Spring Security disabled protection). Các tài liệu được bổ sung trường `references` chính thống trong frontmatter YAML và tái cấu trúc phần thân bài viết theo định dạng chuẩn 4 phần đối chứng mã nguồn (Vulnerable Pattern vs. Remediated Pattern) kèm hướng dẫn khắc phục đa lớp. Toàn bộ 78 unit test retrieval, 1011 test hệ thống và kiểm tra chất lượng `make quality` đạt trạng thái 100% xanh.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp kho tri thức bảo mật chuyên sâu cho các mẫu lỗ hổng phổ biến trong ứng dụng Java Web/Spring (XSS, Path Traversal, CSRF) ngay cả khi OpenGrep chưa kích hoạt quy tắc riêng, cho phép cơ chế tra cứu Fallback theo CWE và Sink Signatures nạp đầy đủ ngữ cảnh khắc phục.
- **Nằm ở đâu trong luồng:** Nằm tại tầng Knowledge Base (`data/knowledge-base/tier2/`), được nạp qua `kb_schema.py` và cung cấp tri thức cho `KnowledgeRetriever` / `tier_lookup` phục vụ việc sinh prompt phân tích của Analyzer cũng như hiển thị chi tiết mã sửa lỗi trên Web Dashboard.
- **Không có nó thì hỏng gì:** Nếu thiếu các tài liệu chuẩn hóa này, các phát hiện SAST chỉ map được theo CWE sẽ thiếu mẫu code đối chứng Java thực tế, dẫn đến nguy cơ LLM sinh khuyến nghị sửa lỗi chung chung, không chuẩn idiomatic và tăng tỷ lệ over-claim do thiếu phân tích điều kiện `not_exploitable_when`.
- **Ngoài phạm vi (cố ý không làm):** Không tự ý đổi `id`, `canonical_category`, `cwe` hay gỡ bỏ cờ `no_rule_yet: true` khi chưa có rule OpenGrep thật tương ứng; không sửa schema của SecurityAnalysisRecord.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `data/knowledge-base/tier2/java-servlet-response-writer.md` | Sửa | Thêm `references` (OWASP XSS Cheat Sheet, CWE-79, Java EE 7 Servlet API); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `response.getWriter().println(userInput)` vs ✅ `HtmlUtils.htmlEscape()` / JSON Content-Type), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho XSS qua Servlet Response Writer |
| `data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md` | Sửa | Thêm `references` (OWASP XSS Cheat Sheet, Thymeleaf Unescaped Text docs, CWE-79); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `th:utext="${userBio}"` vs ✅ `th:text="${userBio}"` / OWASP Java HTML Sanitizer), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho XSS qua Thymeleaf unescaped output |
| `data/knowledge-base/tier2/java-file-path-concat.md` | Sửa | Thêm `references` (OWASP Path Traversal Cheat Sheet, CWE-22, Oracle Java Path API); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `new File(uploadDir, userInput)` vs ✅ `baseDir.resolve(name).normalize().toAbsolutePath()` kèm `startsWith`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho Path Traversal |
| `data/knowledge-base/tier2/java-spring-csrf-disabled.md` | Sửa | Thêm `references` (OWASP CSRF Cheat Sheet, Spring Security CSRF Reference, CWE-352); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `http.csrf(csrf -> csrf.disable())` vs ✅ `CookieCsrfTokenRepository.withHttpOnlyFalse()`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho Spring Security CSRF Disabled |

**`git diff --stat`:**

```text
 data/knowledge-base/tier2/java-file-path-concat.md          | 70 +++++++++++++++---
 data/knowledge-base/tier2/java-servlet-response-writer.md   | 86 +++++++++++++++++++---
 data/knowledge-base/tier2/java-spring-csrf-disabled.md      | 79 +++++++++++++++++---
 data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md | 86 +++++++++++++++++++---
 4 files changed, 278 insertions(+), 43 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Khảo sát 4 tệp tri thức Tier 2 chưa có rule map (`java-servlet-response-writer.md`, `java-thymeleaf-unescaped-output.md`, `java-file-path-concat.md`, `java-spring-csrf-disabled.md`).
2. Bổ sung trường `references` trong frontmatter chứa danh sách URL chuẩn xác từ OWASP Cheat Sheet Series, CWE Mitre, Spring Security Docs và Oracle Java Documentation (bắt đầu bằng `https://`).
3. Tái cấu trúc phần thân tài liệu thành 4 đề mục ngữ nghĩa chuẩn:
   - `## 1. Cơ chế rủi ro (Risk Mechanism)`: Phân tích chi tiết luồng dữ liệu không an toàn và tác động an ninh.
   - `## 2. Mã nguồn minh họa (Code Examples)`: Cung cấp hai khối mã nguồn đối chứng Java/HTML (`### ❌ Không an toàn (Vulnerable Pattern)` vs `### ✅ Đã khắc phục an toàn (Remediated Pattern)`).
   - `## 3. Biện pháp khắc phục chuẩn (Remediation Guide)`: Trình bày 3 lớp phòng thủ chuyên sâu (Phòng thủ theo chiều sâu) và làm rõ vai trò của `not_exploitable_when` chống dương tính giả.
   - `## 4. Tài liệu tham khảo (References)`: Danh sách markdown links có thể click trực tiếp tới tài liệu chính thống.
4. Đảm bảo giữ nguyên các trường metadata bắt buộc: `no_rule_yet: true`, `sink_signatures`, `tier1_parent` và `not_exploitable_when` ($\ge 30$ ký tự).
5. Xác minh toàn diện với bộ test integrity, schema và toàn bộ test suite dự án.

**Luồng dữ liệu:** `OpenGrep finding (CWE fallback / sink matching)` → `kb_schema.load_tier2()` → `Tier2Entry (kèm references, vulnerable/remediated snippets, remediation guide)` → `Analyzer prompt & Web UI Dashboard`.

**Các quyết định kỹ thuật:**
- Mã nguồn Java minh họa sử dụng các thư viện chuẩn phổ biến trong hệ sinh thái Java/Spring (Spring Security, Spring Web `HtmlUtils`, Java NIO `Path`, `CookieCsrfTokenRepository`).
- Đảm bảo tính nhất quán cấu trúc với 3 tài liệu Tier 2 đã được chuẩn hóa ở Task 2.

**Xử lý lỗi / trường hợp biên:** Mọi URL trong `references` được kiểm định qua `kb_schema.py` để đảm bảo đúng định dạng URL và giao thức `http/https`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Doc | `java-servlet-response-writer.md` | `data/knowledge-base/tier2/java-servlet-response-writer.md` | Tài liệu Tier 2 XSS Servlet Response Writer chuẩn hóa 4 phần |
| Doc | `java-thymeleaf-unescaped-output.md` | `data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md` | Tài liệu Tier 2 XSS Thymeleaf Unescaped Output chuẩn hóa 4 phần |
| Doc | `java-file-path-concat.md` | `data/knowledge-base/tier2/java-file-path-concat.md` | Tài liệu Tier 2 Path Traversal File Path Concat chuẩn hóa 4 phần |
| Doc | `java-spring-csrf-disabled.md` | `data/knowledge-base/tier2/java-spring-csrf-disabled.md` | Tài liệu Tier 2 Spring CSRF Disabled chuẩn hóa 4 phần |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/ -v
.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
make quality
```

**Output thật (đã che secret):**

```text
$ .venv/bin/python -m pytest tests/unit/retrieval/ -v
============================== 78 passed in 0.91s ==============================

$ .venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
1011 passed, 41 deselected, 1 warning in 19.49s

$ make quality
All checks passed!
Success: no issues found in 81 source files
Required test coverage of 78.0% reached. Total coverage: 84.37%
1011 passed, 41 deselected, 1 warning in 21.68s
No known vulnerabilities found
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Cấu trúc tài liệu Markdown 4 phần theo chuẩn thống nhất của dự án, kết hợp đối chứng mã nguồn Java rõ ràng và liên kết trực tiếp tới OWASP/CWE/Spring Reference.

**Lý do:** Bám sát tuyệt đối yêu cầu tại Task 3 của plan `docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`:
> *"Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm A: XSS, Path Traversal, CSRF): java-servlet-response-writer.md, java-thymeleaf-unescaped-output.md, java-file-path-concat.md, java-spring-csrf-disabled.md"*.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Chỉ viết mô tả lý thuyết không đưa mã nguồn đối chứng | File ngắn gọn, viết nhanh | Không cung cấp được mẫu đối chứng thực tế để LLM và lập trình viên áp dụng bản vá chuẩn |
| Tự định nghĩa rule giả trong configs/opengrep/ để xóa cờ `no_rule_yet` | Tạo cảm giác hệ thống có nhiều rule | Vi phạm nguyên tắc bảo toàn tính chân thực (No fake/mock), rule OpenGrep cần được xây dựng và kiểm thử qua tập mẫu quét thật |

**Đánh đổi đã chấp nhận:** Dung lượng các tệp Markdown tăng lên nhưng tính ứng dụng và độ chính xác của tri thức phân tích tăng đáng kể.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/ -v` | 0 | 78 passed in 0.91s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1011 passed, 41 deselected in 19.49s |
| `make quality` | 0 | Ruff checks passed, Mypy 81 files clean, 1011 tests passed (Coverage: 84.37%), Pip-audit 0 vulnerabilities |

**Test mới thêm:** Không có test mới cần thêm ở Task 3 (các test integrity và schema đã có sẵn xác thực tính hợp lệ của toàn bộ file Tier 2).

**Bất biến đã giữ:** Không sử dụng test double (no fake/mock/stub), không sửa historical reports, không thêm dependency mới, không phá vỡ schema phân tích, dữ liệu frontmatter tuân thủ nghiêm ngặt `kb_schema.py`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có. Các mẫu code và link tài liệu đã được đối chiếu kỹ với OWASP Cheat Sheets và tài liệu chính thức của Spring Security / Thymeleaf / Java SE.
- **Giả định đã đặt:** Các quy chuẩn này sẽ tiếp tục được áp dụng đồng bộ cho Task 4 (4 tài liệu Tier 2 Nhóm B: JWT, Credentials, Insecure Random, XXE).
- **Việc còn nợ:** Chuyển giao sang Task 4 theo đúng implementation plan.
- **Câu hỏi cho người dùng:** Không có.
