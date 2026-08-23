# Worklog — Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm B: JWT, Credentials, Randomness, XXE)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · **Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](../docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 4`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Task này đã mở rộng và chuẩn hóa toàn diện 4 tài liệu tri thức Tier 2 chưa có OpenGrep rule trực tiếp thuộc Nhóm B (gồm JWT Weak Verification với JJWT parser, Hardcoded Credentials trong kết nối cơ sở dữ liệu, Insecure Randomness với PRNG tuyến tính, và XXE Injection qua DocumentBuilderFactory). Các tài liệu được bổ sung trường `references` chính thống trong frontmatter YAML và tái cấu trúc phần thân bài viết theo định dạng chuẩn 4 đề mục đối chứng mã nguồn Java (Vulnerable Pattern vs. Remediated Pattern) kèm hướng dẫn khắc phục 3 lớp chuyên sâu. Toàn bộ 78 unit test retrieval, 1011 test hệ thống và kiểm tra chất lượng `make quality` đạt trạng thái 100% xanh.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp kho tri thức bảo mật chuyên sâu cho các mẫu lỗ hổng phổ biến trong ứng dụng Java Web/Spring (JWT, Hardcoded Credentials, Insecure Randomness, XXE) ngay cả khi OpenGrep chưa kích hoạt quy tắc riêng, cho phép cơ chế tra cứu Fallback theo CWE và Sink Signatures nạp đầy đủ ngữ cảnh phân tích và bản vá.
- **Nằm ở đâu trong luồng:** Nằm tại tầng Knowledge Base (`data/knowledge-base/tier2/`), được nạp qua `kb_schema.py` và cung cấp tri thức cho `KnowledgeRetriever` / `tier_lookup` phục vụ việc sinh prompt phân tích của Analyzer cũng như hiển thị chi tiết mã sửa lỗi trên Web Dashboard.
- **Không có nó thì hỏng gì:** Nếu thiếu các tài liệu chuẩn hóa này, các phát hiện SAST chỉ map được theo CWE hoặc Sink sẽ thiếu mẫu code đối chứng Java thực tế, dẫn đến nguy cơ LLM sinh khuyến nghị sửa lỗi chung chung, không chuẩn idiomatic và tăng tỷ lệ over-claim do thiếu phân tích điều kiện `not_exploitable_when`.
- **Ngoài phạm vi (cố ý không làm):** Không tự ý đổi `id`, `canonical_category`, `cwe` hay gỡ bỏ cờ `no_rule_yet: true` khi chưa có rule OpenGrep thật tương ứng; không sửa schema của SecurityAnalysisRecord.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Sửa | Thêm `references` (OWASP JSON Web Token Cheat Sheet for Java, JJWT docs, CWE-347); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `Jwts.parser().parseClaimsJwt(jwt)` vs ✅ `Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt)`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho JWT Weak Verification |
| `data/knowledge-base/tier2/java-hardcoded-credential.md` | Sửa | Thêm `references` (OWASP Secrets Management Cheat Sheet, Spring Boot Externalized Configuration, CWE-798); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `DriverManager.getConnection(url, "admin", "P@ssw0rd123!")` vs ✅ `@Value("${spring.datasource.password}")` / Vault), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho Hardcoded Credentials |
| `data/knowledge-base/tier2/java-insecure-random.md` | Sửa | Thêm `references` (OWASP Cryptographic Storage Cheat Sheet, Oracle Java SecureRandom API, CWE-338); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `new Random().nextInt()` cho token/OTP vs ✅ `SecureRandom.getInstanceStrong()`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho Insecure Randomness |
| `data/knowledge-base/tier2/java-documentbuilder-xxe.md` | Sửa | Thêm `references` (OWASP XML External Entity Prevention Cheat Sheet, Oracle DocumentBuilderFactory API, CWE-611); chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xml)` vs ✅ `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo | Chuẩn hóa tri thức Tier 2 cho XXE Injection qua DocumentBuilderFactory |

**`git diff --stat`:**

```text
 data/knowledge-base/tier2/java-documentbuilder-xxe.md  | 100 +++++++++++++++++----
 data/knowledge-base/tier2/java-hardcoded-credential.md |  93 ++++++++++++++++---
 data/knowledge-base/tier2/java-insecure-random.md      |  93 +++++++++++++++----
 data/knowledge-base/tier2/java-jwt-parse-unverified.md |  81 ++++++++++++++---
 4 files changed, 310 insertions(+), 57 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Khảo sát 4 tệp tri thức Tier 2 chưa có rule map thuộc Nhóm B (`java-jwt-parse-unverified.md`, `java-hardcoded-credential.md`, `java-insecure-random.md`, `java-documentbuilder-xxe.md`).
2. Bổ sung trường `references` trong frontmatter chứa danh sách URL chuẩn xác từ OWASP Cheat Sheet Series, CWE Mitre, Spring Boot Docs, JJWT docs và Oracle Java Documentation (toàn bộ bắt đầu bằng `https://`).
3. Tái cấu trúc phần thân tài liệu thành 4 đề mục ngữ nghĩa chuẩn:
   - `## 1. Cơ chế rủi ro (Risk Mechanism)`: Phân tích chi tiết luồng dữ liệu không an toàn và tác động an ninh (Authentication bypass, Credential leakage, PRNG seed reconstruction, XXE Arbitrary File Read / SSRF).
   - `## 2. Mã nguồn minh họa (Code Examples)`: Cung cấp hai khối mã nguồn đối chứng Java (`### ❌ Không an toàn (Vulnerable Pattern)` vs `### ✅ Đã khắc phục an toàn (Remediated Pattern)`).
   - `## 3. Biện pháp khắc phục chuẩn (Remediation Guide)`: Trình bày 3 lớp phòng thủ chuyên sâu (Phòng thủ theo chiều sâu) và làm rõ vai trò của `not_exploitable_when` chống dương tính giả.
   - `## 4. Tài liệu tham khảo (References)`: Danh sách markdown links có thể click trực tiếp tới tài liệu chính thống.
4. Đảm bảo giữ nguyên các trường metadata bắt buộc: `no_rule_yet: true`, `sink_signatures`, `tier1_parent` và `not_exploitable_when` ($\ge 30$ ký tự).
5. Xác minh toàn diện với bộ test integrity, schema và toàn bộ test suite dự án.

**Luồng dữ liệu:** `OpenGrep finding (CWE fallback / sink matching)` → `kb_schema.load_tier2()` → `Tier2Entry (kèm references, vulnerable/remediated snippets, remediation guide)` → `Analyzer prompt & Web UI Dashboard`.

**Các quyết định kỹ thuật:**
- Mã nguồn Java minh họa sử dụng các thư viện chuẩn phổ biến trong hệ sinh thái Java/Spring (JJWT, `SecureRandom.getInstanceStrong()`, Spring Boot Externalized Configuration `@Value`, `DocumentBuilderFactory` secure features).
- Đảm bảo tính nhất quán cấu trúc với toàn bộ 7 tài liệu Tier 2 đã được chuẩn hóa ở Task 2 và Task 3.

**Xử lý lỗi / trường hợp biên:** Mọi URL trong `references` được kiểm định qua `kb_schema.py` để đảm bảo đúng định dạng URL và giao thức `http/https`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Doc | `java-jwt-parse-unverified.md` | `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Tài liệu Tier 2 JWT Weak Verification chuẩn hóa 4 phần |
| Doc | `java-hardcoded-credential.md` | `data/knowledge-base/tier2/java-hardcoded-credential.md` | Tài liệu Tier 2 Hardcoded Credentials chuẩn hóa 4 phần |
| Doc | `java-insecure-random.md` | `data/knowledge-base/tier2/java-insecure-random.md` | Tài liệu Tier 2 Insecure Randomness chuẩn hóa 4 phần |
| Doc | `java-documentbuilder-xxe.md` | `data/knowledge-base/tier2/java-documentbuilder-xxe.md` | Tài liệu Tier 2 DocumentBuilder XXE chuẩn hóa 4 phần |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/ -v
.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
make quality
```

**Output thật (đã che secret):**

```text
$ .venv/bin/python -m pytest tests/unit/retrieval/ -v
============================== 78 passed in 1.00s ==============================

$ .venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
1011 passed, 41 deselected, 1 warning in 19.47s

$ make quality
All checks passed!
Success: no issues found in 81 source files
Required test coverage of 78.0% reached. Total coverage: 84.37%
1011 passed, 41 deselected, 1 warning in 21.83s
No known vulnerabilities found
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Cấu trúc tài liệu Markdown 4 phần theo chuẩn thống nhất của dự án, kết hợp đối chứng mã nguồn Java rõ ràng và liên kết trực tiếp tới OWASP/CWE/Oracle Java/Spring Reference.

**Lý do:** Bám sát tuyệt đối yêu cầu tại Task 4 của plan `docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`:
> *"Chuẩn hóa 4 tài liệu Tier 2 chưa có rule (Nhóm B: JWT, Credentials, Random, XXE): java-jwt-parse-unverified.md, java-hardcoded-credential.md, java-insecure-random.md, java-documentbuilder-xxe.md"*.

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
| `.venv/bin/python -m pytest tests/unit/retrieval/ -v` | 0 | 78 passed in 1.00s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1011 passed, 41 deselected in 19.47s |
| `make quality` | 0 | Ruff checks passed, Mypy 81 files clean, 1011 tests passed (Coverage: 84.37%), Pip-audit 0 vulnerabilities |

**Test mới thêm:** Không có test mới cần thêm ở Task 4 (các test integrity và schema đã có sẵn xác thực tính hợp lệ của toàn bộ file Tier 2).

**Bất biến đã giữ:** Không sử dụng test double (no fake/mock/stub), không sửa historical reports, không thêm dependency mới, không phá vỡ schema phân tích, dữ liệu frontmatter tuân thủ nghiêm ngặt `kb_schema.py`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có. Các mẫu code và link tài liệu đã được đối chiếu kỹ với OWASP Cheat Sheets và tài liệu chính thức của JJWT / Spring Boot / Oracle Java SE.
- **Giả định đã đặt:** Toàn bộ 11/11 tài liệu Tier 2 hiện đã được chuẩn hóa đầy đủ 4 đề mục và có `references` hợp lệ, sẵn sàng chuyển tiếp sang Task 5 (Chuẩn hóa 14 tài liệu Tier 1).
- **Việc còn nợ:** Chuyển giao sang Task 5 theo đúng implementation plan.
- **Câu hỏi cho người dùng:** Không có.
