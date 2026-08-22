# Worklog — Tạo 11 entry Tier 2 và khóa toàn vẹn tri thức bảo mật

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · inherit ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](../docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 3`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã tạo 11 tài liệu tri thức bảo mật Tier 2 (3 entry ánh xạ trực tiếp OpenGrep rules và 8 entry đánh dấu `no_rule_yet`) kèm khai báo chữ ký sink, điều kiện an toàn, và mở rộng bộ kiểm thử toàn vẹn tri thức.
Tài liệu và kiểm thử này phục vụ cho cơ chế tra cứu tất định theo thác nước ba mức ở Task 4 và ép buộc LLM tuân thủ luật trích dẫn tri thức (Luật 10, 11) khi phân tích lỗ hổng SAST.
Kết quả toàn bộ 10/10 test toàn vẹn trong `test_kb_integrity.py` và 985 unit/integration test trong toàn repo đều vượt qua thành công với độ phủ 84.30%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp cơ sở dữ liệu tri thức chuyên sâu (Tier 2) ở mức sink/method cụ thể bằng ngôn ngữ Java, khai báo rõ ràng các điều kiện không khai thác được (`not_exploitable_when`) để giảm thiểu tỷ lệ dương tính giả / over-claim rate của LLM.
- **Nằm ở đâu trong luồng:** Nằm ở tầng lưu trữ tri thức `data/knowledge-base/tier2/`, được nạp qua `load_tier2()` tại `src/project_sentinel/retrieval/kb_schema.py`, phục vụ tra cứu thác nước `lookup_tier2()` trong `src/project_sentinel/retrieval/tier_lookup.py` và làm căn cứ cho validator luật provenance.
- **Không có nó thì hỏng gì:** Nếu thiếu các entry Tier 2 hoặc dữ liệu sink bị trùng/thiếu liên kết cha Tier 1, hệ thống không thể tra cứu tri thức tất định theo `rule_id` / `cwe`, LLM sẽ không có căn cứ điều kiện an toàn để loại trừ các trường hợp không thể khai thác, dẫn đến việc over-claim và vi phạm luật trích dẫn.
- **Ngoài phạm vi (cố ý không làm):** Chưa cài đặt logic tra cứu thác nước `tier_lookup.py` (thuộc Task 4) và chưa cập nhật các rule validator provenance 10 & 11 (thuộc Task 5).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/retrieval/test_kb_integrity.py` | Sửa | Thêm 7 test kiểm tra toàn vẹn Tier 2 (`test_co_dung_muoi_mot_entry_tier2`, `test_moi_tier1_parent_tro_toi_doc_co_that`, `test_moi_rule_id_duoc_khai_deu_ton_tai_that`, `test_entry_khong_co_rule_phai_danh_dau_no_rule_yet`, `test_khong_sink_nao_xuat_hien_o_hai_entry`, `test_khong_rule_id_nao_xuat_hien_o_hai_entry`, `test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc`) | Đảm bảo tính toàn vẹn, tính duy nhất của sink/rule_id và sự tồn tại của tài liệu cha Tier 1 |
| `data/knowledge-base/tier2/java-sql-statement-execute.md` | Tạo | Entry Tier 2 cho SQL Injection qua Statement.execute/executeQuery/executeUpdate, ánh xạ rule `java-sql-statement-execution`, cha `sql-injection` | Cung cấp tri thức sink cho SQL Injection |
| `data/knowledge-base/tier2/java-runtime-exec.md` | Tạo | Entry Tier 2 cho Command Injection qua Runtime.exec/ProcessBuilder.start, ánh xạ rule `java-command-execution`, cha `command-injection` | Cung cấp tri thức sink cho Command Injection |
| `data/knowledge-base/tier2/java-objectinputstream-readobject.md` | Tạo | Entry Tier 2 cho Deserialization qua ObjectInputStream.readObject, ánh xạ rule `java-unsafe-deserialization`, cha `insecure-deserialization` | Cung cấp tri thức sink cho Insecure Deserialization |
| `data/knowledge-base/tier2/java-servlet-response-writer.md` | Tạo | Entry Tier 2 cho XSS qua HttpServletResponse.getWriter/PrintWriter.print, `no_rule_yet: true`, cha `xss` | Cung cấp tri thức sink cho XSS Servlet |
| `data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md` | Tạo | Entry Tier 2 cho XSS qua th:utext, `no_rule_yet: true`, cha `xss` | Cung cấp tri thức sink cho XSS Thymeleaf |
| `data/knowledge-base/tier2/java-file-path-concat.md` | Tạo | Entry Tier 2 cho Path Traversal qua File.<init>/Paths.get, `no_rule_yet: true`, cha `path-traversal` | Cung cấp tri thức sink cho Path Traversal |
| `data/knowledge-base/tier2/java-spring-csrf-disabled.md` | Tạo | Entry Tier 2 cho CSRF qua HttpSecurity.csrf().disable, `no_rule_yet: true`, cha `csrf` | Cung cấp tri thức sink cho CSRF |
| `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Tạo | Entry Tier 2 cho JWT Weak Verification qua Jwts.parser/parseClaimsJwt, `no_rule_yet: true`, cha `jwt-weak-verification` | Cung cấp tri thức sink cho JWT |
| `data/knowledge-base/tier2/java-hardcoded-credential.md` | Tạo | Entry Tier 2 cho Hardcoded Credentials qua DriverManager.getConnection, `no_rule_yet: true`, cha `broken-auth` | Cung cấp tri thức sink cho Hardcoded Credentials |
| `data/knowledge-base/tier2/java-insecure-random.md` | Tạo | Entry Tier 2 cho Insecure Randomness qua Random.nextInt/Math.random, `no_rule_yet: true`, cha `security-misconfiguration` | Cung cấp tri thức sink cho Insecure Randomness |
| `data/knowledge-base/tier2/java-documentbuilder-xxe.md` | Tạo | Entry Tier 2 cho XXE qua DocumentBuilderFactory.newInstance, `no_rule_yet: true`, cha `xxe` | Cung cấp tri thức sink cho XXE |

**`git diff --stat`:**

```text
 tests/unit/retrieval/test_kb_integrity.py | 64 +++++++++++++++++++++++++++++++
 1 file changed, 64 insertions(+)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Áp dụng quy trình Test-Driven Development (TDD). Ban đầu viết 7 test kiểm tra ràng buộc toàn vẹn của thư mục `data/knowledge-base/tier2/` vào `tests/unit/retrieval/test_kb_integrity.py`. Chạy test để xác nhận trạng thái thất bại (RED - `len(load_tier2(TIER2)) == 11` trả về `0 == 11`). Tiếp theo, tạo 11 file Markdown tuân thủ đúng định dạng YAML frontmatter chuẩn Tier 2 theo đặc tả của Task 3 (3 file có liên kết OpenGrep rule và 8 file đánh dấu `no_rule_yet`). Mỗi file đều chứa mô tả sink cụ thể, điều kiện `not_exploitable_when` thực tế dài trên 30 ký tự, và phần trích dẫn nguồn tài liệu chuẩn (Java SE API, OWASP, CWE). Chạy lại test để xác nhận trạng thái thành công (GREEN).

**Luồng dữ liệu:**
`data/knowledge-base/tier2/*.md` → `load_tier2()` (parse frontmatter YAML bằng PyYAML & validate qua `Tier2Entry`) → `test_kb_integrity.py` (kiểm tra 11 files, tính hợp lệ của `tier1_parent`, tính tồn tại của `matches_rule_ids`, tính duy nhất của sink/rule_id và độ dài của `not_exploitable_when`).

**Các quyết định kỹ thuật:**
- Khai báo sink signatures dạng Fully Qualified Name (FQN) của Java (ví dụ `java.sql.Statement.execute`, `javax.servlet.http.HttpServletResponse.getWriter`) hoặc cú pháp framework đặc trưng (`th:utext`, `HttpSecurity.csrf().disable`) để tránh nhập nhằng khi đối chiếu.
- Đảm bảo các `tier1_parent` trỏ chính xác đến các file đã có trong `data/knowledge-base/tier1/`.
- Với 3 entry có rule OpenGrep, các ID (`java-sql-statement-execution`, `java-command-execution`, `java-unsafe-deserialization`) phải khớp 100% với file cấu hình `configs/opengrep/java-security.yml`.
- Các entry chưa có scanner rule phải đánh dấu tường minh `no_rule_yet: true`.

**Xử lý lỗi / trường hợp biên:**
- Trùng lặp sink giữa các entry: Bộ test `test_khong_sink_nao_xuat_hien_o_hai_entry` sẽ phát hiện ngay lập tức nếu một chữ ký sink bị định nghĩa ở 2 entry khác nhau.
- Trùng lặp rule ID: `test_khong_rule_id_nao_xuat_hien_o_hai_entry` ngăn ngừa việc 2 entry cùng nhận một quy tắc quét.
- Điều kiện an toàn sáo rỗng hoặc quá ngắn: `test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc` ép buộc `not_exploitable_when` phải có độ dài tối thiểu 30 ký tự.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| File | `java-sql-statement-execute.md` | `data/knowledge-base/tier2/java-sql-statement-execute.md` | Entry Tier 2 SQL Injection |
| File | `java-runtime-exec.md` | `data/knowledge-base/tier2/java-runtime-exec.md` | Entry Tier 2 Command Injection |
| File | `java-objectinputstream-readobject.md` | `data/knowledge-base/tier2/java-objectinputstream-readobject.md` | Entry Tier 2 Deserialization |
| File | `java-servlet-response-writer.md` | `data/knowledge-base/tier2/java-servlet-response-writer.md` | Entry Tier 2 XSS Servlet |
| File | `java-thymeleaf-unescaped-output.md` | `data/knowledge-base/tier2/java-thymeleaf-unescaped-output.md` | Entry Tier 2 XSS Thymeleaf |
| File | `java-file-path-concat.md` | `data/knowledge-base/tier2/java-file-path-concat.md` | Entry Tier 2 Path Traversal |
| File | `java-spring-csrf-disabled.md` | `data/knowledge-base/tier2/java-spring-csrf-disabled.md` | Entry Tier 2 CSRF |
| File | `java-jwt-parse-unverified.md` | `data/knowledge-base/tier2/java-jwt-parse-unverified.md` | Entry Tier 2 JWT Weak Verification |
| File | `java-hardcoded-credential.md` | `data/knowledge-base/tier2/java-hardcoded-credential.md` | Entry Tier 2 Hardcoded Credentials |
| File | `java-insecure-random.md` | `data/knowledge-base/tier2/java-insecure-random.md` | Entry Tier 2 Insecure Randomness |
| File | `java-documentbuilder-xxe.md` | `data/knowledge-base/tier2/java-documentbuilder-xxe.md` | Entry Tier 2 XXE Injection |
| Test | 7 test toàn vẹn | `tests/unit/retrieval/test_kb_integrity.py` | Kiểm tra tính nhất quán và toàn vẹn của KB Tier 2 |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v
.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
make quality
```

**Output thật (đã che secret):**

```text
tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat PASSED [ 10%]
tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bon_doc_va_dung_id PASSED [ 20%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier PASSED [ 30%]
tests/unit/retrieval/test_kb_integrity.py::test_co_dung_muoi_mot_entry_tier2 PASSED [ 40%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_tier1_parent_tro_toi_doc_co_that PASSED [ 50%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_rule_id_duoc_khai_deu_ton_tai_that PASSED [ 60%]
tests/unit/retrieval/test_kb_integrity.py::test_entry_khong_co_rule_phai_danh_dau_no_rule_yet PASSED [ 70%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_sink_nao_xuat_hien_o_hai_entry PASSED [ 80%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_rule_id_nao_xuat_hien_o_hai_entry PASSED [ 90%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc PASSED [100%]

============================== 10 passed in 0.12s ==============================

985 passed, 41 deselected, 1 warning in 19.29s

make quality:
All checks passed!
Success: no issues found in 79 source files
Required test coverage of 78.0% reached. Total coverage: 84.30%
No known vulnerabilities found
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Tách tri thức sink thành từng file Markdown độc lập chứa YAML frontmatter có cấu trúc chuẩn hoá (`Tier2Entry`), lưu trữ phân cấp tại `data/knowledge-base/tier2/`.

**Lý do:** Kế hoạch `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` dòng 527-706 chỉ định rõ cấu trúc 11 entry Tier 2 và 7 bài test toàn vẹn. Cách tiếp cận này giúp KB tự sở hữu bản đồ sink mà không bị phụ thuộc vào cú pháp của scanner cụ thể, hỗ trợ mở rộng thêm các quy tắc mới chỉ bằng việc thêm file tài liệu.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Gộp tất cả sink vào một file JSON/YAML chung | Dễ đọc cấu trúc trong 1 chỗ | Khó viết tài liệu dài, khó giải thích cơ chế phòng vệ bằng Markdown có định dạng và code snippet, không tương thích với luồng index Markdown tri thức |
| Nhúng trực tiếp quy tắc sink vào code Python | Tốc độ đọc trong RAM nhanh | Vi phạm nguyên tắc phân tách dữ liệu tri thức và mã nguồn; không thể cập nhật tri thức an ninh độc lập |

**Đánh đổi đã chấp nhận:** Số lượng file trong repo tăng lên (11 files mới), nhưng đảm bảo tính module hoá cao và cho phép kiểm tra toàn vẹn tự động qua test suite.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v` | 0 | 10 passed in 0.12s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 985 passed, 41 deselected, 1 warning in 19.29s |
| `make quality` | 0 | ruff pass, mypy pass (79 source files), coverage 84.30% (ngưỡng >= 78%), pip-audit pass |

**Test mới thêm:**

- `tests/unit/retrieval/test_kb_integrity.py::test_co_dung_muoi_mot_entry_tier2` — Khẳng định nạp đủ 11 entry Tier 2.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_tier1_parent_tro_toi_doc_co_that` — Khẳng định `tier1_parent` của mỗi entry luôn trỏ tới file `.md` có thật trong `tier1/`.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_rule_id_duoc_khai_deu_ton_tai_that` — Khẳng định các `matches_rule_ids` tồn tại trong `configs/opengrep/java-security.yml`.
- `tests/unit/retrieval/test_kb_integrity.py::test_entry_khong_co_rule_phai_danh_dau_no_rule_yet` — Khẳng định entry chưa có rule quét phải có cờ `no_rule_yet: true`.
- `tests/unit/retrieval/test_kb_integrity.py::test_khong_sink_nao_xuat_hien_o_hai_entry` — Khẳng định mỗi sink signature là duy nhất trong toàn bộ Tier 2.
- `tests/unit/retrieval/test_kb_integrity.py::test_khong_rule_id_nao_xuat_hien_o_hai_entry` — Khẳng định mỗi rule_id chỉ được gán cho tối đa 1 entry.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc` — Khẳng định `not_exploitable_when` có độ dài tối thiểu 30 ký tự.

**Bất biến đã giữ:**
- Không sử dụng mock/stub/fake.
- Không skip test.
- Không lộ secret / API key.
- Không làm thay đổi các báo cáo lịch sử `reports/week-XX/`.
- Giữ nguyên `CANONICAL_CATEGORIES` và tính tương thích của toàn bộ pipeline.

**Còn fail / chưa chạy được:** Không có

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Danh sách chữ ký sink trong các entry `no_rule_yet` (như `org.springframework.security.config.annotation.web.builders.HttpSecurity.csrf().disable` hoặc `io.jsonwebtoken.JwtParser.parseClaimsJwt`) — cần kiểm tra xem có cần bổ sung thêm các biến thể chữ ký khác trong tương lai khi viết thêm OpenGrep rule hay không.
- **Giả định đã đặt:** Giả định các danh mục trong `CANONICAL_CATEGORIES` là tập đóng cố định phù hợp cho toàn bộ 11 entry hiện tại.
- **Việc còn nợ:** Task 4 (Triển khai tra cứu thác nước `tier_lookup.py`), Task 5 (Thêm validator luật provenance 10 & 11).
- **Câu hỏi cho người dùng:** Không có
