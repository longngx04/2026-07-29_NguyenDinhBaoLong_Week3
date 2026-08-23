# Worklog — Task 2: Chuyển Tier 1 và trỏ keyword search vào đúng tầng

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Gemini 3.6 Flash High ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 2`

---

## 1. Tóm tắt

Đã thực hiện di chuyển toàn bộ 17 tài liệu kiến thức từ thư mục cũ `data/knowledge-base/vulnerabilities/` sang kiến trúc hai tầng `data/knowledge-base/tier1/` và hợp nhất các biến thể còn 14 tài liệu chuẩn.
Bổ sung khai báo tường minh `tier: 1` và định danh `id:` vào YAML frontmatter của từng tài liệu Tier 1, đồng thời trỏ mặc định của bộ tìm kiếm `knowledge_dir` sang thư mục `tier1/` để đảm bảo keyword search chỉ quét tầng khái niệm.
Toàn bộ hệ thống kiểm thử toàn vẹn dữ liệu KB và 978 test case hiện có đều vượt qua 100% xanh kèm `make quality` đạt chuẩn độ phủ 84.26%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Tách bạch tầng tri thức Tier 1 (khái niệm lỗ hổng mức cao, biến thể, khắc phục chung) phục vụ tra cứu keyword search và làm đích tham chiếu (`tier1_parent`) cho các entry sink Tier 2 ở Task 3 & 4.
- **Nằm ở đâu trong luồng:** Nằm ở tầng dữ liệu tri thức tĩnh `data/knowledge-base/tier1/` và adapter truy xuất `src/project_sentinel/retrieval/knowledge_retriever.py`, được gọi trong pipeline phân tích an ninh trước khi dựng prompt gửi LLM.
- **Không có nó thì hỏng gì:** Nếu không hợp nhất và gán ID chuẩn cho Tier 1, các entry Tier 2 ở Task 3 sẽ không có parent ID hợp lệ để liên kết (`test_moi_tier1_parent_tro_toi_doc_co_that` sẽ fail); nếu để keyword search quét cả Tier 2 thì tra cứu mờ sẽ cạnh tranh và làm sai lệch cơ chế tra cứu tất định 3 mức ở Task 4; nếu còn thư mục cũ `vulnerabilities/` thì tìm kiếm sẽ bị trùng lặp kết quả.
- **Ngoài phạm vi (cố ý không làm):** Chưa tạo các entry Tier 2 (đây là nhiệm vụ của Task 3); chưa tích hợp hàm `lookup_tier2` vào `retrieve_knowledge` (nhiệm vụ của Task 4).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/retrieval/test_kb_integrity.py` | Tạo mới | Viết bộ 3 unit test TDD kiểm tra tính toàn vẹn KB Tier 1: kiểm tra thư mục cũ biến mất, kiểm tra đúng 14 doc với 14 `id` chuẩn, kiểm tra mọi doc khai `tier: 1`. | Khóa cứng hợp đồng cấu trúc KB Tier 1 bằng test tự động chạy trên dữ liệu thật. |
| `data/knowledge-base/tier1/csrf.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/csrf.md`, thêm `tier: 1` và `id: csrf` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/idor.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/idor.md`, thêm `tier: 1` và `id: idor` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/path-traversal.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/path-traversal.md`, thêm `tier: 1` và `id: path-traversal` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/insecure-deserialization.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/insecure-deserialization.md`, thêm `tier: 1` và `id: insecure-deserialization` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/jwt-weak-verification.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/jwt-weak-verification.md`, thêm `tier: 1` và `id: jwt-weak-verification` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/broken-auth.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/broken-auth.md`, thêm `tier: 1` và `id: broken-auth` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/ssrf.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/ssrf.md`, thêm `tier: 1` và `id: ssrf` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/xxe.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/xxe.md`, thêm `tier: 1` và `id: xxe` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/html-tampering.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/html-tampering.md`, thêm `tier: 1` và `id: html-tampering` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/security-misconfiguration.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/security-misconfiguration.md`, thêm `tier: 1` và `id: security-misconfiguration` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/vulnerable-components.md` | Tạo / Chuyển | Di chuyển từ `vulnerabilities/vulnerable-components.md`, thêm `tier: 1` và `id: vulnerable-components` vào frontmatter. | Chuẩn hóa tài liệu Tier 1 theo hợp đồng hai tầng. |
| `data/knowledge-base/tier1/command-injection.md` | Tạo / Chuyển | Chuyển từ `vulnerabilities/command-injection-runtime-exec.md`, đổi tên stem thành `command-injection`, gán `id: command-injection` và `tier: 1`. | Đơn giản hóa định danh cấp độ lớp lỗ hổng chung cho Tier 1. |
| `data/knowledge-base/tier1/sql-injection.md` | Tạo mới (Gộp) | Hợp nhất `sql-injection-concat.md` và `sql-injection-login.md` thành các mục `## Biến thể: ...`, gán `id: sql-injection`, `tier: 1`. | Gom các biến thể rời rạc thành một tài liệu lớp lỗ hổng hoàn chỉnh. |
| `data/knowledge-base/tier1/xss.md` | Tạo mới (Gộp) | Hợp nhất `xss-reflected.md`, `xss-stored.md`, `xss-dom.md` thành các mục `## Biến thể: ...`, gán `id: xss`, `tier: 1`. | Gom các biến thể XSS thành một tài liệu lớp lỗ hổng hoàn chỉnh. |
| `data/knowledge-base/vulnerabilities/` | Xóa | Xóa toàn bộ 17 file cũ và thư mục `vulnerabilities/`. | Chống quét trùng lặp dữ liệu cũ. |
| `src/project_sentinel/retrieval/knowledge_retriever.py` | Sửa | Cập nhật giá trị mặc định của tham số `knowledge_dir` thành `Path("data/knowledge-base/tier1")` kèm chú thích tiếng Việt giải thích vì sao. | Giới hạn phạm vi keyword search trong Tier 1 để không xung đột với tra cứu Tier 2. |

**`git diff --stat`:**

```text
 data/knowledge-base/vulnerabilities/broken-auth.md        | 10 ----------
 .../vulnerabilities/command-injection-runtime-exec.md     | 12 ------------
 data/knowledge-base/vulnerabilities/csrf.md               | 10 ----------
 data/knowledge-base/vulnerabilities/html-tampering.md     | 10 ----------
 data/knowledge-base/vulnerabilities/idor.md               | 10 ----------
 .../vulnerabilities/insecure-deserialization.md           | 10 ----------
 .../vulnerabilities/jwt-weak-verification.md              | 10 ----------
 data/knowledge-base/vulnerabilities/path-traversal.md     | 10 ----------
 .../vulnerabilities/security-misconfiguration.md          | 10 ----------
 .../vulnerabilities/sql-injection-concat.md               | 15 ---------------
 .../knowledge-base/vulnerabilities/sql-injection-login.md | 10 ----------
 data/knowledge-base/vulnerabilities/ssrf.md               | 10 ----------
 .../vulnerabilities/vulnerable-components.md              | 10 ----------
 data/knowledge-base/vulnerabilities/xss-dom.md            | 10 ----------
 data/knowledge-base/vulnerabilities/xss-reflected.md      | 10 ----------
 data/knowledge-base/vulnerabilities/xss-stored.md         | 10 ----------
 data/knowledge-base/vulnerabilities/xxe.md                |  8 --------
 src/project_sentinel/retrieval/knowledge_retriever.py     |  4 +++-
 18 files changed, 3 insertions(+), 176 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Thực hiện nghiêm ngặt theo quy trình TDD (Test-Driven Development):
1. Viết bộ kiểm thử `tests/unit/retrieval/test_kb_integrity.py` kiểm tra cấu trúc 14 tài liệu trong `tier1/` và sự biến mất của `vulnerabilities/`.
2. Chạy pytest để ghi nhận trạng thái đỏ (FAIL) rõ ràng.
3. Di chuyển 11 tài liệu, chuẩn hóa tên file `command-injection.md`, hợp nhất 2 file SQLi thành 1 và 3 file XSS thành 1. Bổ sung `tier: 1` và `id:` cho toàn bộ 14 tài liệu.
4. Xóa sạch thư mục `data/knowledge-base/vulnerabilities/`.
5. Đổi mặc định `knowledge_dir` trong `knowledge_retriever.py` sang `tier1/`.
6. Chạy lại test xác nhận trạng thái xanh (PASS), chạy toàn bộ test suite và `make quality`.

**Luồng dữ liệu:**
Finding query (`title`, `cwe`, `owasp`, `rule_id`) → `retrieve_knowledge` → `keyword_search(..., knowledge_dir="data/knowledge-base/tier1")` → Trả về danh sách `RetrievalHit` trỏ tới `data/knowledge-base/tier1/<id>.md`.

**Các quyết định kỹ thuật:**
- Bảo lưu toàn bộ nội dung nguyên gốc từ các file cũ khi hợp nhất sang `sql-injection.md` và `xss.md`, chuyển các tiêu đề riêng thành các section `## Biến thể: ...` để không làm mất bất kỳ từ khóa chuyên ngành nào phục vụ BM25/TF-IDF.
- Sử dụng chính stem của tên file làm `id` định danh duy nhất (ví dụ: `sql-injection`, `xss`, `csrf`), tạo tiền đề trực tiếp cho `tier1_parent` của Task 3.
- Chú thích tiếng Việt trực tiếp tại khai báo tham số trong mã nguồn để giải thích rõ lý do không cho keyword search quét vào `tier2/`.

**Xử lý lỗi / trường hợp biên:**
- Kiểm tra tính toàn vẹn frontmatter đảm bảo mọi file đều có cặp dấu gạch ngang `---` bao bọc và parse được trường `id` và `tier`.
- Xóa hoàn toàn thư mục cũ để tránh trường hợp tìm kiếm đệ quy `rglob("*.md")` quét trùng lặp cả file cũ lẫn file mới.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Test | `test_kb_integrity.py` | `tests/unit/retrieval/test_kb_integrity.py` | Unit test kiểm tra tính toàn vẹn 14 file Tier 1 và xóa thư mục cũ |
| Directory / Docs | `tier1/` | `data/knowledge-base/tier1/*.md` (14 files) | 14 tài liệu kiến thức Tier 1 chuẩn hóa |
| Function default | `retrieve_knowledge` | `knowledge_dir: Path = Path("data/knowledge-base/tier1")` | Trỏ mặc định keyword search vào Tier 1 |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v
make search Q='SQL Injection'
make search Q='XSS'
make quality
```

**Output thật (đã che secret):**

```text
$ .venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v
============================= test session starts ==============================
collected 3 items

tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat PASSED [ 33%]
tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bon_doc_va_dung_id PASSED [ 66%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier PASSED [100%]

============================== 3 passed in 0.04s ===============================

$ make search Q='SQL Injection'
Query: 'SQL Injection' — 4 hit(s)

1. [66.2] SQL Injection
   path: data/knowledge-base/tier1/sql-injection.md
   tags: example, sql-injection, sqli, cwe-89, injection, java
   snippet: Dấu hiệu: SQL Injection / CWE-89 trên form login. Fix: parameterized query + hash mật khẩu, không so sánh plaintext trong SQL động.

2. [31.2] OWASP Top 10 2021 Overview
   path: data/knowledge-base/owasp/owasp-top10.md
...

$ make search Q='XSS'
Query: 'XSS' — 5 hit(s)

1. [32.2] Cross-Site Scripting
   path: data/knowledge-base/tier1/xss.md
   tags: example, xss, cross-site-scripting, cwe-79
   snippet: Cross Site Scripting (XSS) cho phép đánh cắp session cookie hoặc giả mạo hành động. Mitigation: encode output theo context (HTML/attr/JS), Content-Security-Policy.
...
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Gộp các biến thể phân mảnh (`concat`, `login` đối với SQLi; `reflected`, `stored`, `dom` đối với XSS) thành một tài liệu tổng thể mức lớp lỗ hổng Tier 1, cấu trúc lại thư mục thành `data/knowledge-base/tier1/` và cập nhật mặc định `knowledge_retriever.py`.

**Lý do:**
Theo đúng đặc tả trong plan `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` (dòng 368–378 và 494–498):
*"Keyword search CHỈ được quét tier1/. Nếu để nó quét cả tier2/ thì khớp chữ sẽ cạnh tranh với tra cứu tất định, đúng cái ưu thế vừa xây ở Task 4."*
Việc gom nhóm giúp Tier 1 thực sự đóng vai trò tri thức khái niệm tổng quát, trong khi các mẫu sink chi tiết theo ngôn ngữ và framework sẽ được Tier 2 phụ trách riêng biệt ở Task 3.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Giữ nguyên 17 file riêng lẻ trong `tier1/` | Không cần gộp nội dung Markdown | Tạo ra sự phân mảnh không cần thiết ở Tier 1, gây khó khăn cho việc đặt `tier1_parent` tại Tier 2 (ví dụ: sink Statement.execute nên trỏ về `sql-injection-concat` hay `sql-injection-login`?). |
| Giữ `knowledge_dir` trỏ vào `data/knowledge-base` gốc | Không cần sửa mã nguồn Python | Sai kiến trúc vì khi thêm `tier2/` vào, keyword search sẽ quét và tính điểm cạnh tranh với các entry Tier 2, phá vỡ nguyên lý phân tầng và làm suy giảm độ chính xác của tra cứu tất định. |

**Đánh đổi đã chấp nhận:**
Gộp nội dung làm tăng độ dài của `sql-injection.md` và `xss.md`, nhưng cải thiện chất lượng snippet và giữ trọn vẹn ngữ cảnh cho LLM khi tra cứu theo chủ đề lớn.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v` | 0 | 3/3 passed |
| `.venv/bin/python -m pytest tests/unit/retrieval/ -v` | 0 | 56/56 passed |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 978 passed, 41 deselected |
| `make search Q='SQL Injection'` | 0 | Trả về hit hàng đầu trỏ đúng vào `data/knowledge-base/tier1/sql-injection.md` |
| `make search Q='XSS'` | 0 | Trả về hit hàng đầu trỏ đúng vào `data/knowledge-base/tier1/xss.md` |
| `make quality` | 0 | Lint passed, Typecheck passed (79 source files), Coverage 84.26% (vượt 78.0%), pip-audit passed |

**Test mới thêm:**
- `tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat` — Khẳng định thư mục cũ `data/knowledge-base/vulnerabilities` đã bị loại bỏ hoàn toàn.
- `tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bon_doc_va_dung_id` — Khẳng định thư mục `tier1/` chứa đúng 14 tài liệu với 14 `id` chính xác theo danh sách kỳ vọng.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier` — Khẳng định tất cả tài liệu trong `tier1/` đều khai báo `tier: 1` trong frontmatter.

**Bất biến đã giữ:**
- Không sử dụng mock, stub hay fake object nào.
- Toàn bộ test chạy trên dữ liệu và mã nguồn thật.
- Giữ nguyên các báo cáo lịch sử `reports/week-XX/`.
- Không vi phạm các ràng buộc an toàn, không có secret leak.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/retrieval/knowledge_retriever.py:35` — việc đổi mặc định `knowledge_dir` thành `data/knowledge-base/tier1` được thiết kế có chủ đích cho tầng tri thức khái niệm.
- **Giả định đã đặt:** Mọi mã nguồn gọi `retrieve_knowledge` đều kỳ vọng lấy tri thức khái niệm từ Tier 1 (ở Task 4, hàm này sẽ được mở rộng thêm bước gọi tra cứu tất định Tier 2 trước khi fallback sang keyword search Tier 1).
- **Việc còn nợ:** Task 3 (viết 11 entry Tier 2) và Task 4 (bộ tra cứu thác nước 3 mức).
- **Câu hỏi cho người dùng:** Không có.
