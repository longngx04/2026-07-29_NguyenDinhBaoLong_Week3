# Worklog — Bổ sung bộ test toàn vẹn cấu trúc và chống trôi (5-Section & Reference Integrity)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · auto ·
**Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 6`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Bổ sung 5 bài test tự động kiểm tra tính toàn vẹn cấu trúc và chống trôi liên kết tham chiếu (Anti-Drift) cho toàn bộ Kho tri thức gồm 14 tài liệu Tier 1 và 11 tài liệu Tier 2 trong `tests/unit/retrieval/test_kb_integrity.py`. Bộ test bảo đảm 100% tài liệu tuân thủ nghiêm ngặt các đề mục chuẩn hóa Markdown, các khối mã nguồn minh họa (Vulnerable vs. Remediated Pattern) và danh sách liên kết thẩm quyền OWASP/CWE/Oracle hợp lệ. Toàn bộ 15 test trong `test_kb_integrity.py` và 1016 test trong test suite hệ thống đều chạy thành công với `make quality` đạt chuẩn 100%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp bộ guardrail kiểm thử hồi quy tĩnh (static structural regression guardrail) chạy trực tiếp trên kho tri thức bảo mật thực tế (`data/knowledge-base/`), ngăn chặn tình trạng tài liệu Markdown bị sửa đổi làm mất cấu trúc chuẩn hoặc hỏng liên kết tham chiếu.
- **Nằm ở đâu trong luồng:** Chạy ở tầng kiểm thử đơn vị (`tests/unit/retrieval/`), kiểm tra trực tiếp các file tri thức trước khi chúng được nạp bởi `kb_schema.py`, phục vụ `keyword_search.py`, `analysis` pipeline và hiển thị trên Web Dashboard.
- **Không có nó thì hỏng gì:** Nếu không có bộ test này, các thay đổi trong tương lai có thể vô tình xóa mất các đề mục chuẩn (như `## 2. Mã nguồn minh họa`, `### ❌ Không an toàn`), gây lỗi khi Web UI parse trích xuất mã đối chứng hoặc dẫn tới URL tham chiếu sai định dạng làm gãy liên kết trên giao diện người dùng.
- **Ngoài phạm vi (cố ý không làm):** Không gửi HTTP request ra Internet để kiểm tra URL liveness (tuân thủ nguyên tắc không gọi external API/mạng ngoài trong runtime test, kiểm tra định dạng cú pháp URL `http://` / `https://` offline).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/retrieval/test_kb_integrity.py` | Sửa | Thêm 5 test case kiểm tra cấu trúc 4/5 đề mục, code block đối chứng và URL references cho Tier 1 & Tier 2 | Thực thi yêu cầu kiểm tra toàn vẹn cấu trúc và chống trôi của Task 6 |
| `worklog/2026-08-23-task6-kb-integrity-anti-drift.md` | Tạo | Tạo tài liệu worklog chi tiết theo mẫu chuẩn `worklog/_TEMPLATE.md` | Bắt buộc theo quy định AGENTS.md và task prompt template |

**`git diff --stat`:**

```text
 tests/unit/retrieval/test_kb_integrity.py | 114 ++++++++++++++++++++++++++++++
 1 file changed, 114 insertions(+)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Đọc trực tiếp các file `.md` thực tế trong `data/knowledge-base/tier1` và `data/knowledge-base/tier2` thông qua `pathlib.Path`. Phân tích phần YAML Frontmatter để kiểm tra trường `references` (danh sách URL hợp lệ) và kiểm tra phần Markdown Body để xác nhận sự hiện diện của các tiêu đề chuẩn hóa cấp 2 (`## ...`), tiêu đề cấp 3 (`### ❌ ...`, `### ✅ ...`) và các khối code fence.

**Luồng dữ liệu:**
`data/knowledge-base/{tier1,tier2}/*.md` → `path.read_text()` + `_frontmatter(path)` → Quét tiêu đề chuỗi & URL regex/prefix → `pytest assert`

**Các quyết định kỹ thuật:**
- Kiểm tra trực tiếp trên dữ liệu thật (`data/knowledge-base/`), không dùng fixture giả lập vì mục tiêu của test là đảm bảo tính toàn vẹn của dữ liệu sản xuất.
- Đảm bảo kiểm tra rõ ràng số lượng file (11 file Tier 2 và 14 file Tier 1) để tránh việc vô tình bỏ sót hoặc xóa mất file tài liệu.
- Kiểm tra linh hoạt code block có thể là ```` ```java ```` hoặc ```` ```html ```` để phù hợp với cả lỗ hổng mã nguồn Java và lỗ hổng template engine (như Thymeleaf HTML).

**Xử lý lỗi / trường hợp biên:**
- Báo lỗi rõ tên file kèm tiêu đề hoặc URL bị thiếu/sai định dạng qua message assertion của pytest, giúp kỹ sư phát hiện và sửa đổi nhanh chóng.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Test | `test_moi_entry_tier2_co_du_bon_de_muc_chuan` | `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_du_bon_de_muc_chuan` | Kiểm tra 11/11 file Tier 2 có đủ 4 đề mục chuẩn |
| Test | `test_moi_entry_tier2_co_code_block_vulnerable_va_remediated` | `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_code_block_vulnerable_va_remediated` | Kiểm tra 11/11 file Tier 2 có mẫu Không an toàn & Đã khắc phục an toàn |
| Test | `test_moi_entry_tier2_khai_references_url_hop_le` | `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_khai_references_url_hop_le` | Kiểm tra 11/11 file Tier 2 có references hợp lệ |
| Test | `test_moi_doc_tier1_co_du_bon_de_muc_chuan` | `tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_co_du_bon_de_muc_chuan` | Kiểm tra 14/14 file Tier 1 có đủ 4 đề mục chuẩn |
| Test | `test_moi_doc_tier1_khai_references_url_hop_le` | `tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_references_url_hop_le` | Kiểm tra 14/14 file Tier 1 có references hợp lệ |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v
make quality
```

**Output thật (đã che secret):**

```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /home/longngx04/VinSOC/project_sentinel_main/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/longngx04/VinSOC/project_sentinel_main
configfile: pyproject.toml
plugins: respx-0.23.1, xdist-3.8.0, anyio-4.14.2, cov-7.1.0
collecting ... collected 15 items

tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat PASSED [  6%]
tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bon_doc_va_dung_id PASSED [ 13%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier PASSED [ 20%]
tests/unit/retrieval/test_kb_integrity.py::test_co_dung_muoi_mot_entry_tier2 PASSED [ 26%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_tier1_parent_tro_toi_doc_co_that PASSED [ 33%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_rule_id_duoc_khai_deu_ton_tai_that PASSED [ 40%]
tests/unit/retrieval/test_kb_integrity.py::test_entry_khong_co_rule_phai_danh_dau_no_rule_yet PASSED [ 46%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_sink_nao_xuat_hien_o_hai_entry PASSED [ 53%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_rule_id_nao_xuat_hien_o_hai_entry PASSED [ 60%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc PASSED [ 66%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_du_bon_de_muc_chuan PASSED [ 73%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_code_block_vulnerable_va_remediated PASSED [ 80%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_khai_references_url_hop_le PASSED [ 86%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_co_du_bon_de_muc_chuan PASSED [ 93%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_references_url_hop_le PASSED [100%]

============================== 15 passed in 0.20s ==============================
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Viết các assertion tường minh bằng chuỗi substring prefix cho đề mục và URL validation cho frontmatter trong file test `test_kb_integrity.py`.

**Lý do:**
Kế hoạch `docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md` (mục Task 6) chỉ định rõ việc tạo các bài test này để đảm bảo cấu trúc 5 phần và chống trôi liên kết. Việc kiểm tra trực tiếp substring tiêu đề giúp test chạy cực nhanh (0.2s), không phát sinh phụ thuộc bên ngoài và phản ánh trung thực nội dung markdown.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Sử dụng thư viện phân tích Markdown AST (như `markdown-it` hoặc `mistletoe`) | Phân tích cây ngữ pháp Markdown chi tiết | Phải thêm dependency ngoài, vi phạm ràng buộc Global Constraints không thêm dependency mới |
| Gửi HTTP HEAD request để kiểm tra URL sống | Biết chắc URL còn tồn tại | Vi phạm quy định cấm gọi external network trong test offline, làm test chậm và flaky |

**Đánh đổi đã chấp nhận:**
Kiểm tra cú pháp URL prefix offline thay vì kiểm tra liveness online để giữ trọn vẹn tính độc lập và tốc độ của test suite.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_integrity.py -v` | 0 | 15 passed in 0.20s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1016 passed, 41 deselected in 19.51s |
| `make quality` | 0 | Ruff OK, Mypy OK (81 files), Coverage 84.37% (vượt mức yêu cầu 78%), 1016 tests passed |

**Test mới thêm:**

- `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_du_bon_de_muc_chuan` — Khẳng định 100% 11 file Tier 2 có đủ 4 đề mục chuẩn.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_co_code_block_vulnerable_va_remediated` — Khẳng định 100% 11 file Tier 2 có code blocks đối chứng không an toàn và khắc phục an toàn.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_tier2_khai_references_url_hop_le` — Khẳng định 100% 11 file Tier 2 có references hợp lệ.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_co_du_bon_de_muc_chuan` — Khẳng định 100% 14 file Tier 1 có đủ 4 đề mục chuẩn.
- `tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_references_url_hop_le` — Khẳng định 100% 14 file Tier 1 có references hợp lệ.

**Bất biến đã giữ:**
- Không sử dụng test double (mock/stub).
- Không có test nào bị `skip`.
- Không làm lộ bí mật hay token.
- Không sửa đổi schema hay reports lịch sử.
- Toàn bộ test chạy offline deterministic.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có, tất cả các bài test kiểm tra trực tiếp và rõ ràng các bất biến cấu trúc.
- **Giả định đã đặt:** Giả định các file Tier 2 sử dụng code block ```java hoặc ```html cho phần minh họa mã nguồn.
- **Việc còn nợ:** Tiếp tục thực hiện Task 7 (Hiển thị Tri thức & Remediation trên Web UI).
- **Câu hỏi cho người dùng:** Không có.
