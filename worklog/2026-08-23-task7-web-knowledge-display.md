# Worklog — Task 7: Hiển thị Tri thức & Remediation trên Web UI

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · auto-inherited ·
**Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](../docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 7`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã bổ sung chức năng trích xuất và hiển thị dữ liệu tri thức bảo mật (Knowledge Base & Remediation) từ các tài liệu Tier 2 / Tier 1 lên giao diện Web UI phân tích (Analysis screen). Tính năng này phục vụ chuyên gia bảo mật và lập trình viên tra cứu trực tiếp giải pháp thay thế an toàn (`safe_alternative`), ranh giới an toàn không thể khai thác (`not_exploitable_when`), và các badge liên kết URL tham chiếu thẩm quyền (OWASP, CWE, Oracle). Toàn bộ 73 test giao diện Web và toàn bộ 1017 unit test offline đều pass 100%, chất lượng mã đạt `make quality` (ruff, mypy, coverage 83.84%, pip-audit).

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Tải và trình diễn thông tin tri thức chuyên sâu từ `data/knowledge-base/` tương ứng với các `knowledge_refs` có trong kết quả phân tích AI (`analysis.jsonl`), giúp người dùng có đầy đủ ngữ cảnh khắc phục và đối chứng điều kiện an toàn.
- **Nằm ở đâu trong luồng:** Nằm ở tầng trình diễn Web UI (`src/project_sentinel/web/`), đọc kết quả phân tích từ orchestrator (`analysis.jsonl`) và kho tri thức tĩnh (`data/knowledge-base/`) để render view HTML cho người dùng.
- **Không có nó thì hỏng gì:** Người dùng trên Web UI chỉ thấy khuyến nghị ngắn gọn và giải thích sơ bộ mà không xem được giải pháp thay thế mã nguồn chuẩn, ranh giới an toàn (Safe Boundaries) và các tài liệu tham khảo chính thức của OWASP/CWE đã được đối chứng.
- **Ngoài phạm vi (cố ý không làm):** Không chỉnh sửa `schemas/security-analysis-record.schema.json`; không gọi live API ra internet trong lúc render web; không can thiệp vào logic gateway hay execution của các bước khác.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/web/test_findings_analysis.py` | Sửa | Viết test `test_analysis_screen_shows_knowledge_references_and_safe_boundaries` xác nhận giao diện hiển thị đúng link tham chiếu, giải pháp an toàn và điều kiện biên. | Tuân thủ TDD, bảo đảm màn hình Analysis render đúng nội dung tri thức. |
| `src/project_sentinel/web/views.py` | Sửa | Thêm hàm `_split_yaml_frontmatter`, `_load_knowledge_details` sử dụng `parse_tier2` và PyYAML để trích xuất `references`, `safe_alternative`, `not_exploitable_when`, `title`, gắn vào record qua trường `knowledge_details`. | Tầng views chịu trách nhiệm chuẩn bị dữ liệu đọc cho templates mà không làm ô nhiễm model hay orchestrator. |
| `src/project_sentinel/web/templates/analysis.html` | Sửa | Bổ sung khối giao diện "Tài liệu tri thức & Hướng dẫn khắc phục (Knowledge Base & Remediation)" với badge URL clickable, khối mã giải pháp an toàn và hộp cảnh báo Safe Boundaries. | Hiển thị trực quan, thẩm mỹ theo thiết kế giao diện Sentinel. |

**`git diff --stat`:**

```text
 src/project_sentinel/web/templates/analysis.html |  46 ++++++++
 src/project_sentinel/web/views.py                | 129 ++++++++++++++++++++++-
 tests/unit/web/test_findings_analysis.py         |  31 ++++++
 3 files changed, 205 insertions(+), 1 deletion(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Thực hiện quy trình TDD chuẩn: viết test kiểm tra giao diện phân tích với bản ghi chứa `knowledge_refs`, chạy test xác nhận thất bại (RED).
2. Nâng cấp `views.py` với logic đọc an toàn: duyệt qua các `knowledge_refs` của từng finding, giải quyết đường dẫn tương đối từ `ctx.repo_root` hoặc đường dẫn tuyệt đối, ưu tiên dùng `parse_tier2` để lấy dữ liệu có cấu trúc hoàn chỉnh, đồng thời có cơ chế fallback đọc frontmatter YAML tổng quát cho Tier 1 hoặc tài liệu markdown khác.
3. Cập nhật Jinja2 template `analysis.html` để render khối thông tin trực quan: hiển thị tiêu đề tài liệu, điểm khớp (relevance score), giải pháp mã nguồn an toàn (`safe_alternative`), hộp thông tin điều kiện không thể khai thác (`not_exploitable_when`) và danh sách badge URL liên kết ngoài (`references`).
4. Chạy toàn bộ test xác nhận chuyển sang trạng thái xanh (GREEN) và chạy kiểm tra chất lượng `make quality`.

**Luồng dữ liệu:**
`record.root/analysis.jsonl` + `data/knowledge-base/` → `views.analysis_data()` → `_load_knowledge_details()` → `template analysis.html` → HTML response hiển thị trên trình duyệt.

**Các quyết định kỹ thuật:**
- **Ưu tiên `parse_tier2` kèm fallback mềm:** Sử dụng parser chuyên dụng `parse_tier2` vì Tier 2 đã được chuẩn hóa nghiêm ngặt, nhưng có try/except fallback về YAML parser thông thường để không làm sập trang web nếu gặp tài liệu Tier 1 hoặc file markdown tuỳ biến.
- **Xử lý đường dẫn linh hoạt:** Hỗ trợ cả đường dẫn tương đối so với `repo_root` (chuẩn lưu trong `analysis.jsonl`) lẫn đường dẫn cục bộ hoặc tuyệt đối.
- **Bảo mật và tính sẵn sàng:** Toàn bộ liên kết ngoài được mở qua thẻ `<a>` với `target="_blank" rel="noopener noreferrer"`. Không thực hiện bất kỳ network request nào trong lúc render (chỉ xuất text link tĩnh).

**Xử lý lỗi / trường hợp biên:**
- File tri thức bị thiếu hoặc đường dẫn sai: Trả về record tối thiểu kèm tiêu đề là tên đường dẫn, không ném exception gây lỗi 500 cho trang web.
- Record không có `knowledge_refs` hoặc rỗng: Bỏ qua nhẹ nhàng, template chỉ render khối khi `item.knowledge_details` tồn tại.
- File markdown không hợp lệ / lỗi YAML: Bắt exception và tạo fallback rỗng an toàn.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Hàm | `_split_yaml_frontmatter` | `_split_yaml_frontmatter(text: str) -> tuple[str, str]` | Tách frontmatter và body markdown an toàn. |
| Hàm | `_load_knowledge_details` | `_load_knowledge_details(ctx: RunContext, refs: list) -> list[dict[str, Any]]` | Nạp và trích xuất chi tiết tri thức KB cho finding. |
| Hàm | `analysis_data` | `analysis_data(ctx: RunContext, run_id: str) -> dict` | Gắn thêm trường `knowledge_details` cho từng analysis record. |
| Template | `analysis.html` | `src/project_sentinel/web/templates/analysis.html` | Thêm khối giao diện hiển thị Knowledge Base & Remediation. |
| Test | `test_analysis_screen_shows_knowledge_references_and_safe_boundaries` | `tests/unit/web/test_findings_analysis.py` | Test xác thực render đầy đủ link tham chiếu và safe boundaries. |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/web/ -v
make quality
```

**Output thật (đã che secret):**

```text
======================== 73 passed, 1 warning in 1.40s =========================
Success: no issues found in 81 source files
================================ tests coverage ================================
Required test coverage of 78.0% reached. Total coverage: 83.84%
1017 passed, 41 deselected, 1 warning in 23.71s
No known vulnerabilities found
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Trích xuất dữ liệu KB động trong tầng web view `views.py` lúc render màn hình Analysis và truyền vào context template, không lưu đè cấu trúc JSON gốc trong `analysis.jsonl`.

**Lý do:**
- Giữ nguyên vẹn `schemas/security-analysis-record.schema.json` và không làm phình kích thước của artifact `analysis.jsonl` (vốn chỉ cần chứa `path` và `score` của `knowledge_refs`).
- Dữ liệu tri thức luôn được cập nhật mới nhất từ thư mục `data/knowledge-base/` mà không cần chạy lại pipeline phân tích LLM.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Lưu toàn bộ nội dung KB vào `analysis.jsonl` ngay lúc pipeline chạy | Giao diện web không cần đọc file KB | Vi phạm schema JSON của SecurityAnalysisRecord, làm phình to log/artifact và tốn token ngữ cảnh lưu trữ không cần thiết. |
| Dùng iframe hoặc nạp markdown client-side bằng JS | Trực tiếp hiển thị nguyên file markdown | Trộn lẫn nhiều thông tin thừa không liên quan tới finding cụ thể, phụ thuộc JS ngoài và khó kiểm soát bảo mật/giao diện đồng nhất. |

**Đánh đổi đã chấp nhận:**
Web view tốn thêm một vài mili-giây để đọc các file Markdown cục bộ khi nạp trang Analysis, tuy nhiên vì số lượng finding trong mỗi run thường từ vài finding đến vài chục finding và file nằm trên ổ đĩa cục bộ (SSD), độ trễ là không đáng kể (< 2ms).

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/web/ -v` | 0 | 73 passed |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1017 passed, 41 deselected |
| `make quality` | 0 | ruff, mypy (81 source files clean), coverage 83.84% ≥ 78.0%, pip-audit clean |

**Test mới thêm:**

- `tests/unit/web/test_findings_analysis.py::test_analysis_screen_shows_knowledge_references_and_safe_boundaries` — Khẳng định màn hình Analysis hiển thị đúng URL tham chiếu OWASP, giải pháp an toàn `PreparedStatement` và điều kiện biên `not_exploitable_when`.

**Bất biến đã giữ:**
- Không sử dụng mock/stub trong test.
- Không thay đổi schema `security-analysis-record.schema.json`.
- Không gọi network trong runtime render web.
- `make quality` đạt 100% xanh.

**Còn fail / chưa chạy được:** Không có

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/web/views.py`: xử lý đường dẫn tương đối giữa `ctx.repo_root` và `path_str` khi chạy trong các môi trường working directory khác nhau. Đã giải quyết bằng fallback đa tầng.
- **Giả định đã đặt:** Giả định các file tài liệu trong `data/knowledge-base/tier2/` tuân thủ đúng định dạng YAML frontmatter (đã được bảo đảm bởi bộ test toàn vẹn ở Task 6).
- **Việc còn nợ:** Không có
- **Câu hỏi cho người dùng:** Không có
