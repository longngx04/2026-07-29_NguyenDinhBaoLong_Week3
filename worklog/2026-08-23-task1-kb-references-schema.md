# Worklog — Task 1: Nâng cấp `kb_schema.py` hỗ trợ `references` & URL validation

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · inherit ·
**Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](file:///home/longngx04/VinSOC/project_sentinel_main/docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 1`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã mở rộng dataclass `Tier2Entry` trong `kb_schema.py` để bổ sung trường `references: tuple[str, ...] = ()` và kiểm tra tính hợp lệ của mọi URL trong frontmatter YAML. Thay đổi này phục vụ cơ chế chuẩn hóa và giàu hóa kho tri thức bảo mật (Tier 2 entries), bảo đảm các liên kết dẫn chứng (OWASP, CWE, tài liệu kỹ thuật) luôn có cấu trúc hợp lệ và an toàn trước khi nạp vào hệ thống. Kết quả toàn bộ 10 unit test của module `test_kb_schema.py` và 1011 test toàn hệ thống đều PASS 100%, `make quality` đạt 84.37% coverage.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp định nghĩa kiểu dữ liệu và bộ xác thực cú pháp (schema parser & validator) cho các siêu dữ liệu `references` (danh sách URL tham chiếu thẩm quyền) của tài liệu Tier 2 trong Kho tri thức bảo mật (`data/knowledge-base/tier2/*.md`).
- **Nằm ở đâu trong luồng:** Nằm tại tầng `retrieval/kb_schema.py`, chạy khi nạp hoặc truy vấn kho tri thức Tier 2 để phục vụ LLM prompt packet builder (`analysis/packet_builder.py`) và giao diện Web UI (`web/views.py`).
- **Không có nó thì hỏng gì:** Nếu không có trường này, các tài liệu Tier 2 khi thêm danh sách link tài liệu tham khảo sẽ không thể đọc được hoặc bị bỏ qua; nếu không có URL validation, dữ liệu rác hoặc chuỗi không hợp lệ có thể lọt vào prompt của LLM hoặc tạo ra link hỏng / lỗ hổng trên Web UI.
- **Ngoài phạm vi (cố ý không làm):** Chưa cập nhật nội dung của 11 file Tier 2 Markdown (sẽ thực hiện ở Task 2, 3, 4) và chưa cập nhật giao diện hiển thị web (Task 7).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `src/project_sentinel/retrieval/kb_schema.py` | Sửa | Thêm `references: tuple[str, ...] = ()` vào `Tier2Entry`; trong hàm `parse_tier2`, nạp `references` từ frontmatter meta, dùng `_as_str_tuple` và kiểm tra từng URL phải bắt đầu bằng `http://` hoặc `https://`, nếu sai ném `KbSchemaError`. | Là nơi định nghĩa hợp đồng schema và logic phân tích cú pháp frontmatter YAML của tài liệu Tier 2. |
| `tests/unit/retrieval/test_kb_schema.py` | Sửa | Bổ sung 2 unit test: `test_entry_co_references_doc_ra_danh_sach_url` và `test_references_chua_url_khong_hop_le_bi_tu_choi`. | Kiểm thử TDD đảm bảo trường `references` được đọc đúng và từ chối các chuỗi không phải URL hợp lệ. |

**`git diff --stat`:**

```text
 src/project_sentinel/retrieval/kb_schema.py | 16 ++++++++++++++++
 tests/unit/retrieval/test_kb_schema.py      | 26 ++++++++++++++++++++++++++
 2 files changed, 42 insertions(+)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:** Tiếp cận theo quy trình TDD (Test-Driven Development). Đầu tiên bổ sung 2 unit test kiểm tra việc đọc `references` hợp lệ và từ chối URL không hợp lệ vào `test_kb_schema.py`, chạy test và xác nhận trạng thái RED (fail với `AttributeError` và `DID NOT RAISE KbSchemaError`). Sau đó cập nhật `Tier2Entry` và `parse_tier2` trong `kb_schema.py` với kiểm tra tiền tố `http://` / `https://`, chạy lại test xác nhận trạng thái GREEN.

**Luồng dữ liệu:** `File .md` → `_split_frontmatter` → `yaml.safe_load` → `meta.get("references")` → `_as_str_tuple` → `URL prefix validation (http:// / https://)` → `Tier2Entry(..., references=references)`.

**Các quyết định kỹ thuật:**

- Đặt giá trị mặc định cho `references: tuple[str, ...] = ()` ở cuối dataclass `Tier2Entry` để đảm bảo tính tương thích ngược hoàn toàn với các entry chưa có trường này.
- Kiểm tra tính hợp lệ của URL bằng phương thức `ref.startswith("http://") or ref.startswith("https://")` nhanh, chuẩn xác, không phụ thuộc thư viện phân tích URL phức tạp, từ chối mọi chuỗi rác hoặc relative URI không an toàn.
- Bổ sung chú thích tiếng Việt giải thích rõ ràng lý do kiểm tra URL theo phong cách của codebase.

**Xử lý lỗi / trường hợp biên:**

- Trường hợp không có `references` trong meta (`None`): gán tuple rỗng `()`.
- Trường hợp `references` là string đơn lẻ hoặc list: `_as_str_tuple` chuẩn hóa thành tuple chuỗi đã loại bỏ khoảng trắng.
- Trường hợp `references` rỗng (`[]`): `_as_str_tuple` ném `KbSchemaError`.
- Trường hợp có phần tử không bắt đầu bằng `http://` hoặc `https://`: ném `KbSchemaError` kèm đường dẫn file và nội dung sai phạm.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Dataclass Field | `Tier2Entry.references` | `references: tuple[str, ...] = ()` trong [`kb_schema.py`](file:///home/longngx04/VinSOC/project_sentinel_main/src/project_sentinel/retrieval/kb_schema.py) | Lưu trữ danh sách URL tham chiếu thẩm quyền của entry Tier 2. |
| Test | `test_entry_co_references_doc_ra_danh_sach_url` | [`tests/unit/retrieval/test_kb_schema.py`](file:///home/longngx04/VinSOC/project_sentinel_main/tests/unit/retrieval/test_kb_schema.py) | Kiểm tra đọc danh sách URL hợp lệ từ frontmatter. |
| Test | `test_references_chua_url_khong_hop_le_bi_tu_choi` | [`tests/unit/retrieval/test_kb_schema.py`](file:///home/longngx04/VinSOC/project_sentinel_main/tests/unit/retrieval/test_kb_schema.py) | Kiểm tra từ chối chuỗi không phải URL (bắt đầu bằng http/https). |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -v
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
collecting ... collected 10 items

tests/unit/retrieval/test_kb_schema.py::test_entry_hop_le_doc_ra_du_moi_truong PASSED [ 10%]
tests/unit/retrieval/test_kb_schema.py::test_scalar_gap_duoc_gop_thanh_mot_dong PASSED [ 20%]
tests/unit/retrieval/test_kb_schema.py::test_thieu_truong_bat_buoc_bi_tu_choi_va_neu_ten_truong PASSED [ 30%]
tests/unit/retrieval/test_kb_schema.py::test_category_ngoai_tap_dong_bi_tu_choi PASSED [ 40%]
tests/unit/retrieval/test_kb_schema.py::test_tier_sai_bi_tu_choi PASSED  [ 50%]
tests/unit/retrieval/test_kb_schema.py::test_sink_signatures_rong_bi_tu_choi PASSED [ 60%]
tests/unit/retrieval/test_kb_schema.py::test_entry_chua_co_rule_khong_can_matches_rule_ids PASSED [ 70%]
tests/unit/retrieval/test_kb_schema.py::test_load_tier2_tra_ve_rong_khi_thu_muc_khong_ton_tai PASSED [ 80%]
tests/unit/retrieval/test_kb_schema.py::test_entry_co_references_doc_ra_danh_sach_url PASSED [ 90%]
tests/unit/retrieval/test_kb_schema.py::test_references_chua_url_khong_hop_le_bi_tu_choi PASSED [100%]

============================== 10 passed in 0.10s ==============================
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Mở rộng `Tier2Entry` với `references: tuple[str, ...] = ()` và kiểm tra cú pháp URL trực tiếp trong `parse_tier2` bằng `startswith(("http://", "https://"))`.

**Lý do:** Kế hoạch `docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md` tại Task 1 Step 3 đã chỉ định rõ:
> *"Trong `parse_tier2`: Đọc `meta.get("references")`. Nếu có, dùng `_as_str_tuple` và kiểm tra mỗi phần tử phải bắt đầu bằng `"http://"` hoặc `"https://"`. Nếu không, ném `KbSchemaError`. Gán `references` vào `Tier2Entry`."*
Lựa chọn này giữ nguyên cấu trúc immutable dataclass của hệ thống, tái sử dụng hàm helper `_as_str_tuple` sẵn có, đồng thời kiểm tra chặt chẽ định dạng URL mà không cần phụ thuộc bên ngoài.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Dùng regex phức tạp hoặc thư viện `urllib.parse` để parse toàn bộ RFC URL | Bắt được nhiều thành phần như port/query param | Phức tạp không cần thiết, làm chậm quá trình nạp KB hàng loạt và có nguy cơ chấp nhận các URL scheme không mong muốn (file://, javascript://, data://) nếu không cấu hình chặt. |
| Cho phép chuỗi đường dẫn tương đối (relative path) | Linh hoạt nếu dẫn link nội bộ | Bị loại vì `references` trong yêu cầu được thiết kế cho các liên kết thẩm quyền bên ngoài (OWASP, CWE, Spring docs, Oracle). |

**Đánh đổi đã chấp nhận:** Chỉ chấp nhận URL tuyệt đối có scheme HTTP/HTTPS rõ ràng.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -k references -v` | 1 | FAIL (RED state ban đầu trước khi sửa code) |
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -v` | 0 | 10 passed in 0.10s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1011 passed, 41 deselected, 1 warning in 19.60s |
| `make quality` | 0 | Ruff checks passed, Mypy passed (81 files), 1011 tests passed with 84.37% coverage (>= 78.0%), pip-audit passed |

**Test mới thêm:**

- `tests/unit/retrieval/test_kb_schema.py::test_entry_co_references_doc_ra_danh_sach_url` — Khẳng định parser đọc được danh sách URL khi frontmatter có `references`.
- `tests/unit/retrieval/test_kb_schema.py::test_references_chua_url_khong_hop_le_bi_tu_choi` — Khẳng định ném `KbSchemaError` khi có reference không bắt đầu bằng http:// hoặc https://.

**Bất biến đã giữ:** Không dùng test double/mock; không thay đổi schema analysis; bảo đảm tính bất biến của dataclass `Tier2Entry`; kiểm tra đầy đủ `make quality`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có. Logic validation ngắn gọn, tường minh và đã được bảo vệ bởi unit test.
- **Giả định đã đặt:** Mọi reference trong Tier 2 đều là URL ngoại vi (external HTTP/HTTPS links) dẫn tới tài liệu chuẩn quốc tế (OWASP Cheat Sheets, CWE definitions, Official vendor documentations).
- **Việc còn nợ:** Task 2, 3, 4 sẽ lần lượt bổ sung trường `references` vào từng file `.md` trong `data/knowledge-base/tier2/`.
- **Câu hỏi cho người dùng:** Không có.
