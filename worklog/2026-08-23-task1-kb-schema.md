# Worklog — Task 1: Đọc và kiểm frontmatter Tier 2

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · inherit ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 1`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã xây dựng module parser và validator frontmatter YAML cho tri thức Tier 2 của hệ thống Project Sentinel. Module này phục vụ tầng retrieval tất định nhằm tải các file markdown Tier 2 với schema chặt chẽ (id, canonical_category, sink_signatures, matches_rule_ids, safe_alternative, điều kiện khai thác). Kết quả toàn bộ 8 unit test đạt chuẩn, `make quality` đạt 84.26% coverage và không có lỗi mypy/ruff.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Định nghĩa cấu trúc dữ liệu `Tier2Entry` và bộ đọc/kiểm tra tính hợp lệ của frontmatter YAML trong các tài liệu tri thức Tier 2 (chứa thông tin sink signatures, rule mapping, điều kiện khai thác/không khai thác).
- **Nằm ở đâu trong luồng:** Nằm ở tầng `retrieval` (`src/project_sentinel/retrieval/kb_schema.py`), làm nền tảng cho thác nước tra cứu Tier 2 (`tier_lookup.py`) và kiểm tra toàn vẹn KB (`test_kb_integrity.py`).
- **Không có nó thì hỏng gì:** Hệ thống không thể phân tích cú pháp frontmatter YAML phức tạp (nhiều dòng, danh sách, folded scalar) của tài liệu Tier 2, dẫn tới việc tra cứu sink và rule không có dữ liệu đầu vào có cấu trúc tin cậy.
- **Ngoài phạm vi (cố ý không làm):** Chưa thực hiện di chuyển file Tier 1 (thuộc Task 2), chưa viết 11 file Tier 2 (thuộc Task 3), và chưa cài đặt bộ tra cứu thác nước (thuộc Task 4).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `src/project_sentinel/retrieval/kb_schema.py` | Tạo | Định nghĩa `Tier2Entry`, `KbSchemaError`, `CANONICAL_CATEGORIES`, `parse_tier2`, `load_tier2` | Cung cấp interface đọc và validate schema Tier 2 theo spec |
| `tests/unit/retrieval/test_kb_schema.py` | Tạo | 8 unit tests kiểm tra parser, folded scalar, và các điều kiện từ chối khi sai schema | Kiểm chứng TDD cho module kb_schema |

**`git diff --stat`:**

```text
 src/project_sentinel/retrieval/kb_schema.py | 140 ++++++++++++++++++++++++++++
 tests/unit/retrieval/test_kb_schema.py      |  87 ++++++++++++++++++
 2 files changed, 227 insertions(+)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:** Tách phần frontmatter (nằm giữa cặp delimiter `---`) và phần thân markdown của file. Sử dụng PyYAML (`yaml.safe_load`) để parse mapping YAML, sau đó kiểm tra kiểu dữ liệu và sự hiện diện của các trường bắt buộc, giá trị `tier == 2`, và `canonical_category` thuộc tập đóng 10 danh mục bảo mật cho phép.

**Luồng dữ liệu:** `Path tới file .md` → `_split_frontmatter` (tách YAML string và markdown body) → `yaml.safe_load` → validate các trường bắt buộc & kiểu dữ liệu → khởi tạo đối tượng bất biến `Tier2Entry`.

**Các quyết định kỹ thuật:**

- Sử dụng PyYAML thay vì bộ parse thủ công dòng đơn của Tier 1 để hỗ trợ YAML list và folded scalar (`>`).
- Dùng `frozenset` cho `CANONICAL_CATEGORIES` để đảm bảo tra cứu O(1) và tính bất biến.
- Khai báo dataclass `Tier2Entry(frozen=True)` với các thuộc tính dạng tuple bất biến (`tuple[str, ...]`) thay vì `list[str]` để tránh side-effects.

**Xử lý lỗi / trường hợp biên:**
- Thiếu delimiter `---` hoặc không đóng frontmatter: ném `KbSchemaError`.
- YAML sai cú pháp: bắt `yaml.YAMLError` và bọc lại thành `KbSchemaError`.
- Thiếu trường bắt buộc hoặc giá trị list rỗng: ném `KbSchemaError` kèm tên trường.
- Thư mục không tồn tại trong `load_tier2`: trả về danh sách rỗng `[]` an toàn.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Class | `Tier2Entry` | `dataclass(frozen=True)` tại `src/project_sentinel/retrieval/kb_schema.py` | Model chứa dữ liệu một entry Tier 2 |
| Class | `KbSchemaError` | `class KbSchemaError(ValueError)` | Ngoại lệ khi schema Tier 2 không hợp lệ |
| Hằng số | `CANONICAL_CATEGORIES` | `frozenset[str]` | Tập đóng 10 danh mục bảo mật hợp lệ |
| Hàm | `parse_tier2` | `(path: Path) -> Tier2Entry` | Đọc và kiểm tra một file markdown Tier 2 |
| Hàm | `load_tier2` | `(tier2_dir: Path) -> list[Tier2Entry]` | Tải toàn bộ entry Tier 2 từ thư mục |
| Test | `test_kb_schema.py` | `tests/unit/retrieval/test_kb_schema.py` | Bộ test suite 8 ca kiểm thử |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -v
```

**Output thật (đã che secret):**

```text
tests/unit/retrieval/test_kb_schema.py::test_entry_hop_le_doc_ra_du_moi_truong PASSED [ 12%]
tests/unit/retrieval/test_kb_schema.py::test_scalar_gap_duoc_gop_thanh_mot_dong PASSED [ 25%]
tests/unit/retrieval/test_kb_schema.py::test_thieu_truong_bat_buoc_bi_tu_choi_va_neu_ten_truong PASSED [ 37%]
tests/unit/retrieval/test_kb_schema.py::test_category_ngoai_tap_dong_bi_tu_choi PASSED [ 50%]
tests/unit/retrieval/test_kb_schema.py::test_tier_sai_bi_tu_choi PASSED  [ 62%]
tests/unit/retrieval/test_kb_schema.py::test_sink_signatures_rong_bi_tu_choi PASSED [ 75%]
tests/unit/retrieval/test_kb_schema.py::test_entry_chua_co_rule_khong_can_matches_rule_ids PASSED [ 87%]
tests/unit/retrieval/test_kb_schema.py::test_load_tier2_tra_ve_rong_khi_thu_muc_khong_ton_tai PASSED [100%]

============================== 8 passed in 0.08s ===============================
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Dùng PyYAML để parse frontmatter và trả về `Tier2Entry(frozen=True)` với các trường validate nghiêm ngặt.

**Lý do:** Kế hoạch `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` đã chỉ định rõ:
> `keyword_search.parse_markdown` có bộ đọc frontmatter riêng, nhưng nó viết tay và chỉ hiểu `title:` với `tags:` một dòng. Tier 2 cần list nhiều dòng và folded scalar, nên ở đây dùng PyYAML thật. Hai bộ đọc tồn tại song song là có ý: Tier 1 vẫn đi đường cũ, không bị ảnh hưởng.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Mở rộng parser tự chế trong `keyword_search.py` | Không phụ thuộc thư viện yaml parser | Khó bảo trì, dễ lỗi với cú pháp YAML phức tạp như multiline scalar `>` và list phân cấp |
| Thêm pydantic model | Validate tự động | Vi phạm ràng buộc không thêm dependency mới |

**Đánh đổi đã chấp nhận:** Chấp nhận tồn tại hai parser frontmatter riêng biệt cho Tier 1 (regex đơn giản) và Tier 2 (PyYAML) để không gây hồi quy (regression) cho các test và chức năng hiện tại của Tier 1.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_schema.py -v` | 0 | 8 passed in 0.08s |
| `.venv/bin/python -m ruff check src/project_sentinel/retrieval/kb_schema.py tests/unit/retrieval/test_kb_schema.py` | 0 | All checks passed! |
| `.venv/bin/python -m mypy` | 0 | Success: no issues found in 79 source files |
| `make quality` | 0 | 975 passed, coverage 84.26% (>= 78.0%), 0 vulns in pip-audit |

**Test mới thêm:**

- `tests/unit/retrieval/test_kb_schema.py::test_entry_hop_le_doc_ra_du_moi_truong` — Xác nhận parse đủ các trường metadata và body của entry hợp lệ.
- `tests/unit/retrieval/test_kb_schema.py::test_scalar_gap_duoc_gop_thanh_mot_dong` — Xác nhận xử lý đúng folded scalar YAML (`>`).
- `tests/unit/retrieval/test_kb_schema.py::test_thieu_truong_bat_buoc_bi_tu_choi_va_neu_ten_truong` — Bắt buộc có đủ các trường schema.
- `tests/unit/retrieval/test_kb_schema.py::test_category_ngoai_tap_dong_bi_tu_choi` — Từ chối canonical_category không nằm trong tập đóng 10 danh mục.
- `tests/unit/retrieval/test_kb_schema.py::test_tier_sai_bi_tu_choi` — Từ chối khi tier != 2.
- `tests/unit/retrieval/test_kb_schema.py::test_sink_signatures_rong_bi_tu_choi` — Từ chối khi sink_signatures rỗng.
- `tests/unit/retrieval/test_kb_schema.py::test_entry_chua_co_rule_khong_can_matches_rule_ids` — Hỗ trợ `no_rule_yet: true` khi chưa có rule id.
- `tests/unit/retrieval/test_kb_schema.py::test_load_tier2_tra_ve_rong_khi_thu_muc_khong_ton_tai` — Xử lý an toàn khi thư mục không tồn tại.

**Bất biến đã giữ:** Không có test doubles (mock/fake/stub), không có test skip, không thêm dependency mới, không phá vỡ schema hay API hiện tại.

**Còn fail / chưa chạy được:** Không có

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có, schema implementation trực quan và bám sát spec.
- **Giả định đã đặt:** Giả định các file Tier 2 luôn bắt đầu bằng `---` ở dòng đầu tiên.
- **Việc còn nợ:** Task 2 (chuyển Tier 1), Task 3 (viết 11 entry Tier 2), Task 4 (bộ tra cứu thác nước).
- **Câu hỏi cho người dùng:** Không có
