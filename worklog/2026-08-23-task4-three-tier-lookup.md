# Worklog — Task 4: Thác nước ba mức (Deterministic Tier 2 Lookup & Parent Pulling)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Subagent Task 4 ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 4`

---

## 1. Tóm tắt

Đã cài đặt cơ chế tra cứu tri thức bảo mật theo thác nước ba mức tất định (`rule_id` → `cwe` → `keyword`) và tự động kéo theo tài liệu ngữ cảnh lớp cha Tier 1. Module này phục vụ Security Analysis Agent trong việc lấy chính xác tài liệu sink cụ thể (Tier 2) và tài liệu tổng quan (Tier 1) gắn với điểm số tất định (`100.0` và `50.0`). Kết quả toàn bộ 9/9 test mới của Task 4 và 994 test trong test suite đều vượt qua với độ phủ kiểm thử đạt 84.43%, `make quality` xanh 100%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Định tuyến các finding từ SAST scanner tới đúng tài liệu phân tích chuyên sâu Tier 2 theo `rule_id` hoặc `cwe` một cách tất định, bổ sung tài liệu cha Tier 1 vào ngữ cảnh, và chỉ dùng keyword search làm giải pháp bổ trợ trên `tier1/`.
- **Nằm ở đâu trong luồng:** Nằm tại `retrieval/knowledge_retriever.py`, được gọi bởi `analysis/packet_builder.py` trước khi gói `AnalysisPacket` được chuyển sang cho LLM Analyzer.
- **Không có nó thì hỏng gì:** Nếu không có tra cứu tất định, hệ thống phải dựa hoàn toàn vào keyword search (dễ bị nhiễu do trùng từ khoá, không phân biệt được sink cụ thể với danh mục chung), khiến LLM không nhận được các điều kiện khai thác / không khai thác được (`exploitable_when` / `not_exploitable_when`), dẫn tới tỷ lệ over-claim cao và vi phạm luật provenance.
- **Ngoài phạm vi (cố ý không làm):**
  - Không triển khai luật kiểm tra provenance 10 & 11 (thuộc Task 5).
  - Không sửa đổi schema output `schemas/security-analysis-record.schema.json`.
  - Không can thiệp vào calibration hay logic Gateway/DAST.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `src/project_sentinel/retrieval/tier_lookup.py` | Tạo | Cài đặt hàm `lookup_tier2(rule_id, cwe, tier2_dir)` tra cứu theo thứ tự ưu tiên `rule_id` rồi mới đến `cwe`. | Đây là lõi xử lý tra cứu tất định Tier 2 độc lập theo hợp đồng Task 4. |
| `src/project_sentinel/retrieval/knowledge_retriever.py` | Sửa | Thêm `tier`, `match_kind`, `canonical_category` vào `RetrievalHit` và `to_dict()`; định nghĩa hằng số `TIER2_SCORE = 100.0`, `PARENT_SCORE = 50.0`; tích hợp `lookup_tier2` và kéo doc cha Tier 1 trước khi chạy keyword search trên `tier1/`. | Để `retrieve_knowledge` trả về hit cấu trúc đa tầng phục vụ luật provenance và LLM prompt. |
| `tests/unit/retrieval/test_tier_lookup.py` | Tạo | Thêm 9 test unit kiểm tra ưu tiên rule_id, fallback cwe, không khớp, thư mục không tồn tại, kéo doc cha, to_dict, keyword fallback và cách ly Tier 2 khỏi keyword search. | Đảm bảo tính đúng đắn và bất biến của cơ chế tra cứu theo TDD. |
| `tests/unit/retrieval/test_search_acceptance.py` | Sửa | Tách kiểm thử tìm kiếm `OWASP Top 10` và `OpenGrep SAST` sang dùng `search()` trực tiếp do `retrieve_knowledge` chuyên biệt cho `tier1/`. | Giữ vững ranh giới giữa tìm kiếm CLI toàn diện và tra cứu tri thức finding. |

**`git diff --stat`:**

```text
 src/project_sentinel/retrieval/knowledge_retriever.py | 70 +++++++++++++++++++++++++++++++++++++++++++---------------------------
 src/project_sentinel/retrieval/tier_lookup.py         | 34 ++++++++++++++++++++++++++++++++++
 tests/unit/retrieval/test_search_acceptance.py        | 12 +++++++++---
 tests/unit/retrieval/test_tier_lookup.py             | 96 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 4 files changed, 182 insertions(+), 30 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Tiếp cận theo mô hình thác nước tầng bậc có thứ tự ưu tiên rõ ràng:
1. `rule_id` có độ đặc hiệu cao nhất: nếu `rule_id` khớp với `matches_rule_ids` của entry Tier 2 nào, trả về ngay entry đó cùng `match_kind="rule_id"`.
2. Nếu `rule_id` không khớp, thử so khớp `cwe` (chuyển về dạng uppercase không dấu) với danh sách `cwe` của các entry; nếu khớp, trả về entry cùng `match_kind="cwe"`.
3. Khi tìm thấy entry Tier 2, gán điểm cố định `TIER2_SCORE = 100.0` và tự động tìm doc cha `tier1_parent.md` trong `tier1/`, gán điểm `PARENT_SCORE = 50.0` với `match_kind="parent"`.
4. Sau đó, thực hiện keyword search trên `tier1/` để bổ sung các tài liệu liên quan khác, loại bỏ các đường dẫn đã xuất hiện trong `hits` và gắn nhãn `tier=1, match_kind="keyword"`.

**Luồng dữ liệu:**
`Finding (rule_id, cwe, title)` → `lookup_tier2()` → `[Tier 2 Hit (score=100.0)]` + `[Tier 1 Parent Hit (score=50.0)]` → `keyword_search(tier1/)` → `[Keyword Hits (score=BM25)]` → `List[RetrievalHit]`.

**Các quyết định kỹ thuật:**
- Hằng số điểm tất định (`TIER2_SCORE = 100.0`, `PARENT_SCORE = 50.0`): Giúp luật provenance kiểm tra chéo chính xác mà không bị ảnh hưởng bởi biến động điểm số tần suất từ khoá BM25.
- Cách ly hoàn toàn `tier2/` khỏi `keyword_search`: Tránh việc so khớp chuỗi ngẫu nhiên cạnh tranh và ghi đè lên kết quả định tuyến tất định của `lookup_tier2`.
- Xử lý đường dẫn linh hoạt: `retrieve_knowledge` nhận biết được cả khi `knowledge_dir` trỏ trực tiếp vào `tier1/` hoặc trỏ vào thư mục gốc `data/knowledge-base`.

**Xử lý lỗi / trường hợp biên:**
- `knowledge_dir` không tồn tại: trả về danh sách rỗng `[]`.
- `rule_id` và `cwe` đều rỗng: `lookup_tier2` trả về `(None, None)` an toàn, không ném exception.
- Không tìm thấy file cha `tier1_parent.md`: bỏ qua bước chèn doc cha, không gây lỗi hệ thống.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Module | `tier_lookup.py` | `src/project_sentinel/retrieval/tier_lookup.py` | Module tra cứu Tier 2 tất định |
| Hàm | `lookup_tier2` | `def lookup_tier2(rule_id: str, cwe: list[str] \| None, tier2_dir: Path) -> tuple[Tier2Entry \| None, str \| None]` | Hàm tra cứu thác nước `rule_id` → `cwe` |
| Dataclass | `RetrievalHit` | `src/project_sentinel/retrieval/knowledge_retriever.py` | Bổ sung các trường `tier: int`, `match_kind: str`, `canonical_category: str` |
| Hàm | `retrieve_knowledge` | `src/project_sentinel/retrieval/knowledge_retriever.py` | Tích hợp tra cứu đa tầng và phân phối điểm số |
| Test | `test_tier_lookup.py` | `tests/unit/retrieval/test_tier_lookup.py` | Suite 9 unit test cho thác nước tra cứu |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/test_tier_lookup.py -v
.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests
make quality
```

**Output thật (đã che secret):**

```text
tests/unit/retrieval/test_tier_lookup.py::test_rule_id_tra_dung_entry_va_ghi_dung_match_kind PASSED [ 11%]
tests/unit/retrieval/test_tier_lookup.py::test_cwe_chi_chay_khi_rule_id_truot PASSED [ 22%]
tests/unit/retrieval/test_tier_lookup.py::test_rule_id_thang_cwe_khi_ca_hai_deu_khop PASSED [ 33%]
tests/unit/retrieval/test_tier_lookup.py::test_khong_khop_gi_thi_tra_ve_rong_chu_khong_nem_loi PASSED [ 44%]
tests/unit/retrieval/test_tier_lookup.py::test_thu_muc_khong_ton_tai_thi_tra_ve_rong PASSED [ 55%]
tests/unit/retrieval/test_tier_lookup.py::test_hit_tier2_luon_keo_theo_doc_cha PASSED [ 66%]
tests/unit/retrieval/test_moi_hit_deu_mang_tier_va_match_kind_trong_to_dict PASSED [ 77%]
tests/unit/retrieval/test_tier_lookup.py::test_finding_khong_khop_tier2_van_co_hit_keyword PASSED [ 88%]
tests/unit/retrieval/test_tier_lookup.py::test_keyword_search_khong_bao_gio_tra_ve_doc_tier2 PASSED [100%]
============================== 9 passed in 0.14s ===============================
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Tách riêng module `tier_lookup.py` thuần túy làm nhiệm vụ ánh xạ từ thuộc tính finding (`rule_id`, `cwe`) sang `Tier2Entry`, và để `knowledge_retriever.py` làm adapter kết hợp giữa tra cứu tất định và keyword search.

**Lý do:**
- Theo đúng thiết kế tại spec §5.2 và plan Task 4: *"Thứ tự có ý: rule_id trước vì nó chính xác (một rule ứng một họ sink), cwe sau vì nó gần đúng (một CWE bao nhiều sink khác nhau)"*.
- Tách biệt trách nhiệm (Separation of Concerns): `tier_lookup` không phụ thuộc vào BM25 hay tokenization, có thể unit test độc lập với tốc độ cao và không có tác dụng phụ.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Cho keyword search quét cả Tier 2 và cộng thêm điểm boost | Đơn giản, dùng chung một hàm tìm kiếm | Bị loại vì khớp chữ có tính bất định, từ khóa trong body của Tier 2 này có thể khớp với finding của Tier 2 khác, phá vỡ tính tất định mà luật provenance 10 & 11 yêu cầu. |
| Gom chung `lookup_tier2` vào `kb_schema.py` | Giảm bớt 1 file mới | Bị loại vì `kb_schema.py` chỉ có trách nhiệm đọc/validate schema tài liệu tĩnh, còn `tier_lookup.py` chứa nghiệp vụ tìm kiếm/định tuyến. |

**Đánh đổi đã chấp nhận:**
- Thêm một bước kiểm tra file hệ thống cho doc cha `tier1_parent.md` khi có Tier 2 hit, nhưng chi phí I/O là không đáng kể so với lợi ích cung cấp đủ ngữ cảnh lớp cho LLM.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_tier_lookup.py -v` | 0 | 9 passed |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 994 passed, 41 deselected |
| `make quality` | 0 | Ruff check passed, Mypy passed (80 files), Coverage 84.43%, Pip-audit passed |

**Test mới thêm:**
- `tests/unit/retrieval/test_tier_lookup.py::test_rule_id_tra_dung_entry_va_ghi_dung_match_kind` — Khẳng định `rule_id` khớp chính xác entry Tier 2 và trả `match_kind="rule_id"`.
- `tests/unit/retrieval/test_tier_lookup.py::test_cwe_chi_chay_khi_rule_id_truot` — Khẳng định `cwe` chỉ được dùng khi `rule_id` không khớp.
- `tests/unit/retrieval/test_tier_lookup.py::test_rule_id_thang_cwe_khi_ca_hai_deu_khop` — Khẳng định `rule_id` được ưu tiên hơn `cwe`.
- `tests/unit/retrieval/test_tier_lookup.py::test_khong_khop_gi_thi_tra_ve_rong_chu_khong_nem_loi` — Khẳng định trả về `(None, None)` an toàn khi không khớp.
- `tests/unit/retrieval/test_tier_lookup.py::test_thu_muc_khong_ton_tai_thi_tra_ve_rong` — Khẳng định xử lý an toàn khi thư mục không tồn tại.
- `tests/unit/retrieval/test_tier_lookup.py::test_hit_tier2_luon_keo_theo_doc_cha` — Khẳng định hit Tier 2 luôn kéo theo tài liệu cha Tier 1 tương ứng.
- `tests/unit/retrieval/test_tier_lookup.py::test_moi_hit_deu_mang_tier_va_match_kind_trong_to_dict` — Khẳng định `to_dict()` xuất đầy đủ `tier` và `match_kind`.
- `tests/unit/retrieval/test_tier_lookup.py::test_finding_khong_khop_tier2_van_co_hit_keyword` — Khẳng định fallback keyword hoạt động khi không khớp Tier 2.
- `tests/unit/retrieval/test_tier_lookup.py::test_keyword_search_khong_bao_gio_tra_ve_doc_tier2` — Khẳng định keyword search không bao giờ quét vào `tier2/`.

**Bất biến đã giữ:**
- Không sử dụng bất kỳ test double / mock / stub / fake nào.
- Test không bị skip.
- Không in/lộ secret hay API key.
- Schema output JSON không bị sửa đổi.
- Báo cáo lịch sử `reports/week-XX/` không bị đụng tới.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/retrieval/knowledge_retriever.py:59-67` — logic tự động phát hiện `tier2_dir` và `tier1_dir` dựa trên việc `knowledge_dir` được truyền vào là thư mục gốc hay thư mục con. Cần kiểm tra xem có trường hợp cấu hình đặc biệt nào truyền đường dẫn ngoài quy ước hay không.
- **Giả định đã đặt:** Giả định các file Tier 2 luôn có trường `tier1_parent` trỏ tới file `.md` hợp lệ trong `tier1/` (điều này đã được bảo đảm bởi `test_kb_integrity.py`).
- **Việc còn nợ:** Task 5 tiếp theo sẽ sử dụng các trường `tier`, `match_kind`, `canonical_category` trong các hit để cài đặt 2 luật provenance (luật 10 & 11).
- **Câu hỏi cho người dùng:** Không có.
