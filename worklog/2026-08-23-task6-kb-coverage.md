# Worklog — Báo cáo độ phủ Knowledge Base Tier 2 (Task 6)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Subagent ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 6`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Cài đặt module `src/project_sentinel/retrieval/kb_coverage.py` và target `make kb-coverage` để đo lường độ phủ của kho tri thức Tier 2 đối chiếu với các rule OpenGrep thực tế và bộ ground truth recall (75 lỗ hổng WebGoat). Module cung cấp khả năng tự động phân tích khoảng trống (gaps) theo từng CWE, xếp thứ tự ưu tiên theo số lỗ hổng thực tế có trong target để định hướng viết rule tiếp theo. Toàn bộ logic chạy hoàn toàn offline không cần LLM hay Docker, tích hợp kiểm thử tự động và pass 100% `make quality`.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Báo cáo độ phủ của kho tri thức bảo mật Tier 2 đối chiếu với tập rule SAST (OpenGrep) hiện hữu và bộ dữ liệu đánh giá recall thật (`webgoat-vulnerabilities.applicable.json`).
- **Nằm ở đâu trong luồng:** Nằm ở package `retrieval`, phục vụ công tác đo lường / audit và vận hành CLI/Makefile (`make kb-coverage`), chạy độc lập không phụ thuộc vào pipeline runtime.
- **Không có nó thì hỏng gì:** Không thấy được bức tranh tổng thể về khoảng trống tri thức: entry nào đã có rule SAST, entry nào chưa có, và trần trên (upper bound) của độ phủ CWE so với tập lỗ hổng thực tế trong target là bao nhiêu.
- **Ngoài phạm vi (cố ý không làm):** Không tự động sinh rule OpenGrep từ KB; không gọi LLM hoặc đo precision/recall runtime (đo recall runtime thuộc suite eval).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/retrieval/test_kb_coverage.py` | Tạo | Viết 4 unit test kiểm tra đếm entry, đếm rule, trích xuất gap theo CWE kèm số count thật, sắp xếp giảm dần, và tính cwe_reach / truth_total | Kiểm thử TDD theo yêu cầu Task 6 Step 1 |
| `src/project_sentinel/retrieval/kb_coverage.py` | Tạo | Cài đặt `build_report`, `render`, `main` cùng các helper `_known_rule_ids`, `_truth_counts` | Thực thi logic báo cáo độ phủ KB Tier 2 |
| `Makefile` | Sửa | Thêm `kb-coverage` vào `.PHONY` và khai báo target `kb-coverage` | Cung cấp lệnh CLI tiêu chuẩn chạy báo cáo nhanh |
| `worklog/2026-08-23-task6-kb-coverage.md` | Tạo | Ghi nhận chi tiết worklog thực thi Task 6 | Tuân thủ quy định bắt buộc của repository |

**`git diff --stat`:**

```text
 Makefile                                         |   6 +-
 src/project_sentinel/retrieval/kb_coverage.py    | 150 +++++++++++++++++++++++++
 tests/unit/retrieval/test_kb_coverage.py         |  43 +++++++
 3 files changed, 198 insertions(+), 1 deletion(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Module đọc toàn bộ entry Tier 2 thông qua `load_tier2(tier2_dir)`, trích xuất các `rule_id` đang có trong cấu hình OpenGrep (`java-security.yml`), và đọc phân phối CWE từ ground truth recall mặt đất. Từ đó, phân loại các entry thành nhóm "Có rule" và "Chưa có rule", gom nhóm các entry thiếu rule theo CWE, tính số lỗ hổng tương ứng trong ground truth và sắp xếp giảm dần. Cuối cùng, tính tổng số lỗ hổng mà các CWE trong KB có thể chạm tới (`cwe_reach`) để in ra tỷ lệ trần trên (upper bound).

**Luồng dữ liệu:**
`data/knowledge-base/tier2/` + `configs/opengrep/java-security.yml` + `eval/ground-truth/recall/webgoat-vulnerabilities.applicable.json`
→ `load_tier2()` / `_known_rule_ids()` / `_truth_counts()`
→ `build_report()`: phân loại `with_rule` vs `without_rule`, tính `gaps`, tính `cwe_reach`
→ `render()`: format text table
→ CLI / stdout

**Các quyết định kỹ thuật:**
- Không gọi LLM và không cần Docker container để lệnh chạy nhanh, tất định, và chạy an toàn trong CI.
- Sắp xếp gaps theo `(-truth_count, cwe)` để lập tức hiển thị những CWE có nhiều lỗ hổng thực tế nhất chưa có rule SAST lên đầu.
- Rõ ràng trong thông điệp báo cáo: `cwe_reach` là trần trên lý thuyết (upper bound assuming 100% rule recall per CWE), nhắc nhở người đọc xem recall đo thật trong báo cáo sprint.

**Xử lý lỗi / trường hợp biên:**
- File rules hoặc ground truth không tồn tại: trả về tập rỗng / Counter rỗng, không crash.
- Ground truth file hỗ trợ cả dạng top-level JSON list hoặc dict chứa list.
- Trường `truth_total == 0`: fallback chia an toàn tránh `ZeroDivisionError`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Module | `kb_coverage` | `src/project_sentinel/retrieval/kb_coverage.py` | Module đo độ phủ Tier 2 đối chiếu ground truth |
| Hàm | `build_report` | `(tier2_dir: Path, rules_file: Path, truth_file: Path) -> dict[str, Any]` | Xây dựng cấu trúc dữ liệu báo cáo độ phủ |
| Hàm | `render` | `(report: dict[str, Any]) -> str` | Chuyển đổi báo cáo thành chuỗi hiển thị CLI |
| Hàm | `main` | `(argv: list[str] \| None = None) -> int` | CLI entrypoint hỗ trợ truyền tham số đường dẫn |
| Makefile Target | `kb-coverage` | `make kb-coverage` | Lệnh Makefile chạy báo cáo độ phủ |
| Test | `test_kb_coverage` | `tests/unit/retrieval/test_kb_coverage.py` | 4 unit test kiểm tra tính đúng đắn |

**Cách chạy:**

```bash
make kb-coverage
```

**Output thật (đã che secret):**

```text
=== KB Tier 2 ===
  Entry              : 11
  Có rule            : 3
  Chưa có rule       : 8

=== Thiếu rule, xếp theo số lỗ hổng thật trong WebGoat ===
   6x  CWE-79   java-servlet-response-writer, java-thymeleaf-unescaped-output
   5x  CWE-22   java-file-path-concat
   5x  CWE-352  java-spring-csrf-disabled
   3x  CWE-347  java-jwt-parse-unverified
   3x  CWE-798  java-hardcoded-credential
   2x  CWE-338  java-insecure-random
   1x  CWE-611  java-documentbuilder-xxe

  CWE mà KB chạm tới : 42/75 lỗ hổng (56.0%) — đây là TRẦN TRÊN
  Trần này giả định mỗi rule bắt được mọi thực thể của CWE mình phụ trách.
  Recall đo được thật nằm trong reports/week-06/report.md §4.5.
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Xây dựng hàm pure `build_report` nhận các đường dẫn `Path` và trả về `dict` tách biệt với hàm hiển thị `render`.

**Lý do:**
Theo đúng đặc tả của Task 6 trong plan `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`:
*"Lenh nay khong goi LLM va khong can Docker, nen chay duoc trong CI. Dem entry, doi chieu voi rule co that va voi bo nhan recall."*
Việc tách biệt `build_report` và `render` giúp unit test kiểm tra trực tiếp các giá trị số mà không cần parse chuỗi giao diện, đồng thời cho phép tích hợp linh hoạt vào các công cụ CI hoặc báo cáo khác.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Gộp luôn vào `knowledge_retriever.py` | Giảm số file module | Vi phạm nguyên tắc đơn trách nhiệm (Single Responsibility); `knowledge_retriever` phục vụ tìm kiếm runtime, trong khi `kb_coverage` là công cụ phân tích tĩnh / offline metrics. |
| In trực tiếp trong `build_report` mà không qua `render` | Tiết kiệm vài dòng code | Khiến unit test phụ thuộc vào stdout và format chuỗi, khó kiểm thử chính xác các thuộc tính dữ liệu. |

**Đánh đổi đã chấp nhận:**
Tính toán `cwe_reach` dựa trên phép hợp (union) các CWE của Tier 2 entries thay vì kiểm tra từng sink cụ thể, vì đây là con số cận trên (upper bound) danh mục để định lượng tiềm năng bao phủ trước khi có rule chi tiết.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/test_kb_coverage.py -v` | 0 | 4 passed |
| `make kb-coverage` | 0 | In chính xác: Entry: 11, Có rule: 3, Chưa có rule: 8, 42/75 (56.0%) |
| `make quality` | 0 | ruff check OK, mypy 81 files OK, 1006 tests passed (coverage 84.34% >= 78.0%), pip-audit OK |

**Test mới thêm:**

- `tests/unit/retrieval/test_kb_coverage.py::test_dem_dung_so_entry_va_so_entry_co_rule` — Khẳng định đếm đúng 11 entry, 3 có rule, 8 chưa có rule.
- `tests/unit/retrieval/test_kb_coverage.py::test_moi_khoang_trong_kem_so_lo_hong_that_cua_cwe_do` — Khẳng định mỗi khoảng trống chứa đúng số lượng lỗ hổng ground truth cho CWE tương ứng (CWE-79: 6, CWE-22: 5, CWE-352: 5).
- `tests/unit/retrieval/test_kb_coverage.py::test_khoang_trong_xep_giam_dan_theo_so_lo_hong_that` — Khẳng định các khoảng trống được xếp giảm dần theo số lượng lỗ hổng thật.
- `tests/unit/retrieval/test_kb_coverage.py::test_bao_cao_neu_ca_tran_lan_so_do_duoc` — Khẳng định tính đúng tổng ground truth (75) và số lượng CWE reach (42).

**Bất biến đã giữ:**
- Không sử dụng bất kỳ mock / stub / fake class hay provider="fake".
- Không có test nào `skip`.
- Không in secret / API key.
- Không sửa đổi các báo cáo tuần cũ `reports/week-XX/`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/retrieval/kb_coverage.py:85-93` — logic sắp xếp `raw_gaps` với tuple `(-count, cwe)` để đảm bảo thứ tự giảm dần theo count rồi tăng dần theo tên CWE, đã được kiểm chứng bằng test.
- **Giả định đã đặt:** Giả định cấu trúc ground truth recall là JSON array chứa các object có trường `cwe`.
- **Việc còn nợ:** Không có.
- **Câu hỏi cho người dùng:** Không có.
