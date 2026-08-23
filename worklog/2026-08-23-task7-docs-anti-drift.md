# Worklog — Đồng bộ tài liệu và chống trôi số lượng tài liệu kho tri thức

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · inherit ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](../docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 7`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã thêm test chống trôi tài liệu về số lượng văn bản kho tri thức và cấu trúc hai tầng vào bộ kiểm thử hạ tầng. Đã cập nhật `docs/product-brief.md`, `README.md`, và `docs/architecture.md` để phản ánh chính xác cấu trúc KB hai tầng (14 doc tier1, 11 doc tier2), lệnh đo độ phủ `make kb-coverage`, và 11 luật kiểm soát provenance (bao gồm luật 10 và 11). Toàn bộ 1008 test và các kiểm tra `make quality` đều xanh 100%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Đảm bảo toàn bộ tài liệu kỹ thuật, kiến trúc và giới thiệu sản phẩm đồng nhất với hiện trạng mã nguồn thực tế của kho tri thức hai tầng (Two-Tier KB: Tier 1 loại lỗ hổng, Tier 2 họ sink) và các luật provenance mới; đồng thời cài đặt bài test tự động chống hiện tượng tài liệu bị trôi lệch thông tin theo thời gian.
- **Nằm ở đâu trong luồng:** Nằm ở tầng tài liệu và kiểm thử hợp đồng hạ tầng (`tests/unit/infra/`), chạy độc lập trong CI để canh gác tính toàn vẹn của tài liệu.
- **Không có nó thì hỏng gì:** Tài liệu hướng dẫn và mô tả kiến trúc sẽ mô tả sai cấu trúc thư mục KB (còn nhắc 20 tài liệu cũ dạng gộp thay vì 14 Tier 1 + 11 Tier 2), thiếu hướng dẫn lệnh `make kb-coverage`, và thiếu tài liệu hoá luật provenance 10 & 11, khiến người vận hành và các agent khác hiểu sai cơ chế hoạt động của hệ thống.
- **Ngoài phạm vi (cố ý không làm):** Không chỉnh sửa các báo cáo tuần lịch sử (`reports/week-01` đến `reports/week-06`), không đổi schema JSON, không thêm dependency.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/infra/test_docs_complete.py` | Sửa | Thêm 2 test chống trôi `test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc` và `test_readme_noi_ve_hai_tang_va_lenh_do_phu` | Khóa cứng số lượng tài liệu KB (14 tier1, 11 tier2) và buộc tài liệu không được nhắc số cũ "20 tài liệu", phải nhắc `make kb-coverage` |
| `docs/product-brief.md` | Sửa | Cập nhật mục "Phạm vi" mô tả kho tri thức chia hai tầng: 14 tài liệu loại lỗ hổng, 11 tài liệu họ sink tra cứu tất định | Xoá câu "20 tài liệu" cũ và giải thích đúng cơ chế tra cứu + bắt buộc trích dẫn |
| `README.md` | Sửa | Cập nhật nhánh `data/knowledge-base/` thành KB hai tầng, thêm lệnh `make kb-coverage` vào mục Đo chất lượng Agent, và thêm mô tả 2 tầng trước bảng Tài liệu | Cung cấp tài liệu tra cứu chính xác cho người dùng và người đánh giá |
| `docs/architecture.md` | Sửa | Thêm danh sách đầy đủ 11 luật provenance (trong đó ghi rõ luật 10 bắt buộc trích dẫn Tier 2 khi `match_kind="rule_id"` và luật 11 đối chiếu `canonical_category`) | Đồng bộ tài liệu kiến trúc với các luật đã triển khai trong `validators.py` |

**`git diff --stat`:**

```text
 README.md                              |  8 +++++++-
 docs/architecture.md                   | 13 +++++++++++++
 docs/product-brief.md                  |  6 ++++--
 tests/unit/infra/test_docs_complete.py | 20 ++++++++++++++++++++
 4 files changed, 44 insertions(+), 3 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:** Tiếp cận theo phương pháp TDD nghiêm ngặt: đầu tiên viết 2 test chống trôi trong `test_docs_complete.py` và chạy xác nhận test FAIL (RED) do tài liệu chưa được cập nhật. Sau đó tiến hành cập nhật từng tài liệu theo quy chuẩn của plan, chạy lại test xác nhận PASS (GREEN), và cuối cùng chạy toàn bộ test suite cùng `make quality` để xác nhận không có bất kỳ hồi quy nào.

**Luồng dữ liệu:** `tests/unit/infra/test_docs_complete.py` đọc trực tiếp filesystem (`data/knowledge-base/tier1`, `tier2`, `README.md`, `docs/product-brief.md`, `docs/architecture.md`) → đối chiếu số lượng file `.md` và các chuỗi bắt buộc/cấm → trả về kết quả kiểm tra.

**Các quyết định kỹ thuật:**
- Kiểm tra số lượng file thực tế trên đĩa (`len(glob("tier1/*.md")) == 14`, `len(glob("tier2/*.md")) == 11`) thay vì hardcode một chiều, đảm bảo nếu có ai thêm/xóa file tài liệu KB mà không cập nhật test thì test sẽ báo ngay.
- Cấm chuỗi "20 tài liệu" trong `README.md` và `docs/product-brief.md` để tránh tài liệu chép lại số liệu cũ từ các tuần trước.
- Nêu rõ trong `docs/architecture.md` rằng luật 10 chỉ áp dụng với `match_kind="rule_id"` nhằm tránh hiểu nhầm sang tra cứu `cwe` (khớp gần đúng).

**Xử lý lỗi / trường hợp biên:** Test kiểm tra trường hợp chuỗi xuất hiện trong cả chữ hoa lẫn chữ thường hoặc trong các câu nối dài, đảm bảo bắt trọn các biến thể trôi lệch.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Test | `test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc` | `tests/unit/infra/test_docs_complete.py` | Khẳng định tier1 có 14 doc, tier2 có 11 doc, không còn chuỗi "20 tài liệu" |
| Test | `test_readme_noi_ve_hai_tang_va_lenh_do_phu` | `tests/unit/infra/test_docs_complete.py` | Khẳng định README có tier1, tier2, make kb-coverage |
| Doc | `docs/product-brief.md` | `docs/product-brief.md` | Mô tả KB hai tầng |
| Doc | `README.md` | `README.md` | Cấu trúc KB hai tầng, lệnh `make kb-coverage`, mô tả tầng KB |
| Doc | `docs/architecture.md` | `docs/architecture.md` | 11 luật provenance trong kiến trúc chống bịa đặt |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/infra/test_docs_complete.py -v
make kb-coverage
make quality
```

**Output thật (đã che secret):**

```text
$ .venv/bin/python -m pytest tests/unit/infra/test_docs_complete.py -v
tests/unit/infra/test_docs_complete.py::test_required_document_exists[README.md] PASSED [  5%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/architecture.md] PASSED [ 10%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/target-webgoat.md] PASSED [ 15%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/product-brief.md] PASSED [ 21%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/limitations.md] PASSED [ 26%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[docs/demo-script.md] PASSED [ 31%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[eval/README.md] PASSED [ 36%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[exercises/week4-gateway/README.md] PASSED [ 42%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[reports/week-05/report.md] PASSED [ 47%]
tests/unit/infra/test_docs_complete.py::test_required_document_exists[reports/week-06/report.md] PASSED [ 52%]
tests/unit/infra/test_docs_complete.py::test_product_brief_covers_the_six_required_points PASSED [ 57%]
tests/unit/infra/test_docs_complete.py::test_readme_has_an_architecture_diagram PASSED [ 63%]
tests/unit/infra/test_docs_complete.py::test_readme_documents_the_one_command_run PASSED [ 68%]
tests/unit/infra/test_docs_complete.py::test_demo_script_covers_all_seven_required_items PASSED [ 73%]
tests/unit/infra/test_docs_complete.py::test_historical_reports_are_untouched PASSED [ 78%]
tests/unit/infra/test_docs_complete.py::test_limitations_names_residual_security_risks PASSED [ 84%]
tests/unit/infra/test_docs_complete.py::test_documentation_does_not_drift_on_eval_case_counts PASSED [ 89%]
tests/unit/infra/test_docs_complete.py::test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc PASSED [ 94%]
tests/unit/infra/test_docs_complete.py::test_readme_noi_ve_hai_tang_va_lenh_do_phu PASSED [100%]

============================== 19 passed in 0.05s ==============================

$ make kb-coverage
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

**Cách đã chọn:** Triển khai đúng các bước trong Task 7 của plan `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`.

**Lý do:** Khóa tài liệu bằng test tự động là cách duy nhất đảm bảo tài liệu không bị trôi lệch (drift) khi codebase phát triển. Bằng cách đếm trực tiếp file thực tế trong `data/knowledge-base/tier1/` và `tier2/`, test vừa bảo vệ tài liệu vừa bảo vệ sự toàn vẹn của cấu trúc thư mục.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Chỉ sửa tài liệu bằng tay mà không thêm test chống trôi | Nhanh hơn, ít code hơn | Dễ bị trôi lệch trở lại ở các lượt phát triển tiếp theo khi có người sửa KB mà không cập nhật tài liệu |
| Viết linter riêng cho markdown | Linh hoạt tổng quát | Phình phạm vi không cần thiết; pytest có sẵn assert đơn giản, nhanh và nằm chung pipeline test CI |

**Đánh đổi đã chấp nhận:** Tốn thêm ~0.05s trong test suite để đọc và assert nội dung markdown, nhưng đổi lại tính tin cậy tuyệt đối của tài liệu.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/infra/test_docs_complete.py -v` | 0 | 19 passed in 0.05s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1008 passed, 41 deselected in 19.49s |
| `make quality` | 0 | Ruff check passed, mypy (81 files) passed, coverage 84.34% ≥ 78%, pip-audit 0 vuln |
| `make kb-coverage` | 0 | Entry: 11, Có rule: 3, Chưa có rule: 8, Trần: 42/75 (56.0%) |

**Test mới thêm:**

- `tests/unit/infra/test_docs_complete.py::test_tai_lieu_khong_noi_sai_so_doc_trong_kho_tri_thuc` — Khẳng định số lượng tài liệu Tier 1 là 14, Tier 2 là 11, và không còn chuỗi cũ "20 tài liệu" trong `README.md` hay `docs/product-brief.md`.
- `tests/unit/infra/test_docs_complete.py::test_readme_noi_ve_hai_tang_va_lenh_do_phu` — Khẳng định `README.md` có đề cập `tier1`, `tier2` và lệnh `make kb-coverage`.

**Bất biến đã giữ:** Không có test double (mock/fake/stub); không có test nào bị `skip`; không in lộ secret hay API key; các báo cáo lịch sử `reports/week-01` .. `reports/week-06` nguyên vẹn 100%.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có chỗ nào nghi ngờ, các thay đổi tập trung vào tài liệu và test chống trôi theo đúng đặc tả của plan.
- **Giả định đã đặt:** Giả định cấu trúc 14 file Tier 1 và 11 file Tier 2 từ các Task trước là trạng thái ổn định chuẩn.
- **Việc còn nợ:** Task 8 tiếp theo (viết ca đánh giá 13 và đo trước/sau).
- **Câu hỏi cho người dùng:** Không có.
