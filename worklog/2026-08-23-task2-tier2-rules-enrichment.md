# Worklog — Chuẩn hóa 3 tài liệu Tier 2 có rule với 5 phần & Mã nguồn đối chứng

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Gemini 3.6 Flash High ·
**Branch:** `feat/enhance-kb` · **Plan:** [`docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`](file:///home/longngx04/VinSOC/project_sentinel_main/docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md) · **Task ID:** `Task 2`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Task 2 hoàn thành chuẩn hóa toàn diện 3 tài liệu kiến thức chuyên sâu Tier 2 có gắn trực tiếp OpenGrep rule (`java-sql-statement-execute.md`, `java-runtime-exec.md`, `java-objectinputstream-readobject.md`). Cấu trúc tài liệu được nâng cấp thành 5 phần tiêu chuẩn (Frontmatter metadata + 4 đề mục nội dung) kèm đối chứng mã nguồn Java thực tế giữa mẫu dễ bị tổn thương (❌ Vulnerable Pattern) và mẫu đã khắc phục (✅ Remediated Pattern) cùng liên kết tham chiếu thẩm quyền OWASP/CWE/Oracle docs. Toàn bộ 78 retrieval tests và toàn bộ test suite (1011 tests) cùng bộ kiểm tra `make quality` đều vượt qua 100%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Cung cấp tri thức bảo mật chuyên sâu (Tier 2 rules) có cấu trúc đồng nhất, rõ ràng cho pipeline phân tích SAST và hiển thị hướng dẫn khắc phục mã nguồn chi tiết trên Web UI.
- **Nằm ở đâu trong luồng:** Nằm ở tầng tri thức `data/knowledge-base/tier2/`, được `project_sentinel.retrieval` nạp và tra cứu khi phân tích các phát hiện SAST có rule ID tương ứng (`java-sql-statement-execution`, `java-command-execution`, `java-unsafe-deserialization`).
- **Không có nó thì hỏng gì:** Nếu thiếu các mẫu mã nguồn đối chứng và giải thích cơ chế rủi ro chi tiết, LLM analyzer sẽ thiếu ngữ cảnh chính xác để đánh giá khả năng khai thác (exploitability) và đề xuất remediation code chất lượng thấp; đồng thời chuyên gia bảo mật và lập trình viên xem trên Web UI sẽ không có hướng dẫn sửa lỗi trực quan.
- **Ngoài phạm vi (cố ý không làm):** Chưa cập nhật 8 tài liệu Tier 2 còn lại (thuộc Task 3 và Task 4) và 14 tài liệu Tier 1 (thuộc Task 5).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `data/knowledge-base/tier2/java-sql-statement-execute.md` | Sửa | Thêm `references` vào frontmatter; chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ Statement vs ✅ PreparedStatement với placeholder `?`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo OWASP/CWE/Oracle | Chuẩn hóa tri thức Tier 2 cho SQL Injection |
| `data/knowledge-base/tier2/java-runtime-exec.md` | Sửa | Thêm `references` vào frontmatter; chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `Runtime.getRuntime().exec` vs ✅ `ProcessBuilder` tham số tách rời), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo OWASP/CWE/Oracle | Chuẩn hóa tri thức Tier 2 cho Command Injection |
| `data/knowledge-base/tier2/java-objectinputstream-readobject.md` | Sửa | Thêm `references` vào frontmatter; chuẩn hóa 4 đề mục: Cơ chế rủi ro, Mã nguồn minh họa (❌ `ObjectInputStream.readObject()` vs ✅ Jackson `ObjectMapper` / `ObjectInputFilter`), Biện pháp khắc phục 3 lớp, Tài liệu tham khảo OWASP/CWE/Oracle | Chuẩn hóa tri thức Tier 2 cho Insecure Deserialization |

**`git diff --stat`:**

```text
 data/knowledge-base/tier2/java-objectinputstream-readobject.md | 53 ++++++++++++++++++++++++++++++--
 data/knowledge-base/tier2/java-runtime-exec.md                 | 48 ++++++++++++++++++++++++++---
 data/knowledge-base/tier2/java-sql-statement-execute.md        | 69 +++++++++++++++++++++++++++++++++++-------
 3 files changed, 154 insertions(+), 16 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
1. Khảo sát cấu trúc hiện tại của 3 tệp tri thức Tier 2 có rule map (`java-sql-statement-execute.md`, `java-runtime-exec.md`, `java-objectinputstream-readobject.md`).
2. Bổ sung trường `references` trong frontmatter chứa danh sách URL chuẩn xác từ OWASP Cheat Sheet Series, CWE Mitre, và Oracle Java SE Documentation.
3. Tái cấu trúc phần thân bài viết thành 4 mục chuẩn:
   - `## 1. Cơ chế rủi ro (Risk Mechanism)`
   - `## 2. Mã nguồn minh họa (Code Examples)` (chia thành `### ❌ Không an toàn (Vulnerable Pattern)` và `### ✅ Đã khắc phục an toàn (Remediated Pattern)`)
   - `## 3. Biện pháp khắc phục chuẩn (Remediation Guide)` (phân lớp phòng thủ 3 tầng và giải thích vai trò của `not_exploitable_when` chống false positives)
   - `## 4. Tài liệu tham khảo (References)` (liên kết markdown có thể click trực tiếp)
4. Xác minh sự tương thích với schema parser (`kb_schema.py`) và chạy toàn bộ test retrieval, static analysis và test suite hệ thống.

**Luồng dữ liệu:** `OpenGrep finding (rule_id / sink_signatures)` → `Tier lookup / kb_schema.py` → `Nạp Tier2Entry (kèm references, code examples, remediation)` → `Cung cấp ngữ cảnh cho Analyzer / Web UI`.

**Các quyết định kỹ thuật:**
- Sử dụng code snippet Java chuẩn idiomatic (ví dụ dùng `try-with-resources` với `PreparedStatement` và `ObjectInputStream`).
- Mỗi URL tham chiếu đều bắt đầu bằng `https://` và trỏ trực tiếp đến tài liệu chính thống để bảo đảm parser `kb_schema.py` xác thực thành công.
- Giữ nguyên các giá trị nhận diện cốt lõi (`id`, `cwe`, `sink_signatures`, `matches_rule_ids`) để tránh làm sai lệch cơ chế mapping của pipeline.

**Xử lý lỗi / trường hợp biên:** Mọi URL trong `references` được kiểm tra chặt chẽ bởi `kb_schema.py` chống chuỗi không phải URL hoặc thiếu scheme `http/https`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Doc | `java-sql-statement-execute.md` | `data/knowledge-base/tier2/java-sql-statement-execute.md` | Tài liệu Tier 2 SQL Injection đã chuẩn hóa 5 phần và đối chứng mã nguồn |
| Doc | `java-runtime-exec.md` | `data/knowledge-base/tier2/java-runtime-exec.md` | Tài liệu Tier 2 Command Injection đã chuẩn hóa 5 phần và đối chứng mã nguồn |
| Doc | `java-objectinputstream-readobject.md` | `data/knowledge-base/tier2/java-objectinputstream-readobject.md` | Tài liệu Tier 2 Insecure Deserialization đã chuẩn hóa 5 phần và đối chứng mã nguồn |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/retrieval/ -v
make quality
```

**Output thật (đã che secret):**

```text
tests/unit/retrieval/test_kb_integrity.py::test_thu_muc_vulnerabilities_cu_da_bien_mat PASSED [  1%]
tests/unit/retrieval/test_kb_integrity.py::test_tier1_co_dung_muoi_bon_doc_va_dung_id PASSED [  2%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_doc_tier1_khai_dung_tier PASSED [  3%]
tests/unit/retrieval/test_kb_integrity.py::test_co_dung_muoi_mot_entry_tier2 PASSED [  5%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_tier1_parent_tro_toi_doc_co_that PASSED [  6%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_rule_id_duoc_khai_deu_ton_tai_that PASSED [  7%]
tests/unit/retrieval/test_kb_integrity.py::test_entry_khong_co_rule_phai_danh_dau_no_rule_yet PASSED [  8%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_sink_nao_xuat_hien_o_hai_entry PASSED [ 10%]
tests/unit/retrieval/test_kb_integrity.py::test_khong_rule_id_nao_xuat_hien_o_hai_entry PASSED [ 11%]
tests/unit/retrieval/test_kb_integrity.py::test_moi_entry_neu_duoc_dieu_kien_khong_khai_thac_duoc PASSED [ 12%]
...
78 passed in 0.92s
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Cấu trúc tài liệu Markdown 5 phần (frontmatter YAML + 4 section tiêu chuẩn với các tiêu đề mục ngữ nghĩa rõ ràng và mã nguồn Java cụ thể).

**Lý do:** Bám sát tuyệt đối yêu cầu tại Task 2 của plan `docs/superpowers/plans/2026-08-23-enriched-knowledge-base.md`:
> *"Chuẩn hóa 3 tài liệu Tier 2 có rule với 5 phần & Mã nguồn đối chứng: java-sql-statement-execute.md, java-runtime-exec.md, java-objectinputstream-readobject.md"*.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Đưa toàn bộ code ví dụ vào frontmatter YAML | Dễ parse tự động dưới dạng trường riêng | Gây rối cấu trúc YAML, khó định dạng cú pháp Java đa dòng, khó đọc và khó bảo trì |
| Chỉ viết giải thích lý thuyết chung không kèm code block Java | Tài liệu ngắn gọn | Không cung cấp được mẫu đối chứng thực tế để LLM sinh bản vá chính xác và lập trình viên dễ áp dụng |

**Đánh đổi đã chấp nhận:** Dung lượng file Markdown tăng lên nhưng giá trị tri thức và tính trực quan tăng vượt trội.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/unit/retrieval/ -v` | 0 | 78 passed in 0.92s |
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1011 passed, 41 deselected in 19.59s |
| `make quality` | 0 | Ruff checks passed, Mypy 81 files checked, 1011 tests passed (Coverage: 84.37%), Pip-audit 0 vulnerabilities |

**Test mới thêm:** Không có test mới cần thêm ở Task 2 (các test kiểm tra schema và integrity sẵn có đã bao phủ toàn diện; Task 6 sẽ bổ sung thêm các assert chuyên sâu sau khi hoàn thành Task 3-5).

**Bất biến đã giữ:** Không sử dụng test double (no fake/mock/stub), không sửa historical reports, không thêm dependency mới, không phá vỡ schema phân tích, dữ liệu frontmatter tuân thủ nghiêm ngặt `kb_schema.py`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** Không có. Các đoạn code Java minh họa đã được đối chiếu kỹ lưỡng với các tài liệu chuẩn của OWASP và Oracle.
- **Giả định đã đặt:** Các quy ước tiêu đề `## 1. Cơ chế rủi ro`, `## 2. Mã nguồn minh họa`, `## 3. Biện pháp khắc phục chuẩn`, `## 4. Tài liệu tham khảo` sẽ được áp dụng thống nhất cho toàn bộ các file Tier 2 tiếp theo trong Task 3 và Task 4.
- **Việc còn nợ:** Tiếp tục thực hiện Task 3 (4 tài liệu Tier 2 Nhóm A) và Task 4 (4 tài liệu Tier 2 Nhóm B) theo plan.
- **Câu hỏi cho người dùng:** Không có.
