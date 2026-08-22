# Worklog — Ca đánh giá 13 và đo trước/sau (Task 8)

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Gemini 2.5 Flash ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](../../docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 8`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Đã thêm ca đánh giá 13 (`13-tier2-citation.json`) và tiêu chí `must_cite_path` vào bộ đánh giá agent (`eval/run_eval.py`), xác nhận trích dẫn tài liệu Tier 2 khi rule_id khớp. Chạy bộ đánh giá thật `make eval` đạt pass rate 97.4% (ca 13 đạt 100% 3/3 lần lặp) và chạy pipeline thật `cli run --yes` để đo đạc và lập báo cáo so sánh trước/sau tại `reports/week-06/kb-two-tier-measurement.md`. Toàn bộ hệ thống vượt qua kiểm tra chất lượng `make quality` với 1009/1009 test pass và 84.34% coverage.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Bổ sung ca đánh giá tự động (eval case 13) để kiểm thử việc trích dẫn Tier 2 KB của Security Analysis Agent; đo lường hiệu quả định lượng của kiến trúc Kho tri thức hai tầng trên dữ liệu thực tế (WebGoat) và ghi nhận vào báo cáo đo đạc.
- **Nằm ở đâu trong luồng:** Nằm ở tầng đánh giá độc lập (`eval/`) và báo cáo đo lường chất lượng tổng thể (`reports/week-06/`).
- **Không có nó thì hỏng gì:** Không kiểm chứng được bằng tự động hóa xem LLM có tuân thủ trích dẫn Tier 2 hay không; thiếu dữ liệu đo đạc so sánh thực tế trước/sau khi triển khai Two-Tier KB.
- **Ngoài phạm vi (cố ý không làm):** Không sửa schema `security-analysis-record.schema.json`; không sinh tự động rule OpenGrep từ KB.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/integration/test_eval_harness.py` | Sửa | Thêm `test_tieu_chi_must_cite_path_bat_duoc_record_khong_trich_dan` | Kiểm tra tiêu chí `must_cite_path` theo quy trình TDD (RED trước khi code) |
| `eval/run_eval.py` | Sửa | Cập nhật `evaluate()` hỗ trợ tiêu chí `must_cite_path` | Bắt buộc record phải chứa path tài liệu trong `knowledge_refs` |
| `eval/cases/13-tier2-citation.json` | Tạo | Tạo ca đánh giá 13 với input SQLi có `rule_id` khớp Tier 2 | Ca đánh giá thực tế bắt buộc trích dẫn `java-sql-statement-execute.md` |
| `eval/README.md` | Sửa | Thêm ca 13 vào bảng Ca mở rộng và bổ sung `must_cite_path` | Cập nhật tài liệu bộ đánh giá |
| `configs/prompts/security-analysis-system.md` | Sửa | Thêm hướng dẫn rõ ràng về trường `evidence` khi thiếu source | Giúp LLM sinh scanner evidence thay vì rỗng khi không có source code |
| `reports/week-06/kb-two-tier-measurement.md` | Tạo | Báo cáo chi tiết đo đạc trước/sau trên lần chạy thật `20260822T205249Z` | Cung cấp bằng chứng định lượng theo Step 7 của Task 8 |

**`git diff --stat`:**

```text
 configs/prompts/security-analysis-system.md |  1 +
 eval/README.md                              |  2 ++
 eval/cases/13-tier2-citation.json           | 25 ++++++++++++++++++++++
 eval/run_eval.py                            | 15 +++++++++++++
 reports/week-06/eval-results.md             | 38 +++++++++++++++--------------
 reports/week-06/kb-two-tier-measurement.md  | 62 +++++++++++++++++++++++++++++++++++++++++++++++++++
 tests/integration/test_eval_harness.py      | 28 +++++++++++++++++++++++
 7 files changed, 153 insertions(+), 18 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:** Tiếp cận theo chuẩn TDD. Đầu tiên viết unit/integration test cho tiêu chí `must_cite_path` trong `test_eval_harness.py` và xác nhận FAIL (RED). Tiếp theo cập nhật logic trong hàm `evaluate()` của `eval/run_eval.py` để duyệt qua các `knowledge_refs` của record và đối chiếu với `must_cite_path`, sau đó chạy lại test xác nhận PASS (GREEN). Tiếp đến tạo ca đánh giá `13-tier2-citation.json`, cập nhật `eval/README.md`, chạy `make eval` 3 lần lặp để kiểm tra độ tin cậy của model trên toàn bộ 13 ca. Cuối cùng, kích hoạt pipeline `project_sentinel.cli run --yes` để thu thập số liệu chạy thật, chấm điểm recall/triage bằng `make score-ground-truth`, và lập báo cáo `reports/week-06/kb-two-tier-measurement.md`.

**Luồng dữ liệu:** `Finding input` → `cli analyze` → `analysis.jsonl` → `evaluate(case, records)` → `EvalOutcome` (`must_cite_path in cited_paths`).

**Các quyết định kỹ thuật:**
- Tiêu chí `must_cite_path` kiểm tra tập hợp tất cả các `path` có trong `knowledge_refs` của các record được sinh ra. Nếu thiếu, ghi nhận fail và nêu rõ danh sách các tài liệu đã trích thực tế.
- Bổ sung chỉ dẫn rõ ràng cho `evidence` trong system prompt để ngăn ngừa model xuất mảng rỗng khi không có source code tại vị trí finding, bảo đảm tuân thủ đúng schema `minItems: 1`.

**Xử lý lỗi / trường hợp biên:**
- Trường hợp `record.get("knowledge_refs")` là None hoặc chứa phần tử không phải dict: xử lý an toàn bằng comprehension guard.
- Trường hợp không sinh record: `should_produce_record: true` sẽ kích hoạt false negative.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| File ca đánh giá | `13-tier2-citation.json` | `eval/cases/13-tier2-citation.json` | Ca đánh giá yêu cầu trích dẫn Tier 2 KB |
| Báo cáo đo đạc | `kb-two-tier-measurement.md` | `reports/week-06/kb-two-tier-measurement.md` | Báo cáo so sánh trước/sau khi có Two-Tier KB |
| Test | `test_tieu_chi_must_cite_path_bat_duoc_record_khong_trich_dan` | `tests/integration/test_eval_harness.py` | Test cho tiêu chí `must_cite_path` |
| Logic eval | `must_cite_path` check | `eval/run_eval.py:evaluate()` | Kiểm tra trích dẫn tài liệu bắt buộc |

**Cách chạy:**

```bash
# Chạy test harness eval
.venv/bin/python -m pytest tests/integration/test_eval_harness.py -k must_cite -v

# Chạy toàn bộ bộ đánh giá 13 ca với LLM thật
make eval

# Chạy đo đạc trên pipeline thật
KEY=$(sed -n "s/^SENTINEL_GATEWAY_API_KEY=//p" .env) SENTINEL_GATEWAY_API_KEY="$KEY" .venv/bin/python -m project_sentinel.cli run --yes
make score-ground-truth ANALYSIS=artifacts/runs/<run-id>/analysis.jsonl
```

**Output thật (đã che secret):**

```text
--- Lần chạy 1/3 ---
01-sql-injection: Pass
02-xss: Pass
03-path-traversal: Pass
04-empty-input: Pass
05-malformed-input: Pass
06-injection-in-finding: Pass
07-dast-finding: Pass
08-mixed-sast-dast: Pass
09-no-exploit-payload: Pass
10-missing-source-file: Pass
11-unknown-rule-no-fabrication: Pass
12-confirmed-needs-evidence: Pass
13-tier2-citation: Pass
--- Lần chạy 2/3 ---
...
13-tier2-citation: Pass
--- Lần chạy 3/3 ---
...
13-tier2-citation: Pass

Kết quả: /home/longngx04/VinSOC/project_sentinel_main/reports/week-06/eval-results.md
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Triển khai tiêu chí `must_cite_path` trực tiếp trong hàm `evaluate()` của `run_eval.py` và tạo file JSON chuẩn cho ca 13.

**Lý do:** Bám sát tuyệt đối đặc tả tại Step 1-5 của Task 8 trong plan `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`. Tiêu chí này biến yêu cầu trích dẫn thành điều kiện tất định kiểm tra được bằng code Python, không phụ thuộc vào suy đoán cảm tính.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Kiểm tra trích dẫn thông qua `title_contains` | Đơn giản, không cần sửa `evaluate()` | Không kiểm tra được đường dẫn file chính xác trong `knowledge_refs`, dễ bị dương tính giả nếu model chỉ nhắc tên tài liệu trong văn xuôi |
| Hardcode kiểm tra riêng cho ca 13 theo `case.case_id == "13-tier2-citation"` | Không ảnh hưởng ca khác | Phá vỡ tính generic của bộ khung đánh giá (eval harness); `must_cite_path` có thể tái sử dụng cho các ca đánh giá khác trong tương lai |

**Đánh đổi đã chấp nhận:** Chấp nhận thời gian chạy `make eval` (3 lần lặp x 13 ca = 39 lượt gọi LLM) và `make run` để thu thập dữ liệu thực tế chính xác nhất.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest tests/integration/test_eval_harness.py -k must_cite -v` | 0 | 1 passed |
| `.venv/bin/python -m pytest tests/integration/test_eval_harness.py -v` | 0 | 25 passed |
| `make eval` | 0 | 13/13 ca đạt đa số, pass rate 97.4% (38/39 lượt), ca 13 đạt 100% (3/3) |
| `make quality` | 0 | Ruff check pass, Mypy pass (81 files), Pytest coverage 84.34% (1009 passed), pip-audit clean |
| `make kb-coverage` | 0 | 11 entry, 3 có rule, 8 chưa có rule, trần 42/75 (56.0%) |
| `make search Q="SQL Injection"` | 0 | 5 hits (tier1, tier2, owasp) |

**Test mới thêm:**

- `tests/integration/test_eval_harness.py::test_tieu_chi_must_cite_path_bat_duoc_record_khong_trich_dan` — Khẳng định `evaluate()` phát hiện và đánh trượt record không trích dẫn tài liệu bắt buộc trong `must_cite_path`, và đánh đạt khi có trích dẫn đúng.

**Bất biến đã giữ:**
- Không sử dụng mock/fake/stub.
- Không skip test.
- Không in secret/API key ra output/báo cáo.
- Không sửa đổi schema `security-analysis-record.schema.json`.
- Không thay đổi các báo cáo lịch sử `reports/week-01` đến `reports/week-05`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `eval/run_eval.py:232-245` — Logic lấy `cited` tập hợp `path` từ tất cả các record trong nhóm để kiểm tra `must_cite_path`.
- **Giả định đã đặt:** Giả định các ca đánh giá có thể chạy song song bằng `ThreadPoolExecutor` qua `EVAL_WORKERS`.
- **Việc còn nợ:** Không có.
- **Câu hỏi cho người dùng:** Không có.
