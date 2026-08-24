# Worklog — Bước LLM kiểm lại finding (LLM Verify Findings)

**Ngày:** 2026-08-24 · **Agent/Model:** Antigravity · Gemini Pro / Flash ·
**Branch:** `feat/llm-verify-findings` · **Plan:** [`docs/superpowers/plans/2026-08-24-llm-verify-findings.md`](docs/superpowers/plans/2026-08-24-llm-verify-findings.md) · **Task ID:** `Task 1–11`

---

## 1. Tóm tắt

Đã triển khai hoàn chỉnh bước gác cổng `verify` dùng LLM nằm giữa `normalize` và `analyze` để sàng lọc các cảnh báo scanner báo nhầm (false positive) trước khi đưa vào phân tích chuyên sâu. Đồng thời thống nhất logic trộn SAST + DAST thành một pipeline dùng chung `merge_normalized` để đường chạy CLI và Orchestrator hoàn toàn đồng nhất. Toàn bộ tính năng tuân thủ chặt chẽ 4 bất biến: fail-open toàn phần (không bao giờ kéo run sang `FAILED`), quyết định loại bỏ tất định ở tầng Python (`triage/rules.py`), bảo toàn `findings.json` gốc (xuất `findings.verified.json` riêng), và bảo toàn tuyệt đối kiến trúc các tuần trước.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:**
  1. Thêm gói `project_sentinel.triage` với chức năng gọi LLM đánh giá từng finding thô cùng trích xuất code/HTTP evidence, kết luận `true_positive`/`false_positive`/`uncertain`.
  2. Bổ sung luật lọc tất định `should_drop(verdict)`: chỉ loại finding khi và chỉ khi `verdict == "false_positive"` VÀ `confidence == "high"`.
  3. Bổ sung bước `verify` (bước 3 trong luồng 10 bước) vào State Machine và Runner của Orchestrator.
  4. Cung cấp fallback mềm trong `step_analyze`: tự động đọc `findings.verified.json` nếu có, fallback về `findings.json` nếu bước `verify` bị bỏ qua hoặc gặp sự cố.
  5. Cập nhật báo cáo markdown & JSON metrics với mục "Đã loại ở bước verify" và 3 chỉ số mới: `findings_verified`, `findings_dropped`, `verify_degraded`.
  6. Rút gọn logic chuẩn hoá trộn SAST + DAST + Gateway Log thành hàm `merge_normalized` trong `ingestion/merge_pipeline.py`.
- **Nằm ở đâu trong luồng:** Nằm ngay sau `step_normalize` và ngay trước `step_analyze` trong `PHASE_ONE`.
- **Không có nó thì hỏng gì:** Scanner (OpenGrep / ZAP) thường có tỷ lệ false positive cao; không có bước này thì LLM phân tích chuyên sâu tốn nhiều token và ngữ cảnh cho các cảnh báo không có thật trong code kiểm thử hoặc banner tĩnh.
- **Ngoài phạm vi (cố ý không làm):**
  - Không nạp Knowledge Base ở bước `verify` (bước này chỉ kiểm chứng thực tế code/network, không chấm mức độ nghiêm trọng hay giải pháp khắc phục).
  - Không sửa hay ghi đè `findings.json`.
  - Không sửa đổi schema hay logic của `analysis/calibration.py`, `analysis/pipeline.py`.

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `src/project_sentinel/ingestion/merge_pipeline.py` | Tạo | Hàm `merge_normalized`, `normalise_finding_fields`, CLI `main()` | Thống nhất logic trộn SAST+DAST dùng chung cho CLI và Orchestrator |
| `src/project_sentinel/orchestrator/steps/ingest.py` | Sửa | `step_normalize` gọi `merge_normalized`; thêm `_analysis_input` ưu tiên đọc `findings.verified.json` | Đồng bộ logic và cho phép `analyze` đọc danh sách đã lọc mềm |
| `Makefile` | Sửa | Cập nhật target `normalize` và `scan-all` sử dụng `merge_pipeline` | Đồng bộ lệnh make thủ công với pipeline |
| `schemas/verify-verdict.schema.json` | Tạo | JSON Schema draft 2020-12 cho kết quả verify verdict | Định nghĩa hợp đồng dữ liệu chuẩn xác cho LLM output |
| `configs/prompts/verify-finding-system.md` | Tạo | System prompt cho bước triage LLM verify | Hướng dẫn LLM thẩm định bằng chứng code/HTTP |
| `src/project_sentinel/triage/__init__.py` | Tạo | Package marker cho module triage | Khởi tạo package triage |
| `src/project_sentinel/triage/rules.py` | Tạo | Hàm `should_drop(verdict: dict) -> bool` | Quyết định nghiệp vụ tất định tại tầng Python |
| `src/project_sentinel/triage/verifier.py` | Tạo | `verify_findings(...)` gọi LLM song song, xuất `verify.jsonl`, `verify-summary.json`, `findings.verified.json` | Thực thi vòng lặp LLM triage với fail-open toàn phần |
| `src/project_sentinel/orchestrator/state.py` | Sửa | `STEP_NAMES` (10 bước), `STEP_BUDGET_S["verify"] = 360`, `RunState.VERIFYING`, `from_dict` hỗ trợ run cũ | Cập nhật State Machine và tương thích ngược |
| `src/project_sentinel/orchestrator/steps/verify.py` | Tạo | Hàm `step_verify(record, ctx)` | Triển khai bước 3 với fail-open handling |
| `src/project_sentinel/orchestrator/steps/__init__.py` | Sửa | Re-export `step_verify` | Cập nhật interface công khai cho các bước |
| `src/project_sentinel/orchestrator/runner.py` | Sửa | Chèn `step_verify` vào `PHASE_ONE` | Thực thi `step_verify` trong luồng chạy |
| `src/project_sentinel/orchestrator/report.py` | Sửa | Đọc verify summary, verdict và hiển thị bảng các finding bị loại | Báo cáo minh bạch các finding đã bị loại |
| `tests/unit/ingestion/test_merge_pipeline.py` | Tạo | 11 unit tests cho merge pipeline và CLI | Kiểm thử trộn SAST/DAST |
| `tests/unit/triage/test_rules.py` | Tạo | 27 tests cho schema validation và drop rules | Đảm bảo hợp đồng dữ liệu và luật tất định |
| `tests/unit/triage/test_verifier.py` | Tạo | 9 tests cho vòng lặp LLM với `ScriptedProvider` | Kiểm thử fail-open, timeout, malformed JSON, atomicity |
| `tests/unit/orchestrator/test_state_verify_step.py` | Tạo | 5 tests cho state machine và backward compatibility | Đảm bảo state machine 10 bước hoạt động đúng |
| `tests/unit/orchestrator/test_step_verify.py` | Tạo | 3 tests cho `step_verify` | Kiểm thử fail-open khi thiếu file hoặc gặp ngoại lệ |
| `tests/unit/orchestrator/test_step_analyze_input.py` | Tạo | 2 tests cho logic chọn input của analyze | Kiểm thử fallback giữa `findings.verified.json` và `findings.json` |
| `tests/unit/orchestrator/test_report_verify_section.py` | Tạo | 3 tests cho bảng báo cáo verify | Kiểm thử thống kê và hiển thị lý do loại |
| `tests/integration/test_verify_step.py` | Tạo | 3 integration tests gọi LLM thật (`@pytest.mark.llm`) | Kiểm chứng với LLM provider thực tế |

**`git diff --stat`:**

```text
 Makefile                                           |   18 +-
 configs/prompts/verify-finding-system.md           |   78 +
 .../plans/2026-08-24-llm-verify-findings.md        | 2320 ++++++++++++++++++++
 .../specs/2026-08-24-llm-verify-findings-design.md |  337 +++
 schemas/verify-verdict.schema.json                 |   39 +
 src/project_sentinel/ingestion/merge_pipeline.py   |  150 ++
 src/project_sentinel/orchestrator/report.py        |   64 +
 src/project_sentinel/orchestrator/runner.py        |    4 +-
 src/project_sentinel/orchestrator/state.py         |   25 +-
 .../orchestrator/steps/__init__.py                 |   17 +-
 src/project_sentinel/orchestrator/steps/ingest.py  |  120 +-
 src/project_sentinel/orchestrator/steps/verify.py  |   81 +
 src/project_sentinel/triage/__init__.py            |    1 +
 src/project_sentinel/triage/rules.py               |   28 +
 src/project_sentinel/triage/verifier.py            |  214 ++
 tests/unit/ingestion/test_merge_pipeline.py        |  200 ++
 .../orchestrator/test_report_verify_section.py     |   88 +
 tests/unit/orchestrator/test_state.py              |    8 +-
 tests/unit/orchestrator/test_state_verify_step.py  |   66 +
 tests/unit/orchestrator/test_step_analyze_input.py |   35 +
 tests/unit/orchestrator/test_step_scan_dast.py     |    8 +-
 tests/unit/orchestrator/test_step_verify.py        |   80 +
 tests/unit/triage/__init__.py                      |    0
 tests/unit/triage/test_rules.py                    |   94 +
 tests/unit/triage/test_verifier.py                 |  245 +++
 tests/unit/web/test_run_screen.py                  |    2 +-
 26 files changed, 4203 insertions(+), 119 deletions(-)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Triển khai theo phương pháp Test-Driven Development (TDD) chia nhỏ thành 11 task tuần tự. Đầu tiên là tạo tầng chuẩn hoá `merge_pipeline` và hợp đồng `schemas/verify-verdict.schema.json`. Tiếp theo là tầng nghiệp vụ `project_sentinel.triage` với quy tắc loại bỏ độc lập và vòng lặp LLM song song fail-open. Sau đó tích hợp vào Orchestrator state machine, runner, report generator, và kết thúc bằng kiểm thử đầu-cuối với LLM thật.

**Luồng dữ liệu:**
`raw.json` + `zap-raw.json` → `merge_normalized` → `findings.json` → `step_verify` (LLM triage song song) → Ghi `verify.jsonl`, `verify-summary.json`, và `findings.verified.json` (ghi atomic) → `step_analyze` đọc `findings.verified.json` → `step_report` tổng hợp thống kê và các mục đã loại.

**Các quyết định kỹ thuật:**
- **Fail-open toàn phần:** Bất kỳ lỗi nào phát sinh (mạng đứt, LLM crash, JSON sai cú pháp, schema không hợp lệ, id lạ không có trong tập đầu vào) đều mặc định giữ lại finding (`outcome.kept.append(finding)`), không bao giờ làm sập pipeline.
- **Tất định nghiệp vụ:** LLM chỉ phân loại và cung cấp rationale. Quyết định loại hoàn toàn do Python logic `should_drop` thực hiện (`verdict == "false_positive" and confidence == "high"`).
- **Atomic write:** `findings.verified.json` được ghi qua file tạm `.tmp` rồi đổi tên nguyên tử (`os.replace`) để tránh tình trạng đọc dở dang từ các tiến trình web/worker.
- **Tương thích ngược:** `RunRecord.from_dict` tự động điền các bước thiếu với status `skipped` khi nạp các `state.json` cũ 9 bước, tự động re-index thứ tự các bước.

**Xử lý lỗi / trường hợp biên:**
- `findings.json` không tồn tại hoặc rỗng: `step_verify` ghi log cảnh báo và chuyển sang `skipped`, run vẫn tiếp tục bình thường.
- LLM trả về markdown formatting kèm json (ví dụ ` ```json ... ``` `): được bóc tách an toàn qua regex `_extract_json_text`.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Module | `project_sentinel.ingestion.merge_pipeline` | `src/project_sentinel/ingestion/merge_pipeline.py` | Pipeline chuẩn hoá và trộn SAST + DAST dùng chung |
| Schema | `verify-verdict.schema.json` | `schemas/verify-verdict.schema.json` | JSON Schema xác thực kết luận triage của LLM |
| Config | `verify-finding-system.md` | `configs/prompts/verify-finding-system.md` | System prompt thẩm định finding thô |
| Module | `project_sentinel.triage.rules` | `src/project_sentinel/triage/rules.py` | Luật loại bỏ tất định `should_drop` |
| Module | `project_sentinel.triage.verifier` | `src/project_sentinel/triage/verifier.py` | Vòng lặp triage song song đa luồng và ghi artifact |
| Step | `step_verify` | `src/project_sentinel/orchestrator/steps/verify.py` | Bước Orchestrator thực thi triage an toàn |
| Test | Integration verify suite | `tests/integration/test_verify_step.py` | Suite kiểm thử đầu cuối với LLM thật |

**Cách chạy:**

```bash
# Kiểm thử toàn bộ offline
make quality && make agent-test

# Kiểm thử với LLM thật (cần LLM_API_KEY trong .env)
.venv/bin/python -m pytest -m llm tests/integration/test_verify_step.py -v
```

**Output thật (đã che secret):**

```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /home/longngx04/VinSOC/project_sentinel_main/.venv/bin/python
cachedir: .pytest_cache
rootdir: /home/longngx04/VinSOC/project_sentinel_main
configfile: pyproject.toml
plugins: respx-0.23.1, xdist-3.8.0, anyio-4.14.2, cov-7.1.0
collecting ... collected 3 items                                                              

tests/integration/test_verify_step.py::test_verify_khong_bao_gio_loai_nhieu_hon_so_finding_dau_vao PASSED [ 33%]
tests/integration/test_verify_step.py::test_verdict_luon_hop_le_theo_schema PASSED [ 66%]
tests/integration/test_verify_step.py::test_rationale_khong_chua_payload_khai_thac PASSED [100%]

============================== 3 passed in 14.92s ==============================

All checks passed!
Success: no issues found in 88 source files
Required test coverage of 78.0% reached. Total coverage: 85.08%
1138 passed, 44 deselected, 1 warning in 67.45s (0:01:07)
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:** Tách module độc lập `triage` nằm ngoài `analysis`, thiết kế fail-open toàn diện, và lọc mềm danh sách qua artifact `findings.verified.json` riêng biệt.

**Lý do:**
1. Tránh phình to `analysis/pipeline.py` và bảo toàn tính toàn vẹn của logic phân tích chuyên sâu đã được nghiệm thu từ các tuần trước.
2. Đảm bảo nguyên tắc bảo toàn dữ liệu: scanner findings gốc trong `findings.json` không bao giờ bị mất dấu hoặc xoá nhầm. Mọi quyết định loại bỏ đều có bản ghi vết đối soát trong `verify.jsonl`.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Tích hợp triage trực tiếp vào `step_analyze` | Ít file hơn, không cần thêm step vào state machine | Vi phạm Single Responsibility; nếu LLM gặp sự cố thì không thể phân biệt giữa lỗi phân tích hay lỗi triage; làm mất tính mô-đun hoá |
| Sửa trực tiếp file `findings.json` | Đơn giản, bước sau không cần đổi logic đọc file | Vi phạm nguyên tắc bảo toàn provenance gốc; mất khả năng phúc tra lại scanner thô |

**Đánh đổi đã chấp nhận:** Tăng thêm 1 bước trong state machine (từ 9 lên 10 bước) nhưng đổi lại sự minh bạch hoàn toàn và khả năng phục hồi tự động khi có sự cố mạng/LLM.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---|---|
| `.venv/bin/python -m pytest -m "not llm and not live_gateway" -q tests` | 0 | 1013 passed |
| `.venv/bin/python -m pytest -m llm tests/integration/test_verify_step.py -v` | 0 | 3 passed |
| `make quality && make agent-test` | 0 | 1138 passed, coverage 85.08% |
| `.venv/bin/python -m ruff check src tests` | 0 | All checks passed! |
| `.venv/bin/python -m mypy src tests` | 0 | Success: no issues found |

**Test mới thêm:**
- `tests/unit/ingestion/test_merge_pipeline.py` (11 tests): Kiểm thử chức năng trộn SAST+DAST và correlation log.
- `tests/unit/triage/test_rules.py` (27 tests): Kiểm thử schema `verify-verdict.schema.json` và quy tắc `should_drop`.
- `tests/unit/triage/test_verifier.py` (9 tests): Kiểm thử fail-open, invalid schema, unmapped ids, atomic write.
- `tests/unit/orchestrator/test_state_verify_step.py` (5 tests): Kiểm thử 10 bước state machine và backward compatibility.
- `tests/unit/orchestrator/test_step_verify.py` (3 tests): Kiểm thử `step_verify` trong orchestrator.
- `tests/unit/orchestrator/test_step_analyze_input.py` (2 tests): Kiểm thử fallback logic của `step_analyze`.
- `tests/unit/orchestrator/test_report_verify_section.py` (3 tests): Kiểm thử hiển thị bảng finding bị loại trong report.
- `tests/integration/test_verify_step.py` (3 tests): Kiểm thử tích hợp trực tiếp với LLM provider thật.

**Bất biến đã giữ:**
- Không sử dụng bất kỳ mock/stub nào vi phạm quy tắc D9/D10.
- Không commit `.env` hay in secret trong log.
- Giữ nguyên vẹn các báo cáo lịch sử `reports/week-01..06`.
- Fail-open: Bước verify không bao giờ kéo run sang `FAILED`.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/triage/verifier.py:126` — cơ chế `ThreadPoolExecutor` song song hóa các lệnh gọi LLM theo cấu hình `config.llm_concurrency` (mặc định 3 luồng).
- **Giả định đã đặt:** Giả định OpenRouter / LLM Provider tuân thủ đúng format JSON trả về; nếu model trả về markdown format thì regex helper `_extract_json_text` sẽ bóc tách phần JSON bên trong.
- **Việc còn nợ:** Không có.
- **Câu hỏi cho người dùng:** Không có.
