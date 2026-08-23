# Worklog — Task 5: Hai luật provenance (10 & 11) và bổ sung system prompt

**Ngày:** 2026-08-23 · **Agent/Model:** Antigravity · Gemini 2.5 Pro ·
**Branch:** `feat/zap-dast` · **Plan:** [`docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md`](../docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md) · **Task ID:** `Task 5`

> Điền đủ 8 mục. Mục nào không có nội dung thì ghi `Không có` — không được xoá mục.
> Mọi số liệu phải là kết quả chạy thật. Che secret bằng `***`.

---

## 1. Tóm tắt

Triển khai hai luật kiểm tra nguồn gốc (provenance) mới (Luật 10 và Luật 11) trong hàm `validate_provenance` để biến tài liệu KB Tier 2 thành ràng buộc cứng có thể kiểm chứng bằng Python. Bổ sung các quy tắc chỉ dẫn cứng tương ứng vào system prompt phân tích bảo mật và viết test guardrail cho system prompt. Toàn bộ 1002 test của hệ thống vượt qua thành công và bộ kiểm tra chất lượng `make quality` đạt 100% xanh với độ bao phủ 84.50%.

---

## 2. Task này có chức năng gì

- **Chức năng trong hệ thống:** Bắt buộc LLM Agent phải trích dẫn tài liệu KB Tier 2 tương ứng khi packet có hit khớp theo `rule_id` (Luật 10) và đồng thời kiểm tra `title` của record đầu ra phải khớp chính xác với `canonical_category` của tài liệu Tier 2 đã trích dẫn (Luật 11), loại bỏ ảo giác đặt tên danh mục lỗ hổng và bỏ qua tri thức bảo mật chuyên sâu.
- **Nằm ở đâu trong luồng:** Nằm ở tầng hậu xử lý và kiểm định phân tích (`src/project_sentinel/analysis/validators.py`), được gọi bởi `analysis/pipeline.py` sau khi LLM sinh output JSON để quyết định record có hợp lệ hay bị loại/phạt vi phạm provenance.
- **Không có nó thì hỏng gì:** Nếu không có hai luật này, KB chỉ là ngữ cảnh bị động (passive context); agent có thể tuỳ tiện bỏ qua tài liệu hướng dẫn chuyên biệt cho sink hoặc đặt tên lỗ hổng tuỳ ý (như bịa tên hoặc chép nguyên văn message của scanner), dẫn đến sai lệch chuẩn hoá và over-claim kết quả.
- **Ngoài phạm vi (cố ý không làm):** Không tự động sửa `title` thay cho LLM (chỉ phát hiện và báo lỗi để loại/yêu cầu sinh lại); không ràng buộc bắt buộc trích dẫn đối với hit khớp mờ/gần đúng theo CWE (`match_kind == "cwe"`).

---

## 3. Đã làm gì

| File | Thao tác | Nội dung thay đổi | Vì sao phải đụng file này |
|---|---|---|---|
| `tests/unit/analysis/test_provenance_knowledge.py` | Tạo | Viết 7 unit tests kiểm tra toàn diện các kịch bản của Luật 10 và Luật 11 (bỏ qua hit rule_id, trích đúng, hit CWE không bắt buộc, sai lệch title, chuẩn hoá khoảng trắng/hoa thường, không có hit Tier 2, bắt path bịa đặt). | Tuân thủ TDD (test đỏ trước khi sửa code), kiểm chứng hành vi của validator mới. |
| `src/project_sentinel/analysis/validators.py` | Sửa | Thêm Luật 10 (bắt buộc trích hit Tier 2 có `match_kind == 'rule_id'`) và Luật 11 (đối chiếu `title` của record với `canonical_category` của hit Tier 2 đã trích) vào hàm `validate_provenance`. | Nơi thực thi các quy tắc kiểm tra provenance của toàn bộ pipeline phân tích. |
| `configs/prompts/security-analysis-system.md` | Sửa | Bổ sung 2 hard rule vào cuối khối Hard rules hướng dẫn LLM trích dẫn path/score khi `match_kind` là "rule_id", đặt `title` theo `canonical_category`, và diễn giải theo điều kiện `not_exploitable_when`. | Cung cấp hợp đồng chỉ dẫn rõ ràng cho LLM trước khi validator phạt vi phạm. |
| `tests/unit/guardrails/test_system_prompt_rules.py` | Sửa | Thêm test `test_prompt_bat_buoc_trich_dan_tai_lieu_tier2` kiểm tra sự hiện diện của các từ khoá quy tắc mới trong file prompt. | Đảm bảo system prompt không bị thoái lui (regression) làm mất các chỉ dẫn bắt buộc. |

**`git diff --stat`:**

```text
 configs/prompts/security-analysis-system.md       |  7 ++++
 src/project_sentinel/analysis/validators.py       | 42 +++++++++++++++++++++++
 tests/unit/analysis/test_provenance_knowledge.py  | 93 +++++++++++++++++++++++++++++++++++++++++++++++++++
 tests/unit/guardrails/test_system_prompt_rules.py | 10 ++++++
 4 files changed, 152 insertions(+)
```

---

## 4. Làm như thế nào

**Cách tiếp cận:**
Triển khai theo phương pháp Test-Driven Development (TDD). Viết test suite cho Luật 10 và 11 trước, chạy xác nhận trạng thái RED (2 tests fail do chưa có logic kiểm tra). Sau đó, bổ sung logic kiểm tra vào cuối hàm `validate_provenance` trước khi trả kết quả, đổi tên biến tránh xung đột type annotation với mypy. Cập nhật system prompt và bổ sung guardrail test để khóa tính toàn vẹn của prompt.

**Luồng dữ liệu:**
`LLM Analysis Output Record` + `AnalysisPacket (input_knowledge_hits)` → `validate_provenance()`:
1. Trích tập `cited_paths` từ `record.knowledge_refs`.
2. Lọc danh sách `required_hits` từ `input_knowledge_hits` có `match_kind == "rule_id"`.
3. Kiểm tra mọi `hit["path"]` trong `required_hits` đều phải nằm trong `cited_paths` (Luật 10).
4. Ánh xạ các hit Tier 2 (`tier == 2`) theo path và so sánh `record["title"].casefold()` với `hit["canonical_category"].casefold()` cho từng tài liệu đã trích (Luật 11).
5. Trả về `(is_valid, errors)`.

**Các quyết định kỹ thuật:**
- Không bắt buộc trích dẫn với `match_kind == "cwe"` vì một CWE có thể bao gồm nhiều sink khác nhau; việc gán ép trích dẫn hit CWE có thể ép agent trích tài liệu không liên quan đến ngữ cảnh thực tế của finding.
- So sánh `title` và `canonical_category` sử dụng `.casefold()` và `.strip()` để chấp nhận các biến thể không phân biệt chữ hoa chữ thường hoặc khoảng trắng thừa nhưng vẫn giữ đúng danh mục chuẩn.
- Đặt tên biến trong loop riêng biệt (`tier2_hit`) để đảm bảo tính tường minh và tương thích với mypy typechecker (`Dict[str, Any] | None`).

**Xử lý lỗi / trường hợp biên:**
- `record_dict` thiếu trường `knowledge_refs`, `title` rỗng hoặc `None`: xử lý an toàn bằng default getters và chuyển kiểu chuỗi an toàn.
- `input_knowledge_hits` là `None` hoặc rỗng: lùi về danh sách rỗng an toàn mà không gây `AttributeError`.
- Trích dẫn path Tier 2 bịa đặt không có trong packet: vẫn bị Luật 3 (bắt path tri thức không tồn tại) chặn ngay lập tức.

---

## 5. Output là gì

**Thành phần mới hoặc thay đổi:**

| Loại | Tên | Chữ ký / đường dẫn | Mô tả |
|---|---|---|---|
| Test File | `test_provenance_knowledge.py` | `tests/unit/analysis/test_provenance_knowledge.py` | 7 unit tests kiểm tra toàn vẹn Luật 10 và Luật 11. |
| Function Edit | `validate_provenance` | `src/project_sentinel/analysis/validators.py:82` | Thêm logic Luật 10 (bắt buộc trích Tier 2 `rule_id`) và Luật 11 (khớp `canonical_category`). |
| Config Edit | `security-analysis-system.md` | `configs/prompts/security-analysis-system.md` | Bổ sung 2 hard rules về trích dẫn tri thức Tier 2 và `not_exploitable_when`. |
| Test Case | `test_prompt_bat_buoc_trich_dan_tai_lieu_tier2` | `tests/unit/guardrails/test_system_prompt_rules.py:113` | Kiểm tra prompt chứa đầy đủ các điều khoản yêu cầu. |

**Cách chạy:**

```bash
.venv/bin/python -m pytest tests/unit/analysis/test_provenance_knowledge.py tests/unit/guardrails/test_system_prompt_rules.py -v
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
collecting ... collected 23 items                                                             

tests/unit/analysis/test_provenance_knowledge.py::test_bo_qua_hit_rule_id_la_loi_va_thong_diep_neu_dung_path PASSED [  4%]
tests/unit/analysis/test_provenance_knowledge.py::test_trich_dan_dung_thi_khong_loi PASSED [  8%]
tests/unit/analysis/test_provenance_knowledge.py::test_hit_theo_cwe_khong_bat_buoc_trich_dan PASSED [ 13%]
tests/unit/analysis/test_provenance_knowledge.py::test_title_lech_canonical_category_la_loi_va_neu_ten_dung PASSED [ 17%]
tests/unit/analysis/test_provenance_knowledge.py::test_title_khac_hoa_thuong_va_khoang_trang_van_duoc_chap_nhan PASSED [ 21%]
tests/unit/analysis/test_provenance_knowledge.py::test_khong_co_hit_tier2_thi_khong_rang_buoc_gi_them PASSED [ 26%]
tests/unit/analysis/test_provenance_knowledge.py::test_trich_path_tier2_khong_co_trong_packet_van_bi_luat_3_chan PASSED [ 30%]
tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_forbids_changing_goal_from_app_content PASSED [ 34%]
tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_forbids_disclosing_secrets PASSED [ 39%]
tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_forbids_out_of_scope_tools PASSED [ 43%]
tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_declares_untrusted_block_as_data PASSED [ 47%]
tests/unit/guardrails/test_system_prompt_rules.py::test_fixture_exists_and_is_valid_json[ignore-instructions] PASSED [ 52%]
tests/unit/guardrails/test_system_prompt_rules.py::test_fixture_exists_and_is_valid_json[exfiltrate-endpoint] PASSED [ 56%]
tests/unit/guardrails/test_system_prompt_rules.py::test_fixture_exists_and_is_valid_json[pii-leak] PASSED [ 60%]
tests/unit/guardrails/test_system_prompt_rules.py::test_injection_fixtures_are_detected[ignore-instructions] PASSED [ 65%]
tests/unit/guardrails/test_system_prompt_rules.py::test_injection_fixtures_are_detected[exfiltrate-endpoint] PASSED [ 69%]
tests/unit/guardrails/test_system_prompt_rules.py::test_exfiltrate_fixture_is_caught_by_an_exfiltration_pattern PASSED [ 73%]
tests/unit/guardrails/test_system_prompt_rules.py::test_exfiltrate_pattern_catches_direct_leaks_and_ignores_benign_prose PASSED [ 78%]
tests/unit/guardrails/test_system_prompt_rules.py::test_pii_fixture_is_not_flagged_as_injection PASSED [ 82%]
tests/unit/guardrails/test_system_prompt_rules.py::test_pii_fixture_is_actually_redacted PASSED [ 86%]
tests/unit/guardrails/test_system_prompt_rules.py::test_llm_payload_contains_allowed_endpoints_and_wrapped_evidence PASSED [ 91%]
tests/unit/guardrails/test_system_prompt_rules.py::test_openrouter_uses_the_same_payload_builder PASSED [ 95%]
tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_bat_buoc_trich_dan_tai_lieu_tier2 PASSED [100%]

============================== 23 passed in 0.10s ==============================
```

---

## 6. Vì sao chọn cách implement này

**Cách đã chọn:**
Bổ sung trực tiếp 2 luật vào hàm xác thực nguồn gốc `validate_provenance` ở vị trí trước khi trả kết quả, đồng thời cập nhật system prompt với hai hard rules tương ứng.

**Lý do:**
Theo đúng chỉ định trong plan `docs/superpowers/plans/2026-08-23-knowledge-base-two-tier.md` (Task 5, Step 3 & Step 6) và spec §5.2. Hàm `validate_provenance` đã nhận sẵn `input_knowledge_hits` từ `pipeline.py`, do đó việc kiểm tra `match_kind == 'rule_id'` và đối chiếu `canonical_category` là phương án tự nhiên nhất, giữ nguyên chữ ký hàm và không phá vỡ tính tương thích ngược.

**Phương án đã cân nhắc và loại bỏ:**

| Phương án | Ưu | Vì sao loại |
|---|---|---|
| Tự động gán/sửa đè `title = canonical_category` khi trích dẫn Tier 2 | Tránh phải loại bỏ record do lỗi đặt tên | Vi phạm nguyên tắc bảo mật và triết lý của Project Sentinel: không sửa chữa dữ liệu của LLM một cách mập mờ; lỗi phải được phát hiện và báo rõ nguyên nhân (fail loud). |
| Bắt buộc trích dẫn cả khi `match_kind == 'cwe'` | Tăng tỷ lệ trích dẫn tri thức | Bị loại vì CWE là phân loại mức cao bao quát nhiều sink. Một finding có thể kích hoạt CWE nhưng đoạn mã thực tế không sử dụng sink trong tài liệu Tier 2, bắt trích dẫn sẽ ép agent tạo ra trích dẫn gượng ép. |

**Đánh đổi đã chấp nhận:**
Khắt khe hơn trong khâu xác thực đầu ra của LLM: nếu LLM không tuân thủ prompt về `title` hoặc quên trích dẫn tài liệu Tier 2 khi có match `rule_id`, record sẽ bị từ chối và yêu cầu tạo lại.

---

## 7. Kiểm chứng

| Lệnh | Exit code | Kết quả |
|---|---:|---|
| `.venv/bin/python -m pytest tests/unit/analysis/test_provenance_knowledge.py -v` (khi chưa sửa code) | 1 | 2 failed, 5 passed (Đúng yêu cầu TDD RED) |
| `.venv/bin/python -m pytest tests/unit/analysis/test_provenance_knowledge.py tests/unit/guardrails/test_system_prompt_rules.py -v` | 0 | 23 passed (TDD GREEN) |
| `pytest -m "not llm and not live_gateway" -q tests` | 0 | 1002 passed, 41 deselected in 19.49s |
| `make quality` | 0 | ruff ok, mypy ok (80 source files), 1002 passed, coverage 84.50% (ngưỡng 78.0%), pip-audit clean |

**Test mới thêm:**

- `tests/unit/analysis/test_provenance_knowledge.py::test_bo_qua_hit_rule_id_la_loi_va_thong_diep_neu_dung_path` — Bỏ qua hit Tier 2 tra theo `rule_id` phải bị báo lỗi và nêu rõ path thiếu.
- `tests/unit/analysis/test_provenance_knowledge.py::test_trich_dan_dung_thi_khong_loi` — Trích dẫn đầy đủ hit Tier 2 thì hợp lệ.
- `tests/unit/analysis/test_provenance_knowledge.py::test_hit_theo_cwe_khong_bat_buoc_trich_dan` — Hit theo CWE là khớp gần đúng, không bắt buộc trích dẫn.
- `tests/unit/analysis/test_provenance_knowledge.py::test_title_lech_canonical_category_la_loi_va_neu_ten_dung` — `title` lệch với `canonical_category` của tài liệu Tier 2 đã trích bị từ chối.
- `tests/unit/analysis/test_provenance_knowledge.py::test_title_khac_hoa_thuong_va_khoang_trang_van_duoc_chap_nhan` — `title` chỉ khác chữ hoa/thường hoặc khoảng trắng vẫn được chấp nhận.
- `tests/unit/analysis/test_provenance_knowledge.py::test_khong_co_hit_tier2_thi_khong_rang_buoc_gi_them` — Không có hit Tier 2 trong packet thì không kích hoạt ràng buộc Luật 10/11.
- `tests/unit/analysis/test_provenance_knowledge.py::test_trich_path_tier2_khong_co_trong_packet_van_bi_luat_3_chan` — Bịa đặt path Tier 2 không có trong packet vẫn bị Luật 3 chặn.
- `tests/unit/guardrails/test_system_prompt_rules.py::test_prompt_bat_buoc_trich_dan_tai_lieu_tier2` — Kiểm tra system prompt chứa đủ các hướng dẫn về `match_kind`, `canonical_category` và `not_exploitable_when`.

**Bất biến đã giữ:**
- Không sử dụng bất kỳ test double nào (không fake/mock/stub).
- Không có test nào bị skip.
- Không để lộ secret hay API key.
- Không sửa đổi schema hay reports lịch sử.

**Còn fail / chưa chạy được:** Không có.

---

## 8. Cần người review kỹ ở đâu

- **Chỗ ít chắc chắn nhất:** `src/project_sentinel/analysis/validators.py:258-274` — Cơ chế so khớp `canonical_category` với `record["title"]` sử dụng `.casefold()` đối với tất cả các tài liệu Tier 2 đã trích dẫn trong `knowledge_refs`.
- **Giả định đã đặt:** Giả định các tài liệu Tier 2 luôn có thuộc tính `canonical_category` hợp lệ (đã được kiểm tra qua `kb_schema.py` ở Task 1).
- **Việc còn nợ:** Không có.
- **Câu hỏi cho người dùng:** Không có.
