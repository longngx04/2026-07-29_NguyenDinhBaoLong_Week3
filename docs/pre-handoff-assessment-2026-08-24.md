# Đánh giá trước handoff — Project Sentinel

**Ngày đánh giá:** 2026-08-24
**Vai trò đánh giá:** Senior AI Engineer
**Nhánh:** `feat/llm-verify-findings`
**Nguồn yêu cầu:** `[NCUD-GPAI] VinUni x VinSOC 6-week of Project Sentinnel-1.pdf`

## Kết luận điều hành

**Điểm: 82/100 — đạt yêu cầu tối thiểu của PDF; cần nêu rõ các caveat còn lại khi handoff mentor.**

Project có nền tảng kỹ thuật tốt: cấu trúc rõ, 1.145 test offline xanh, coverage 84,86%,
schema/provenance/allowlist/HITL/redaction được triển khai nghiêm túc, Gateway thật chặn đúng
policy, và UI desktop đủ tốt để demo. Tuy nhiên, nhánh hiện tại thêm bước `verify` làm mất lỗ
hổng thật; run mới loại 9/23 finding, trong đó 4 finding có ground truth `true_positive` và 1
finding `needs_review`. Đây là lỗi chặn handoff vì nó làm hệ thống bảo mật giảm recall trong khi
giao diện vẫn báo run `DONE`.

**Gate:** `PASS MINIMUM WITH CAVEATS`. Không cần viết thêm Multi-Agent, MCP/A2A, GraphRAG hay
semantic search trước mentor. Cần trình bày trung thực giới hạn verifier/metric còn lại.

## Phạm vi và cách chấm

Đối chiếu theo rubric ở trang 14–15 của PDF:

| Hạng mục PDF | Trọng số | Điểm | Nhận xét ngắn |
| :--- | ---: | ---: | :--- |
| Hệ thống hoạt động | 30 | **27** | Luồng scan đến finalize chạy thật, gồm DAST; Gateway thật đạt. |
| Chất lượng AI Agent | 20 | **14** | Schema/provenance/calibration tốt; proposal nay gắn với runtime evidence; verifier vẫn có nguy cơ false negative. |
| An toàn hệ thống | 20 | **19** | Allowlist hai tầng, HITL, prompt-injection defense, redaction và loopback isolation đều mạnh. |
| Chất lượng mã nguồn | 15 | **11** | 1.145 test, lint/type/audit xanh; metric drift, policy test-double/skip không khớp thực tế, thiếu global run guard. |
| Tài liệu và trình bày | 15 | **11** | Tài liệu đầy đủ; vẫn cần rà soát copy 9/10 bước và mobile trước demo. |
| **Tổng** | **100** | **82** | **Đạt minimum, handoff kèm caveat.** |

## Bằng chứng chạy thật

| Kiểm chứng | Kết quả thực tế | Kết luận |
| :--- | :--- | :--- |
| `make quality` | `1145 passed, 44 deselected`; coverage `84.86%`; ruff sạch; mypy sạch; pip-audit không thấy CVE đã biết | PASS |
| Bandit `-lll` trên `src/project_sentinel` | Exit 0 | PASS |
| `make up` trên cổng mặc định | Fail vì `127.0.0.1:8000` đang bị Docker process cũ chiếm | ENV/READINESS FAIL |
| `make agent-test` trên cổng mặc định | Fail vì `127.0.0.1:9080` đang bị Docker process cũ chiếm | ENV/READINESS FAIL |
| Stack cô lập `18000/19080` | Web, WebGoat, Gateway probe và Gateway DAST lên; Web/Gateway/WebGoat healthy | PARTIAL PASS |
| ZAP cold-start sau fix | API/health lên trong khoảng 11 giây; DAST run có finding ZAP | PASS |
| Gateway live | `8 passed` | PASS |
| Gateway policy thật | `15 passed, 1 deselected`; request chunked giả mạo kiểm riêng trả HTTP 400 | PASS |
| Run mới `20260824T083544Z` | 10/10 bước `done`, 140,0 s, 37 finding (23 SAST, 14 ZAP), report sinh thành công | PASS; một LLM call timeout nên analysis ghi `PARTIAL` |
| Validate run mới | `Validated 14 analysis records successfully.` | PASS |
| Ground-truth scoring run mới | Scanner 14/75; tới báo cáo cuối 11/75; Agent làm mất 3 lỗ hổng đã biết | FAIL về recall |
| KB coverage/search | 17 entry Tier 2; 9 có rule, 8 chưa có; truy vấn SQL Injection trả 5 kết quả | PASS, còn thiếu rule |

Run mới dùng DAST thật sau khi sửa readiness của ZAP. Nó là bằng chứng scan → normalize → verify →
analyze → propose → report → finalize; proposal/probe bị skip đúng policy vì không có objective
được chứng minh bởi route evidence.

## Đối chiếu yêu cầu tối thiểu PDF

| Yêu cầu tối thiểu | Trạng thái | Bằng chứng / caveat |
| :--- | :---: | :--- |
| Chạy SAST hoặc DAST | ✅ | OpenGrep và ZAP chạy thật trong run `20260824T083544Z`. |
| Chuẩn hóa kết quả quét | ✅ | OpenGrep/ZAP normalizer và merge pipeline có schema, provenance. |
| Agent tạo báo cáo bảo mật | ⚠️ | Có report thật, nhưng verifier làm mất TP và một giải thích `Runtime.exec` sai kỹ thuật. |
| Custom Python Tool | ✅ | Safe Probe có allowlist, rate limit, timeout, response cap, audit. |
| Request qua API Gateway | ✅ | Gateway live/policy tests đạt; run mới an toàn skip request vì không có objective có evidence. |
| Allowlist endpoint | ✅ | Python + Nginx enforce method/path/template/body. |
| Phê duyệt thủ công | ✅ | CLI dừng và chỉ tiếp tục sau khi nhập `approve`; fingerprint/idempotency có thật. |
| Kiểm thử Prompt Injection | ✅ | Có unit/integration acceptance; output không tin cậy được scrub trước tái sử dụng. |
| Che dữ liệu nhạy cảm | ✅ | Redaction chokepoint cho LLM và log; secret live không bị in trong quá trình review. |
| README và demo cuối kỳ | ⚠️ | Có tài liệu/demo tốt, nhưng nội dung 9 bước, số test và mobile còn cần rà soát. |

Project đáp ứng đủ mặt chức năng để được xem là hoàn thành theo minimum. Hai dấu ⚠️ cần được nêu
trung thực trong phần giới hạn của buổi mentor.

## Findings theo mức ưu tiên

### P0 — phải sửa trước handoff

#### 1. Bước `verify` làm mất lỗ hổng thật

- Code loại finding khi LLM trả `false_positive + high` tại
  `src/project_sentinel/triage/rules.py:21-28` và
  `src/project_sentinel/triage/verifier.py:163-178`.
- Run thật: 23 finding → giữ 14, loại 9.
- Đối chiếu `eval/ground-truth/webgoat-findings.json`: 5/9 quyết định loại không phải false
  positive; gồm `opengrep-008`, `012`, `015`, `018` là true positive và `003` là needs review.
- Bốn rationale loại TP chỉ dựa vào việc code nằm trong WebGoat/bài học bảo mật. Đây không phải
  bằng chứng false positive; WebGoat cố ý chứa lỗ hổng thật.
- Recall cuối giảm từ scanner 14/75 xuống report 11/75.
- Test LLM hiện chỉ kiểm số lượng không vượt input, schema hợp lệ và không chứa payload tại
  `tests/integration/test_verify_step.py:40-132`; không có gate precision/recall cho verifier.

**Sửa đề xuất:** trước mentor, không cho LLM xoá finding. Đổi `verify` thành annotation
(`suspected_false_positive`) và vẫn đưa toàn bộ finding qua `analyze`. Chỉ suppress tự động khi
có luật tất định hoặc ground-truth gate với false-negative bằng 0 trên bộ 23 case. Thêm eval chạy
toàn orchestrator, vì `make eval` hiện gọi trực tiếp CLI `analyze` tại `eval/run_eval.py:307-318`
nên không hề kiểm bước `verify`.

#### 2. Proposal an toàn nhưng không liên quan finding — đã sửa

- `validate_objective` hiện yêu cầu path của objective xuất hiện trong URL runtime evidence thuộc
  chính finding; danh sách evidence rỗng bị từ chối.
- Kiểm này chạy ngay sau LLM và chạy lại ở `step_propose` khi đọc artifact, trước approval/network
  I/O. Operator override vẫn là một hành động người vận hành chủ động, chịu allowlist riêng.
- Run `20260824T083544Z` từ chối 12 objective không liên quan và tạo `proposal.json` an toàn:
  “Agent không đề xuất bước kiểm chứng nào.”

**Caveat:** demo một probe thành công cần finding có runtime evidence khớp một route đã review;
không được bịa route chỉ để tạo request.

#### 3. Tài liệu/UI nói 9 bước trong khi runtime có 10

Runtime hiện là `scan → normalize → verify → analyze → propose → approval → probe → scrub → report
→ finalize`, nhưng README, architecture, demo guide, CLI help và UI vẫn ghi 9 bước. Các vị trí nổi
bật: `README.md:32,270,348`, `docs/architecture.md:27,229,275`,
`DEMO_MENTOR_GUIDE_VI.md:80,101,470,548,594`, `src/project_sentinel/cli.py:8,70`,
`web/templates/console.html:14,28,140`.

UI desktop render 10 station nhưng `finalize` rơi xuống hàng thứ hai dưới tiêu đề “Tiến trình chín
bước”. Đây là lỗi mentor nhìn thấy ngay.

**Sửa đề xuất:** sau khi quyết định giữ hay bỏ verify, cập nhật đồng bộ mọi consumer. Không sửa
`reports/week-XX/` vì đó là báo cáo lịch sử; thêm note superseded nếu cần.

### P1 — nên sửa để demo ổn định

#### 4. Startup có thể báo thành công giả và chưa xử lý cổng bận — giảm rủi ro, còn theo dõi

- `make up` và `make agent-test` thất bại trên máy hiện tại do cổng 8000/9080 bị Docker process cũ
  chiếm; thông báo chưa chỉ rõ container/process nào cần xử lý.
- Vòng chờ `Makefile:265-272` chỉ nhìn Gateway 401, hết 30 lần vẫn luôn in “Project Sentinel is
  running”; không fail nếu Gateway chưa ready và không kiểm Web UI/ZAP.
- ZAP cold-start trước đây bị auto-update add-on chặn API bind. Compose nay dùng `-silent` và
  readiness đủ dài; API/health đã lên trong khoảng 11 giây ở live run.

**Sửa đề xuất:** thêm `make doctor`/preflight kiểm cổng, Docker, submodule, key; dùng
`docker compose up --wait --wait-timeout ...`; sau loop phải exit 1; in `docker compose ps` và log
service lỗi. Handoff gate phải kiểm Web UI 200, Gateway unauth 401, Gateway auth 200, WebGoat và ZAP
healthy.

#### 5. Metric LLM bỏ sót toàn bộ chi phí bước verify

- Run mới thực hiện 23 lời gọi verify + 16 lời gọi analyze, tức tối thiểu 39 call.
- `metrics.json` và `report.md` chỉ ghi 16 call; token usage 137.827 chỉ tính analyze.
- `orchestrator/metrics.py:16,96-109,143-162` chỉ đọc `analysis-summary.json` và xem duy nhất
  `analyze` là LLM step.

Feature verify vì vậy trông như giảm call/cost, nhưng số liệu hiện không chứng minh được. So với
artifact cũ, analyze token chỉ giảm từ 147.670 xuống 137.827 trong khi verify token bị mất hoàn
toàn; tổng cost có khả năng tăng.

**Sửa đề xuất:** provider phải trả usage cho verify; `verify-summary.json` ghi call/token/retry;
metrics cộng theo từng stage và UI hiển thị breakdown. Đặt budget/circuit breaker theo run.

#### 6. Một số kết luận văn xuôi vẫn sai dù schema/provenance đúng

Run mới nói `Runtime.exec(String)` có thể nối lệnh bằng `;` hoặc `&&` tại
`artifacts/runs/20260824T070606Z/report.md:34-40`. Ground truth của project nêu đúng rằng
`Runtime.exec(String)` không tự gọi shell, nên các ký tự đó không tạo shell chaining trong trường
hợp này. KB Tier 2 tại `data/knowledge-base/tier2/java-runtime-exec.md:28-32` cũng đang diễn đạt
lẫn giữa tokenization và shell interpretation.

**Sửa đề xuất:** sửa KB theo đúng semantics Java; thêm validator/eval cho caveat này; tránh claim
khai thác cụ thể khi không thấy `/bin/sh -c`, `cmd.exe /c` hoặc shell tương đương.

#### 7. Web cho phép tạo nhiều run tốn tiền đồng thời

Mỗi POST `/runs` tạo run mới và background task ngay tại `web/main.py:64-69`. Khoá hiện tại chỉ
chống resume trùng trong cùng một run, không chống double-click hoặc nhiều run đồng thời. Hai nút
start ở `base.html:23-25` và `console.html:17-21` không có idempotency key/disable state.

**Sửa đề xuất:** global single-flight hoặc queue có giới hạn; idempotency token cho POST; disable
nút ngay khi submit; hiển thị cost estimate và run đang hoạt động.

#### 8. Policy “không test double/không skip” không khớp repository

- `tests/test_no_doubles.py:35-47` chỉ bắt tên class bắt đầu bằng Fake/Mock/Stub/Dummy.
- `ScriptedProvider` ở `tests/unit/triage/test_verifier.py:56-75` trả response dựng sẵn, không gọi
  mạng; `RecordingProvider` và nhiều Counting/Exploding transport có cùng bản chất.
- Có `pytest.mark.skipif` khi submodule/doc vắng tại
  `tests/integration/test_recall_scoring.py:62-65`,
  `tests/unit/analysis/test_evidence_window_reaches_entry_point.py:31-34` và
  `tests/test_docs_are_honest.py:41-58`.

Đây không phải lỗi theo PDF, nhưng vi phạm chính policy nội bộ mà project tuyên bố. Cần chọn một
trong hai: cho phép pure in-memory test doubles với taxonomy rõ, hoặc thay chúng bằng real
dependency tests. Không nên đổi tên class để lách AST guard.

### P2 — cải thiện sau khi chốt correctness

#### 9. UI desktop tốt, mobile bị overflow

**Điểm UI: 7,3/10** (desktop 8,5; mobile 4,0; accessibility/feedback 7,0).

Điểm mạnh: visual hierarchy rõ, dark security-console hợp ngữ cảnh, state color nhất quán, history,
approval queue, evidence tabs và log live dễ đọc. UI có `lang=vi`, viewport, focus-visible,
`prefers-reduced-motion`, ARIA cho nav/tab/log.

Ở viewport 390×844, tiêu đề, mô tả và bảng bị cắt ngang; ảnh review cho thấy card rộng hơn màn
hình. CSS responsive chỉ có vài rule tại `style.css:1357-1366`, trong khi table có
`min-width:720px` tại `style.css:438`. Cần thêm `min-width:0` cho flex/grid child, giới hạn overflow
trong `.table-wrap`, chuyển history thành card/compact columns trên mobile và kiểm breakpoint
390/768/1024.

UI run còn chưa đưa “DAST skipped” và “9 finding bị verify loại” thành warning cấp cao; trạng thái
`DONE`, error `0` dễ khiến người xem bỏ qua suy giảm. Nên có badge `DEGRADED`/`SAST ONLY`, metric
`verified/dropped`, và liên kết tới rationale.

#### 10. Image runtime cài cả dependency phát triển

Build sạch mất khoảng 244,5 s; image web 165,6 MB và chứa `pytest`, `mypy`, `pip-audit`. Dockerfile
cài toàn bộ `requirements.txt`. Tách `requirements-runtime.txt` hoặc dependency group/multi-stage
để cold build và attack surface nhỏ hơn. Đây là tối ưu sau P0/P1, không phải lý do chặn riêng.

#### 11. README/test count đã cũ

README và demo guide ghi `1051 passed`, coverage `83.8%`; thực tế hiện là 1.140 passed, 85,08%.
Nên tránh hard-code số biến động hoặc sinh bảng evidence tự động từ `make handoff-check`.

## Phần làm vượt yêu cầu PDF

### Vượt yêu cầu có giá trị

- Cả SAST và DAST dù minimum chỉ cần một.
- Hai lane Gateway, template/body binding và enforce độc lập ở Python + Nginx.
- Provenance, schema validation, output safety và calibration sau LLM.
- KB hai tầng, recall ground truth, eval lặp, persistent artifact/state và UI lịch sử.
- Idempotency cho resume/probe, audit/redaction và threat model rõ.

Những phần này nên giữ; chúng là điểm khác biệt tốt khi trình bày với mentor.

### Vượt yêu cầu nhưng hiện gây hại hoặc chưa chứng minh giá trị

- LLM verifier riêng trước analysis: không nằm trong PDF, thêm 23 call, làm mất TP và chưa được
  eval end-to-end.
- ZAP daemon sống lâu: tăng cold-start/ops complexity để phục vụ DAST baseline; auto-update add-on
  đã bị tắt để API bind deterministically.
- Concurrency LLM cao và nhiều lớp artifact/metric nhưng cost accounting chưa theo kịp.

Không nên thêm Multi-Agent, MCP/A2A, Hybrid Search, GraphRAG, LangFuse hay LLM-as-a-Judge lúc này;
PDF nêu rõ đó là phần mở rộng. Chúng không sửa được recall 14,7% hay false-negative gate.

## Đánh giá phần chưa commit

Scope đã review:

- `Makefile`: bỏ `--build` mặc định khỏi `make up`, thêm `make up-build`.
- `README.md`: giải thích cache/rebuild.
- `tests/unit/infra/test_makefile_startup.py`: 2 test dry-run cho command shape.

**Kết luận:** hướng thay đổi đúng và 2 test đã nằm trong run `make quality` xanh. Nó giảm thời gian
restart hằng ngày, không làm thay đổi security boundary. Tuy nhiên chưa đủ để gọi startup ổn định:
test chỉ chứng minh có/không có `--build`, không bắt false-success của health loop, cổng bận hoặc
ZAP unhealthy. Nên giữ diff này và bổ sung readiness/doctor ở task riêng; không gộp sửa lớn vào
commit cache nếu muốn review dễ.

## Thứ tự sửa khuyến nghị

### Trước mentor — bắt buộc

1. Tắt khả năng auto-drop của verify; thêm ground-truth regression gate và chạy lại score.
2. Hoàn tất: chặn proposal không liên quan trước network I/O; run mới nói thẳng khi không có probe
   phù hợp. Cần bổ sung scenario evidence hợp lệ nếu muốn demo probe.
3. Đồng bộ 10 bước trên README/docs/CLI/UI; cập nhật UI rail.
4. Hoàn tất phần ZAP readiness và đã có artifact full DAST mới; còn `make up` fail-loud/port
   preflight là hardening riêng.
5. Sửa metric LLM để đếm verify; cập nhật evidence hiện tại.
6. Fix mobile overflow và hiển thị `DEGRADED/SAST ONLY` rõ.

### Sau mentor — tăng giá trị sản phẩm

1. Thêm rule SAST cho 8 Tier-2 entry chưa có rule; ưu tiên CWE-79, CWE-22, CWE-352, CWE-347.
2. Đo `attacker_control` độc lập để lấy lại severity high/critical một cách có bằng chứng.
3. Queue/single-flight cho web run; cost budget và cancellation.
4. Tách runtime/dev dependencies và thêm deploy target nếu sản phẩm cần dùng ngoài local demo.

## Handoff gate đề xuất

Chỉ handoff khi tất cả điều sau có bằng chứng mới:

- `make quality` xanh.
- `make up-build` trên môi trường sạch; tất cả 5 service healthy trong timeout hữu hạn.
- Web 200; Gateway unauth 401; request allowlisted auth 200; forbidden/chunked bị chặn.
- Một run hiện tại có SAST + DAST, manual approval, report, schema valid, không `PARTIAL`/`DEGRADED`.
- Verifier không làm mất bất kỳ true positive/needs-review nào trong bộ ground truth 23 finding.
- Metric đếm đủ verify + analyze calls/tokens.
- Probe verdict không phải `unrelated_endpoint`.
- UI kiểm desktop 1440 và mobile 390 không overflow; copy nói đúng số bước.
- README/demo guide khớp command và evidence mới.

**VERDICT cuối:** `PASS MINIMUM WITH CAVEATS — có thể handoff nếu trình bày rõ verifier vẫn cần
ground-truth regression gate, metric LLM chưa đủ và UI/docs cần rà soát cuối.`
