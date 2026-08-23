# Week 6 — Tích hợp, đánh giá và bàn giao

**Ngày:** 2026-08-23 · **Lần chạy tham chiếu:** `20260823T111417Z` · **Model:** `qwen/qwen3-235b-a22b-2507` · **Target:** OWASP WebGoat `v2025.3`

> Mọi con số trong báo cáo này lấy từ một lần chạy đầu-cuối có thật, chạy trong Docker,
> có LLM thật và có người bấm duyệt. Không có số nào được ước lượng hay chép lại từ lần
> chạy cũ. Muốn kiểm chứng: `make up` rồi `make run`, đối chiếu với
> `artifacts/runs/20260823T111417Z/metrics.json`.

---

## 1. Kết quả trong một trang

```text
  ĐẦU VÀO                     XỬ LÝ                        ĐẦU RA
  ┌──────────────┐            ┌────────────────┐           ┌──────────────────┐
  │ WebGoat      │  23 SAST   │  Agent + KB    │  34 record│ report.md        │
  │ v2025.3      │ ─────────► │  41 lời gọi LLM│ ────────► │ metrics.json     │
  │ 3 rule SAST  │  14 DAST   │  4 lớp kiểm    │  3 nhóm   │ events.jsonl     │
  │ 17+17 doc KB │ ─────────► │  tất định      │  bị loại  │ gateway-req.jsonl│
  └──────────────┘   = 37     └────────────────┘           └──────────────────┘
                                       │
                                       ▼
                              1 request qua Gateway
                              người duyệt: cli-operator
```

| Hạng mục | Số đo | Nguồn |
| :--- | ---: | :--- |
| Cảnh báo thô | **37** (23 SAST + 14 DAST) | `metrics.json → findings_by_tool` |
| Record phân tích | **34/37 nhóm** | `analysis-summary.json` |
| Thời gian toàn luồng | **355,0 s** | `metrics.json → total_elapsed_ms` |
| Request qua Gateway | **1**, bị chặn **0** | `metrics.json → requests_total` |
| Người phê duyệt | **cli-operator** (người thật gõ `approve`) | `metrics.json → approvals` |
| Lỗi LLM / ứng dụng | **0 / 0** | `metrics.json → errors` |
| Bộ kiểm thử | **1051 test xanh**, coverage **83,8 %** | `make quality` |
| Bộ đánh giá Agent | **13/13 ca**, 39/39 lượt | `make eval` |

---

## 2. Luồng chín bước — đã chạy trọn vẹn

```text
   GIAI ĐOẠN 1 — không có gì rời khỏi hệ thống
   ┌────────────────────────────────────────────────────────────────┐
   │ 1 scan       OpenGrep + ZAP daemon     10,88 s  → 37 cảnh báo │
   │ 2 normalize  chuẩn hoá + đối chiếu      0,17 s   → findings.json│
   │ 3 analyze    Agent + kho tri thức     343,87 s   → 34 record   │
   │ 4 propose    Agent đề xuất request      0,01 s   → proposal.json│
   └───────────────────────────┬────────────────────────────────────┘
                    ┌──────────▼──────────┐
                    │  5  CỔNG PHÊ DUYỆT  │  luồng DỪNG, hỏi người
                    │  mặc định = TỪ CHỐI │  → ĐÃ DUYỆT (cli-operator)
                    └──────────┬──────────┘
   GIAI ĐOẠN 2 — có traffic thật │
   ┌───────────────────────────▼────────────────────────────────────┐
   │ 6 probe      POST /WebGoat/attack qua Gateway → HTTP 302       │
   │ 7 scrub      quét injection + che PII         → scrubbed.json  │
   │ 8 report     dựng báo cáo cho người đọc       → report.md      │
   │ 9 finalize   chốt số liệu                     → metrics.json   │
   └────────────────────────────────────────────────────────────────┘
```

Thời gian từng bước, đo thật (`metrics.json → step_elapsed_ms`, đơn vị giây):

```text
  analyze   ████████████████████████████████████████████  343,87  (96,9 %)
  scan      █▍                                             10,88  ( 3,1 %)
  normalize ▏                                               0,17
  probe     ▏                                               0,03
  approval  ▏                                               0,02
  report    ▏                                               0,02
  propose   ▏                                               0,01
  scrub     ▏                                               0,00
```

**Bước `analyze` chiếm 96,9 % thời gian.** Đây là giới hạn thông lượng của LLM, không phải
giới hạn đúng/sai. Khi trình diễn, đừng chạy `analyze` trực tiếp trước mặt người xem.

---

## 3. SAST và DAST — hai nguồn, một báo cáo

Tuần này DAST được đưa vào **cùng một bước `scan`**, không phải một quy trình rời.

| Nguồn | Công cụ | Cảnh báo | Đơn vị đếm |
| :--- | :--- | ---: | :--- |
| SAST | OpenGrep 1.26.0, 3 rule Java | **23** | một dòng mã |
| DAST | OWASP ZAP 2.17.0 (spider + passive) | **14** | một loại cảnh báo trên URL |

DAST đo thêm: **27 endpoint** phát hiện được, **56 instance**.

> **Hai con số 23 và 14 không cùng đơn vị.** Một finding SAST gắn với một dòng mã; một
> cảnh báo ZAP gắn với một URL và có thể lặp trên nhiều instance. Cộng thành 37 là để tiện
> theo dõi, không phải một đại lượng có nghĩa.

### 3.1 DAST làm Gateway có tác dụng thật

Điểm quan trọng nhất của việc thêm DAST: **WebGoat được chạy thật, nên Gateway đứng trước
nó mới có việc để làm.** Đối chiếu tĩnh ↔ động trên 23 finding SAST:

```text
  reachable                ████████████████████████████████████  17   (73,9 %)
  route_known_not_reached  ████                                   2   ( 8,7 %)
  no_route                 ████████                               4   (17,4 %)
```

`reachable` nghĩa là endpoint **tồn tại và chạm tới được qua Gateway**, đã được chứng minh
bằng request thật. Nó **không** có nghĩa lỗ hổng đã được chứng minh — xem mục 6.

Bằng chứng nằm ở `gateway-access.log` của chính lần chạy: **40 dòng**, trong đó **11 request
POST trả HTTP 200**, và **0 request bị chặn vì vượt giới hạn tốc độ**.

---

## 4. Chất lượng Agent — đo trên 23 cảnh báo WebGoat thật

Bộ nhãn do người review đặt cho từng cảnh báo OpenGrep (`eval/ground-truth/`).

### 4.1 Scanner — thuộc tính của OpenGrep, không phải của Agent

```text
  true_positive   █████████████  13
  false_positive  ██████          6
  needs_review    ████            4
                                 ──
                                 23     Precision (chặt) = 56,5 %
```

### 4.2 Agent triage

| Chỉ số | Số đo | Đọc thế nào |
| :--- | ---: | :--- |
| Finding khớp được record | 20/23 | 3 finding nằm trong nhóm bị loại (mục 5) |
| Label accuracy | **55,0 %** | accuracy nhiều lớp, **không phải** precision |
| Over-claim rate | **20,0 %** | 1 dương tính giả bị trình bày như lỗ hổng thật |
| `category` đúng | **20/20 — 100 %** | tên loại lỗ hổng chuẩn hoá bằng luật Python |
| `severity` đúng | 4/20 — 20,0 % | xem giải thích ngay dưới |
| `attacker_control` đúng | 7/20 — 35,0 % | xem giải thích ngay dưới |

**`severity` và `attacker_control` thấp là hệ quả có chủ ý, không phải Agent kém.** Vì
`attacker_control` chưa có phép đo độc lập, tầng Python kẹp cứng nó về `not_proven`, kéo
theo trần severity xuống `medium`. Hệ thống **không còn phát ra `high` hay `critical`** —
phân bố thật của lần chạy này là `medium 22, low 6, info 6`. Bộ nhãn người review thì có
nhãn `high`/`critical`, nên độ khớp tất yếu giảm. Đánh đổi: một `medium` trung thực đổi lấy
một `high` không có bằng chứng.

### 4.3 Recall — câu hỏi bộ nhãn 23 finding không trả lời được

Bộ nhãn trên trả lời "cái được báo có thật không". Nó **không** trả lời "cái có thật có
được tìm ra không". Đối chiếu với 75 lỗ hổng đã biết của WebGoat:

```text
  Scanner tìm tới        ███████                14/75   18,7 %
  Tới được báo cáo cuối  ██████                 13/75   17,3 %
  Bỏ sót                 ██████████████████████ 61/75
```

**Đây là con số cần nhìn trước tiên.** Hệ thống chỉ thấy 18,7 % số lỗ hổng có thật, vì bộ
rule chỉ có **3 rule**. Precision cao chỉ có nghĩa *"những gì nó tình cờ thấy thì nó đọc
khá đúng"*. **Đừng dùng "không tìm thấy gì" như bằng chứng rằng mã nguồn đã sạch.**

Một lỗ hổng scanner đã tìm ra nhưng không tới được báo cáo cuối (14 → 13): nó nằm trong
một nhóm bị loại ở mục 5.

---

## 5. Ba nhóm không ra được record — nói thẳng

`completeness` của lần chạy này là **`PARTIAL`**, không phải `COMPLETE`. 3/37 nhóm không
sinh được record và **những finding trong đó không có mặt trong báo cáo cuối**:

| Nhóm | Lý do bị loại |
| :--- | :--- |
| 1 | `schema`: model trả về JSON sai schema, thử lại một lần vẫn sai |
| 2 | `provenance`: trích đoạn mã nguồn bị đổi so với đầu vào — luật chống bịa bắt được |
| 3 | `schema`: `analysis_id` sai định dạng thập lục phân |

Cả ba được ghi trong `analysis-summary.json → unresolved_group_reasons`, và `report.md`
của lần chạy in một dải cảnh báo đậm. Hệ thống **mất dữ liệu một cách có ghi nhận**, không
im lặng.

Trong 41 lời gọi LLM có **3 phản hồi không hợp lệ** và **1 phản hồi bị chặn vì chứa payload
khai thác** — bộ lọc an toàn đầu ra hoạt động.

---

## 6. Bốn lớp chặn bịa đặt — và chỗ còn thủng

Đầu ra của LLM bị coi là **dữ liệu không đáng tin**, đi qua bốn lớp kiểm tất định:

| Lớp | Chặn cái gì | Bằng chứng ở lần chạy này |
| :--- | :--- | :--- |
| JSON Schema | Sai cấu trúc | 3 phản hồi bị loại |
| Provenance | Bịa finding ID, vị trí, CWE, trích đoạn mã | 1 nhóm bị loại vì sửa trích đoạn |
| Output safety | Payload khai thác trong lời khuyên | 1 phản hồi bị chặn |
| Calibration | Kết luận vượt quá bằng chứng | severity trần `medium`, không record nào `confirmed` |

Kho tri thức cũng là một ràng buộc, không phải ngữ cảnh thụ động: **33/34 record trích dẫn
tài liệu KB**, và khi tra được tài liệu Tier 2 theo `rule_id` thì record **bắt buộc** phải
trích nó, nếu không sẽ bị loại như lỗi provenance.

**Chỗ còn thủng, phải nói rõ:** `attacker_control` là trường Agent tự khai, không có phép
đo độc lập. Vì thế Python kẹp cứng nó về `not_proven` thay vì tin. Đó là cách chặn, không
phải cách chứng minh — muốn khôi phục khả năng xếp ưu tiên theo mức nghiêm trọng thì phải
có `measured_attacker_control`.

---

## 7. Kho tri thức hai tầng

| Tầng | Số tài liệu | Trả lời câu hỏi |
| :--- | ---: | :--- |
| Tier 1 | **17** | Loại lỗ hổng này là gì |
| Tier 2 | **17** | API/header cụ thể này nguy hiểm khi nào, và **khi nào không** |

Tier 2 được tra bằng **khoá tất định** (`rule_id` của scanner, rồi `cwe`), không phải khớp
từ khoá. Độ phủ hiện tại (`make kb-coverage`):

```text
  Entry Tier 2        : 17
  Neo theo rule SAST  :  3
  Neo theo plugin DAST:  6
  Chưa có rule        :  8   ← KB đi trước công cụ, đây là khoảng trống có chủ ý
```

Tám entry chưa có rule là danh sách việc cần làm để nâng recall, không phải nợ kỹ thuật.

---

## 8. Kiểm thử

| Nhóm | Số test |
| :--- | ---: |
| Phân tích và chống bịa | 209 |
| Guardrails (injection, che PII, phê duyệt) | 137 |
| Tích hợp (Gateway thật, WebGoat thật) | 116 |
| Truy xuất và kho tri thức | 90 |
| Giao diện web | 73 |
| Gateway và allowlist | 64 |
| Bất biến hạ tầng | 47 |
| DAST client | 15 |
| **Tổng chạy được không cần LLM** | **1051** |

Coverage **83,8 %** (ngưỡng 78 %). `ruff` và `mypy` sạch. `pip-audit` không tìm thấy lỗ
hổng phụ thuộc.

Bộ đánh giá Agent: **13/13 ca đạt, 39/39 lượt** qua 3 lần lặp. Lưu ý trung thực: ở một đợt
đo trước đó, ca `12-confirmed-needs-evidence` chỉ đạt 2/3 — kết quả bộ đánh giá **có dao
động** vì mỗi ca gọi LLM thật. Vì vậy `make eval` mặc định chạy lặp 3 lần và tính theo đa số.

---

## 9. Đối chiếu tiêu chí hoàn thành Tuần 6

| Tiêu chí đề bài | Trạng thái | Bằng chứng |
| :--- | :---: | :--- |
| Hệ thống chạy được bằng một quy trình rõ ràng | ✅ | `make up` rồi `make run` |
| Có ít nhất một luồng hoàn chỉnh từ quét đến báo cáo cuối | ✅ | `20260823T111417Z`, 9/9 bước `done` |
| Không kiểm thử ngoài môi trường được cấp phép | ✅ | WebGoat không publish cổng; 13 test bất biến mạng |
| Có cơ chế phê duyệt cho request rủi ro | ✅ | `decided_by: cli-operator`, mặc định TỪ CHỐI |
| Có kiểm thử cho Guardrails và che dữ liệu | ✅ | 137 test, gồm 6 ca bắt buộc của Tuần 5 |
| Thành viên khác chạy lại được theo README | ✅ | clone sạch → `make agent-test` xanh trong 32 s |

---

## 10. Giới hạn còn tồn tại

1. **Recall 18,7 %.** Chỉ 3 rule SAST. Đây là giới hạn lớn nhất của sản phẩm.
2. **Không phát ra được `high`/`critical`** vì `attacker_control` bị kẹp cứng — mất khả
   năng xếp ưu tiên theo mức nghiêm trọng.
3. **`completeness: PARTIAL`.** 3/37 nhóm mất ở lần chạy này; tỷ lệ dao động giữa các lần.
4. **DAST chỉ baseline** (spider + passive scan), không active scan. Chứng minh được
   endpoint chạm tới được, không chứng minh được lỗ hổng khai thác được.
5. **Khoá DAST theo vòng đời stack**, không theo từng lần quét — hệ quả của việc chuyển
   ZAP thành daemon.
6. **ZAP daemon đôi khi bỏ qua `-port`** và bind cổng ngẫu nhiên trên localhost; đã thêm
   healthcheck để lỗi hiện ra thay vì im lặng. Chưa tìm ra nguyên nhân gốc.
7. **Kết quả LLM dao động** giữa các lần chạy. Mọi con số trong báo cáo này là **một lần
   lấy mẫu**, không phải hằng số.

---

## 11. Chạy lại

```bash
# Toàn bộ stack: WebGoat, Gateway (2 lane), ZAP daemon, giao diện web
export SENTINEL_GATEWAY_API_KEY="$(openssl rand -hex 32)"
make up

# Luồng chín bước. DỪNG ở cổng phê duyệt và hỏi bạn.
make run

# Kiểm thử không cần LLM
make quality              # 1051 test + ruff + mypy + coverage + audit
make agent-test           # test trên Gateway và WebGoat thật

# Đo chất lượng Agent
make eval                                                   # 13 ca, lặp 3 lần
make score-ground-truth ANALYSIS=artifacts/runs/<id>/analysis.jsonl
make kb-coverage                                            # độ phủ kho tri thức
```

---

## 12. Đề xuất cải tiến, theo thứ tự giá trị

1. **Thêm rule SAST.** Recall 18,7 % là trần của toàn hệ thống; mọi cải thiện khác đều bị
   nó chặn trên. Tám entry Tier 2 chưa có rule ở mục 7 là danh sách sẵn có.
2. **Đo `attacker_control` thay vì kẹp cứng.** Lấy lại khả năng xếp ưu tiên theo mức
   nghiêm trọng, và làm `severity` khớp bộ nhãn trở lại.
3. **Giảm tỷ lệ nhóm bị loại.** 3/37 nhóm mất là dữ liệu người đọc không bao giờ thấy.
4. **Rút ngắn bước `analyze`.** 96,9 % thời gian nằm ở đây; song song hoá theo nhóm là
   đường rõ nhất.
