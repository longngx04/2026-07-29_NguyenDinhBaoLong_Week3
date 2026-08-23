# DAST chạy từ giao diện — đo và trạng thái

**Ngày:** 2026-08-23 · **Spec:** `docs/superpowers/specs/2026-08-23-dast-daemon-api-design.md`

## 1. Vấn đề gốc

Bấm quét từ giao diện luôn chỉ ra 23 finding SAST. Nhật ký lần chạy `20260823T084826Z`:

```text
[warn] Bo qua DAST: Bước scan thất bại (mã 127): Docker is required to run the real ZAP Baseline scan.
```

Hai tầng nguyên nhân: container `web` không có Docker CLI (mà `scan-zap.sh` cần
`docker compose`), và `make up` không bật profile `dast` nên `gateway-dast` với `zap`
không tồn tại.

## 2. Đã kiểm chứng bằng chạy thật

| Chỉ số | Trước | Sau |
| :--- | ---: | ---: |
| Client chạy từ container `web` | không chạy được | **thành công** |
| Bằng chứng Gateway DAST | — | **40 dòng**, đều `channel=dast` |
| Finding sau chuẩn hoá | 0 | **10** |
| Docker CLI trong `web` | không có | **không có** |
| `/var/run/docker.sock` trong `web` | không có | **không có** |
| Cổng host của ZAP | — | **không có** (chỉ `8090/tcp` nội bộ) |
| `make quality` | xanh | **xanh** |

Ba dòng cuối là **điều kiện phủ định**: nếu chúng đổi thì thay đổi này thất bại kể cả khi
số finding đúng. Chúng được khoá bằng test trong `tests/unit/infra/test_compose_invariants.py`.

Plugin id thu được: `10009, 10020, 10021, 10024, 10027, 10031, 10036, 10038, 10109, 10202`.

## 3. Chênh lệch với luồng cũ, đã truy nguyên

Luồng `zap-baseline.py` cũ cho **14** finding; luồng mới cho **10**. Bốn plugin thiếu là
`10049`, `10063`, `10110`, `90004`.

Nguyên nhân: cả bốn nằm trong bộ `pscanrulesBeta`, **không có sẵn trong ảnh ZAP**.
`zap-baseline.py` tự tải add-on lúc khởi động; daemon trần thì không. Đã kiểm chứng: cài
`pscanrulesBeta` qua API thì cả bốn rule xuất hiện (67 rule passive thay vì 63), và client
giờ tự cài mỗi lần quét, có suy giảm mềm nếu không có mạng.

Ghi chú: **không** đặt `-addoninstall` vào `command` của container — đó là lệnh
chạy-rồi-thoát, ZAP cài xong rồi tắt và container chết. Quan sát được thật.

## 4. Chưa kiểm chứng được

**Chưa bấm quét đầu-cuối từ giao diện.** Cổng 8000 bị các tiến trình `docker-proxy` mồ côi
thuộc root giữ, còn lại sau hai lần Docker daemon đứt trong phiên làm việc. Gỡ bằng
`sudo kill <pid>` hoặc `sudo systemctl restart docker`. Đây là vấn đề môi trường, không
phải của mã: phần DAST đã được kiểm qua `docker compose run` trên cùng mạng, cùng volume,
cùng ảnh.

**ZAP daemon đôi khi bỏ qua `-port`** và bind `127.0.0.1:<ngẫu nhiên>` thay vì
`0.0.0.0:8090`. Quan sát được nhiều lần, chưa tìm ra nguyên nhân gốc. Đã thêm healthcheck
cho service `zap` để lỗi hiện ra ở `docker compose ps` thay vì để client chờ hết 300 giây
rồi báo mơ hồ. Ghi vào `docs/limitations.md`.
