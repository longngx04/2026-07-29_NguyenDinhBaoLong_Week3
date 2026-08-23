# DAST chạy được từ giao diện — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bấm quét từ giao diện web chạy được cả SAST lẫn DAST, mà container `web` vẫn không có Docker CLI và không có docker socket.

**Architecture:** ZAP đổi từ container dùng-một-lần thành daemon chạy nền, chỉ lộ API trên mạng nội bộ. Container `web` điều khiển nó qua HTTP API thay vì `docker compose`. Log của `gateway-dast` ghi thêm ra một volume dùng chung để đọc được mà không cần `docker compose logs`.

**Tech Stack:** Python 3.12 (`urllib` chuẩn thư viện, không thêm dependency), Docker Compose, nginx, ZAP 2.17.0 Automation Framework.

**Spec:** [`docs/superpowers/specs/2026-08-23-dast-daemon-api-design.md`](../specs/2026-08-23-dast-daemon-api-design.md)

## Global Constraints

- **Container `web` KHÔNG được có Docker CLI và KHÔNG được mount `/var/run/docker.sock`.** Đây là điều kiện phủ định quan trọng ngang mọi tiêu chí khác; vi phạm là task thất bại kể cả khi số finding đúng.
- ZAP **không** được khai `ports:` — API chỉ ở mạng nội bộ.
- Ảnh ZAP giữ nguyên digest đã pin: `ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2`.
- **Không thêm dependency.** Dùng `urllib.request` như `src/project_sentinel/probe/transport.py` đang làm.
- DAST **không bao giờ** làm sập một lần chạy — `step_scan` bắt lỗi và ghi `skipped`, giữ nguyên hành vi hiện tại.
- Hai kiểm tra an toàn của `scripts/scan-zap.sh` phải được giữ nguyên ngữ nghĩa: bằng chứng traffic đi qua lane DAST, và khoá DAST không rò vào báo cáo/log.
- ZAP chỉ được nhắm `gateway-dast`, không bao giờ `webgoat` trực tiếp.
- Chú thích tiếng Việt giải thích **vì sao**, theo phong cách repo. `make quality` xanh sau mỗi commit.

---

## File Structure

**Tạo mới**

| File | Trách nhiệm |
| :--- | :--- |
| `src/project_sentinel/dast/__init__.py` | Gói mới. |
| `src/project_sentinel/dast/zap_client.py` | Điều khiển ZAP daemon qua API. Không biết gì về orchestrator. |
| `infra/docker/zap/scan-plan.yaml` | Một Automation Plan: spider → requestor → passiveScan-wait. |
| `tests/unit/dast/__init__.py` | |
| `tests/unit/dast/test_zap_client.py` | Client, dùng transport giả, không cần mạng. |

**Sửa**

| File | Sửa gì |
| :--- | :--- |
| `docker-compose.yml` | `zap` thành daemon; volume log dùng chung; `web` mount `:ro`. |
| `infra/docker/gateway/templates/default.conf.template` | Lane DAST ghi log ra thêm một file. |
| `scripts/scan-zap.sh` | Thành lớp vỏ mỏng gọi client. |
| `Makefile` | `up`/`down` bật profile `dast`, sinh hai khoá mới. |
| `tests/unit/infra/test_compose_invariants.py` | Bất biến mới cho `zap` và volume log. |
| `docs/limitations.md` | Đánh đổi khoá DAST theo vòng đời stack. |
| `README.md` | Nói `make up` giờ chạy cả DAST. |

---

## Task 1: ZAP thành daemon, khoá API không bao giờ ra host

**Files:**
- Modify: `docker-compose.yml` (service `zap`)
- Modify: `tests/unit/infra/test_compose_invariants.py`

**Interfaces:**
- Consumes: không có.
- Produces: service `zap` nghe API trên `8090` trong mạng `sentinel-net`, đọc khoá từ biến môi trường `SENTINEL_ZAP_API_KEY`. Task 3 nối tới `http://zap:8090`.

- [ ] **Step 1: Viết test đỏ cho bất biến mới**

Thêm vào `tests/unit/infra/test_compose_invariants.py`:

```python
def test_zap_api_never_reaches_the_host(compose):
    """API cua ZAP dieu khien duoc mot trinh duyet tan cong. No khong duoc ra host."""
    zap = compose["services"]["zap"]
    assert "ports" not in zap, (
        "zap khai 'ports' — API se bind len host. Chi duoc dung 'expose'."
    )
    assert zap.get("expose") == ["8090"]


def test_zap_runs_as_a_daemon_with_a_key_from_the_environment(compose):
    command = " ".join(compose["services"]["zap"].get("command", "").split())
    assert "-daemon" in command
    assert "api.key=${SENTINEL_ZAP_API_KEY}" in command, (
        "Khoa API phai lay tu bien moi truong, khong duoc la hang trong file"
    )


def test_zap_still_only_ever_targets_the_dast_gateway(compose):
    """Bat bien cu, phai con xanh sau khi doi sang daemon."""
    rendered = yaml.safe_dump(compose["services"]["zap"], allow_unicode=True)
    assert "webgoat" not in rendered, "ZAP khong bao gio duoc nham thang WebGoat"
```

- [ ] **Step 2: Chạy test, xác nhận đỏ**

Run: `.venv/bin/python -m pytest tests/unit/infra/test_compose_invariants.py -k zap -v`
Expected: FAIL — `test_zap_runs_as_a_daemon_with_a_key_from_the_environment` đỏ vì `zap` chưa có `command`.

- [ ] **Step 3: Đổi service `zap` trong `docker-compose.yml`**

```yaml
  zap:
    profiles: ["dast"]
    image: ghcr.io/zaproxy/zaproxy@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2
    # Daemon chay suot vong doi stack. Container `web` khong co Docker nen no
    # khong the `docker compose run zap`; no dieu khien daemon nay qua API.
    command: >
      zap.sh -daemon -host 0.0.0.0 -port 8090
      -config api.key=${SENTINEL_ZAP_API_KEY}
      -config api.addrs.addr.name=.*
      -config api.addrs.addr.regex=true
    # `expose` chu KHONG `ports`: API cua ZAP dieu khien duoc mot trinh duyet
    # tan cong, no khong duoc xuat hien tren bat ky giao dien host nao.
    expose:
      - "8090"
    environment:
      - ZAP_AUTH_HEADER=X-Sentinel-DAST-Key
      - ZAP_AUTH_HEADER_VALUE=${SENTINEL_DAST_API_KEY:-}
    volumes:
      - ./artifacts:/zap/wrk:rw
      - ./infra/docker/zap:/zap/plans:ro
    depends_on:
      gateway-dast:
        condition: service_healthy
    networks:
      - sentinel-net
```

Mount `./infra/docker/zap:/zap/plans:ro` là để daemon đọc được plan file mà không phải copy qua `artifacts/` như script cũ đang làm.

- [ ] **Step 4: Chạy test, xác nhận xanh**

Run: `.venv/bin/python -m pytest tests/unit/infra/test_compose_invariants.py -v`
Expected: PASS toàn bộ, kể cả các test cũ.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml tests/unit/infra/test_compose_invariants.py
git commit -m "feat(dast): run ZAP as an internal daemon instead of a one-shot container"
```

---

## Task 2: Log gateway DAST thành file đọc được không cần Docker

**Files:**
- Modify: `infra/docker/gateway/templates/default.conf.template`
- Modify: `docker-compose.yml` (volume `sentinel-dast-log`, `gateway-dast`, `web`)
- Modify: `tests/unit/infra/test_compose_invariants.py`
- Modify: `tests/unit/gateway/test_dast_gateway_config.py`

**Interfaces:**
- Consumes: service `zap` (Task 1) không liên quan trực tiếp.
- Produces: file `/var/log/sentinel/dast-access.log` trong volume `sentinel-dast-log`, `web` đọc được ở chế độ chỉ đọc. Task 3 đọc đúng đường dẫn này.

- [ ] **Step 1: Viết test đỏ**

Thêm vào `tests/unit/gateway/test_dast_gateway_config.py`:

```python
def test_dast_lane_also_writes_its_log_to_a_file():
    """`docker compose logs` can Docker. Container web khong co Docker, nen bang
    chung phai nam o mot file doc duoc qua volume."""
    server = _dast_server()
    assert "access_log /dev/stdout sentinel_dast_access;" in server, (
        "Giu dong stdout de `docker compose logs` van dung duoc khi go loi tren host"
    )
    assert "access_log /var/log/sentinel/dast-access.log sentinel_dast_access;" in server
```

Thêm vào `tests/unit/infra/test_compose_invariants.py`:

```python
def test_dast_log_volume_is_shared_and_web_can_only_read_it(compose):
    """Day la BANG CHUNG. Tien trinh doc no khong duoc phep sua no."""
    assert "sentinel-dast-log" in (compose.get("volumes") or {})

    gateway_dast = compose["services"]["gateway-dast"]["volumes"]
    assert any("sentinel-dast-log:/var/log/sentinel" in v for v in gateway_dast)

    web = compose["services"]["web"]["volumes"]
    ro = [v for v in web if "sentinel-dast-log" in v]
    assert ro, "web phai mount volume log"
    assert ro[0].endswith(":ro"), f"web phai mount CHI DOC, dang la {ro[0]}"
```

- [ ] **Step 2: Chạy test, xác nhận đỏ**

Run: `.venv/bin/python -m pytest tests/unit/gateway/test_dast_gateway_config.py tests/unit/infra/test_compose_invariants.py -k "log" -v`
Expected: FAIL — chưa có dòng access_log thứ hai, chưa có volume.

- [ ] **Step 3: Sửa nginx template**

Trong khối `server { listen 8081; … }` của `infra/docker/gateway/templates/default.conf.template`, ngay dưới dòng `access_log /dev/stdout sentinel_dast_access;`, thêm:

```nginx
    # Ghi ra CA HAI noi. stdout de `docker compose logs` van dung duoc khi go loi
    # tren host; file de container `web` doc duoc bang chung ma khong can Docker.
    access_log /var/log/sentinel/dast-access.log sentinel_dast_access;
```

- [ ] **Step 4: Thêm volume vào compose**

Ở cuối `docker-compose.yml`, thêm khối `volumes` cấp cao nhất (hoặc bổ sung nếu đã có):

```yaml
volumes:
  sentinel-dast-log:
```

Trong `gateway-dast`, thêm:

```yaml
    volumes:
      - sentinel-dast-log:/var/log/sentinel
```

Trong `web`, thêm dòng thứ hai vào `volumes` đã có:

```yaml
    volumes:
      - ./artifacts:/app/artifacts
      # Chi doc: day la bang chung, tien trinh doc no khong duoc sua no.
      - sentinel-dast-log:/var/log/sentinel:ro
```

- [ ] **Step 5: Bảo đảm thư mục tồn tại trong ảnh gateway**

nginx không tự tạo thư mục log. Thêm vào `infra/docker/gateway/Dockerfile`:

```dockerfile
# nginx khong tu tao thu muc log; khong co no thi worker chet ngay khi khoi dong.
RUN mkdir -p /var/log/sentinel
```

- [ ] **Step 6: Chạy test, xác nhận xanh**

Run: `.venv/bin/python -m pytest tests/unit/gateway/ tests/unit/infra/ -v`
Expected: PASS

- [ ] **Step 7: Kiểm chứng thật**

```bash
SENTINEL_DAST_API_KEY=$(openssl rand -hex 32) \
SENTINEL_ZAP_API_KEY=$(openssl rand -hex 32) \
  docker compose --profile dast up --build --detach gateway-dast webgoat
docker compose --profile dast exec gateway-dast ls -l /var/log/sentinel/
```
Expected: thấy `dast-access.log`.

- [ ] **Step 8: Commit**

```bash
git add infra/docker/gateway/ docker-compose.yml tests/unit/gateway/test_dast_gateway_config.py tests/unit/infra/test_compose_invariants.py
git commit -m "feat(dast): write the DAST lane access log to a shared volume"
```

---

## Task 3: Client điều khiển ZAP qua API

**Files:**
- Create: `src/project_sentinel/dast/__init__.py`, `src/project_sentinel/dast/zap_client.py`
- Create: `infra/docker/zap/scan-plan.yaml`
- Create: `tests/unit/dast/__init__.py`, `tests/unit/dast/test_zap_client.py`

**Interfaces:**
- Consumes: daemon ZAP ở `http://zap:8090` (Task 1); file log ở `/var/log/sentinel/dast-access.log` (Task 2).
- Produces:
  - `class DastError(RuntimeError)`
  - `@dataclass(frozen=True) ZapConfig` với `base_url: str`, `api_key: str`, `dast_key: str`, `dast_header: str = "X-Sentinel-DAST-Key"`, `plan_path: str = "/zap/plans/scan-plan.yaml"`, `gateway_log_path: Path = Path("/var/log/sentinel/dast-access.log")`, `ready_timeout_s: float = 120.0`, `plan_timeout_s: float = 600.0`, `poll_interval_s: float = 2.0`
  - `def run_dast(report_path: Path, log_path: Path, *, config: ZapConfig, call: Callable[[str, dict[str, str]], dict] | None = None, sleep: Callable[[float], None] = time.sleep) -> None`
  - `ZapConfig.from_env() -> ZapConfig`

`call` và `sleep` được tiêm vào để test không cần mạng và không cần chờ thật.

- [ ] **Step 1: Viết plan file**

`infra/docker/zap/scan-plan.yaml` — chép **nguyên vẹn** 11 mục `requests` từ
`infra/docker/zap/requestor-plan.yaml` vào job `requestor`:

```yaml
env:
  contexts:
    - name: sentinel-dast
      urls:
        - http://gateway-dast:8081/WebGoat/
  parameters:
    failOnError: true
    progressToStdout: true

jobs:
  # 1. Spider: thay cho phan crawl cua zap-baseline.py
  - type: spider
    parameters:
      context: sentinel-dast
      url: http://gateway-dast:8081/WebGoat/login
      maxDuration: 1

  # 2. Requestor CHAY TRUOC passiveScan-wait, khac voi truoc day. Truoc day
  #    baseline va requestor la hai tien trinh ZAP roi nhau, nen phan hoi cua
  #    cac request POST khong he duoc passive scan. Dat o day thi chung duoc quet.
  #    He qua: so alert co the TANG — day la thay doi hanh vi co chu y.
  - type: requestor
    parameters:
      user: ""
    requests:
      - url: http://gateway-dast:8081/WebGoat/InsecureDeserialization/task
        method: POST
        data: "token="
      # … chép đủ 11 mục từ requestor-plan.yaml, giữ nguyên url/method/data …

  # 3. Cho passive scan chay het hang doi
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
```

- [ ] **Step 2: Viết test đỏ cho đường thuận lợi**

`tests/unit/dast/test_zap_client.py`:

```python
"""Client dieu khien ZAP daemon. Moi test dung transport gia — khong cham mang."""

import json
from pathlib import Path

import pytest

from project_sentinel.dast.zap_client import DastError, ZapConfig, run_dast

GATEWAY_LOG = "channel=dast method=GET path=/WebGoat/login status=200\n"


def _config(tmp_path: Path, **overrides) -> ZapConfig:
    log = tmp_path / "dast-access.log"
    log.write_text(GATEWAY_LOG, encoding="utf-8")
    base = {
        "base_url": "http://zap:8090",
        "api_key": "zapkey",
        "dast_key": "dastkey",
        "gateway_log_path": log,
        "ready_timeout_s": 5.0,
        "plan_timeout_s": 5.0,
        "poll_interval_s": 0.0,
    }
    base.update(overrides)
    return ZapConfig(**base)


def _fake_call(alerts=None, progress=None):
    """Transport gia: tra ve phan hoi theo path duoc goi."""
    calls: list[str] = []

    def call(path: str, params: dict) -> dict:
        calls.append(path)
        if path == "core/view/version":
            return {"version": "2.17.0"}
        if path == "replacer/action/addRule":
            return {"Result": "OK"}
        if path == "automation/action/runPlan":
            return {"planId": "7"}
        if path == "automation/view/planProgress":
            return progress or {"planId": "7", "finished": "2026-08-23", "error": []}
        if path == "core/view/alerts":
            return {"alerts": alerts if alerts is not None else []}
        raise AssertionError(f"path khong mong doi: {path}")

    call.calls = calls  # type: ignore[attr-defined]
    return call


def test_duong_thuan_loi_ghi_ra_bao_cao_va_log(tmp_path):
    report = tmp_path / "zap-alerts.json"
    out_log = tmp_path / "out.log"
    call = _fake_call(alerts=[{"pluginId": "10038", "alert": "CSP Header Not Set"}])

    run_dast(report, out_log, config=_config(tmp_path), call=call)

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert isinstance(payload["site"], list)
    assert payload["site"][0]["alerts"][0]["pluginId"] == "10038"
    assert out_log.read_text(encoding="utf-8") == GATEWAY_LOG


def test_header_dast_duoc_tiem_truoc_khi_chay_plan(tmp_path):
    """Khong tiem header thi ZAP khong qua noi gateway-dast."""
    call = _fake_call()
    run_dast(tmp_path / "r.json", tmp_path / "l.log", config=_config(tmp_path), call=call)
    assert call.calls.index("replacer/action/addRule") < call.calls.index(
        "automation/action/runPlan"
    )
```

- [ ] **Step 3: Chạy test, xác nhận đỏ**

Run: `.venv/bin/python -m pytest tests/unit/dast/test_zap_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'project_sentinel.dast'`

- [ ] **Step 4: Viết `zap_client.py`**

```python
"""Dieu khien ZAP daemon qua API noi bo.

Container `web` KHONG co Docker CLI va KHONG co docker socket — day la co y, xem
spec §1.1. Nen no khong the `docker compose run zap` nhu script cu. Thay vao do no
noi chuyen voi mot daemon ZAP chay san tren mang noi bo.

Hai kiem tra an toan o cuoi file la ban sao ngu nghia cua hai kiem tra trong
`scripts/scan-zap.sh`: bang chung traffic that su di qua lane DAST, va khoa DAST
khong ro ri ra artifact.
"""

from __future__ import annotations

import json
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PLAN = "/zap/plans/scan-plan.yaml"
DEFAULT_GATEWAY_LOG = Path("/var/log/sentinel/dast-access.log")


class DastError(RuntimeError):
    """DAST khong hoan thanh. step_scan bat loi nay va ghi `skipped`."""


@dataclass(frozen=True)
class ZapConfig:
    base_url: str
    api_key: str
    dast_key: str
    dast_header: str = "X-Sentinel-DAST-Key"
    plan_path: str = DEFAULT_PLAN
    gateway_log_path: Path = field(default=DEFAULT_GATEWAY_LOG)
    ready_timeout_s: float = 120.0
    plan_timeout_s: float = 600.0
    poll_interval_s: float = 2.0

    @classmethod
    def from_env(cls) -> "ZapConfig":
        import os

        dast_key = os.getenv("SENTINEL_DAST_API_KEY", "")
        api_key = os.getenv("SENTINEL_ZAP_API_KEY", "")
        if not dast_key or not api_key:
            raise DastError(
                "Thieu SENTINEL_DAST_API_KEY hoac SENTINEL_ZAP_API_KEY trong moi truong"
            )
        return cls(
            base_url=os.getenv("SENTINEL_ZAP_URL", "http://zap:8090"),
            api_key=api_key,
            dast_key=dast_key,
            gateway_log_path=Path(
                os.getenv("SENTINEL_DAST_LOG", str(DEFAULT_GATEWAY_LOG))
            ),
        )


def _http_call(config: ZapConfig) -> Callable[[str, dict[str, str]], dict]:
    def call(path: str, params: dict[str, str]) -> dict:
        query = urllib.parse.urlencode({**params, "apikey": config.api_key})
        url = f"{config.base_url}/JSON/{path}/?{query}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            # Khong bao gio dua `url` vao thong diep: no chua apikey.
            raise DastError(f"Goi ZAP API '{path}' that bai: {type(exc).__name__}") from exc

    return call


def _wait_until_ready(call, config, sleep) -> None:
    deadline = time.monotonic() + config.ready_timeout_s
    last: str = "chua goi duoc lan nao"
    while time.monotonic() < deadline:
        try:
            version = call("core/view/version", {}).get("version")
        except DastError as exc:
            last = str(exc)
        else:
            if version:
                return
            last = "ZAP tra ve phan hoi khong co truong version"
        sleep(config.poll_interval_s)
    raise DastError(f"ZAP daemon khong san sang trong {config.ready_timeout_s}s: {last}")


def _add_dast_key_header(call, config) -> None:
    call(
        "replacer/action/addRule",
        {
            "description": "sentinel-dast-key",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": config.dast_header,
            "matchRegex": "false",
            "replacement": config.dast_key,
        },
    )


def _run_plan(call, config, sleep) -> None:
    started = call("automation/action/runPlan", {"filePath": config.plan_path})
    plan_id = str(started.get("planId") or "")
    if not plan_id:
        raise DastError("ZAP khong tra ve planId khi chay plan")

    deadline = time.monotonic() + config.plan_timeout_s
    while time.monotonic() < deadline:
        progress = call("automation/view/planProgress", {"planId": plan_id})
        errors = progress.get("error") or []
        if errors:
            raise DastError(f"Plan ZAP loi: {errors}")
        if progress.get("finished"):
            return
        sleep(config.poll_interval_s)
    raise DastError(f"Plan ZAP khong xong trong {config.plan_timeout_s}s")


def _write_report(report_path: Path, alerts: list[dict[str, Any]]) -> None:
    # Giu nguyen hinh dang {"site": [{"alerts": [...]}]} ma zap_normalizer dang doc.
    payload = {"site": [{"@name": "sentinel-dast", "alerts": alerts}]}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    report_path.chmod(0o600)


def _assert_traffic_went_through_gateway(log_path: Path) -> None:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "channel=dast" not in text:
        raise DastError(
            "ZAP sinh ra bao cao nhung log Gateway DAST khong co dong nao — "
            "khong chung minh duoc traffic di qua lane"
        )


def _assert_key_did_not_leak(report_path: Path, log_path: Path, dast_key: str) -> None:
    for path in (report_path, log_path):
        if dast_key in path.read_text(encoding="utf-8", errors="replace"):
            raise DastError(f"Khoa DAST ro ri vao {path.name}")


def run_dast(
    report_path: Path,
    log_path: Path,
    *,
    config: ZapConfig,
    call: Callable[[str, dict[str, str]], dict] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Chay mot lan DAST day du. Nem DastError neu bat ky buoc nao that bai."""
    api = call or _http_call(config)

    _wait_until_ready(api, config, sleep)
    _add_dast_key_header(api, config)
    _run_plan(api, config, sleep)

    alerts = api("core/view/alerts", {}).get("alerts") or []
    _write_report(report_path, list(alerts))

    if not config.gateway_log_path.is_file():
        raise DastError(f"Khong thay log Gateway DAST tai {config.gateway_log_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config.gateway_log_path, log_path)
    log_path.chmod(0o600)

    _assert_traffic_went_through_gateway(log_path)
    _assert_key_did_not_leak(report_path, log_path, config.dast_key)
```

- [ ] **Step 5: Chạy test, xác nhận xanh**

Run: `.venv/bin/python -m pytest tests/unit/dast/test_zap_client.py -v`
Expected: PASS, 2 test

- [ ] **Step 6: Viết test đỏ cho các đường hỏng**

Thêm vào `tests/unit/dast/test_zap_client.py`:

```python
def test_daemon_khong_san_sang_thi_bao_loi_chu_khong_treo(tmp_path):
    def call(path, params):
        raise DastError("connection refused")

    with pytest.raises(DastError, match="khong san sang"):
        run_dast(tmp_path / "r.json", tmp_path / "l.log",
                 config=_config(tmp_path), call=call, sleep=lambda _: None)


def test_plan_loi_thi_bao_loi_kem_thong_diep_cua_zap(tmp_path):
    call = _fake_call(progress={"planId": "7", "error": ["job spider failed"]})
    with pytest.raises(DastError, match="spider failed"):
        run_dast(tmp_path / "r.json", tmp_path / "l.log",
                 config=_config(tmp_path), call=call, sleep=lambda _: None)


def test_log_gateway_khong_co_dong_dast_nao_thi_bao_loi(tmp_path):
    """Bao cao co the sinh ra ma traffic chua tung di qua lane. Do la bang chung rong."""
    log = tmp_path / "dast-access.log"
    log.write_text("channel=probe method=GET path=/x\n", encoding="utf-8")
    with pytest.raises(DastError, match="lane"):
        run_dast(tmp_path / "r.json", tmp_path / "l.log",
                 config=_config(tmp_path, gateway_log_path=log),
                 call=_fake_call(), sleep=lambda _: None)


def test_khoa_dast_ro_ri_vao_bao_cao_thi_bao_loi(tmp_path):
    call = _fake_call(alerts=[{"pluginId": "1", "other": "dastkey"}])
    with pytest.raises(DastError, match="ro ri"):
        run_dast(tmp_path / "r.json", tmp_path / "l.log",
                 config=_config(tmp_path), call=call, sleep=lambda _: None)


def test_thong_diep_loi_khong_bao_gio_chua_apikey(tmp_path):
    """URL cua ZAP mang apikey trong query string. No khong duoc vao thong diep loi."""
    from project_sentinel.dast.zap_client import _http_call

    config = _config(tmp_path, base_url="http://127.0.0.1:1")
    with pytest.raises(DastError) as caught:
        _http_call(config)("core/view/version", {})
    assert "zapkey" not in str(caught.value)


def test_thieu_bien_moi_truong_thi_bao_loi_ro_rang(monkeypatch):
    monkeypatch.delenv("SENTINEL_DAST_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_ZAP_API_KEY", raising=False)
    with pytest.raises(DastError, match="SENTINEL_"):
        ZapConfig.from_env()
```

- [ ] **Step 7: Chạy test, xác nhận xanh**

Run: `.venv/bin/python -m pytest tests/unit/dast/ -v`
Expected: PASS, 8 test. Không cần sửa code — bước 4 đã xử lý các đường này.

- [ ] **Step 8: Commit**

```bash
git add src/project_sentinel/dast/ tests/unit/dast/ infra/docker/zap/scan-plan.yaml
git commit -m "feat(dast): drive ZAP through its internal API instead of the Docker CLI"
```

---

## Task 4: Nối client vào luồng và bật lane DAST khi `make up`

**Files:**
- Modify: `scripts/scan-zap.sh`
- Modify: `Makefile` (`up`, `down`)
- Test: `tests/unit/dast/test_zap_client.py` (không đổi), kiểm chứng thủ công

**Interfaces:**
- Consumes: `run_dast`, `ZapConfig.from_env` (Task 3); service `zap` (Task 1); file log (Task 2).
- Produces: `scripts/scan-zap.sh` nhận hai tham số vị trí như cũ, nên `ctx.dast_command` trong `orchestrator/context.py` **không phải đổi**.

- [ ] **Step 1: Thay `scripts/scan-zap.sh` bằng lớp vỏ mỏng**

Giữ nguyên tên file và giao diện hai tham số, vì `RunContext.default()` đang trỏ vào đó.

```bash
#!/usr/bin/env bash
# Lop vo mong goi vao client Python. MOT ban cai dat duy nhat cho ca host lan
# container: hai ban song song se troi khoi nhau, dung loai loi da xay ra voi
# normalizer va zap_normalizer.
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
report_path="${1:-$project_root/artifacts/raw/zap.json}"
gateway_log="${2:-$project_root/artifacts/dast/gateway-access.log}"

python="${SENTINEL_PYTHON:-$project_root/.venv/bin/python3}"
if [ ! -x "$python" ]; then python=python3; fi

exec "$python" -m project_sentinel.dast.zap_client "$report_path" "$gateway_log"
```

- [ ] **Step 2: Thêm `main()` vào `zap_client.py`**

```python
def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Chay mot lan DAST qua ZAP daemon.")
    parser.add_argument("report", type=Path)
    parser.add_argument("log", type=Path)
    args = parser.parse_args(argv)
    try:
        run_dast(args.report, args.log, config=ZapConfig.from_env())
    except DastError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ZAP report: {args.report}")
    print(f"DAST Gateway evidence: {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Sửa `make up` và `make down`**

Trong `Makefile`, target `up`: thêm sinh hai khoá mới và bật profile `dast`.

```makefile
up:
	@KEY=$${SENTINEL_GATEWAY_API_KEY:-$$(sed -n 's/^SENTINEL_GATEWAY_API_KEY=//p' .env 2>/dev/null)}; \
	KEY=$${KEY:-$$(sed -n 's/^SENTINEL_API_KEY=//p' .env 2>/dev/null)}; \
	if [ -z "$$KEY" ]; then KEY="$$(openssl rand -hex 32)"; fi; \
	DAST_KEY=$${SENTINEL_DAST_API_KEY:-$$(openssl rand -hex 32)}; \
	ZAP_KEY=$${SENTINEL_ZAP_API_KEY:-$$(openssl rand -hex 32)}; \
	SENTINEL_GATEWAY_API_KEY="$$KEY" \
	SENTINEL_DAST_API_KEY="$$DAST_KEY" \
	SENTINEL_ZAP_API_KEY="$$ZAP_KEY" \
	docker compose --profile target --profile app --profile dast up --build --detach; \
	...giữ nguyên vòng chờ health và ba dòng in ra...
```

Target `down` cũng phải thêm `--profile dast`, nếu không container ZAP và gateway-dast sẽ ở lại:

```makefile
down:
	@SENTINEL_GATEWAY_API_KEY=dummy SENTINEL_DAST_API_KEY=dummy SENTINEL_ZAP_API_KEY=dummy \
	docker compose --profile target --profile app --profile dast down
```

- [ ] **Step 4: Truyền hai khoá vào container `web`**

Trong `docker-compose.yml`, service `web`, thêm vào `environment`:

```yaml
      - SENTINEL_DAST_API_KEY=${SENTINEL_DAST_API_KEY:-}
      - SENTINEL_ZAP_API_KEY=${SENTINEL_ZAP_API_KEY:-}
      - SENTINEL_ZAP_URL=http://zap:8090
```

- [ ] **Step 5: Kiểm chứng thật, đầu-cuối**

```bash
make down
make up
sleep 20
docker compose --profile dast exec zap curl -sS \
  "http://127.0.0.1:8090/JSON/core/view/version/?apikey=$SENTINEL_ZAP_API_KEY" || true
docker exec sentinel-sec-web-1 python -m project_sentinel.dast.zap_client \
  /app/artifacts/raw/zap.json /app/artifacts/dast/gateway-access.log
```
Expected: in ra hai đường dẫn artifact, exit 0.

- [ ] **Step 6: Điều kiện phủ định — phải còn đúng**

```bash
docker exec sentinel-sec-web-1 sh -c 'command -v docker || echo "KHONG CO docker CLI"'
docker exec sentinel-sec-web-1 sh -c 'ls /var/run/docker.sock 2>/dev/null || echo "KHONG CO socket"'
docker compose --profile dast ps --format '{{.Service}} {{.Ports}}' | grep zap
```
Expected: hai dòng đầu in "KHONG CO"; dòng cuối **không** có `0.0.0.0` hay `127.0.0.1`.
Nếu bất kỳ điều kiện nào sai, task này **thất bại** kể cả khi DAST chạy được.

- [ ] **Step 7: Commit**

```bash
git add scripts/scan-zap.sh src/project_sentinel/dast/zap_client.py Makefile docker-compose.yml
git commit -m "feat(dast): wire the ZAP client into the scan step and start the DAST lane with make up"
```

---

## Task 5: Kiểm chứng từ giao diện, đo, và ghi tài liệu

**Files:**
- Modify: `docs/limitations.md`, `README.md`
- Create: `reports/week-06/dast-from-ui-measurement.md`

**Interfaces:**
- Consumes: toàn bộ Task 1–4.
- Produces: không có interface mã.

- [ ] **Step 1: Chạy một lần quét từ giao diện**

```bash
make down && make up && sleep 25
curl -sS -X POST http://127.0.0.1:8000/runs -H 'Origin: http://127.0.0.1:8000' -i | head -3
```
Chờ bước scan xong rồi kiểm:

```bash
R=$(ls -t artifacts/runs | head -1)
python3 -c "
import json
d=json.load(open(f'artifacts/runs/$R/state.json'))
print([s for s in d['steps'] if s['name']=='scan'])
"
python3 -c "
import json, collections
f=json.load(open('artifacts/runs/$R/findings.json'))['findings']
print('tong:',len(f),'|',dict(collections.Counter(x['tool'] for x in f)))
"
```
Expected: `dast` trong detail là `done`; tổng **37 finding**, `{'opengrep': 23, 'zap': 14}`.

Nếu số ZAP khác 14, **không được sửa cho khớp** — ghi con số thật vào bảng ở bước 3 và
nêu lý do: thứ tự job đã đổi ở `scan-plan.yaml` (requestor chạy trước `passiveScan-wait`)
nên phản hồi POST giờ cũng được passive scan.

- [ ] **Step 2: Ghi đánh đổi vào `docs/limitations.md`**

Thêm một mục riêng, không nhét vào câu khác:

```markdown
- **Khoá DAST tồn tại theo vòng đời stack, không theo từng lần quét.** Docker Compose
  truyền `SENTINEL_DAST_API_KEY` vào `gateway-dast` lúc **tạo container**, nên không thể
  cấp khoá mới cho mỗi lần quét mà không dựng lại container. Trước đây `scan-zap.sh` sinh
  khoá tạm cho từng lần chạy; đổi sang ZAP daemon thì mất tính chất đó. Giảm nhẹ: khoá
  vẫn sinh ngẫu nhiên mỗi lần `make up`, không bao giờ vào Git, không bao giờ ra host, và
  kiểm tra chống rò rỉ khoá vào báo cáo/log vẫn giữ nguyên.
- **ZAP daemon là một service chạy suốt có API điều khiển được.** Nó bị chặn ba lớp:
  khai `expose` chứ không `ports` nên không có cổng host, bắt buộc API key, và chỉ nằm
  trên mạng nội bộ `sentinel-net`. Có test khoá cả ba trong
  `tests/unit/infra/test_compose_invariants.py`.
```

- [ ] **Step 3: Ghi bảng đo**

`reports/week-06/dast-from-ui-measurement.md`:

```markdown
# DAST chạy từ giao diện — đo trước/sau

**Lần chạy:** `<run-id>` · **Ngày:** 2026-08-23

| Chỉ số | Trước | Sau |
| :--- | ---: | ---: |
| Finding khi bấm quét từ giao diện | 23 | <đo được> |
| `dast_status` trong `state.json` | `skipped` | <đo được> |
| Alert ZAP | 0 | <đo được> |
| Docker CLI trong container `web` | không có | không có |
| `/var/run/docker.sock` trong `web` | không có | không có |
| Cổng host của ZAP | — | không có |

Ba dòng cuối là điều kiện phủ định: nếu chúng đổi thì thay đổi này thất bại kể cả khi
số finding đúng.
```

- [ ] **Step 4: Cập nhật `README.md`**

Trong mục mô tả `make up`, nói rõ nó giờ bật cả lane DAST:

```markdown
`make up` dựng toàn bộ stack: WebGoat, Gateway (lane probe), Gateway (lane DAST), ZAP
daemon và giao diện web. Bấm quét từ giao diện sẽ chạy **cả SAST lẫn DAST** — container
web điều khiển ZAP qua API nội bộ, nó không có Docker CLI và không có docker socket.
```

- [ ] **Step 5: Chạy toàn bộ cổng chất lượng**

```bash
make quality
make eval
```
Expected: `make quality` xanh; `make eval` exit 0.

- [ ] **Step 6: Commit**

```bash
git add docs/limitations.md README.md reports/week-06/dast-from-ui-measurement.md
git commit -m "docs(dast): record the UI scan measurement and the stack-lifetime key trade-off"
```

---

## Kiểm tra cuối

- [ ] `make quality` xanh
- [ ] `make eval` exit 0
- [ ] Bấm quét từ giao diện ra **37 finding** (23 SAST + 14 DAST), `dast_status == "done"`
- [ ] `docker exec sentinel-sec-web-1 command -v docker` → **không có**
- [ ] `docker exec sentinel-sec-web-1 ls /var/run/docker.sock` → **không có**
- [ ] `docker compose ps` → service `zap` **không có cổng host**
- [ ] `make down` dọn sạch cả `zap` và `gateway-dast`
