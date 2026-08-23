"""Hop dong tinh cua luong DAST.

Bon bat bien duoi day truoc kia duoc khoa tren `scripts/scan-zap.sh`. Script do gio
la lop vo mong goi vao `project_sentinel.dast.zap_client`, nen BAT BIEN VAN CON
nhung da chuyen cho: hai cai nam o `infra/docker/zap/scan-plan.yaml`, hai cai nam o
client. Test nay di theo chung sang cho moi thay vi bi xoa.
"""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts/scan-zap.sh"
PLAN = REPO_ROOT / "infra/docker/zap/scan-plan.yaml"
CLIENT = REPO_ROOT / "src/project_sentinel/dast/zap_client.py"


def _plan() -> dict:
    return yaml.safe_load(PLAN.read_text(encoding="utf-8"))


def test_zap_targets_only_the_dast_gateway():
    text = PLAN.read_text(encoding="utf-8")
    assert "http://gateway-dast:8081/WebGoat/login" in text
    assert "http://webgoat:8080" not in text, "ZAP khong bao gio duoc nham thang WebGoat"


def test_plan_runs_baseline_jobs_not_an_active_scan():
    """Active scan gui payload tan cong that. Quyet dinh cu: chi spider va passive."""
    jobs = [job["type"] for job in _plan()["jobs"]]
    assert "spider" in jobs
    assert "passiveScan-wait" in jobs
    assert "activeScan" not in jobs, "Active scan nam ngoai pham vi du an"


def test_requestor_runs_before_passive_scan_so_post_responses_get_scanned():
    """Truoc day requestor chay o mot tien trinh ZAP roi, nen phan hoi POST khong
    duoc passive scan. Thu tu nay la thay doi hanh vi co chu y."""
    jobs = [job["type"] for job in _plan()["jobs"]]
    assert jobs.index("requestor") < jobs.index("passiveScan-wait")


def test_gateway_evidence_must_come_from_the_current_scan():
    """Script cu dung `--since "$scan_started_at"`. Client phai giu ngu nghia do
    bang cach chi doc phan log duoc ghi them trong lan quet nay."""
    text = CLIENT.read_text(encoding="utf-8")
    assert "st_size" in text and "seek(offset)" in text, (
        "Client phai ghi lai vi tri cuoi file log truoc khi chay plan"
    )
    assert "channel=dast" in text


def test_wrapper_delegates_to_the_single_python_implementation():
    """Hai ban cai dat song song se troi khoi nhau."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "project_sentinel.dast.zap_client" in text
    assert "docker compose" not in text, (
        "Container web khong co Docker; script khong duoc goi docker nua"
    )
