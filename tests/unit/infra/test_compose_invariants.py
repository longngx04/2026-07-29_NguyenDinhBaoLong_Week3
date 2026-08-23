"""Khoá các bất biến mạng và bố cục của Docker Compose."""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_scan_compose_file_is_merged_away():
    assert not (REPO_ROOT / "compose.scan.yml").exists(), (
        "compose.scan.yml phải được gộp vào docker-compose.yml"
    )


def test_all_services_exist(compose):
    assert set(compose["services"]) == {
        "scanner",
        "webgoat",
        "gateway",
        "gateway-dast",
        "zap",
        "web",
    }


def test_service_profiles(compose):
    services = compose["services"]
    assert services["scanner"]["profiles"] == ["scan"]
    assert services["webgoat"]["profiles"] == ["target", "dast"]
    assert services["gateway"]["profiles"] == ["target"]
    assert services["gateway-dast"]["profiles"] == ["dast"]
    assert services["zap"]["profiles"] == ["dast"]
    assert services["web"]["profiles"] == ["app"]


def test_webgoat_is_never_published_on_host(compose):
    assert "ports" not in compose["services"]["webgoat"], (
        "WebGoat là ứng dụng cố ý có lỗ hổng; không bao giờ được mở ra host"
    )


def test_only_gateway_binds_loopback(compose):
    assert compose["services"]["gateway"]["ports"] == ["127.0.0.1:9080:8080"]
    assert "ports" not in compose["services"]["gateway-dast"]
    assert "ports" not in compose["services"]["zap"]


def test_every_host_port_binds_loopback_only(compose):
    for name, service in compose["services"].items():
        for mapping in service.get("ports", []):
            assert str(mapping).startswith("127.0.0.1:"), (
                f"Service {name} bind {mapping} — mapping không có prefix "
                "127.0.0.1: sẽ bind mọi interface theo mặc định của Docker"
            )


def test_no_required_env_var_breaks_scan_profile(compose):
    for name, service in compose["services"].items():
        for entry in service.get("environment", []):
            assert ":?" not in str(entry), (
                f"Service {name} environment {entry} dùng interpolation bắt buộc (:?); "
                "Compose interpolate toàn bộ file trước khi lọc profile, "
                "nên sẽ làm chết make scan khi thiếu key"
            )


GATEWAY_DIR = REPO_ROOT / "infra" / "docker" / "gateway"
REQUIRE_KEY_SCRIPT = GATEWAY_DIR / "docker-entrypoint.d" / "00-require-key.sh"


def test_gateway_image_refuses_empty_api_key():
    dockerfile = (GATEWAY_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert "docker-entrypoint.d" in dockerfile, (
        "Dockerfile gateway phải COPY entrypoint guard vào /docker-entrypoint.d/ "
        "để container fail loud khi SENTINEL_GATEWAY_API_KEY rỗng"
    )
    assert REQUIRE_KEY_SCRIPT.exists(), (
        "Thiếu docker-entrypoint.d/00-require-key.sh — key rỗng sẽ làm nginx map "
        "chấp nhận request không header (auth bypass)"
    )
    script = REQUIRE_KEY_SCRIPT.read_text(encoding="utf-8")
    assert "SENTINEL_GATEWAY_API_KEY" in script, (
        "Script guard phải kiểm tra biến SENTINEL_GATEWAY_API_KEY"
    )
    assert "exit 1" in script, (
        "Script guard phải thoát 1 khi key rỗng để container chết hẳn"
    )


def test_web_service_binds_loopback_only(compose):
    assert compose["services"]["web"]["ports"] == ["127.0.0.1:8000:8000"]


def test_web_service_does_not_receive_the_llm_key_by_default(compose):
    environment = compose["services"]["web"].get("environment", [])
    joined = " ".join(str(item) for item in environment)
    assert "LLM_API_KEY=sk-" not in joined, "Không hard-code khoá vào compose"


def test_zap_targets_the_dast_gateway_not_webgoat(compose):
    zap = compose["services"]["zap"]
    assert "gateway-dast" in zap["depends_on"]
    assert "webgoat" not in zap["depends_on"]
    environment = "\n".join(str(item) for item in zap["environment"])
    assert "ZAP_AUTH_HEADER=X-Sentinel-DAST-Key" in environment
    assert "ZAP_AUTH_HEADER_VALUE=" in environment


def test_zap_image_is_version_pinned(compose):
    image = compose["services"]["zap"]["image"]
    assert image.startswith("ghcr.io/zaproxy/zaproxy@sha256:")
    assert len(image.rsplit(":", 1)[1]) == 64


def test_dast_gateway_is_internal_and_readiness_uses_its_key(compose):
    gateway = compose["services"]["gateway-dast"]
    assert gateway["expose"] == ["8081"]
    assert "ports" not in gateway
    health = " ".join(str(item) for item in gateway["healthcheck"]["test"])
    assert "X-Sentinel-DAST-Key" in health
    assert "127.0.0.1:8081/WebGoat/actuator/health" in health
    assert "localhost:8081" not in health, "BusyBox resolves localhost to ::1"


def test_zap_api_never_reaches_the_host(compose):
    """API cua ZAP dieu khien duoc mot trinh duyet tan cong. No khong duoc ra host."""
    zap = compose["services"]["zap"]
    assert "ports" not in zap, (
        "zap khai 'ports' — API se bind len host. Chi duoc dung 'expose'."
    )
    assert zap.get("expose") == ["8090"]


def test_zap_runs_as_a_daemon_with_a_key_from_the_environment(compose):
    """Command phai o dang DANH SACH. Dang chuoi mot dong bi tach nhap nhang khien
    ZAP bo qua `-port` va roi ve mot cong ngau nhien tren localhost — quan sat duoc
    that: no nghe 127.0.0.1:42225 thay vi 0.0.0.0:8090."""
    command = compose["services"]["zap"].get("command")
    assert isinstance(command, list), f"command phai la danh sach, dang la {type(command)}"
    assert "-daemon" in command
    assert "8090" in command and "-port" in command
    assert "api.key=${SENTINEL_ZAP_API_KEY}" in command, (
        "Khoa API phai lay tu bien moi truong, khong duoc la hang trong file"
    )


def test_zap_still_only_ever_targets_the_dast_gateway(compose):
    """Bat bien cu, phai con xanh sau khi doi sang daemon."""
    rendered = yaml.safe_dump(compose["services"]["zap"], allow_unicode=True)
    assert "webgoat" not in rendered, "ZAP khong bao gio duoc nham thang WebGoat"


def test_dast_log_volume_is_shared_and_web_can_only_read_it(compose):
    """Day la BANG CHUNG. Tien trinh doc no khong duoc phep sua no."""
    assert "sentinel-dast-log" in (compose.get("volumes") or {})

    gateway_dast = compose["services"]["gateway-dast"]["volumes"]
    assert any("sentinel-dast-log:/var/log/sentinel" in v for v in gateway_dast)

    web = compose["services"]["web"]["volumes"]
    ro = [v for v in web if "sentinel-dast-log" in v]
    assert ro, "web phai mount volume log"
    assert ro[0].endswith(":ro"), f"web phai mount CHI DOC, dang la {ro[0]}"


def test_zap_command_never_uses_a_run_and_exit_action(compose):
    """`-addoninstall` la lenh chay-roi-thoat: ZAP cai xong addon roi TAT, va
    container chet. Quan sat duoc that. Viec cai addon thuoc ve client."""
    command = compose["services"]["zap"]["command"]
    assert "-addoninstall" not in command
    assert "-daemon" in command


def test_zap_healthcheck_proves_the_api_is_actually_listening(compose):
    """Quan sat duoc: ZAP thinh thoang bo qua `-port` va roi ve mot cong ngau nhien
    tren localhost. Khong co healthcheck thi container bao "Up" trong khi API chet,
    va client chi phat hien sau khi cho het han gio."""
    health = compose["services"]["zap"].get("healthcheck")
    assert health, "zap phai co healthcheck"
    probe = " ".join(health["test"])
    assert "8090" in probe and "core/view/version" in probe
