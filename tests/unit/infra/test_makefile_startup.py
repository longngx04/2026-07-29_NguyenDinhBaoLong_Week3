"""Kiem tra lenh khoi dong giu Docker cache cho cac lan demo thuong ngay."""

from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[3]


def _render_make_target(target: str) -> str:
    completed = subprocess.run(
        ["make", "--dry-run", "--no-print-directory", target],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def test_up_reuses_existing_docker_images():
    command = _render_make_target("up")

    assert "docker compose --profile target --profile app --profile dast up" in command
    assert "--build" not in command


def test_up_build_explicitly_forces_docker_rebuild():
    command = _render_make_target("up-build")

    assert "docker compose --profile target --profile app --profile dast up --build --detach" in command
