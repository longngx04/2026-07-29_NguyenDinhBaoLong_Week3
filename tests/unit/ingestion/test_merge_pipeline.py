import json
from pathlib import Path

import pytest

from project_sentinel.ingestion.merge_pipeline import (
    merge_normalized,
    normalise_finding_fields,
)


def _write(path: Path, source: str, findings: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"source": source, "count": len(findings), "findings": findings}
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


SAST_FINDING = {
    "id": "opengrep-001",
    "tool": "opengrep",
    "severity": "high",
    "file_or_url": "src/app/Handler.java",
    "line": 69,
    "title": "Potential command injection",
    "rule_id": "java-command-execution",
    "cwe": "CWE-78",
    "owasp": "A03:2021-Injection",
    "message": "Runtime.exec receives a command value.",
}


def test_khong_co_zap_thi_chi_giu_sast(tmp_path):
    sast = tmp_path / "sast-findings.json"
    _write(sast, "opengrep", [SAST_FINDING])
    output = tmp_path / "findings.json"

    counts = merge_normalized(
        sast_findings=sast,
        zap_alerts=None,
        gateway_log=None,
        output=output,
        project_root=tmp_path,
    )

    assert counts == {"findings": 1, "zap_findings": 0, "correlated": 0}
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert [f["id"] for f in payload["findings"]] == ["opengrep-001"]


def test_zap_alerts_khong_ton_tai_khong_bao_loi(tmp_path):
    """Máy không chạy Docker vẫn phải normalize được."""
    sast = tmp_path / "sast-findings.json"
    _write(sast, "opengrep", [SAST_FINDING])
    output = tmp_path / "findings.json"

    counts = merge_normalized(
        sast_findings=sast,
        zap_alerts=tmp_path / "khong-co-file-nay.json",
        gateway_log=None,
        output=output,
        project_root=tmp_path,
    )

    assert counts["findings"] == 1
    assert counts["zap_findings"] == 0


def test_tron_sast_va_dast(tmp_path):
    sast = tmp_path / "sast-findings.json"
    _write(sast, "opengrep", [SAST_FINDING])
    alerts = tmp_path / "zap.json"
    alerts.write_text(
        json.dumps(
            {
                "site": [
                    {
                        "@name": "http://gateway-dast:8081",
                        "alerts": [
                            {
                                "pluginid": "10009",
                                "alert": "In Page Banner Information Leak",
                                "riskcode": "1",
                                "cweid": "497",
                                "desc": "<p>Banner leak</p>",
                                "solution": "<p>Configure the server</p>",
                                "instances": [
                                    {
                                        "uri": "http://gateway-dast:8081/WebGoat/logout",
                                        "method": "GET",
                                        "param": "",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "findings.json"

    counts = merge_normalized(
        sast_findings=sast,
        zap_alerts=alerts,
        gateway_log=None,
        output=output,
        project_root=tmp_path,
    )

    assert counts["findings"] == 2
    assert counts["zap_findings"] == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    tools = sorted(f["tool"] for f in payload["findings"])
    assert tools == ["opengrep", "zap"]
    # File SAST gốc không bị sửa.
    assert len(json.loads(sast.read_text(encoding="utf-8"))["findings"]) == 1


def test_cwe_owasp_luon_la_list_sau_khi_tron(tmp_path):
    """Hai normalizer cho hai hình dạng; mọi thứ đọc về sau chỉ được thấy một."""
    sast = tmp_path / "sast-findings.json"
    _write(sast, "opengrep", [SAST_FINDING])
    alerts = tmp_path / "zap.json"
    alerts.write_text(json.dumps({"site": []}), encoding="utf-8")
    output = tmp_path / "findings.json"

    merge_normalized(
        sast_findings=sast,
        zap_alerts=alerts,
        gateway_log=None,
        output=output,
        project_root=tmp_path,
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    for finding in payload["findings"]:
        assert isinstance(finding["cwe"], list)
        assert isinstance(finding["owasp"], list)


@pytest.mark.parametrize(
    "value,expected",
    [("CWE-78", ["CWE-78"]), (None, []), ("", []), (["CWE-89"], ["CWE-89"])],
)
def test_normalise_finding_fields_ep_ve_list(value, expected):
    findings = [{"cwe": value, "owasp": value}]
    normalise_finding_fields(findings)
    assert findings[0]["cwe"] == expected
    assert findings[0]["owasp"] == expected


def test_file_sast_khong_co_mang_findings_thi_bao_loi(tmp_path):
    sast = tmp_path / "sast-findings.json"
    sast.write_text(json.dumps({"source": "opengrep"}), encoding="utf-8")

    with pytest.raises(ValueError, match="findings"):
        merge_normalized(
            sast_findings=sast,
            zap_alerts=None,
            gateway_log=None,
            output=tmp_path / "out.json",
            project_root=tmp_path,
        )


def test_main_tron_duoc_tu_dong_lenh(tmp_path):
    sast = tmp_path / "sast-findings.json"
    _write(sast, "opengrep", [SAST_FINDING])
    output = tmp_path / "findings.json"

    from project_sentinel.ingestion.merge_pipeline import main

    code = main(
        [
            "--sast",
            str(sast),
            "--zap-alerts",
            str(tmp_path / "khong-ton-tai.json"),
            "--output",
            str(output),
            "--project-root",
            str(tmp_path),
        ]
    )

    assert code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["count"] == 1


def test_main_tra_ma_loi_khi_thieu_file_sast(tmp_path, capsys):
    from project_sentinel.ingestion.merge_pipeline import main

    code = main(
        ["--sast", str(tmp_path / "khong-co.json"), "--output", str(tmp_path / "o.json")]
    )

    assert code == 1
    assert "error:" in capsys.readouterr().err
