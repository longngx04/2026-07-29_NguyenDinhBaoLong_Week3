"""KB đứng ở đâu so với lỗ hổng có thật trong WebGoat.

Lệnh này không gọi LLM và không cần Docker, nên chạy được trong CI.
Mục tiêu là đối chiếu các entry Tier 2 trong KB với rule hiện có và tập nhãn
recall mặt đất để chỉ rõ khoảng trống độ phủ mà không tạo ảo tưởng về độ hoàn thiện.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any

import yaml

from project_sentinel.retrieval.kb_schema import load_tier2

DEFAULT_TIER2 = Path("data/knowledge-base/tier2")
DEFAULT_RULES = Path("configs/opengrep/java-security.yml")
DEFAULT_TRUTH = Path(
    "eval/ground-truth/recall/webgoat-vulnerabilities.applicable.json"
)


def _known_rule_ids(rules_file: Path) -> set[str]:
    """Trích xuất tập hợp rule_id từ file cấu hình OpenGrep.

    Nếu file không tồn tại, trả về tập rỗng để không làm gãy luồng báo cáo khi chạy thử
    với đường dẫn tùy biến.
    """
    if not rules_file.is_file():
        return set()
    data = yaml.safe_load(rules_file.read_text(encoding="utf-8")) or {}
    return {str(rule.get("id")) for rule in data.get("rules", []) if rule.get("id")}


def _truth_counts(truth_file: Path) -> tuple[collections.Counter[str], int]:
    """Đếm số lượng lỗ hổng theo CWE từ ground truth recall mặt đất.

    Trả về (Counter[cwe -> count], tổng số lỗ hổng). Định dạng ground truth có thể là
    list trực tiếp hoặc dict bọc list dưới một khóa.
    """
    if not truth_file.is_file():
        return collections.Counter(), 0
    items = json.loads(truth_file.read_text(encoding="utf-8"))
    if isinstance(items, dict):
        items = next(
            (value for value in items.values() if isinstance(value, list)), []
        )
    counter: collections.Counter[str] = collections.Counter(
        str(item.get("cwe")) for item in items if isinstance(item, dict)
    )
    return counter, len(items)


def build_report(
    tier2_dir: Path,
    rules_file: Path,
    truth_file: Path,
) -> dict[str, Any]:
    """Đếm entry, đối chiếu với rule có thật và với bộ nhãn recall.

    Tách rõ entry nào đã có rule SAST tương ứng và entry nào chưa có (khoảng trống).
    Các khoảng trống được nhóm theo CWE và xếp giảm dần theo số lỗ hổng thực tế trong WebGoat
    để định hướng ưu tiên viết rule tiếp theo.
    """
    entries = load_tier2(tier2_dir)
    known_rules = _known_rule_ids(rules_file)
    truth, truth_total = _truth_counts(truth_file)

    sast_entries = [
        entry
        for entry in entries
        if any(rule in known_rules for rule in entry.matches_rule_ids)
    ]
    dast_entries = [
        entry
        for entry in entries
        if any(rule.isdigit() for rule in entry.matches_rule_ids)
    ]
    no_rule_entries = [
        entry
        for entry in entries
        if entry not in sast_entries and entry not in dast_entries
    ]
    with_rule = sast_entries + dast_entries
    without_rule = no_rule_entries

    gaps_by_cwe: dict[str, list[str]] = collections.defaultdict(list)
    for entry in without_rule:
        for cwe in entry.cwe:
            gaps_by_cwe[cwe].append(entry.id)

    raw_gaps = [
        (cwe, sorted(ids), int(truth.get(cwe, 0)))
        for cwe, ids in gaps_by_cwe.items()
    ]
    raw_gaps.sort(key=lambda item: (-item[2], item[0]))
    gaps = [
        {"cwe": cwe, "entries": entries_list, "truth_count": count}
        for cwe, entries_list, count in raw_gaps
    ]

    reached_cwes = {cwe for entry in entries for cwe in entry.cwe}
    cwe_reach = sum(truth.get(cwe, 0) for cwe in reached_cwes)

    return {
        "entries": len(entries),
        "with_rule": len(with_rule),
        "with_sast": len(sast_entries),
        "with_dast": len(dast_entries),
        "without_rule": len(without_rule),
        "sast_entries": len(sast_entries),
        "dast_entries": len(dast_entries),
        "no_rule_entries": len(no_rule_entries),
        "gaps": gaps,
        "cwe_reach": cwe_reach,
        "truth_total": truth_total,
    }


def render(report: dict[str, Any]) -> str:
    """Định dạng báo cáo độ phủ thành văn bản rõ ràng dễ đọc trên CLI.

    Bao gồm số entry tổng, số có rule, danh sách thiếu rule kèm số lỗ hổng thật,
    và con số trần trên CWE reach.
    """
    lines = [
        "=== KB Tier 2 ===",
        f"  Entry              : {report['entries']}",
        f"  Entry neo theo SAST: {report['with_sast']} | neo theo DAST: {report['with_dast']} | chưa có rule: {report['without_rule']}",
        f"  Có rule            : {report['with_rule']}",
        f"  Chưa có rule       : {report['without_rule']}",
        "",
        "=== Thiếu rule, xếp theo số lỗ hổng thật trong WebGoat ===",
    ]
    for gap in report["gaps"]:
        lines.append(
            f"  {gap['truth_count']:2}x  {gap['cwe']:8} {', '.join(gap['entries'])}"
        )
    total = report["truth_total"] or 1
    lines += [
        "",
        f"  CWE mà KB chạm tới : {report['cwe_reach']}/{report['truth_total']} "
        f"lỗ hổng ({100 * report['cwe_reach'] / total:.1f}%) — đây là TRẦN TRÊN",
        "  Trần này giả định mỗi rule bắt được mọi thực thể của CWE mình phụ trách.",
        "  Recall đo được thật nằm trong reports/week-06/report.md §4.5.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Điểm vào CLI cho báo cáo độ phủ KB Tier 2."""
    parser = argparse.ArgumentParser(description="Độ phủ của KB Tier 2.")
    parser.add_argument("--tier2", type=Path, default=DEFAULT_TIER2)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    args = parser.parse_args(argv)
    print(render(build_report(args.tier2, args.rules, args.truth)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
