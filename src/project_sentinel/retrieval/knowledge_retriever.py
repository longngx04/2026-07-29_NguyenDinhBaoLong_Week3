"""
Knowledge retrieval adapter for Project Sentinel Security Analysis Agent.
Reuses keyword search engine to retrieve relevant knowledge documents.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from project_sentinel.retrieval.keyword_search import (
    parse_markdown,
    search as keyword_search,
)
from project_sentinel.retrieval.tier_lookup import lookup_tier2

# Điểm của hit tất định là HẰNG SỐ, không phải điểm keyword. Luật provenance 9
# đối chiếu score agent trích với score hệ thống tính, nên nó phải tất định.
TIER2_SCORE = 100.0
PARENT_SCORE = 50.0


@dataclass
class RetrievalHit:
    """Structured knowledge retrieval hit."""
    path: str
    title: str
    score: float
    snippet: str
    tier: int = 1
    match_kind: str = "keyword"
    canonical_category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert hit to dictionary payload for LLM analysis packet or output record."""
        return {
            "path": self.path,
            "title": self.title,
            "score": round(self.score, 2),
            "snippet": self.snippet,
            "tier": self.tier,
            "match_kind": self.match_kind,
            "canonical_category": self.canonical_category,
        }


def retrieve_knowledge(
    title: str,
    rule_id: str = "",
    cwe: Optional[List[str]] = None,
    owasp: Optional[List[str]] = None,
    # Keyword search CHỈ được quét tier1/. Nếu để nó quét cả tier2/ thì khớp chữ
    # sẽ cạnh tranh với tra cứu tất định, đúng cái ưu thế vừa xây ở Task 4.
    knowledge_dir: Path = Path("data/knowledge-base/tier1"),
    top_k: int = 3,
    max_snippet_chars: int = 700,
) -> List[RetrievalHit]:
    """Retrieve relevant knowledge hits for a finding group using deterministic tier lookup + keyword search.

    Returns structured hits sorted by relevance score. Returns empty list if query is empty
    and deterministic lookup yields no results, or knowledge_dir does not exist.
    """
    if not knowledge_dir.exists() or not knowledge_dir.is_dir():
        return []

    hits: List[RetrievalHit] = []

    # Xác định thư mục tier1 và tier2 linh hoạt (hỗ trợ cả khi knowledge_dir trỏ vào tier1/ hoặc data/knowledge-base)
    if (knowledge_dir / "tier2").is_dir():
        tier2_dir = knowledge_dir / "tier2"
        tier1_dir = (knowledge_dir / "tier1") if (knowledge_dir / "tier1").is_dir() else knowledge_dir
    else:
        tier2_dir = knowledge_dir.parent / "tier2"
        tier1_dir = knowledge_dir

    # 1. Tra cứu tất định Tier 2 (rule_id -> cwe)
    entry, match_kind = lookup_tier2(rule_id, cwe, tier2_dir)
    if entry is not None and match_kind is not None:
        hits.append(
            RetrievalHit(
                path=entry.path.as_posix(),
                title=entry.canonical_category,
                score=TIER2_SCORE,
                snippet=entry.body[:max_snippet_chars],
                tier=2,
                match_kind=match_kind,
                canonical_category=entry.canonical_category,
            )
        )
        parent_path = tier1_dir / f"{entry.tier1_parent}.md"
        if parent_path.is_file():
            parent_doc = parse_markdown(parent_path)
            hits.append(
                RetrievalHit(
                    path=parent_path.as_posix(),
                    title=parent_doc.title,
                    score=PARENT_SCORE,
                    snippet=parent_doc.body[:max_snippet_chars],
                    tier=1,
                    match_kind="parent",
                    canonical_category="",
                )
            )

    # 2. Keyword search trên tier1/
    # Da co tri thuc tat dinh (Tier 2 + doc cha) thi keyword chi con hang 2-3
    # de dong gop, ma hang 2-3 theo dinh nghia la ho khac -> nhieu thuan tuy.
    # Do duoc 46/46 hit keyword tren 23 finding SAST deu sai ho lo hong.
    if not any(h.tier == 2 for h in hits):
        query_parts: List[str] = []
        if title and title.strip():
            query_parts.append(title.strip())
        if rule_id and rule_id.strip():
            query_parts.append(rule_id.strip())
        if cwe:
            query_parts.extend([str(c).strip() for c in cwe if str(c).strip()])
        if owasp:
            query_parts.extend([str(o).strip() for o in owasp if str(o).strip()])

        query = " ".join(query_parts).strip()
        if query and tier1_dir.is_dir():
            try:
                raw_hits = keyword_search(query=query, knowledge_dir=tier1_dir, limit=top_k)
            except (FileNotFoundError, OSError, ValueError):
                raw_hits = []

            seen = {hit.path for hit in hits}
            for score, doc, snippet in raw_hits:
                rel_path = doc.path.as_posix()
                if rel_path in seen:
                    continue
                clean_snippet = snippet if len(snippet) <= max_snippet_chars else snippet[:max_snippet_chars] + "..."
                hits.append(
                    RetrievalHit(
                        path=rel_path,
                        title=doc.title,
                        score=score,
                        snippet=clean_snippet,
                        tier=1,
                        match_kind="keyword",
                        canonical_category="",
                    )
                )
                if len(hits) >= top_k + 2:
                    break

    return hits
