"""Tolerant parser for the deliberately simple local-LLM response contract."""
from __future__ import annotations
import re

_HEADERS = ("SUMMARY", "SEVERITY_RATIONALE", "RECOMMENDED_ACTIONS")

def parse_llm_response(raw_text: str) -> dict[str, object]:
    """Never raise for malformed model output; provide visible placeholders."""
    sections = {name: "[not provided by model]" for name in _HEADERS}
    pattern = r"(?ms)^((?:SUMMARY|SEVERITY_RATIONALE|RECOMMENDED_ACTIONS)):\s*(.*?)(?=^(?:SUMMARY|SEVERITY_RATIONALE|RECOMMENDED_ACTIONS):|\Z)"
    for name, content in re.findall(pattern, raw_text or ""):
        sections[name] = content.strip() or sections[name]
    actions = re.sub(r"^\s*\d+[.)]\s*", "", sections["RECOMMENDED_ACTIONS"], flags=re.M).splitlines()
    return {"summary": sections["SUMMARY"], "severity_rationale": sections["SEVERITY_RATIONALE"], "recommended_actions": [a.strip() for a in actions if a.strip()] or ["[not provided by model]"]}
