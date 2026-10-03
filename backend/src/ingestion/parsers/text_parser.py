"""
text_parser.py — Parses plain-text and Markdown files.

Responsibilities:
* Read the full file text.
* For Markdown: strip syntax, use section headers as chunk boundaries.
* Chunk text into paragraphs of ~200–400 words, splitting on blank
  lines / headers.
* Run deterministic regex-based entity extraction:
  - IPv4 addresses
  - Domain names (with false-positive filtering)
  - MD5 / SHA1 / SHA256 hashes (by hex length: 32 / 40 / 64)
  - CVE IDs
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..format_detector import FormatType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

# Version numbers that look like domains (e.g. "1.2.3")
_VERSION_RE = re.compile(r"^\d+\.\d+")

# Markdown header line
_MD_HEADER_RE = re.compile(r"^#{1,6}\s+")

# Markdown inline syntax (bold, italic, code, links, images)
_MD_STRIP_RE = re.compile(
    r"!\[.*?\]\(.*?\)"         # images
    r"|(?:\[.*?\]\(.*?\))"    # links
    r"|`{1,3}.*?`{1,3}"       # inline code / fenced
    r"|\*{1,2}(.*?)\*{1,2}"   # bold/italic
    r"|_{1,2}(.*?)_{1,2}"     # bold/italic alt
    r"|~~(.*?)~~",             # strikethrough
    flags=re.DOTALL,
)

_CHUNK_TARGET_WORDS = 300  # target mid-point
_CHUNK_MIN_WORDS = 50


# ---------------------------------------------------------------------------
# Helpers — Markdown stripping
# ---------------------------------------------------------------------------

def _strip_markdown(text: str) -> str:
    """Remove common Markdown syntax, preserving plain text content."""
    # Strip inline decorations
    cleaned = _MD_STRIP_RE.sub(lambda m: next((g for g in m.groups() if g), ""), text)
    # Strip leading # from headers (keep the text)
    cleaned = _MD_HEADER_RE.sub("", cleaned)
    return cleaned


# ---------------------------------------------------------------------------
# Helpers — Chunking
# ---------------------------------------------------------------------------

def _split_into_blocks(text: str, is_markdown: bool) -> list[str]:
    """
    Split text into raw blocks using blank lines and Markdown headers as
    boundaries.  Returns non-empty blocks.
    """
    lines = text.splitlines()
    blocks: list[str] = []
    current: list[str] = []

    for line in lines:
        is_boundary = (not line.strip()) or (is_markdown and _MD_HEADER_RE.match(line))
        if is_boundary:
            if current:
                blocks.append("\n".join(current))
                current = []
            # Keep the header line as the start of the next block
            if is_markdown and _MD_HEADER_RE.match(line):
                current.append(line)
        else:
            current.append(line)

    if current:
        blocks.append("\n".join(current))

    return [b for b in blocks if b.strip()]


def _merge_blocks_into_chunks(blocks: list[str]) -> list[str]:
    """
    Merge small blocks into chunks targeting ~300 words each.
    Blocks that are already large enough become their own chunk.
    """
    chunks: list[str] = []
    current_words: list[str] = []
    current_count = 0

    for block in blocks:
        words = block.split()
        if current_count + len(words) > _CHUNK_TARGET_WORDS and current_count >= _CHUNK_MIN_WORDS:
            chunks.append(" ".join(current_words))
            current_words = words
            current_count = len(words)
        else:
            current_words.extend(words)
            current_count += len(words)

    if current_words:
        chunks.append(" ".join(current_words))

    return [c for c in chunks if c.strip()]


# ---------------------------------------------------------------------------
# Helpers — Entity extraction
# ---------------------------------------------------------------------------

def _is_version_number(candidate: str) -> bool:
    """Return True if the candidate looks like a software version string."""
    return bool(_VERSION_RE.match(candidate))


def _extract_entities(text: str) -> dict[str, list[str]]:
    """
    Extract IOCs from *text* using deterministic regex matching.

    Returns a dict with keys ``ips``, ``domains``, ``hashes``, ``cves``,
    each containing a deduplicated list.
    """
    ips = list(dict.fromkeys(_IPV4_RE.findall(text)))

    raw_domains = _DOMAIN_RE.findall(text)
    domains = list(
        dict.fromkeys(
            d for d in raw_domains
            if not _is_version_number(d) and d not in ips
        )
    )

    hashes = list(dict.fromkeys(_HASH_RE.findall(text)))
    cves = list(dict.fromkeys(_CVE_RE.findall(text)))

    return {"ips": ips, "domains": domains, "hashes": hashes, "cves": cves}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_text(
    file_path: Path,
    fmt: FormatType,
) -> tuple[dict[str, Any], list[str]]:
    """
    Parse a plain-text or Markdown file into entity metadata and text chunks.

    Parameters
    ----------
    file_path:
        Path to the ``.txt`` or ``.md`` file.
    fmt:
        :attr:`FormatType.TXT` or :attr:`FormatType.MD`.

    Returns
    -------
    tuple[dict, list[str]]
        * ``entities_dict`` — keys ``ips``, ``domains``, ``hashes``, ``cves``.
        * ``chunks_list``   — list of text chunk strings (~200–400 words each).
    """
    path = Path(file_path)
    is_md = (fmt == FormatType.MD)

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        logger.error("Cannot read text file %s: %s", path, exc)
        return {"ips": [], "domains": [], "hashes": [], "cves": []}, []

    # Strip markdown syntax for entity extraction and chunking
    clean_text = _strip_markdown(raw_text) if is_md else raw_text

    # Entity extraction runs on the cleaned text
    entities = _extract_entities(clean_text)

    # Chunking
    blocks = _split_into_blocks(raw_text, is_markdown=is_md)
    # Strip markdown from each block before storing chunks
    if is_md:
        blocks = [_strip_markdown(b) for b in blocks]
    chunks = _merge_blocks_into_chunks(blocks)

    logger.info(
        "Parsed text file %s → %d chunks, entities: %s",
        path.name,
        len(chunks),
        {k: len(v) for k, v in entities.items()},
    )
    return entities, chunks
