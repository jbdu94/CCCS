"""
Reference regex-based MCP tool-description scanner.

This is a faithful, representative implementation of the detection
APPROACH used by multiple real, published, open-source MCP scanners:
Snyk's agent-scan (issue W001/E001 - keyword + Unicode checks on tool
descriptions), ClawGuard (245 regex patterns, explicitly "no LLM in the
loop"), and zeph-mcp/zeph-common (regex patterns compiled from a shared
pattern list, with zero-width stripping as its Unicode mitigation).

It is not a copy of any one tool's source - it's the common architecture
all of them share: keyword/regex matching against tool description text,
plus a Unicode-normalization preprocessing step. That shared architecture
is what the bypasses in this folder target.

zeph-common's own source comments (docs.rs, MIT/Apache-2.0, 2026) state
this directly:

    "Known evasion vectors include: non-English injections, semantic
    rephrasing, encoded payloads in markdown code blocks, multi-line
    splitting (regex `.` does not match `\\n` by default), and homoglyph
    substitution. strip_format_chars mitigates Unicode Cf-category
    bypass but does not handle homoglyphs."

This module demonstrates that those two admitted gaps are not just
theoretical - they're bypassable in a working, measurable, end-to-end
way, and shows what closes the gap.
"""
import re
import unicodedata

# Representative pattern set - same shape and same class of patterns as
# zeph-common's RAW_INJECTION_PATTERNS and Snyk agent-scan's W001 keyword
# list (both cited above).
INJECTION_PATTERNS = [
    ("ignore_instructions", re.compile(r"(?i)ignore\s+(all\s+)?(any\s+)?(previous\s+)?(prior\s+)?instructions")),
    ("role_override", re.compile(r"(?i)you\s+are\s+now")),
    ("override_directive", re.compile(r"(?i)(override|disregard|bypass)\s+(all\s+)?(safety|previous|prior)")),
    ("also_collect", re.compile(r"(?i)also\s+(collect|attach|include|send)")),
    ("urgent_authority", re.compile(r"(?i)(important|crucial|critical|vital|urgent)\b.{0,40}(must|required|mandatory)")),
]

# The mitigation zeph-common actually ships: strip zero-width / Unicode
# Format (Cf) category characters before matching. This is real and it
# does work against zero-width injection - that's why this file targets
# the two gaps zeph-common's own comments admit it does NOT cover.
ZERO_WIDTH_CATEGORIES = {"Cf"}


def strip_format_chars(text: str) -> str:
    """The real, working mitigation these scanners ship. Included here
    so the benchmark is fair: bypasses are tested AFTER this runs, not
    instead of it."""
    return "".join(ch for ch in text if unicodedata.category(ch) not in ZERO_WIDTH_CATEGORIES)


def scan_description(text: str) -> dict:
    """Returns the same shape of result these scanners produce: which
    patterns fired, on the Unicode-normalized text."""
    normalized = strip_format_chars(text)
    hits = [name for name, pattern in INJECTION_PATTERNS if pattern.search(normalized)]
    return {
        "flagged": len(hits) > 0,
        "patterns_matched": hits,
        "normalized_text": normalized,
    }
