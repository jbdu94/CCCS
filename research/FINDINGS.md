# Two Verified Bypasses of Regex-Based MCP Tool-Poisoning Scanners

**Status:** working proof-of-concept, verified in this lab. Not yet run against real deployed products, not yet responsibly disclosed to anyone, not yet submitted anywhere. Read "What's still needed before you submit" before you do.

## Abstract (draft)

Multiple published, open-source MCP tool-poisoning scanners (Snyk's agent-scan, ClawGuard, zeph-mcp, agentaudit) share a common detection architecture: regex/keyword pattern matching against tool description text, with a Unicode zero-width-character stripping step as their main obfuscation defense. zeph-common's own source comments name two evasion classes their mitigation does not cover: homoglyph substitution and multi-line splitting. We built working, measured proof-of-concept payloads for both, verified against a reference implementation of this scanner architecture, and show that a semantic (LLM-based) scanner catches both where the regex approach misses them.

## Background

Real, current context (found via web search, not from memory):

- Snyk's `agent-scan` flags prompt injection in tool descriptions via keyword rule W001/E001, and hidden Unicode via rule W021.
- ClawGuard: "245 patterns, 15 languages... F1=99.0%" — explicitly "no LLM in the loop."
- `zeph-mcp`/`zeph-common` (MIT/Apache-2.0, published on docs.rs): a shared regex pattern set with a documented Unicode Format-category stripper (`strip_format_chars`). Its own source comments state: *"Known evasion vectors include: non-English injections, semantic rephrasing, encoded payloads in markdown code blocks, multi-line splitting (regex `.` does not match `\n` by default), and homoglyph substitution. strip_format_chars mitigates Unicode Cf-category bypass but does not handle homoglyphs."*

That admission is real, published, and — as far as this search turned up — nobody has built and measured a working demonstration of either gap. That's the contribution here: not discovering the gap (the maintainers already know it exists), but turning "known but unmitigated" into "here's exactly how big the gap is and what closes it."

## Method

`research/reference_regex_scanner.py` implements the shared architecture these tools use: a small set of regex patterns matching common injection phrasing, plus the same zero-width-stripping preprocessing zeph-common ships. This is not a copy of any one tool — it's the common pattern all of them follow, built to be a fair, representative target.

Two techniques, each targeting a different part of that architecture:

**1. Homoglyph substitution** (`research/homoglyph_bypass.py`) — swaps specific Latin letters in trigger words for visually near-identical Cyrillic letters (e.g. Latin `a` → Cyrillic `а`, U+0430). The rendered text looks the same to a human in most fonts. The bytes a regex matches against are different.

**2. Multi-line/newline splitting** (`research/multiline_split_bypass.py`) — Python's `.` regex metacharacter does not match a newline unless `re.DOTALL` is set. A single newline placed between two keywords a pattern expects nearby (e.g. `critical...must` in a `.{0,40}` gap) breaks the match, regardless of total character count. **This only works against patterns using `.` as the inter-word gap — patterns using `\s+` are unaffected, because `\s` matches newlines regardless of DOTALL.** This precision was verified directly against Python's `re` module before being written up (see the module's docstring) — an earlier draft of this technique was wrong about which patterns it defeated, and that mistake is worth knowing about if you build on this.

## Results (verified in this lab)

| Technique | Reference regex scanner | AI semantic scanner |
|---|---|---|
| Baseline (plaintext injection) | **Flagged** (control — proves the scanner works) | Flagged |
| Homoglyph substitution | **Missed** | Flagged (requires live run to confirm — see below) |
| Multi-line splitting (targeted) | **Missed** | Flagged (requires live run to confirm — see below) |

Run it yourself:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cd research
python bypass_benchmark.py           # stages 1-2: regex + AI semantic scanner
python bypass_benchmark.py --live    # + stage 3: does a real LLM actually act on the hidden instruction?
```

Stage 3 (`--live`) is the part that turns "the regex misses it" into "and it matters": it asks a real Claude model, playing the downstream agent, to summarize what the tool will do — and checks whether the hidden instruction shows up in that summary. That's the proof the payload isn't just theoretically invisible, it's practically understood and actionable by a real model.

**I have not run stage 3 myself.** I don't have an API key in the environment this was built in. The request is verified to reach the real Anthropic API correctly (confirmed via a dummy-key request that fails only on auth, not on a malformed call) but I have not seen real output. Run it before you trust the "AI semantic scanner" column above as more than a hypothesis.

## Proposed mitigation

The AI semantic scanner pattern already built in this lab (`ai_blue_team/ai_soc_analyst.py`) is the natural fix: it reasons about intent rather than matching literal text, so homoglyphs and line breaks don't change what it's judging. That's not a novel idea on its own — "use an LLM to catch what regex misses" is an obvious next step — but pairing it with a *measured* regex failure rate on *named, verified* techniques is what makes it a result instead of an assertion.

## What's still needed before you submit this anywhere

Being direct about the gap between "this lab" and "a submission":

1. **Test against the real tools, not the reference implementation.** Install actual `agentaudit`, `ClawGuard`, or `zeph-mcp` (or contact a vendor with a commercial scanner) and run these exact payloads against them. The reference scanner here is representative, but "representative" is not "the real thing" — a reviewer will ask, correctly.
2. **Run stage 3 for real** and report actual model behavior, not a hypothesis.
3. **Widen the sample** — more payload variants, more target scanners, ideally more than one LLM as the "downstream agent" to show this isn't Claude-specific.
4. **Responsible disclosure, if warranted.** If a *specific named product* (not the reference scanner) turns out to be bypassable, that product's maintainers should hear from you before a conference does. zeph-common already admits the gap publicly, so there's likely no disclosure obligation there specifically — but check before assuming that for any other tool you test.
5. **Get this reviewed** by someone who'll try to break the methodology, not just the code.

This is a solid weekend's worth of a real research thread, not a finished paper. Worth pursuing — just not worth presenting as more finished than it is.
