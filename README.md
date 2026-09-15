# Purple Team Sandbox — UC1 / UC2 / UC3 (AI red team + AI blue team)

A disposable, isolated lab for running real purple team exercises where
**AI does both sides**:

- **AI red team** — a real Claude tool-calling agent (`ai_red_team/`) that
  plans and executes each attack against the live target. It is not given
  a script; it's given tools and an objective, and it decides what to do,
  turn by turn, based on what the target actually returns.
- **AI blue team** — a real Claude "SOC analyst" (`ai_blue_team/`) that
  reads the real telemetry the attack generated and reasons about what
  happened, instead of matching it against a fixed list of patterns.
- **Scripted versions of both** (`red_team/` and `blue_team/`) are kept
  alongside the AI versions — deterministic, free, no API key required.
  Use `--mode compare` to run both against the same target back-to-back
  and show the difference live. This is the strongest demo moment: same
  attack surface, same target, one side dumb automation, the other side
  genuine AI reasoning.

Every mode is a closed loop: red team makes real HTTP calls against a real
running service, the service writes real structured logs, blue team
(scripted or AI) reads those real logs and produces a real verdict.
Nothing is pre-scripted to succeed.

**Nothing here touches your organization's real infrastructure.** The
target runs in its own Docker container on an isolated bridge network, on
your machine only. Tear it down after the workshop and there is nothing
left.

## Safety design

- The AI red team agent's entire action space is the tool list it's
  given — each tool is a thin wrapper around one target endpoint. There
  is no general shell or network tool exposed to it anywhere in this lab,
  so it cannot act outside the sandbox even if it wanted to.
- Every agent run has a hard turn cap (default 8) so a model that loops
  can't run away on cost or time.
- The target's tool-call endpoint never executes real shell commands,
  even inside its own container — "execution" is always simulated and
  only logs what a real poisoned tool would have attempted.
- Runs fully offline by default for the target service (`MOCK_MODE=true`)
  — the AI modes need `ANTHROPIC_API_KEY` for the red/blue agents, but the
  target itself has no external dependency.
- All credentials issued (UC2) and all secrets returned (UC3) are
  synthetic, lab-only strings — never real keys or real database
  credentials.

## Prerequisites

- Docker + Docker Compose
- Python 3.11+ on the host
- An `ANTHROPIC_API_KEY` — only needed for `--mode ai` or `--mode compare`

## Setup

```bash
# 1. Start the isolated target
docker compose up -d --build
curl http://localhost:8000/healthz

# 2. Install host-side dependencies
pip install -r requirements.txt

# 3. For AI mode, set your key
export ANTHROPIC_API_KEY=sk-ant-...
```

## Cloud-realistic targets (UC1 / UC2)

For maximum "this is actually implementable" credibility, UC1 and UC2
can also run against a REAL, deployed Azure or AWS target instead of the
local sandbox - Azure API Center + Entra ID managed identity, or AWS
Agent Registry + Bedrock AgentCore Identity. See `cloud_target/README.md`
for setup, and add `--cloud azure` or `--cloud aws` to any UC1/UC2 run.

## Multiple runs for a defensible result

A single run is an anecdote. `--runs N` repeats the full exercise N times
and reports aggregate detection-rate statistics (full-detection rate
across N runs, mean/min/max findings rate, detection-time variance) -
the same standard of rigor as the SADF numbers from AI Village, not a
one-off demo result:

```bash
python run_exercise.py --uc 1 --mode compare --runs 10
```

## SIEM / CASB / EDR integration

Findings from this lab can feed real security tools, and real tool
findings can feed back into detection. See `connectors/` for the code;
here's what's actually possible with each, and what isn't:

| Tool | Direction | What it does |
|---|---|---|
| Splunk | Push only | Forwards findings to Splunk via HTTP Event Collector - `--forward-splunk` |
| CrowdStrike | Both | Pushes confirmed UC2 findings as Custom IOCs; pulls real Falcon alerts as correlation context for the AI analyst - `--enrich-crowdstrike` |
| Netskope | Pull only | Pulls real DLP/CASB alerts as correlation context - `--enrich-netskope`. Netskope has no public endpoint for a third party to push a custom alert in; their outbound tool (Cloud Exchange) pushes Netskope's own alerts out to other platforms, it isn't a channel for us to write into |

```bash
export SPLUNK_HEC_URL=https://your-splunk:8088/services/collector/event
export SPLUNK_HEC_TOKEN=...
export CROWDSTRIKE_CLIENT_ID=...
export CROWDSTRIKE_CLIENT_SECRET=...
export NETSKOPE_TENANT_HOSTNAME=yourtenant.goskope.com
export NETSKOPE_API_TOKEN=...

python run_exercise.py --uc 2 --mode ai --enrich-crowdstrike --enrich-netskope --forward-splunk
```

Any connector left unconfigured skips cleanly (prints why, doesn't error
out) - you can enable just the ones your environment actually has.

## Run an exercise

```bash
cd harness

# Fast, free, deterministic — good for rehearsal
python run_exercise.py --uc 1 --mode scripted

# Real AI agent attacking, real AI analyst detecting
python run_exercise.py --uc 1 --mode ai

# Both, back-to-back, with a side-by-side comparison table — the demo
python run_exercise.py --uc 1 --mode compare
python run_exercise.py --uc all --mode compare
```

Each run prints, live:
- what the red team (script or AI agent) actually did — for the AI
  agent, this includes its own reasoning text between tool calls, so the
  audience sees it think, not just act
- what the blue team (rules or AI analyst) found when it read the
  resulting log, with confidence scores for the AI analyst
- a verdict count and timing for both sides

## What to point at live, on stage

- **UC1 compare**: the scripted attacker always registers the same tool
  name and payload; the AI agent composes its own cover story and its
  own rug-pull timing each run — run it twice and show it's not the same
  attack twice.
- **UC3 compare**: the scripted attacker sends a fixed prompt list; the
  AI agent adapts its phrasing based on what the target actually said
  back. If the first angle fails, watch it try a different one.
- **The regex miss**: the scripted UC3 detector misses a real leak
  because the fake key contains a hyphen (`sk-lab-FAKE...`) that its
  regex doesn't match — which happens to be how real Anthropic/OpenAI
  keys are actually formatted. Run `--mode compare` on UC3 and show the
  AI analyst catching it anyway, then explain why the regex didn't.

## Inspect raw telemetry

```bash
cat logs/events.jsonl | python -m json.tool
```

Same file both the scripted and AI blue teams read — good to show the
audience the actual data a detector (of either kind) works from.

## Tear down (leave nothing behind)

```bash
./teardown.sh
```

Stops and removes the container, removes the isolated network, deletes
the log file. Run this after every workshop delivery.

## Cost note

Each `--mode ai` pass makes roughly 3–8 Claude API calls per side
(red agent turns + one blue analysis call), using `claude-sonnet-5` by
default. Set `RED_TEAM_MODEL` / `BLUE_TEAM_MODEL` env vars to override.
Trivial cost for a workshop rehearsal; still worth not looping `--mode
compare --uc all` unattended.

## Rules of engagement

This lab is for use against the target service defined here, in this
isolated environment, only. Do not point the red team agent or scripts
at any other host. See the Rules of Engagement section of
`purple-teaming-ai-agents.md` for the full authorization/scope checklist
this lab assumes you've already satisfied.
