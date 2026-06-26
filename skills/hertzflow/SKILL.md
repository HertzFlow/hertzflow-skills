---
name: hertzflow
description: >-
  HertzFlow on-chain trade-decision intelligence. Currently covers Binance
  Alpha forensic across all surf-SQL EVM chains (BSC / Ethereum / Arbitrum /
  Base / Polygon / Optimism) — insider distribution, 真实派发 confirmed
  sell-out, 筹码三分法 (operator / CEX pool / verifiable retail), anomaly
  waves, monitoring exports. Solana runs in HOLDER_SNAPSHOT mode.

  Auto-trigger whenever the user pastes a raw 0x-prefixed 40-hex EVM CA,
  a Solana base58 CA, mentions a Binance Alpha token by ticker, or asks
  about 链上 forensic / 内幕出货 / 派发 / chip structure / quiet insider /
  Alpha distribution / on-chain dump — even if they don't say "hertzflow"
  explicitly. Pipeline runs deterministically (~2-10 min per CA depending
  on activity + surf cache state); LLM only fills narrative slots, never
  picks the verdict or writes SQL.

  Perp metrics, bridge audits, and HertzFlow core contract analysis
  sub-domains are coming — when those ship, this skill will dispatch to
  them based on input pattern (perp symbol, bridge protocol name, etc.)
  using the router table below.

  REQUIRES a Surf account + SURF_API_KEY. New users get 2000 free credits
  (~6-8 reports) via the HertzFlow private invite. Full forensic costs
  ~$1.5-3 USD per CA in Surf credits after the free tier runs out.
metadata:
  version: "0.9.0"
tools:
  - bash
---

# hertzflow — Crypto trade-decision intelligence (single skill, multi-domain)

`hertzflow` is HertzFlow's umbrella skill for on-chain + CEX trading
research. Like Surf, it's one skill with internal routing — read the
table below to see which sub-domain handles the user's request, then
follow that sub-domain's `INSTRUCTIONS.md`.

## 🌐 Language — MANDATORY, read first

**Detect the language of the user's most recent message and use that
language for everything: your conversation replies AND the generated
report.** This is not optional and not a preference the user has to
ask for.

- Message contains CJK characters (`一-鿿`, kana, hangul) → operate in
  **Chinese** (`zh`): reply in Chinese, run the pipeline with `--lang zh`.
- Otherwise (English / Latin-script prompt) → operate in **English**
  (`en`): reply in English, run the pipeline with `--lang en`.

Supported report languages are `zh` and `en` (static, human-curated
packs). For a prompt in any other language, reply in that language but
generate the report in `en` (closest supported), and say so in one line.

The report-body language is locked at **pipeline** time via
`forensic_pipeline.py --lang {zh|en}` — it cannot be changed at render
time, and narrative fills must be authored in the same language. See the
"Report language" section of `alpha/INSTRUCTIONS.md` for the exact rule.
Getting this wrong forces a full pipeline re-run (re-spends Surf credits),
so set it from the user's language up front.

## Routing table

| If the user input matches… | Sub-domain | Instructions file |
|---|---|---|
| Raw 0x-prefixed 40-hex EVM CA (`0xea37a8de…`) | `alpha` (Binance Alpha forensic) | `alpha/INSTRUCTIONS.md` |
| Solana base58 CA (e.g. `Grass7B4R…`) | `alpha` (HOLDER_SNAPSHOT mode) | `alpha/INSTRUCTIONS.md` |
| Ticker of a token currently on Binance Alpha (`$JCT`, `$VELVET`, etc.) | `alpha` — first resolve ticker → CA via `surf search-token --q <ticker>`, then dispatch | `alpha/INSTRUCTIONS.md` |
| Natural-language phrasing about Alpha distribution / 内幕出货 / 链上派发 / quiet insider / chip structure | `alpha` | `alpha/INSTRUCTIONS.md` |
| Perp symbol (e.g. `BTCUSDT`) + analysis intent | `perp` (not yet shipped) | — coming soon |
| Bridge protocol name + audit intent | `bridge` (not yet shipped) | — coming soon |
| HertzFlow's own contract address + diagnostic intent | `core` (not yet shipped) | — coming soon |

## First action when invoked

1. Identify the sub-domain from the routing table above (default: `alpha`).
2. `cat <sub-domain>/INSTRUCTIONS.md` (paths are relative to this skill's
   install root — at runtime that's `~/.claude/skills/hertzflow/` or the
   equivalent agent skill dir, NOT the repo root. So for the alpha
   sub-domain, read `alpha/INSTRUCTIONS.md`.) Or read it via the
   agent's file-read tool) — that file is the full per-domain SKILL.md,
   including onboarding (Surf CLI install + API key prompt), prerequisites,
   3-step workflow (`forensic_pipeline.py` → LLM fill → `render_report.py`),
   writable-slot guide, validator rules, output schema.
3. Follow the instructions in that file verbatim. Do **not** re-derive the
   workflow from this router file — the per-domain instructions are
   authoritative and version-locked.

## Why this skill is structured this way

- **Single slash `/hertzflow`**: HertzFlow is one product brand covering
  multiple research domains (Alpha forensic, perp metrics, bridge audit,
  HertzFlow core). Users invoke one slash, the router handles dispatch.
- **Description bait is wide**: the description (above) tells the agent
  to auto-trigger on natural-language mentions of insider distribution,
  chip structure, etc. — like Surf, users don't have to type the slash
  explicitly.
- **Sub-domain isolation**: each sub-domain lives in its own folder with
  its own `INSTRUCTIONS.md`, helpers, and version tracking. Adding `perp/`
  later does not require touching `alpha/` code.

## Trust boundaries (apply to every sub-domain)

- **Pipeline (Python).** Deterministic. Owns all SQL, on-chain reads,
  evidence-graph IDs. The only layer that touches data.
- **LLM (any model).** Fills narrative slots inside structured writable
  fields. Cannot write SQL. Cannot pick the verdict. Cannot decide thresholds.
- **Validator.** Rejects LLM writes outside the writable slots, references
  to data not in the evidence graph, duplicated boilerplate, and any
  attempt to overwrite locked pipeline output.

Every sub-domain's `INSTRUCTIONS.md` must respect these three boundaries.

## Upgrade

```bash
npx skills update hertzflow
```

That pulls the latest revision from `main` of `HertzFlow/hertzflow-skills`.
Run after major releases (`v0.9.x` → `v1.0.0` etc.). Current version is
in the frontmatter (`metadata.version`) and `alpha/v06/helpers/_version.py`.
