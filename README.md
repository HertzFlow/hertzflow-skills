# hertzflow-skills

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Skills package](https://img.shields.io/badge/skills-hertzflow-blue)](https://www.npmjs.com/package/skills)

> **HertzFlow Skills** — a trading toolkit curated and developed by the
> HertzFlow research team, designed to give traders faster on-chain +
> CEX insight and support better trade-decision calls. Actively
> maintained and expanding.

[English](#english) · [中文](#中文)

---

## English

### What is HertzFlow Skills

`hertzflow-skills` is the umbrella repository for HertzFlow's open-source
AI-agent trading toolkit. Each skill inside this repo plugs into your
AI coding agent (Claude Code, Cursor, Codex CLI, Windsurf, and ~50
others) and gives the agent a specific research capability — on-chain
forensics, CEX intelligence, perp metrics, and more.

You install the whole suite once with a single command, and every
sub-skill lives in its own folder under `skills/`. New capabilities are
added over time without breaking what you've already installed.

#### Available sub-skills

| Sub-skill | Slash | Status | What it does |
|---|---|---|---|
| **Alpha forensic** | `/hertzflow` | ✅ Shipped (v0.9.x) | On-chain forensic for any Binance Alpha–listed token on a surf-SQL-covered EVM chain (BSC / Ethereum / Arbitrum / Base / Polygon / Optimism) + Solana HOLDER_SNAPSHOT. Paste a CA, get a trader-facing report on insider distribution, real-distribution confirmed sell-out, chip 3-way (operator / CEX / verifiable retail), anomaly waves, monitoring exports. |

More sub-skills from the HertzFlow research team are in active
development and will be added to this same `/hertzflow` slash as they
ship — the skill is designed so new capabilities slot in without you
needing to reinstall anything.

### What the Alpha forensic sub-skill does (most-shipped today)

If you trade on Binance Alpha, you've probably seen this pattern:
a token launches, runs up, and then bleeds for weeks. The people
who saw the bleed coming weren't reading tea leaves — they were
reading the **on-chain data**. They saw the project push supply
into ten wallets before the launch. They saw two of those wallets
quietly drip-feed into the LP. They saw the other eight sitting
there, ready to dump on any rally.

**HertzFlow's Alpha sub-skill makes that view available with one
command.** Paste the contract address, wait 2–10 minutes (depending
on token activity and surf cache state), and get back a trader-facing
report: who currently holds what, how the supply was distributed,
which wallets to watch from here, the token's current on-chain state
(5-tier: clean / watch / operator-dumped / dormant-insider-risk /
recent-distribution), and a 7-dimension at-a-glance TL;DR covering
chip structure, insider sell-out, volume quality, supply risk, and
market stage.

You **do not** need to know what a "mint event" or a "fan-out" is.
You don't need to keep ten BscScan tabs open. You don't need to
write SQL. The sub-skill does the on-chain forensic work in the
background and hands you a plain-language report.

### What can it help you do

For any Binance Alpha–listed BSC token, the skill answers the six
questions a serious trader actually has to ask:

1. **Is the inner circle dumping right now?**
   The report splits supply movement into three phases: pre-launch
   OTC seeding, downstream carrier hops, and the most recent 72 hours
   of large transfers. You see at a glance whether distribution is
   finished or still active — and where in that cycle the token is.

2. **How much can you actually buy without moving the price?**
   The skill pulls Binance Alpha's **official depth API** (not
   aggregator estimates) and computes the maximum single-tranche buy
   under 5 % slippage. Aggregator-based retail tools (1inch / DEX
   Screener etc.) only see DEX pool depth and miss Binance's internal
   MM book, so they often understate true tranche capacity by an
   order of magnitude or more; this report gives you a number you can
   size against.

3. **Who currently holds what?**
   Holders grouped by role: project deployer / project lockup
   (vesting + multisig + treasury + DEX-infra + CEX custody, Arkham
   confirmed) / quiet insider (never moved) / partial dumper /
   dumper-destination (retail receiving downstream) / DEX pool /
   other (uncategorized retail). Each row shows current balance,
   percent of supply, and dollar value. You instantly see how much
   "hidden" supply is still parked, waiting for a rally.

4. **Where did the supply come from?**
   An **m6 lineage table** (tucked into a `<details>` fold inside the
   holdings section) lists every wallet that received tokens from the
   project deployer — how much they got, how much they still hold,
   and what percentage they've already dumped. You can tell apart
   project vesting addresses, market makers, and wallets that *look*
   like retail but were funded directly by the project.

5. **Which wallets should you watch from here?**
   You get a 15–20 wallet monitoring list with role labels and alert
   conditions, exported as JSON that pastes directly into Binance
   Wallet or OKX address-tracking. The moment a quiet insider starts
   moving, you know.

6. **What's this token's on-chain state right now?**
   The report's **Decision summary** assigns the token to one of
   5 chain-state tiers — *clean / watch / operator-dumped /
   dormant-insider-risk / recent-distribution* — plus a 0–10 risk
   score and a max single-tranche entry size pulled from Alpha's
   depth API. The state tier + 7-dimension at-a-glance TL;DR is
   what you actually trade on; the skill deliberately does **not**
   give buy / sell instructions — it describes the chain, you make
   the call.

The goal is simple: give a non-engineer trader the same on-chain read
that a full-time chain analyst would produce. End-to-end runtime is
typically 2–10 minutes depending on token activity.

### Chain coverage

Most Alpha tokens are on BSC, but Alpha also lists tokens on other EVM
chains — the skill runs full on-chain forensics on all of them. Solana
is the only exception, called out below.

| Chain | Realtime price / vol / mcap / FDV | Full historical forensic (m6 lineage / 72h anomaly / wash infra / cross-sym) |
|---|:-:|:-:|
| **BSC** (BNB Chain) | ✅ | ✅ |
| **Ethereum** | ✅ | ✅ |
| **Arbitrum** | ✅ | ✅ |
| **Base** | ✅ | ✅ |
| **Polygon** | ✅ | ✅ |
| **Optimism** | ✅ | ✅ |
| **Solana** | ✅ | ❌ HOLDER_SNAPSHOT mode (no surf SQL coverage for Solana) |
| Sui / TRON / other non-EVM | ✅ (realtime only, no forensic) | ❌ |

Full historical forensic — pre-launch OTC seeding, downstream carrier
hops, anomaly waves, wash-infrastructure detection, cross-sym operator
registry — **runs on all 6 surf-SQL-covered EVM chains**. The pipeline
auto-routes SQL to the right per-chain tables via `chain_router.py`;
no manual chain flag needed.

Solana tokens run in **HOLDER_SNAPSHOT mode**: Alpha API realtime data
+ top holders + Arkham labels still come through, but every SQL-driven
detector section (m6 lineage, real-distribution sell-out quantification,
wash detection, 72h anomaly, TGE LP-first-trade) is skipped, with a
prominent banner at the top of the report.

Non-EVM, non-Solana tokens (Sui / TRON / etc.) return realtime price /
vol / FDV only — the forensic sections are entirely skipped.

### Install

```bash
npx skills add HertzFlow/hertzflow-skills
```

That command always installs the latest stable revision from `main`.
You do **not** need to pin a version. To upgrade later:

```bash
npx skills update hertzflow
```

The skill is delivered through the
[vercel-labs/skills](https://www.npmjs.com/package/skills) universal
installer.

### Prerequisites

1. **Surf account.** Register a free account at
   <https://agents.asksurf.ai/>, install the Surf CLI per
   [the official docs](https://docs.asksurf.ai/cli/cli), then:

   ```bash
   surf auth --api-key sk-...        # persistent
   # or
   export SURF_API_KEY=sk-...        # env var
   ```

2. **`curl` and `jq`.** Standard on macOS / Linux. On Windows, use
   WSL or Git Bash.

The free anonymous Surf tier cannot complete a full report — register
for a free account to get the bonus credits needed.

### How it works

```
CA + alpha_listing_date
        ↓
forensic_pipeline.py     (Python, ~1–8 min, deterministic — no LLM)
  emits skeleton.json     locked data + <LLM_NARRATIVE_PLACEHOLDER> slots
        ↓
LLM fill                 (your agent fills ~100-250 narrative slots)
  emits filled.json
        ↓
validate_report_data.py  (rejects out-of-bounds writes, hallucinations,
                          duplicated narrative, missing provenance)
        ↓
render_report.py         (Jinja2, deterministic)
  emits report.md + monitoring/*.json
```

Three strict trust boundaries:

- **Pipeline (Python).** Owns ~70 % of the report — all SQL, on-chain
  reads, holder distribution, evidence graph IDs. Only layer that
  touches data.
- **LLM (any model).** Fills ~100–250 narrative slots (varies by
  token activity and m6 lineage size). Cannot write SQL, cannot pick
  the verdict, cannot decide thresholds.
- **Validator.** Rejects any LLM write outside its slots, any
  reference to data not in the evidence graph, and any duplicated
  boilerplate.

Result: different LLMs running the same skeleton produce the same
verdict. Cross-model convergence tests show ~91 % leaf-level identity
and 100 % match on `verdict` and `action` enums.

### Language

Reports ship in two languages — Simplified Chinese (default) and
English. Both `forensic_pipeline.py` and `render_report.py` accept a
`--lang {zh,en}` flag, which must match between the two calls.

```bash
python3 skills/hertzflow/alpha/v06/forensic_pipeline.py \
    --ca 0x... --out-dir ./out/ --lang en

python3 skills/hertzflow/alpha/v06/render_report.py \
    --skeleton ./out/.work/skeleton.json \
    --filled   ./out/.work/filled.json \
    --out      ./out/report.md \
    --lang     en
```

### Output files

```
out/
├── report.md                              # user-facing report (Markdown)
├── monitoring/
│   ├── monitoring_paste.json              # Binance / OKX paste-import
│   ├── monitoring_gmgn.txt                # GMGN paste (bare addresses)
│   ├── monitoring_gmgn_quoted.txt         # GMGN paste (quoted form)
│   ├── monitoring_binance_web3.csv        # Binance Web3 CSV upload
│   ├── monitoring_okx.csv                 # OKX CSV upload
│   └── monitoring_wallets_full.json       # analytics (full record set)
└── .work/                                 # hidden intermediates
    ├── skeleton.json
    └── filled.json
```

### How to read `report.md`

The report is a single Markdown file structured top-to-bottom. If you
only look at one thing, look at **🎯 At-a-glance** at the very top —
it compresses the entire report into 7 lines. The table below maps
to the actual section headings you'll see in the rendered report
(ordered as they appear).

| Section | What it tells you |
|---|---|
| **🎯 At-a-glance** (`🎯 一屏结论`, new in v0.8.7.0) | **Read this first.** 7-dimension deterministic TL;DR derived purely from detector output (no LLM narrative): current phase / chip structure (operator % / CEX pool % / verifiable retail %) / insider sell-out status / volume quality / supply risk / market stage / monitoring focus. Each dimension carries a colored severity emoji + a concrete number as evidence. Everything below is the supporting evidence. |
| **🎯 Quick summary** (`🎯 速读摘要`) | A project card: contract, Alpha tier, confirmed on-chain insider sell-out in USD, cross-chain distribution flags, report completeness notice. Aimed at non-technical retail traders. |
| **💹 Realtime market data** (`💹 代币行情`) | Price + 24h change + 24h vol (Alpha + DEX) + market cap + FDV + LP USD, all pulled from Alpha API / surf project-detail. |
| **📋 Decision summary** (`📋 决策摘要`) | Risk score (0-10), chain-state tier (5 classes: clean / watch / operator-dumped / dormant-insider-risk / recent-distribution, all displayed in Chinese), primary chain, max single-tranche buy ($), short-term catalysts, blindspots you must cross-check yourself. |
| **🎯 Chain state** (`🎯 链上状态`) | Detailed breakdown of the 5-tier state classifier + risk attribution (which detectors fired, how many points each adds). |
| **🧠 Behavior profile (10 fine-grained classes)** (`🧠 当前链上行为画像`) | A1-A4 / B1-B4 / C1-C4 / D2 on-chain signal labels. Orthogonal to the 5-tier chain state — a single token can be "recent-distribution" + simultaneously match A1+A2+B2+C3, etc. |
| **🔴 Real distribution (insider confirmed sell-out floor)** (`🔴 真实派发`) | **One of the two report cores.** Quantifies the on-chain confirmed insider sell-out as a floor estimate, in USD + % of circulating supply. Algorithm: insider's own (a) transfers into CEX deposit addresses + (b) direct DEX self-sell swaps, priced at insider-self-sell TWAP (not wash quotes). **Sub-section 🎯 Pump-vs-retail check** (`🎯 拉盘对手盘验证`, new in v0.8.7.1): 3-bucket chip classifier as a 3-row main table — operator / CEX pool / verifiable retail — each shown as % of circ. The 11 operator sub-buckets (m6 lineage / A2 control / multisig / vesting / mint reserves / minted-to-operator cluster / …) are tucked into an expandable fold so the first-eye view stays uncluttered. |
| **📊 Risk signal aggregation** (`📊 风险信号聚合`) | Parent section containing **detector summary** (which on-chain detectors fired + counts) + **rhythm narrative** (distribution pacing across waves — finished / mid-cycle / just starting). The 3 anomaly waves below are children of this section. |
| **3 anomaly waves** (`第一波 上线前 OTC 预分发` / `第二波 分发主体向下游分发` / `第三波 近 72h 异常活动`) | Token movement clustered into 3 time windows. Wave 1 = pre-launch OTC seeding (Rule 11). Wave 2 = mid-period downstream redistribution. Wave 3 = last 72 h large transfers. Each event shows USD value, from/to (short address), and a one-line interpretation. |
| **Primary chain** (`主战场链`) | Which chain the token actually trades on (BSC / Ethereum / Base / etc.) + cross-chain deployment flag + report's coverage scope for that chain. |
| **Entry-price anchors** (`入场价 锚点`) | Listing-day open, current price, anchor price snapshots — used for sizing reference. |
| **Alpha allocation** (`项目方话语权`) | How Alpha API reports the official supply split (project + team + community + Alpha pool) — *not* on-chain forensic; complementary to the holdings distribution below. |
| **Short-term CEX catalysts** (`短期上 CEX 催化剂`) | Which CEX perpetual venues the token is listed on, with timestamps. Drives the tier classification + any 14-day "new catalyst" flag. |
| **Entry size cap** (`进场上限`) | The most important sizing line: **max single-tranche buy at ≤5 % slippage**, pulled from Binance Alpha's official depth API. Compare to your intended position size. |
| **Holdings distribution** (`各角色持仓分布`) | Current holders grouped by role: DEX pool / project deployer / project lockup (vesting + multisig + treasury + DEX-infra + CEX custody, Arkham confirmed) / quiet insider / partial dumper / dumper destination / other. Each row shows balance, % of supply, USD value. **Contains a `<details>` fold** (`📂 上溯发现 (项目方钱包 → 内幕谱系)`) with the full m6 lineage table — every wallet that received from the deployer, its current balance, and dumped %. |
| **💰 High-value funding source attribution** (`💰 高价值地址资金来源`) | High-value wallets classified by how they acquired their tokens over the past 365 days: mint (received directly from 0x0) / DEX buy / P2P (other EOA transfers, including unidentified CEX withdrawals). ⛏️ high mint% = mining-token operator or sockpuppet airdrop farmer; 🟢 high DEX% = real retail buyer; 🔵 high P2P% = operator aggregation hub or OTC recipient. **Contains 4 sub-sections**: 🌉 bridge / mint-authority self-sell detail (v0.7.24a) · 🌊 high-throughput dumper wallets (v0.7.24b) · 🎯 CEX-fanout large-scale distribution control (v0.7.24e) · 🔗 multi-chain distribution tracking (v0.7.24c). |
| **🌐 Wallet cluster graph** (`🌐 钱包图 cluster`, v0.8.6.5) | Bubblemaps-style cluster detection — wallets that transfer high-value tokens (≥ 0.5% supply per edge) to each other form a connected component of ≥3 nodes. Surfaces operator-controlled clusters that aren't via the deployer trace (m6) or CEX fanout. |
| **Monitoring wallets + alerts** (`监控钱包 + 实时告警`) | The 6–20 most actionable addresses for ongoing tracking, with alert conditions (large transfer into DEX router / CEX deposit address auto-reports). Exported separately as the JSON / CSV files described below. |
| **🗺️ Multi-role address index** (`🗺️ 多角色地址索引`, v0.7.28) | Cross-section index of addresses that appear in multiple roles (e.g. a wallet that's both an m6 insider + a CEX-fanout hub) — useful for spotting structural operator wallets. |
| **Machine-readable JSON footer** (`机器可读 JSON`) | Stable event / wallet / row IDs (`evt_NNN`, `m6_NNN`, `node_NNN`) that the narrative cites — provenance you can grep against if you re-run later. Also contains a machine-readable `verdict` enum (`EXIT_IF_HOLDING` / `WAIT` / `ADVISORY`) for downstream AI agents; the user-facing body **does not** display this enum because the v0.7.25+ design replaced verdict-style "buy / sell" calls with the more honest 5-tier chain-state classifier above. |

If the report header carries a `⚠️ N narrative quality warnings` line,
the structural data is fine but the narrative slots that produced
those warnings should be re-filled by your LLM agent for a cleaner
read. The data itself is locked and validated either way.

### S1 / S2 / S3 tier definitions

The CEX listing tier is the single most important upstream catalyst
classifier in the report — it determines what kind of price action you
should expect and which exits are available.

| Tier | Definition | What it means for you |
|---|---|---|
| **S1** | Alpha only — token is listed on Binance Alpha but on **no** CEX perpetual futures venue anywhere. | Price action is driven almost entirely by Alpha order flow + on-chain holders. No external short pressure. Exit liquidity = Alpha depth only. |
| **S2** | Alpha + **Binance** perpetual futures. | Binance perp typically becomes the primary price-discovery venue (OI / depth usually exceed Alpha's own order book) and gives retail a directional short channel. **Two common misconceptions**: (1) Alpha tokens have **withdrawal lock-ups** (~90 days to 6 months) — during the lock window spot can't be moved, so spot-vs-perp **basis arbitrage is not actually executable** by retail; retail can only directional-short the perp. (2) **Binance perp listing is itself a major catalyst**, usually a pump-then-dump as shorts pile in. Volatility **expands** around the listing event, not compresses — convergence is a 3-6 month phenomenon as OI matures. |
| **S3** | Alpha + at least one **non-Binance** CEX perp (Aster, Bitget, OPG, etc.) — **whether or not Binance perp is also live**. | A non-Binance venue is the catalyst path. S3 does **not** imply S2: a token can reach S3 via Aster without Binance perp being live. The report shows which venues triggered S3. |

The tier is computed from real listing data in the report header, not
from the listing time. Look for the `tier` field in the header line.

### How to use the monitoring exports

The `monitoring/` folder is the actionable piece — the wallets the
report tells you to watch, formatted for direct import into the four
trackers most Alpha traders already use. **Paste route is more
reliable than file upload — try paste first.**

#### Binance Wallet (tracker / address watch)

1. Open the Binance Wallet app → *Address tracking* / *Track address*.
2. Choose **paste / import as JSON** (Binance UI calls this
   "GMGN format").
3. Open `monitoring/monitoring_paste.json`, select all, copy, paste
   into the dialog. Each row has `{address, name, emoji}`; the name
   carries the role label (e.g. `H-Deployer-3a6dc`).
4. Confirm — addresses appear in your watch list with role labels.

If paste fails, fall back to `monitoring_binance_web3.csv` via the
file-upload route (the web wallet supports CSV, not JSON).

#### OKX Wallet (address tracking)

1. OKX Wallet → *Watchlist* / *Track address*.
2. Choose paste-import. The same `monitoring_paste.json` works.
3. If paste fails, upload `monitoring_okx.csv` instead (columns:
   `Network, Address, Label, Note`).

#### GMGN (alerts)

GMGN's bulk import widget is **likely Solana-only** today — paste
attempts on BSC `0x…` addresses have returned "Invalid format" in
our testing. If GMGN bulk import works for BSC for you, try
`monitoring_gmgn.txt` (bare list) first, then
`monitoring_gmgn_quoted.txt` (quoted array) as a fallback.
Otherwise add wallets to GMGN one-by-one or stick with Binance /
OKX.

#### `monitoring_wallets_full.json` (analytics only)

This is the **full record set** — every wallet the pipeline
identified, with current balance, dumped %, role enum, evidence
graph reference, and recent-72h activity flag. Use this if you want
to script your own alerts or feed the data into a spreadsheet. It is
**not** importable into any tracker UI.

Wallet label format is `<SYM>-<ROLE>-<addr5>` (e.g.
`H-Deployer-3a6dc`, `H-Dumper-1de14`), ≤25 chars to clear known
tracker character limits. Role tokens: `Deployer / Dumper / PDumper /
Quiet / LP / Anomaly / Other`.

### License

[MIT](LICENSE) — free to use, modify, and redistribute. Attribution
appreciated but not required.

### About

Built by [HertzFlow](https://hertzflow.xyz) and released to the
community. HertzFlow is a permissionless perpetuals exchange on BNB
Chain; this skill is part of the open-source toolkit we use internally
and contribute back to the ecosystem.

---

## 中文

### HertzFlow Skills 是什么

`hertzflow-skills` 是 **由 HertzFlow 研究团队整理开发的交易用户
工具集**, 旨在帮助交易者更快地获得洞察, 辅助交易决断。持续更新
维护中。

每个 sub-skill 都嵌入你的 AI coding agent (Claude Code / Cursor /
Codex CLI / Windsurf / Cline / Continue / Aider 等 50+ 种), 给
agent 加一项专属研究能力 — 链上取证、CEX 情报、永续盘口、跨链桥
审计等。

一条命令装整套, 各 sub-skill 在 `skills/` 下独立子目录, 未来加新
能力不影响你已经装好的部分。

#### 当前已有的 sub-skill

| Sub-skill | Slash | 状态 | 干什么 |
|---|---|---|---|
| **Alpha forensic** | `/hertzflow` | ✅ 已发布 (v0.9.x) | 对任意 Binance Alpha 上线的 EVM token (BSC / Ethereum / Arbitrum / Base / Polygon / Optimism) 跑完整链上取证; Solana 走 HOLDER_SNAPSHOT 模式。粘贴 CA, 拿到一份给交易者看的报告: 内幕派发情况、真实派发确认变现下界、筹码三分法 (庄家 / CEX / 可验证非庄家)、异动波次、监控钱包导出。 |

HertzFlow 研究团队还在持续开发新 sub-skill, ship 后会自动并入同一个
`/hertzflow` slash — 架构上设计成新能力直接 slot in, 老用户不需要
重装任何东西。

### Alpha forensic sub-skill 干什么 (当前最成熟的子项)

做 Alpha 交易的, 应该见过这个模式: 一个币上线, 拉一波, 然后阴跌
几周。提前知道要阴跌的人不是看 K 线看出来的 — 他们看的是**链上
数据**。他们看到项目方上线前把筹码推到 10 个地址、看到其中 2 个
悄悄往 LP 里 drip、看到剩下 8 个还在那等着, 等行情一拉就准备砸。

**HertzFlow 的 Alpha sub-skill 让你也能看到这一层, 一条命令搞定**。
把合约地址粘进你的 AI agent, 等 **2-10 分钟** (看代币活跃度 + surf
缓存命中情况), 拿到一份**给交易者看的报告**: 现在谁手里有多少
筹码、筹码是怎么派发的、接下来要盯哪些钱包、当前链上状态属于 5
档里的哪一档 (无显著触发 / 观察中 / 派完离场 / 潜伏内幕未派 / 近期
派发), 以及一个 7 维度 一屏结论 TL;DR (筹码结构、内幕套现情况、
成交质量、供应风险、盘口阶段) — **报告只描述链上, 不给买卖建议**,
操作判断由你结合自己仓位 + 风险偏好决定。

你**不需要懂链上数据**。不需要知道什么叫 "mint event"、"fan-out"。
不需要同时开十个 BscScan 盯。不需要写 SQL。Sub-skill 在后台跑完
链上取证, 给你一份大白话报告。

### 它能帮你做什么

对任意一个 Binance Alpha 上线的 BSC 代币, skill 回答严肃交易者
必须问的 6 个问题:

1. **内幕现在是不是在出货?**
   报告把筹码动向分成三段: 上线前 OTC 铺货 / 下游 carrier 接力 /
   最近 72 小时大额转账。一眼看出派发是已经结束, 还是在进行中,
   以及代币处于这个周期的哪个位置。

2. **不滑点你到底能买多少?**
   Skill 直接拉 **Binance Alpha 官方深度 API** (不是聚合器估算),
   算出 5% 滑点下最大单笔买入金额。聚合器类散户工具 (1inch / DEX
   Screener 等) 只看 DEX 池深度, 看不到 Binance 内部 MM 的盘口,
   **经常低估真实可吃的 size 至少一个数量级**。报告给你一个能拿来
   size 的真实数字。

3. **当前谁手里拿着多少?**
   持仓按角色分组: 项目方部署钱包 / 项目方+基建+分发池 (vesting +
   多签 + treasury + DEX 基建 + CEX 托管, Arkham 已确认) / 潜伏
   内幕 (从未动过) / 分发中内幕 / 散户接收 (内幕下游) / DEX 主池 /
   其他 (未分类散户)。每行有当前余额、占总供应比例、美元价值。
   一眼看出还有多少"隐藏"筹码停在那, 等行情拉起来出。

4. **筹码是从哪来的?**
   一张 **m6 内幕谱系表** (塞在持仓分布段的 `<details>` fold 里)
   列出每个收过项目方分发的钱包: 收了多少、当前还剩多少、已派出 %。
   你能区分**项目方 vesting 地址** / **做市商** / **表面散户但
   实际是项目方关联钱包**。

5. **接下来应该盯哪些钱包?**
   你拿到一份 15-20 钱包的监控列表, 带角色标签 + 告警条件, 导出
   为 JSON 直接粘进 **Binance Wallet** 或 **OKX 地址追踪**。沉默
   的内幕一动手, 你立刻收到提醒。

6. **这个代币现在链上是什么状态?**
   报告的 **决策摘要 段** 给出 5 档链上状态判定 (无显著触发 /
   观察中 / 派完离场 / 潜伏内幕未派 / 近期派发) + 风险评分 (0-10)
   + 进场上限 (LP 5% 深度). 状态档位 + 一屏结论 7 维度才是你真正
   交易要看的; **skill 故意不给"买 / 卖 / 持有"指令** — 报告只
   描述链上, 你自己结合仓位 + 风险偏好做判断。

目标很简单: 让一个不懂链上的 Alpha 交易者, 拿到一份等同于全职链上
分析师产出的报告。完整流程 (pipeline + LLM 填充 + render) 通常
**2-10 分钟**跑完。

### 支持哪些链

跟你打交道最多的是 BSC, 但 Alpha 也会上其他 EVM 链的币 — 这些 skill
都能跑全套链上取证。Solana 例外, 单独说明:

| 链 | 实时行情 (价格 / vol / mcap / FDV) | 完整链上取证 (m6 谱系 / 72h 异动 / 对敲设置 / 跨币种庄家) |
|---|:-:|:-:|
| **BSC** (BNB Chain) | ✅ | ✅ |
| **Ethereum** | ✅ | ✅ |
| **Arbitrum** | ✅ | ✅ |
| **Base** | ✅ | ✅ |
| **Polygon** | ✅ | ✅ |
| **Optimism** | ✅ | ✅ |
| **Solana** | ✅ | ❌ HOLDER_SNAPSHOT 模式 (Solana 没 surf SQL 表) |
| Sui / TRON / 其他非 EVM | ✅ (只有行情, 没有链上取证) | ❌ |

完整链上取证 — 上线前 OTC 铺货、下游 carrier 接力、异动波次、对敲
设置检测、跨币种庄家集合 — 在 6 条 surf SQL 覆盖的 EVM 链上**全部
支持**, pipeline 自动把 SQL 路由到对应链的数据表, 不需要手动指定。

Solana 代币走 **HOLDER_SNAPSHOT 模式**: Alpha API 实时数据 + 头部
持币人 + Arkham 标签仍能拿到, 但所有依赖 SQL 的检测段 (m6 谱系 /
真实派发卖出量化 / 对敲检测 / 72h 异动 / TGE LP 首笔) 跳过, 报告头
部会有明显提示。

非 EVM / 非 Solana 代币 (Sui / TRON 等) 只返回实时行情字段, 链上
取证全部跳过。

### 安装

```bash
npx skills add HertzFlow/hertzflow-skills
```

这条命令永远拉 `main` 分支 HEAD = 最新 stable。**不要带 `@v0.X.X`
后缀**, 除非有特殊原因要 pin 旧版本。老用户升级:

```bash
npx skills update hertzflow
```

通过 [vercel-labs/skills](https://www.npmjs.com/package/skills)
universal installer 分发。

### 前置依赖

1. **Surf 账户**。在 <https://agents.asksurf.ai/> 注册免费账户, 按
   [官方文档](https://docs.asksurf.ai/cli/cli) 装 Surf CLI, 然后:

   ```bash
   surf auth --api-key sk-...        # 持久化
   # 或
   export SURF_API_KEY=sk-...        # 环境变量
   ```

2. **`curl` 和 `jq`**。macOS / Linux 自带。Windows 用 WSL 或
   Git Bash。

匿名 Surf tier 跑不完整份报告 — 注册免费账户拿赠送 credit 后才够用。

### 工作原理

```
CA + Alpha 上线日期
        ↓
forensic_pipeline.py     (Python, ~1-8 分钟, 确定性 — 无 LLM 参与)
  生成 skeleton.json      locked 数据 + <LLM_NARRATIVE_PLACEHOLDER> 槽位
        ↓
LLM 填充                 (你的 agent 只填 ~100-250 个 narrative 槽位)
  生成 filled.json
        ↓
validate_report_data.py  (拦截越界写入 / 幻觉 / 重复填充 / 没 provenance)
        ↓
render_report.py         (Jinja2, 确定性)
  生成 report.md + monitoring/*.json
```

三层严格的信任边界:

- **Pipeline (Python)**。占报告 ~70%, 所有 SQL、链上读取、持仓
  分布、evidence graph ID 都在这一层。**只有 pipeline 接触数据**。
- **LLM (任意模型)**。填 ~100-250 个 narrative 槽位 (取决于代币活跃度
  + m6 谱系大小)。**不能写 SQL, 不能选 verdict, 不能定阈值**。
- **Validator**。拦截 LLM 越界写入、引用不在 evidence graph 的
  数据、以及重复填充的样板话。

结果: 不同 LLM 跑同一份 skeleton 得到同一个 verdict。跨模型一致
性测试显示 ~91% 叶子节点完全相同, `verdict` 和 `action` enum
100% 匹配。

### 报告语言

报告支持中英文双语 — 默认中文。`forensic_pipeline.py` 和
`render_report.py` 都接受 `--lang {zh,en}` 参数, 两步必须一致。

```bash
python3 skills/hertzflow/alpha/v06/forensic_pipeline.py \
    --ca 0x... --out-dir ./out/ --lang zh

python3 skills/hertzflow/alpha/v06/render_report.py \
    --skeleton ./out/.work/skeleton.json \
    --filled   ./out/.work/filled.json \
    --out      ./out/report.md \
    --lang     zh
```

### 输出文件

```
out/
├── report.md                              # 用户报告 (Markdown)
├── monitoring/
│   ├── monitoring_paste.json              # Binance / OKX 粘贴导入
│   ├── monitoring_gmgn.txt                # GMGN 粘贴 (纯地址列表)
│   ├── monitoring_gmgn_quoted.txt         # GMGN 粘贴 (带引号格式)
│   ├── monitoring_binance_web3.csv        # Binance Web3 CSV 上传
│   ├── monitoring_okx.csv                 # OKX CSV 上传
│   └── monitoring_wallets_full.json       # 分析用 (完整记录, 含余额 + 派发 %)
└── .work/                                 # 隐藏中间文件
    ├── skeleton.json
    └── filled.json
```

### 怎么看 `report.md`

报告是一份 Markdown, 自顶向下按结构往下看。如果只看一眼, 看最顶上
的 **🎯 一屏结论** 就够了 — 那是把整份报告浓缩成 7 行的版本。下面
的表格跟你在 render 出的报告里实际看到的章节标题一一对应 (顺序也
按 render 出的顺序排)。

| 章节 | 看什么 |
|---|---|
| **🎯 一屏结论** (v0.8.7.0 新增) | **第一眼就看这个**。7 维度确定性 TL;DR 由 detector 输出推导, 不含 LLM narrative: 当前阶段 / 筹码结构 (庄家 % / 交易所 % / 非庄家 %) / 内幕套现情况 / 成交质量 / 供应风险 / 盘口阶段 / 监控重点。每个维度配 emoji 严重度 + 具体数字证据。下面全部章节都是这 7 行的支撑材料。 |
| **🎯 速读摘要** | 几行项目卡片: 合约、Alpha tier、内幕已链上变现 USD、跨链出货情况、本报告完整度提示。给非技术散户看。 |
| **💹 代币行情 (实时)** | 价格 / 24h 涨跌 / 24h 成交 (Alpha + DEX) / 市值 / FDV / LP USD。取自 Alpha API + surf project-detail。 |
| **📋 决策摘要** | 风险评分 (0-10), 链上状态标签 (5 档全中文: 无显著触发 / 观察中 / 派完离场 / 潜伏内幕未派 / 近期派发), 主战场链, 进场上限 ($), 短期催化, 必须自行核对的盲区。 |
| **🎯 链上状态** | 5 档状态的详细拆解 + 风险归因 (哪几个 detector 触发的, 各加几分)。 |
| **🧠 当前链上行为画像 (10 类细分)** | A1-A4 / B1-B4 / C1-C4 / D2 链上侦测信号细分标签。跟上方 5 档链上状态**正交** — 同一个 token 可以是"近期派发" + 同时命中 A1+A2+B2+C3 等多个画像。 |
| **🔴 真实派发 (内幕 确认卖出下界)** | 本段是报告核心一: 内幕钱包**已经在链上确认变现**的下界, 用 USD + 占流通 % 表达。算法: insider 自己 (a) 转入 CEX 充值地址 + (b) DEX 自卖 swap, 用 insider 自卖 TWAP 计价 (非 wash 报价)。**子段 🎯 拉盘对手盘验证** (v0.8.7.1 新增): 筹码三分法 3 行主表 — 庄家弹药 / 交易所中转池 / 可验证非庄家方抛压, 各显示占流通 %。庄家弹药 11 个子桶详情 (m6 谱系 / A2 控筹 / 多签 / vesting / 铸币储备 / 已铸给庄家集群 等) 全部塞进可展开 fold, 第一眼不再吓人。 |
| **📊 风险信号聚合** | 父段, 含 **检测器汇总** (哪些 链上 detector 触发 + 各自命中次数) + **节奏识别 narrative** (跨波次派发节奏 — 已完成 / 进行中 / 刚启动)。下面 3 波异动事件都是这段的子段。 |
| **3 波异动事件** (`第一波 上线前 OTC 预分发` / `第二波 分发主体向下游分发` / `第三波 近 72h 异常活动`) | 链上转账按 3 个时间窗口分簇。波 1 = 上线前 OTC 铺货 (Rule 11)。波 2 = 中期下游再分发。波 3 = 近 72h 大额转账。每个事件附 USD 金额、from/to 短地址、一行文字解读。 |
| **主战场链** | 这个代币实际在哪条链上交易 (BSC / Ethereum / Base 等) + 跨链部署 flag + 报告在该链上的覆盖范围。 |
| **入场价 锚点** | 上线首日开盘价、当前价、锚点价快照 — 给 size 做参考。 |
| **项目方话语权** | Alpha API 报的官方供应分配 (项目方 + 团队 + 社区 + Alpha 池) — **不是链上取证**, 跟下面的"持仓分布"互补看。 |
| **短期上 CEX 催化剂** | 该代币在哪些 CEX 永续上线、上线时间戳。决定 tier 分类 + 14 天内是否有"新催化剂"标记。 |
| **进场上限** | **最重要的 size 参考线**: 5% 滑点下单笔最大买入 USD, 取自 Binance Alpha 官方深度 API。拿这个数字跟你打算开的仓位对比。 |
| **各角色持仓分布** | 当前持有者按角色分组: DEX 主池 / 项目方钱包 / 项目方+基建+分发池 (vesting + 多签 + treasury + DEX 基建 + CEX 托管, Arkham 已确认) / 潜伏钱包 / 分发中钱包 / 散户接收 / 其他。每行附余额、占供应比例、USD 价值。**段内含 `<details>` fold** (`📂 上溯发现 (项目方钱包 → 内幕谱系)`) 列出完整 **m6 谱系表** — 每个收过项目方分发的钱包、当前余额、已派 %。 |
| **💰 高价值地址资金来源 (mint / DEX / P2P)** | 高价值钱包按 365 天内**怎么拿到 token** 分类: mint (零地址直接铸造) / DEX 买入 / P2P (其他 EOA 转账, 含 CEX 提现)。⛏️ Mint 占比高 = 矿币 / 跨链桥操作员 / 空投马甲; 🟢 DEX 占比高 = 真散户; 🔵 P2P 占比高 = 操作员归集 / OTC 收。**段内含 4 个子段**: 🌉 跨链桥 / 铸币权限合约自卖明细 (v0.7.24a) · 🌊 高频出货钱包 (v0.7.24b) · 🎯 CEX 提币大规模分发控筹 (v0.7.24e) · 🔗 跨链出货追踪 (v0.7.24c)。 |
| **🌐 钱包图 cluster** (v0.8.6.5) | Bubblemaps 风格的集群检测 — 互相高额转账 (单边 ≥ 0.5% 流通) 的钱包形成 ≥3 节点的 connected component。找出不通过 deployer trace (m6) 或 CEX fanout 也能识别的庄家控筹集群。 |
| **监控钱包 + 实时告警** | 后续要持续盯的 6-20 个核心地址 + 告警条件 (大额转入 DEX router / CEX 充值地址自动上报)。同时导出为下方说明的 JSON / CSV 文件。 |
| **🗺️ 多角色地址索引** (v0.7.28) | 多段交叉索引 — 列出在多个角色段都出现的地址 (例如同时是 m6 内幕 + CEX-fanout hub 的钱包), 帮你 spot 结构性庄家钱包。 |
| **机器可读 JSON (footer)** | 稳定的事件 / 钱包 / 行 ID (`evt_NNN` / `m6_NNN` / `node_NNN`) — narrative 引用的所有数据来源, 二次跑可以 grep 校对。footer 里还含一个机器可读的 `verdict` enum (`EXIT_IF_HOLDING` / `WAIT` / `ADVISORY`) 给下游 AI agent 用; **user-facing body 不显示 verdict 字** — v0.7.25+ 设计把 "买 / 卖" 式 verdict 替换成上面 决策摘要 段的 5 档链上状态, 更诚实。 |

如果报告头部有 `⚠️ N 条文字质量提示` 这一行, 说明数据是干净的但
narrative 槽位质量不达标 (重复模板 / 数字幻觉 / 通用 boilerplate), 让
LLM agent 重填那几个槽位即可。
**数据本身是 pipeline 锁住的, 不论 warning 在不在都已经过 validator**。

### S1 / S2 / S3 tier 定义

CEX 上线 tier 是报告里最重要的上游催化分类 — 它决定你对这个币
该期待什么样的价格走势, 以及出场流动性有多少。

| Tier | 定义 | 对你的意义 |
|---|---|---|
| **S1** | 只在 Binance Alpha 上线, **任何 CEX 永续都没有**。 | 价格几乎全靠 Alpha 单簿 + 链上持币人推动。**没有外部做空压力**。出场流动性 = Alpha 深度。 |
| **S2** | Alpha + **Binance 永续**。 | Binance perp 通常是主要价格发现场所 (OI / 深度一般大于 Alpha 单簿), 给散户开了做空通道。**两个常见误解**: (1) Alpha 代币有**提币锁定期** (~90 天-6 月), 锁定期内现货不能动, 散户**做不了 spot vs perp 基差套利**, 只能 perp 单边 short; (2) **Binance perp 上线本身是大催化**, 通常先 pump 后 dump (shorts pile in), 上线前后波动**放大**不是压缩 — 真要等波动收敛得 perp 上线 3-6 月 OI 沉淀以后。 |
| **S3** | Alpha + 至少一个**非 Binance 的 CEX 永续** (Aster / Bitget / OPG 等) — **不要求 Binance perp 必须先上**。 | 催化路径来自非 Binance venue。S3 **不蕴含 S2** — 一个币可以走 Aster 路径直接到 S3, Binance perp 还没上。报告里会显示具体是哪个 venue 触发的 S3。 |

Tier 是从真实上线数据算出来的, **不是从上线时间推测**。看报告头部
的 `tier` 字段。

### 怎么用监控导出文件

`monitoring/` 文件夹是**可执行**部分 — 报告告诉你要盯的钱包,
已经按四种主流 Alpha 交易者用的 tracker 格式导出好了。**粘贴
导入比文件上传可靠, 优先用粘贴。**

#### Binance Wallet (地址追踪)

1. 打开 Binance Wallet App → *地址追踪* / *Track address*。
2. 选**粘贴导入 JSON** (Binance 界面叫 "GMGN 格式")。
3. 打开 `monitoring/monitoring_paste.json`, 全选复制, 粘进对话框。
   每行是 `{address, name, emoji}`, name 含角色标签
   (例如 `H-Deployer-3a6dc`)。
4. 确认 — 地址带角色标签出现在监控列表里。

粘贴失败就走文件上传, 用 `monitoring_binance_web3.csv` (Binance
Web3 钱包文件上传只接受 CSV, 不接受 JSON)。

#### OKX Wallet (地址追踪)

1. OKX Wallet → *Watchlist* / *Track address*。
2. 选粘贴导入。同一份 `monitoring_paste.json` 直接用。
3. 粘贴失败改 `monitoring_okx.csv` (列: `Network, Address, Label, Note`)。

#### GMGN (告警)

GMGN 的 bulk import widget **当前疑似只支持 Solana** — 我们测试
BSC `0x…` 地址粘贴都报 "Invalid format"。如果你那边 GMGN BSC bulk
import 能用, 先试 `monitoring_gmgn.txt` (纯地址列表), 不行再试
`monitoring_gmgn_quoted.txt` (带引号数组)。都不行就 GMGN UI 里
一个一个手动加, 或者干脆只用 Binance / OKX。

#### `monitoring_wallets_full.json` (仅分析用)

这是**完整记录集** — pipeline 识别到的所有钱包, 含当前余额、派发 %、
角色 enum、evidence graph 引用、近 72h 活动 flag。**不能导入任何
tracker UI**, 用来自己写脚本告警或灌进表格分析。

钱包标签格式 `<SYM>-<ROLE>-<addr5>` (例如 `H-Deployer-3a6dc` /
`H-Dumper-1de14`), ≤25 字符跨平台兼容。角色 enum: `Deployer /
Dumper / PDumper / Quiet / LP / Anomaly / Other`。

### 许可证

[MIT](LICENSE) — 自由使用、修改、再分发。注明出处友好但非必须。

### 关于

由 [HertzFlow](https://hertzflow.xyz) 构建并开源回馈社区。
HertzFlow 是 BNB Chain 上的 permissionless perpetuals 交易所,
这个 skill 是我们内部使用的开源工具套件之一。
