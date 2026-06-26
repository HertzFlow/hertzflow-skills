# hertzflow — alpha sub-domain (Binance Alpha forensic, v0.6+)

> This is the per-sub-domain instructions file for the `alpha` sub-domain
> of the `/hertzflow` skill. The entry-point `SKILL.md` (in
> `skills/hertzflow/SKILL.md`) routes here whenever the user pastes a raw
> 0x-prefixed 40-hex EVM CA, a Solana base58 CA, or asks about Binance
> Alpha-style on-chain forensic. **Do not re-derive the workflow from the
> entry-point SKILL.md — this file is authoritative for alpha.**
>
> REQUIRES Surf account + SURF_API_KEY. New users get 2000 free credits
> (~6-8 reports) via HertzFlow private invite — agent MUST follow the
> `## Onboarding` section verbatim and surface the coupon URL
> `http://agents.asksurf.ai/?coupon=hertzflow` during the
> Surf key prompt regardless of whether the user claims to have a key.
> Full forensic ~$1.5-3 USD per CA in Surf credits after free tier.

## What this skill is

Forensic analysis for Binance Alpha-listed tokens. Output is a ~15KB
markdown report covering: anomaly waves (Rule 11 + 72h), CEX catalyst
trace, LP depth + entry-size anchor, holdings distribution, deployer→
insider lineage flowchart, monitoring wallets, decision verdict +
structured action block.

**Chain coverage (v0.7.20)**: BSC, Ethereum, Base, Arbitrum, Polygon,
Optimism (full EVM coverage). Solana SQL tables are routable but
**Solana CAs are NOT yet accepted by Section A** — the entry-point CA
regex is `0x[a-fA-F0-9]{40}` so base58 Solana CAs return `INVALID_CA`.
Full Solana support requires adding base58 CA validation, a Solana
deployer-trace helper, and Solana-specific address validators in
`rule_11_backward_trace`. Tracked separately.

`forensic_pipeline.py` reads the Alpha API's `chainId` for the CA and
routes every Surf SQL query (transfers + dex_trades) to the matching
`agent.{chain}_*` ClickHouse partition via `helpers/chain_router.py`.
Unsupported chain IDs fail-loud with `UnsupportedChainError` rather than
silently falling back to BSC (the v0.7.19.x PLAY bug where an
`chainId=8453` Base token ran against `bsc_transfers` and produced an
empty forensic).

## Core principle

> **Pipeline locks data. LLM only writes narrative. Validator rejects
> anything else.**

The skill orchestrates 3 deterministic commands (`forensic_pipeline.py`,
LLM fill, `render_report.py`). The LLM never writes SQL, never picks
verdict.enum, never decides decision_anchors, never modifies
evidence_graph. It writes ~15 narrative slots; the validator enforces
both content quality AND that locked fields stayed locked. This
architecture was adopted after earlier LLM-render approaches failed
cross-LLM convergence testing — different LLMs would produce different
verdicts on the same skeleton because each freelanced in different
ways.

## Architecture (one diagram)

```
CA + alpha_listing_date
        ↓
forensic_pipeline.py (Python, ~12-25s)
  ├─ section_a_scope         (Alpha API + Spot graduation cross-probe)
  ├─ rule_11_backward_trace  (mint → deployer outflow → receivers → dumps)
  ├─ section_anomaly_72h     (recent large transfers)
  ├─ section_cex_trace       (Binance/Aster/Bitget perp probe → tier S1/S2/S3)
  ├─ section_liq             (DexScreener pool + Alpha 5% depth + LP 24h flow)
  ├─ section_tge             (LP creation ts + Alpha open ts + current px)
  ├─ section_alloc           (Rule 11 receivers → quiet/partial/full buckets)
  ├─ section_multi_chain     (single-chain BSC coverage check)
  ├─ section_f_holders       (top-50 current balance via surf)
  ├─ section_l_distribution  (role classification + flowchart nodes/edges)
  ├─ section_cross_sym       (cross-symbol mega-whale detection + 6-step
  │                           on-chain role classification per whale)
  └─ section_wash_infra      (5-step pure on-chain wash-infrastructure
                              detection: X / P / Q triplet signature)
        ↓
report_data_skeleton.json
  ├─ locked          (pipeline writes, frozen; LLM cannot touch)
  ├─ derived_locked  (pipeline computes from locked; LLM cannot touch)
  └─ writable        (LLM fills <LLM_NARRATIVE_PLACEHOLDER> slots)
        ↓
LLM fills the ~15 writable slots
        ↓
validate_report_data.py
  ├─ schema_version sanity
  ├─ locked + derived_locked invariance (V_LOCKED_FIELD_MODIFIED,
  │                                       V_LOCKED_FIELD_ABSENT,
  │                                       V_LOCKED_FIELD_COUNT)
  ├─ writable quality (min_length, min_count, semantic META check)
  ├─ provenance: evt_ref claims match evidence_graph data
  ├─ causal Rule 11 (m6.rows ↔ anomaly.waves consistency)
  ├─ R1-R12 cross-field rules
  └─ R12 placeholder removal (rejects <LLM_NARRATIVE_PLACEHOLDER>
                              AND <PIPELINE_PHASE_*> markers)
        ↓
render_report.py (mandatory in-process validate → jinja2 render)
        ↓
report.md
```

## Onboarding (agent must follow verbatim)

> **Audience for this section is the LLM agent (Claude / adversarial review / Kimi /
> Cursor / etc.) installing this skill on behalf of the user, not the
> human reader.** Follow steps 1-4 in order, switch locale based on the
> user's most recent message language (CJK characters → `zh`, otherwise
> → `en`), and pull every user-facing string from the `onboarding_i18n`
> bundle below. **Do not mix languages in a single message.** When the
> user has not specified yet, default to `en`.

### Step 1 — Ensure Surf CLI is installed

```bash
if ! command -v surf >/dev/null 2>&1; then
  # Display onboarding_i18n.installing_surf_cli[locale] to the user first.
  curl -fsSL https://downloads.asksurf.ai/cli/releases/install.sh | sh
fi
```

The pipeline assumes Python 3.10+, `jinja2`, `curl`, and `jq` are already
present (LLM CLI clients ship these). If any genuinely missing tool
surfaces during preflight, fall back to the matching `pip install`
or system-package command and explain it in the user's locale.

### Step 2 — Surf key prompt (paste `onboarding_i18n.surf_key_prompt[locale]` + `onboarding_i18n.coupon_banner[locale]`)

Send **both strings in a single user-facing message**, in the active
locale only. The coupon banner is **mandatory** — display it even when
the user claims to already have a key, so they know where to claim more
free credits later when this balance runs out.

After sending the prompt, wait for the user to paste a string that
looks like `sk-...`. If the user replies "no" / "I will register first"
/ a non-key message, re-display the same prompt + banner unchanged.

### Step 3 — Persist the key and verify

```bash
surf auth --api-key "$USER_PASTED_KEY"
if surf auth 2>&1 | grep -q "api-key: sk-"; then
  # Display onboarding_i18n.auth_success[locale].
  :
else
  # Display onboarding_i18n.auth_failure[locale], then GOTO Step 2.
  :
fi
```

### Step 4 — Hand off to the forensic loop

Once `surf auth` reports a saved `sk-...`, the skill is installed. From
this point use the `onboarding_i18n.ca_prompt`, `ca_invalid`,
`preflight_paid_step_warning`, and `report_ready` strings in the same
locale for every subsequent interaction.

### `onboarding_i18n` bundle (inline, single source of truth)

```yaml
onboarding_i18n:

  installing_surf_cli:
    en: |
      Surf CLI not found on your machine — installing now (one-time, ~10s).
    zh: |
      本机没装 Surf CLI, 我现在帮你装一下 (一次性, ~10 秒).

  surf_key_prompt:
    en: |
      **Surf API key required**

      Do you already have a Surf API key (starts with `sk-`)?

      Paste it now to continue. If you don't have one yet, use the
      registration link below.
    zh: |
      **需要 Surf API key**

      你有 Surf API key (`sk-` 开头那串) 吗?

      有的话直接粘给我. 没有的话用下面链接注册.

  coupon_banner:
    en: |
      🎁 **HertzFlow private invite — 2000 free credits (~6-8 forensic reports)**

      → http://agents.asksurf.ai/?coupon=hertzflow

      The coupon auto-applies on signup. Once registered, go to
      **Dashboard → API Keys**, copy your `sk-...` key, and paste it
      back here.
    zh: |
      🎁 **HertzFlow 私邀链接 — 2000 免费 credits (够跑 6-8 份 forensic 报告)**

      → http://agents.asksurf.ai/?coupon=hertzflow

      Coupon 注册时自动入账. 注册完去 **Dashboard → API Keys** 复制
      `sk-...` 那串粘回来.

  auth_success:
    en: |
      ✅ Surf authenticated. You can now paste any BSC / EVM contract
      address to run forensic.
    zh: |
      ✅ Surf 认证成功. 现在可以粘任何 BSC / EVM 合约地址跑 forensic 了.

  auth_failure:
    en: |
      ❌ That key didn't validate. Please double-check it from
      **Dashboard → API Keys** and paste again.
    zh: |
      ❌ 这个 key 验证失败. 去 **Dashboard → API Keys** 再核对一次粘给我.

  ca_prompt:
    en: |
      Paste the BSC / EVM contract address (starts with `0x`) you want
      to analyze.
    zh: |
      把要分析的 BSC / EVM 合约地址 (`0x` 开头那串) 粘给我.

  ca_invalid:
    en: |
      That doesn't look like a valid EVM contract address (expected
      `0x` + 40 hex chars). Please paste again.
    zh: |
      这不像合法的 EVM 合约地址 (应该是 `0x` + 40 位 hex). 重新粘一次.

  preflight_paid_step_warning:
    en: |
      ⚠️ Free preflight done. The next step is the paid forensic —
      estimated **~$1.5-3** in Surf credits (≈ 6-8 % of the 2000-credit
      free invite balance). Proceed? (Y/N)
    zh: |
      ⚠️ 免费的 preflight 跑完了. 下一步是付费 forensic — 估算约
      **$1.5-3** 的 Surf credits (大概用掉 2000 免费额度的 6-8 %).
      继续吗? (Y/N)

  report_ready:
    en: |
      ✅ Report saved → `{path}`. Opening it in your editor now.
    zh: |
      ✅ 报告生成完, 保存在 `{path}`. 帮你在编辑器里打开了.
```

## Prerequisites (dependency list)

| Tool | Why |
|---|---|
| `surf` CLI | All on-chain SQL + `token-holders` + `project-detail` calls — installed in Onboarding Step 1. |
| `SURF_API_KEY` (saved via `surf auth` or env var) | Anonymous tier (~30 credits/day) cannot complete a report (~250-350 credits) — claimed in Onboarding Step 2 via the HertzFlow invite. |
| Python 3.10+ with `jinja2` | Pipeline + render. `pip install jinja2` if missing. |
| `curl`, `jq` | Standard CLI calls. macOS/Linux default; Windows users see the **Windows runtime notes** subsection below. |
| `ETHERSCAN_API_KEY` (optional) | Fallback label resolver if BscScan public scrape rate-limits. |

### Optional upstream Surf skill

For Cursor / skills-ecosystem users who also want Surf's own workflow
skill alongside `hertzflow`:

```bash
npx skills add asksurf-ai/surf-skills --skill surf
```

### Preflight (run first, fail closed)

```bash
for tool in surf curl jq python3; do
  command -v "$tool" >/dev/null || { echo "INSUFFICIENT_DATA: missing $tool"; exit 1; }
done
surf auth 2>&1 | grep -q "api-key: sk-" || {
  # Bilingual fallback because at preflight time the agent may not have
  # the user's locale signal yet. Both strings stay machine-greppable.
  echo "INSUFFICIENT_DATA: surf auth required."
  echo "🎁 EN: Claim 2000 free credits at http://agents.asksurf.ai/?coupon=hertzflow then run 'surf auth --api-key sk-...'"
  echo "🎁 中文: 用 http://agents.asksurf.ai/?coupon=hertzflow 领 2000 免费 credits, 然后跑 'surf auth --api-key sk-...'"
  exit 1
}
echo "$CA_INPUT" | grep -qE '^0x[a-fA-F0-9]{40}$' || {
  echo "INSUFFICIENT_DATA: CA failed regex ^0x[a-fA-F0-9]{40}$"; exit 1
}
CA_LOWER=$(echo "$CA_INPUT" | tr 'A-F' 'a-f')
```

### Windows runtime notes (PowerShell / ARM)

**EN** — the pipeline runs unchanged on Windows, including Surface Laptop
ARM via Prism emulation, but PowerShell 5.x has three gotchas worth
calling out before you blame the pipeline:

1. **`curl` is a PowerShell alias for `Invoke-WebRequest`.** Always use
   the bundled binary `curl.exe` (e.g. `curl.exe --version`); otherwise
   `--fail` and `-sSL` are silently reinterpreted and the surf installer
   one-liner is wrong.
2. **Anything written to `stderr` triggers `NativeCommandError`** in
   PowerShell 5.x even on exit 0, so `forensic_pipeline.py` writes its
   banner to **`stdout` since v0.7.17**. Do **not** redirect with
   `2>&1 | Tee-Object` — it loses the per-stream split that the
   pipeline relies on. Use `python3 ... > skeleton.log 2> skeleton.err`
   or run inside `cmd.exe`.
3. **Tail-section hangs leave the skeleton missing.** As of v0.7.17 the
   pipeline writes `.work/skeleton_partial.json` after every section
   plus `_status: in_progress` + `_last_section_completed`, so even a
   hard kill / SIGINT leaves a partial skeleton you can inspect. The
   slowest tail section (`section_wash_infra`) obeys
   `BINANCE_ALPHA_WASH_INFRA_MAX_SECONDS` (default 300s).
   **v0.7.18** parallelized Steps 2-5 of `wash_infra_detector` via an
   8-way `ThreadPoolExecutor` so BEAT-sized tokens (70 candidates after
   Step 1 filter) drop from ~420s serial to ~50-60s parallel. Override
   the worker count via `BINANCE_ALPHA_WASH_INFRA_WORKERS` (default 8).
   On ARM-emulated Python you generally do NOT need to bump the budget
   any more; if you still see truncation, drop workers to 4 first
   (surf rate-limit, not wall-clock).

4. **Chinese narrative in your fill step needs UTF-8 I/O.** Windows
   Python defaults to `cp936` for stdin/stdout when running under the
   classic Windows console / piped through tools that don't set the
   code page. Symptom: your fill script wrote
   `"内幕方仍持 86.89% 总供应"` but the file reads back as
   `"???????? 86.89% ????"` and `render_report.py` either crashes on
   non-UTF-8 bytes or emits a report full of `?`.

   Apply **all three** layers — Python env, host console, file open
   — because each closes a different gap (Python interpreter, OS
   console buffer, file-level encoding):

   **Python env (always):**
   ```cmd
   set PYTHONIOENCODING=utf-8
   set PYTHONUTF8=1
   ```

   **Host console (`cmd.exe`):**
   ```cmd
   chcp 65001
   ```

   **Host console (PowerShell 5.1 / 7):**
   ```powershell
   $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
   [Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)
   [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
   ```

   **In any fill script you author**, open files explicitly UTF-8:
   ```python
   with open(path, "w", encoding="utf-8") as f:
       json.dump(data, f, ensure_ascii=False)
   ```

   (`ensure_ascii=False` keeps Chinese as Chinese instead of escaping
   to `\uXXXX` bloat; the validator handles both, but the file is
   smaller and inspectable. The script-level fix alone is **not**
   enough if `cmd.exe` / PowerShell still pipes through a non-UTF-8
   code page on the way in.)

**中文** — pipeline 在 Windows (含 Surface Laptop 7 ARM, Prism 模拟) 跑
没问题, 但 PowerShell 5.x 有 3 个坑出问题先看这里, 别先怪 pipeline:

1. **`curl` 在 PowerShell 是 `Invoke-WebRequest` 的别名**. 永远显式调
   `curl.exe` (例: `curl.exe --version`), 否则 `--fail` / `-sSL` 被静默
   重新解释, surf 安装命令直接错.
2. **任何写到 `stderr` 都会触发 `NativeCommandError`** (PowerShell 5.x,
   即使 exit 0). 所以 v0.7.17 起 `forensic_pipeline.py` 的 banner 改写
   `stdout`. 不要用 `2>&1 | Tee-Object` 把两个流合并 — pipeline 依赖
   stdout/stderr 分流. 推荐: `python3 ... > skeleton.log 2> skeleton.err`,
   或者直接在 `cmd.exe` 里跑.
3. **尾部 section 卡住时 skeleton 文件会丢**. v0.7.17 起 pipeline 每跑
   完一个 section 就写 `.work/skeleton_partial.json` (含 `_status:
   in_progress` + `_last_section_completed`), 即使 SIGINT / 硬杀也能
   inspect 部分结果. 最慢的尾 section (`section_wash_infra`) 现在受
   `BINANCE_ALPHA_WASH_INFRA_MAX_SECONDS` env (默认 300s) 控制. ARM
   模拟下每条 surf SQL 慢 2-3 倍, 建议调到 600-900s 而不是直接杀进程.

## Report language — MANDATORY, derive from the user's input language

> **This is the bridge the agent MUST close: the report body language is a
> SEPARATE i18n system from the `onboarding_i18n` prompt strings, and it
> does NOT auto-detect.** The pipeline owns the report-body locale via
> `forensic_pipeline.py --lang {zh|en}` (equivalently the
> `BINANCE_ALPHA_LANG` env var). **Both default to `zh`.** A full `en.json`
> language pack ships and is at parity with `zh.json` — but nothing in the
> pipeline inspects the user's message, so if you don't pass `--lang`, every
> report comes out Chinese regardless of what language the user wrote in.

**Rule (same locale logic as `onboarding_i18n`): before running the
pipeline, pick `--lang` from the user's most recent message:**

- Message contains CJK characters (`一-鿿` etc.) → `--lang zh`
- Otherwise (English / Latin-script) → `--lang en`

Locked report-body strings are baked into the skeleton at pipeline time, so
**the language cannot be changed at render or fill time** — it must be set on
the `forensic_pipeline.py` call. Authoring narrative fills in step 2 must
match the chosen `--lang` (English narrative for `--lang en`). Getting this
wrong means a full pipeline re-run (re-spends Surf credits), so set it once,
up front.

## Quick start (3 commands)

```bash
# Paths below are relative to this `alpha/` sub-domain root inside the
# installed skill (~/.claude/skills/hertzflow/alpha/). Run them from
# there, or prefix with the absolute install path.

# 0. Pick LANG from the user's most recent message (see rule above):
#    CJK chars → zh, otherwise → en.
LANG_FLAG=en   # or zh

# 1. Pipeline — produces skeleton + initial monitoring_wallets export
python3 v06/forensic_pipeline.py "$CA_LOWER" --lang "$LANG_FLAG" --out /tmp/skeleton.json

# 2. LLM fills writable slots (see "LLM fill guide" below)
#    Read /tmp/skeleton.json, replace every "<LLM_NARRATIVE_PLACEHOLDER>"
#    with a real narrative string IN THE SAME LANGUAGE as --lang,
#    write to /tmp/filled.json.

# 3. Render — validator runs in-process first; render aborts on any error
#    Also re-emits monitoring_wallets/* with LLM-filled alert text
python3 v06/render_report.py \
  --skeleton /tmp/skeleton.json \
  --filled /tmp/filled.json \
  --out /tmp/report.md
```

Total wall clock: ~12-25s pipeline + LLM fill (varies) + <1s render.

### 🚫 Step 2 must be authored by you — DO NOT invoke `tests/smoke_fill.py`

**EN** — `tests/smoke_fill.py` is a CI/E2E test fixture that produces
placeholder narrative strings (e.g. `(alpha variant)`, `(bravo variant)`).
It exists to exercise the pipeline → render plumbing in unit tests;
**it is not a production fill step**.

**中文** — `tests/smoke_fill.py` 是 CI/E2E 测试用的 fixture, 产出 NATO
后缀占位符 (`(alpha variant)` / `(bravo variant)` ...). 它只用来跑
pipeline → render 的单元测试管道, **不是生产环境的 fill 步骤**.

`render_report.py` enforces this at the code level (v0.7.2) /
`render_report.py` 在代码层硬挡 (v0.7.2):

- **EN**: Smoke fixtures carry `_smoke_test_fixture: true` at top level
  of `filled.json`. Render exits 3 ("REFUSED") on detection. Even if
  the flag is stripped, render fingerprint-detects NATO-suffix stubs
  (≥3 distinct words → exit 3). Override requires BOTH
  `BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1` AND
  `BINANCE_ALPHA_SMOKE_OVERRIDE_REASON="<text>"` (CI/E2E only).
- **中文**: Smoke fixture 在 `filled.json` 顶层注入
  `_smoke_test_fixture: true`. Render 检到 → exit 3 ("REFUSED"). 即使
  把 flag 删了, render 还会扫 NATO 后缀指纹 (≥3 个不同词 → exit 3).
  Override 必须同时设两个 env var:
  `BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1` 和
  `BINANCE_ALPHA_SMOKE_OVERRIDE_REASON="<理由>"` (仅 CI/E2E 用).

**The correct workflow for step 2 / Step 2 正确流程:**

1. **EN**: Read `/tmp/skeleton.json` directly (it's plain JSON).
   **中文**: 直接读 `/tmp/skeleton.json` (普通 JSON).
2. **EN**: For every value equal to the literal string
   `"<LLM_NARRATIVE_PLACEHOLDER>"`, write a real narrative string based
   on the locked data adjacent to it. See *LLM fill guide* below for
   per-slot length minimums and content rules.
   **中文**: 把每个等于字面量 `"<LLM_NARRATIVE_PLACEHOLDER>"` 的字段
   替换成基于相邻 locked 数据的真实 narrative. 每个 slot 的最小长度
   和内容规则见下面 *LLM fill guide*.
3. **EN**: Save to `/tmp/filled.json` and run `render_report.py`.
   **中文**: 写到 `/tmp/filled.json`, 跑 `render_report.py`.

**Background / 背景**: cross-LLM acceptance testing of v0.7.1 found that
both adversarial review and Claude agents defaulted to running
`python3 tests/smoke_fill.py` as their fill step, yielding reports full
of placeholder text that looked "filled" but carried no analytical
content. v0.7.1 跨 LLM 验收时发现 adversarial review 和 Claude 都默认调
`tests/smoke_fill.py` 当 fill 步骤, 产出看似"已填"实际无 analytical
content 的占位符报告. The v0.7.2 render gate exists because docs alone
were not sufficient — agents read code paths over prose. v0.7.2 的
render gate 就是因为光靠 docs 拦不住 — agent 读代码路径优先级 > 读文档.
If your fill step is correct, the gate is invisible. / 如果你的 fill
步骤正确, gate 不会出现.

## Output files

Pipeline + render produce, in addition to the report.md, a `monitoring/`
directory next to the skeleton/report with 4 wallet-tracker import files:

| File | Format | Importable by |
|---|---|---|
| `monitoring_wallets.json` | canonical v0.6 schema | own scripts / analytics — NOT for tracker import |
| **Paste route** (text-area paste, no file upload) |
| `monitoring_paste.json` | `[{address, name, emoji}, ...]` JSON | **Binance Wallet + OKX wallet** paste (verified). Binance UI calls it "GMGN format" |
| `monitoring_gmgn.txt` | `[0xabc, 0xdef, ...]` address-only | **GMGN paste probe 1** (per docs Import section) |
| `monitoring_gmgn_quoted.txt` | `["0xabc", "0xdef", ...]` quoted array | **GMGN paste probe 2** (alternative interpretation of docs) |
| **File upload route** (CSV/XLSX required) |
| `monitoring_binance_web3.csv` | `name,address,network` | **Binance Web3 Wallet file upload** (user reported file upload route accepts CSV/XLSX, not JSON) |
| `monitoring_okx.csv` | `Network,Address,Label,Note` | **OKX wallet file upload** (CSV/XLSX route) |

**GMGN known issue**: GMGN's bulk import widget is likely Solana-only — docs example uses Solana base58 addresses, and our BSC 0x... addresses got "Invalid format" on both paste probes. If GMGN BSC bulk import is unsupported, monitor those wallets via GMGN UI one-by-one OR use Binance Wallet / OKX instead.

**Wallet filter (beta.12)**: Only wallets with non-zero balance, critical role (OPERATOR_RELAY / 潜伏钱包), or recent 72h activity are emitted. 已派完 wallets with 0 balance are excluded (no longer actionable — just historical). Full list stays in `monitoring_wallets.json` for analytical reference.

**Use paste before upload**: paste route is generally more reliable; only fall back to file upload when paste fails. Match file to the route you're using:
- Paste route: open `monitoring_paste.json` / `monitoring_gmgn*.txt`, Ctrl+A Ctrl+C, paste in platform dialog
- Upload route: drag/select the `.csv` file in the platform's file picker

Label format: `<SYM>-<ROLE>-<addr5>` (e.g., `ZEST-Deployer-3a6dc`, `ZEST-Dumper-1de14`).
≤25 chars to clear all known tracker char limits. ROLE token enum:
`Deployer / Dumper / PDumper / Quiet / LP / Anomaly / Other`.

Pipeline-time emit uses empty `alert` field; render-time re-emit fills it
with the LLM's monitoring narrative.

## What goes in writable slots — LLM fill guide

The skeleton emits `<LLM_NARRATIVE_PLACEHOLDER>` at every writable path.
LLM must replace each with a real narrative string that:

1. References the locked data adjacent to it (don't invent numbers).
2. For `*.events[].nature`, the description must be consistent with the
   `evt_ref` it sits next to — validator looks up the evt_ref in
   evidence_graph and rejects amount/ts/from/to contradictions within
   5% tolerance.
3. Meets the min_length specified in `field_authority.yaml`.
4. Does NOT contain META commentary (see anti-patterns).
5. Does NOT contain hypothetical fallback language ("如果主链不是 BNB
   Chain ..." — META corpus rejects this).

### 🚫 No hardcoded numbers in fill scripts (v0.7.19.5)

If you author a `fill.py` script that gets reused across runs (multiple
tokens, repeated runs of the same token), **every number cited in
narrative MUST be read from the skeleton dict, not written as a
literal**. The token's price, volume, LP, holdings %, wallet counts,
median price, etc. all change between runs; a literal in the script
silently ships stale data on the next run, with the locked tables
right next to it showing fresh data — self-contradicting report.

**Wrong (literal):**
```python
sk["liq"]["interpretation"] = (
    "Alpha 24h vol $16,678,802 看似充沛, 但 DEX 主池 LP 仅 $635K, "
    "5% 滑点 ~$8K, ..."
)
```

**Right (skeleton-bound):**
```python
meta = sk["meta"]; liq = sk["liq"]
vol_24h = meta.get("alpha_vol_24h_usd")
main_lp = liq.get("dex_pool_liquidity_usd")
entry_cap = liq.get("alpha_5pct_depth_usd_est")
sk["liq"]["interpretation"] = (
    f"Alpha 24h vol ${vol_24h/1e6:.2f}M 看似充沛, 但 DEX 主池 LP "
    f"{('$' + format(main_lp, ',.0f')) if main_lp else '本次拉取失败'}, "
    f"5% 滑点 ~${entry_cap:,}, ..."
)
```

**v0.7.19.5 validator enforces this:** `V_NARRATIVE_NUMERIC_HALLUCINATION`
is now a STRUCTURAL error (hard fail, `render_report.py` exits 1)
when any narrative number does not match a locked field within 5%.
The pre-v0.7.19.5 soft-warning behavior is opt-in via
`BINANCE_ALPHA_ALLOW_NUMERIC_WARNINGS=1` (use only for dev / CI flows
that intentionally test against stale fixtures).

**Self-check before publishing your fill script:**

```bash
# Any literal $-number or N.N% in fill script body?
grep -nE '\$[0-9][0-9,]*(\.[0-9]+)?[KM]?\b' fill.py | grep -v '^[0-9]*:.*#'
grep -nE '\b[0-9]+\.[0-9]+%' fill.py | grep -v '^[0-9]*:.*#'
# Both should return 0 hits (excluding comments).
```

Then `python3 render_report.py ...` — if `V_NARRATIVE_NUMERIC_HALLUCINATION`
fires, your narrative is referencing a number that does not exist in
the skeleton's locked pool (either from a previous run or hallucinated).

Writable slots (15 categories):

| Path | Min len | Notes |
|---|---|---|
| `verdict.one_liner` | 100 | One sentence summary of the verdict. Must mention the dominant signal (quiet wallet size, anomaly count, etc.) |
| `anomaly.waves[].status_text` | 2 | e.g. "已完成", "进行中", "未启动" |
| `anomaly.waves[].events[].hours_ago_text` | 3 | e.g. "约 12 小时前", "约 3 天前" |
| `anomaly.waves[].events[].nature` | 10 | Narrative of the transfer. MUST match evt_ref data (5% tolerance enforced) |
| `anomaly.detector_summary[].detail` | 10 | One-line interpretation per detector category |
| `anomaly.rhythm.title` | 10 | Title for the 分发 (on-chain transfer) rhythm narrative |
| `anomaly.rhythm.waves[].detail` | 10 | Per-wave rhythm commentary |
| `anomaly.verdict_impact` | 80 | How anomaly findings shape the verdict |
| `multi_chain.interpretation` | 30 | Comment on chain coverage / cross-chain risk |
| `tge.interpretation` | 30 | Comment on TGE timing + current vs anchor multiple |
| `alloc.interpretation` | 30 | Comment on Rule 11 分发 (on-chain dispersal) breakdown |
| `cex_trace.interpretation` | 30 | Comment on tier + CEX catalyst |
| `liq.interpretation` | 30 | Comment on entry-size cap + LP flow |
| `holdings_distribution.key_takeaways[]` (≥3) | 20 | 3+ bullets summarizing the role distribution |
| `lineage.m4_notes[]` (≥2) | 20 | LP-前预分配 解读 bullets |
| `lineage.m6.rows[].identity_narrative` | 5 | Brief identity guess per m6 row |
| `lineage.m6.rows[].status_narrative` | 5 | Current status per m6 row |
| `monitoring_wallets[].alert` | 15 | One-line alert condition |
| `monitoring_footer` | 30 | Overall monitoring purpose statement |
| `decision_action_block.immediate_action.narrative` | 30 | Why this action, plain language |
| `decision_action_block.stop_loss.rationale` | 20 | Why this stop trigger price |
| `decision_action_block.re_entry_conditions[].narrative` | 15 | What the condition means in plain language |

## 大白话 narrative — avoid internal jargon (beta.8)

When filling writable slots, write in 中文大白话 — your reader is a
trader, not a forensic engineer. Do NOT use these internal schema
names in narrative text.

### 严格术语契约 — **派发 ≠ 分发** (v0.7.15)

These two words are NOT interchangeable. Mixing them in narrative is a
factual error, not a style preference:

| 术语 | 含义 | 用在 |
|---|---|---|
| **分发** (distribute / on-chain transfer) | 链上 token 从 A 转到 B,**还没卖** | rule_11 / lineage / m6 / holdings / anomaly waves — every description of an on-chain transfer between wallets. `dumped_pct` in 中文 narrative reads as **"已分 X%"** (转出率, NOT 卖出率). |
| **派发** (dump / sell-out / realized exit) | 链下/CEX 卖出, 或 DEX swap 已 realized | dump_tracker's confirmed-sold output (`confirmed_est_profit_usd` = "估算套现") and sell-pressure / 砸盘风险 narrative ONLY. |

**Examples**:
- ✓ "项目方上线前向内幕地址**分发** 1B token" (on-chain transfer)
- ✗ "项目方上线前**派发**" (wrong — they didn't sell, they only moved)
- ✓ "潜伏钱包开始**派发**会引发砸盘" (sell-pressure risk)
- ✗ "潜伏钱包累计**派发** 10 亿" (wrong — should be 分发 / 转出)
- ✓ "已确认**派发** $3.6M (CEX 充值 + DEX swap)" (confirmed sell)
- ✗ "已确认**分发** $3.6M" (wrong — $ figures are sell-out, not transfer)

### Internal-jargon → 大白话 table

| Internal jargon | 大白话替换 |
|---|---|
| `Rule 11` / `Rule 11 backward trace` | "项目方分发追溯" / "上线前内幕分发追溯" |
| `OPERATOR_RELAY` / `Operator relay` | "庄家中转地" |
| `DUMPER_DEST` / `dumper-destination` | "散户接收" / "分发下游" |
| `RULE11_QUIET` / `Quiet wallet` / `quiet wallet` | "潜伏钱包" (内幕未分发) |
| `RULE11_PARTIAL` / `Partial Dumper` | "分发中钱包" |
| `RULE11_FULL` / `Full Dumper` | "已分完钱包" |
| `evt_ref` / `m6_ref` / `node_ref` | "事件 #X" / "内幕 #X" / "钱包 #X" |
| `dumped_pct` | "已分 X%" (转出率) |
| `confirmed_est_profit_usd` | "估算套现 ~$X" / "确认派发金额" |
| `Pre-launch` | "上线前" |

The pipeline already writes these 中文 labels in locked fields (e.g.,
holdings_distribution.role_rows[].role_label uses "庄家中转地"). Your
writable narrative MUST match that style — don't reintroduce English
enum names, and don't mix 派发/分发.

OK to keep: hex addresses (0xabc...), USD $ symbols, EXIT_IF_HOLDING /
AVOID enum strings (those are verdict enums, by design machine-readable
+ user-displayed atomically).

## META anti-patterns (validator rejects)

The semantic check loads `schema/meta_blacklist_corpus.txt` and rejects
writable values matching any of these patterns. **Do not write any of
this content into narrative slots**:

- Self-referential commentary ("以下分析基于...", "本报告...")
- Hedged fallback templates ("如果主链不是 BNB Chain, 则...")
- Skill-version mentions ("本工具 v0.5.9 ...")
- Methodology notes mid-narrative ("Rule 11 backward trace 的做法是...")
- Empty placeholders ("详见上述...", "请见...")
- KOL / external analyst cites ("据 @某某 推文", "根据某 KOL 分析...")

The corpus is loaded at validator construction; new patterns are added
in commits, never inline.

## Provenance contract (V_PROVENANCE_NARRATIVE_MISMATCH)

Every `anomaly.waves[].events[].nature` field sits adjacent to an
`evt_ref` (e.g., `evt_034`). The validator looks up `evt_034` in
`evidence_graph` and reads its `amount`, `ts`, `from`, `to`. If the
narrative claims a different amount (>5% tolerance) or a different
timestamp (>10 min) or a wrong from/to address, validator emits
`V_PROVENANCE_NARRATIVE_MISMATCH` and render aborts.

Practical rule: when narrating an event, quote the exact numbers from
the skeleton row, don't paraphrase.

Bad: "deployer dumped ~$7M to some wallet recently"
Good: "deployer `0x27eac580…` 向 `0x2deb0290…` 转出 30 tokens (evt_004,
2026-02-26 12:34 UTC)"

## The 9 forensic Decision Anchor rules

These are content-level requirements every report MUST satisfy.
v0.6 enforces most via locked-field structure; LLM narrative must
align with the locked data, not invent alternatives.

### Rule 0 — Spot graduation is terminal

Binance Alpha and Binance Spot are mutually exclusive. Once a token
graduates to Spot, it is REMOVED from Alpha. Forensic methodology
(S1/S2/S3 tiers, 庄家归集 detector, vesting unlock anchor) is
**scoped to Alpha only**. For Spot-graduated CAs, Section A aborts
with `SPOT_GRADUATED` and the skill stops.

S1/S2/S3 tier definitions:
- **S1** — Alpha only, no CEX perp anywhere.
- **S2** — Alpha + Binance perpetual futures.
- **S3** — Alpha + at least one non-Binance CEX perp (Aster / Bitget
  / OPG). **S3 does NOT imply S2** — a token can reach S3 via Aster
  without Binance ever touching it. `s2_date` is nullable when
  `tier=S3`.

Section CEX-TRACE renders Binance row based on `s2_date`, NOT on tier
alone.

### Rule 11 — Deployment backward trace BEFORE current snapshot

Alpha tokens are deployed weeks before listing. Forensic value lives
in the deployment→listing window, not the current-holders snapshot.

`rule_11_backward_trace` runs 4 steps automatically:

1. **Find mint event** (`from = 0x0`). Capture mint timestamp +
   deployer wallet. Window: `block_date >= alpha_listing_date - 90d`.
2. **Trace deployer outflows** in `[mint_date, alpha_listing_date]`.
   Every receiver is a pre-launch allocation insider (M4 class).
3. **Per receiver, compute** `total_received` / `current_balance` /
   `dumped_pct = total_out / total_received * 100`. Sort desc by
   dumped_pct.
4. **For top dumpers, trace destinations** via BscScan label probe
   (Section X). Categorize: CEX hot wallet → "已开始 CEX 派发"; DEX
   LP pool → "DEX 抛压"; unlabeled EOA → "OTC 清洗".

Pipeline output:

- `lineage.m6.rows[]` — every pre-launch receiver, with stable
  `m6_ref` provenance ID.
- `anomaly.waves[]` — wave 1 (pre-launch dispersal), wave 2 (dumper
  distribution), wave 3 (recent 72h).
- `lineage.flowchart_nodes/edges[]` — mermaid graph from deployer →
  receivers → top destinations.
- `alloc.rows[]` — receiver bucket aggregation (quiet / partial /
  full dumpers).

Quiet (0% dumped) receivers are **future supply risk**. Their
cumulative size = the verdict's primary downgrade trigger.

### Rule 5 — 3-tier price anchors (current vs anchor multiple)

Every report MUST surface the current-price anchor against TGE
benchmarks:
- (a) LP creation first-swap price (Section TGE)
- (b) Alpha open price (Section TGE)
- (c) Current price (DexScreener / Alpha API)

Decision anchor = current ÷ Alpha-open multiplier. v0.6 emits the
times in `tge.rows[]`; if first-swap price isn't directly indexed,
TGE row shows `—` and LLM narrates the multiplier from context.

### Rule 4 — Liquidity = entry size cap

Every report MUST emit the **Alpha 5% slippage cap** (= Alpha vol_24h
/ 96 × 0.05 heuristic) as the headlined entry-size anchor. NOT
"liquidity OK", NOT TVL. A concrete USD figure the trader can act on.

`section_liq` emits this in `liq.rows[0]` + as
`decision_action_block.immediate_action.tranche_max_usd` /
`decision_anchors[0]`.

### Rule 6 — Allocation as bargaining power

Alpha allocation % vs industry baseline (3-10% typical). <3% = STRONG
project bargaining power (project doesn't need Alpha flow → catalyst
likely on bigger venues). >10% = WEAK.

If Alpha API doesn't publish allocation, `section_alloc` infers from
Rule 11 receiver distribution. Do NOT fabricate from external sources.

### Rule 7 — CEX traces = short-term catalyst

14-day scan for project wallets sending to Coinbase / Kraken / Bybit /
KuCoin / Binance major deposit addresses. ≥2 exchanges hit → HIGH
signal (1-2 weeks listing likely).

v0.6 phase B emits Binance perp listing check only; Aster + Bitget
are `NOT_IMPLEMENTED` stubs that surface in `cex_trace.rows` for
manual verification.

### Rule 8 — Explicit blindspot disclosure

Sections that couldn't run (data gap / API failure / cost cap / RPC
down) MUST be listed in a "Data Gap" appendix. Do NOT silently omit.
Do NOT fabricate data from external sources to fill gaps.

### Rule 9 — Every finding → one decision

Every numeric finding in the report must map to a specific trading
decision anchor. If a number can't be answered with "what do I do
with this?" — drop it.

Keep:
- "$10,228 5% slippage cap" — direct size anchor
- "current vs Alpha open 1.87×" — vs anchor multiple
- "Alpha 配额 1%" — bargaining power anchor
- "Rule 11 Quiet 500 万 tokens (0.5% 总供应)" — future抛压 size

Drop:
- "84 wallets holding" (no actionability without baseline)
- "sniper PNL $50k" (user can't act on it)

### Rule 10 — Hard prohibition: no external KOL cites

Reports MUST NOT reference external analyst / KOL by name. No "per
@..." or "from some-KOL intel" or "based on community research". This
skill's output is independent forensic — if a data point can't be
derived from on-chain / Alpha API / RPC, it goes in Data Gap, never
cherry-picked from external opinion.

Reason: (a) maintains skill independence + audit trail (b) avoids
selection bias from external sourcing (c) prevents the "borrowed
conviction" failure mode.

### Rule MULTI-CHAIN — single-chain BSC minimal coverage

v0.6 phase B.3 ships with `section_multi_chain` minimal: single-chain
BSC check + RPC totalSupply sanity. Cross-chain detection (CoinGecko
platforms lookup for ETH wrapper / Base wrapper / Solana primary)
deferred to v0.7.

If chain != BSC: `multi_chain.gate_note` triggers verdict downgrade
to ADVISORY (acknowledges partial coverage).

## Verdict heuristic (pipeline-derived, LLM cannot override)

`_derive_verdict_enum` reads Rule 11 + anomaly72 signals:

- **EXIT_IF_HOLDING (建议卖出)** if:
  - Any quiet wallet holds ≥ 5M tokens (size threshold), OR
  - Any pre_launch_receiver with `dumped_pct ≥ 95%` is "active" (still
    has nonzero balance + recent activity), OR
  - `anomaly72.n_recent_events ≥ 10`
- **WAIT (等等看)** if `anomaly72.n_recent_events ≥ 3`
- **ADVISORY (中性无方向)** otherwise

Downgrade chain: baseline → verdict → next_tier_enum (one step further
down). LLM narrates the verdict via `verdict.one_liner`; LLM cannot
modify enum / baseline / next_tier — those are derived_locked and
validator rejects any change.

## decision_action_block structure (new in v0.6)

Replaces v0.5's freeform "action narrative" with structured slots:

```json
{
  "immediate_action": {
    "action_enum": "sell" | "hold" | "wait" | "buy",   // derived_locked
    "venue_enum": "alpha",                              // locked
    "tranches_n": 3,                                    // locked
    "tranche_max_usd": 3409,                            // locked (from Alpha 5% cap)
    "horizon_hours": 48,                                // locked
    "slippage_pct_cap": 3,                              // locked
    "narrative": "<LLM_NARRATIVE_PLACEHOLDER>"          // writable
  },
  "stop_loss": {
    "trigger_price_usd": 0.952,                         // locked (from liq overrides)
    "current_price_usd": 1.12,                          // locked
    "delta_pct": -15.0,                                 // locked
    "rationale": "<LLM_NARRATIVE_PLACEHOLDER>"          // writable
  },
  "re_entry_conditions": [
    {
      "condition_type": "rule11_quiet_wallets_dumped_pct",  // locked enum
      "threshold": 80,                                      // locked
      "current_value": 0,                                   // locked
      "narrative": "<LLM_NARRATIVE_PLACEHOLDER>"            // writable
    }
  ]
}
```

LLM writes only the 3 `narrative` / `rationale` fields. Everything
else is pipeline-derived from Rule 11 + section_liq.

## Validator error reference

Common errors and what they mean:

| Error code | Meaning | LLM action |
|---|---|---|
| `V_SCHEMA_VERSION` | skeleton/filled schema_version don't match | Don't modify `_schema_version` |
| `V_LOCKED_FIELD_MODIFIED: path=X` | LLM changed a locked or derived_locked field | Restore the original value from skeleton; only narrative slots are yours |
| `V_LOCKED_FIELD_ABSENT: path=X` | A locked scalar path is missing in both skeleton + filled | Pipeline regression — re-run forensic_pipeline.py |
| `V_LOCKED_FIELD_COUNT: path=X` | Array length mismatch between skeleton + filled | Don't add or remove array elements; only fill the existing placeholders |
| `V_WRITABLE_PLACEHOLDER` | A writable slot still contains `<LLM_NARRATIVE_PLACEHOLDER>` | Fill that slot |
| `V_WRITABLE_TOO_SHORT: min_length=N got=M` | Narrative shorter than spec | Expand to meet min_length |
| `V_WRITABLE_TOO_FEW: min_count=N got=M` | List has fewer items than spec (e.g., `key_takeaways[]` needs ≥3) | Add more bullets |
| `V_SEMANTIC_META_FAIL: path=X matches blacklist pattern Y` | Narrative contains META commentary | Rewrite to remove self-referential / hedged-template language |
| `V_PROVENANCE_NARRATIVE_MISMATCH: evt_ref=X claims A but evidence has B` | Narrative contradicts the evt_ref it cites | Quote the exact numbers from the skeleton row |
| `V_R11_M6_WAVES_INCONSISTENT` | `m6.rows` has dumpers that don't appear in `anomaly.waves` | Pipeline bug — re-run forensic_pipeline.py |
| `V_R12_PLACEHOLDER: path=X` | A `<LLM_NARRATIVE_PLACEHOLDER>` or `<PIPELINE_PHASE_*>` marker survived to filled | Fill the slot |

## File tree

```
v06/
├── DESIGN_v06.md              # architectural decisions
├── SKILL_v06.md               # this file
├── forensic_pipeline.py       # orchestrator (3 rounds, ~10 helpers)
├── validate_report_data.py    # validator (~22 checks, hardcoded schema/)
├── render_report.py           # jinja2 template engine + security hardening
├── helpers/
│   ├── evidence_graph.py            # stable-ID assignment (evt/m6/node/mon/anc)
│   ├── parallel_surf.py             # concurrent surf onchain-sql runner
│   ├── section_a_scope.py           # Alpha API + Spot graduation cross-probe
│   ├── rule_11_backward_trace.py    # mint → deployer → receivers → dumps
│   ├── section_anomaly_72h.py       # recent 24-72h large transfers
│   ├── section_cex_trace.py         # Binance perp probe → tier derivation
│   ├── section_liq.py               # DexScreener + Alpha 5% depth + LP flow
│   ├── section_tge.py               # LP creation + Alpha open + current px
│   ├── section_alloc.py             # Rule 11 receivers → bucket aggregation
│   ├── section_multi_chain.py       # single-chain BSC minimal
│   ├── section_f_holders.py         # top-50 current balance
│   └── section_l_distribution.py    # role classification + flowchart build
├── schema/
│   ├── field_authority.yaml         # 3-tier registry (locked/derived_locked/writable)
│   └── meta_blacklist_corpus.txt    # META commentary anti-patterns
└── tests/
    ├── smoke_fill.py                          # E2E fixture (CI ONLY — render refuses by default)
    └── test_derived_locked_enforcement.py     # 11-case regression suite
```

## Cost model

Per-CA cost (Surf credits, ~$0.0079/credit):

| Section | ~Credits | Wall clock |
|---|---|---|
| section_a_scope | 0 (API + RPC) | ~0.5s |
| rule_11_backward_trace | ~60-120 | ~5-11s |
| section_anomaly_72h | ~30-50 | ~1-2s |
| section_cex_trace | 0 (Binance API) | ~0.5s |
| section_liq | ~20-30 | ~1-2s |
| section_tge | ~10-20 | ~1-2s |
| section_alloc | 0 (aggregation) | <1s |
| section_multi_chain | 0 (RPC) | <1s |
| section_f_holders | ~50-80 | ~2-3s |
| section_l_distribution | 0 (aggregation) | <1s |
| **Total** | **~200-300 credits** | **~12-25s** |

USD: ~$1.6-2.4 per forensic in surf credits + LLM API tokens for the
fill step (~5-10k input tokens, ~2-3k output tokens — under $0.05 on
Claude Sonnet 4.6 or adversarial review GPT-5).

## What v0.6 does NOT cover (acknowledged limitations)

1. **Cross-chain detection** — `section_multi_chain` v0.6 is minimal
   single-chain BSC. CoinGecko platforms lookup for ETH/Base/Solana
   wrappers is deferred. If primary chain isn't BSC, the verdict
   downgrades to ADVISORY (acknowledges partial coverage).
2. **Aster + Bitget perp listing detection** — `section_cex_trace`
   v0.6 implements Binance perp only. Aster/Bitget surface as
   `NOT_IMPLEMENTED` for manual verification.
3. **Sniper average buy price** — `section_tge` v0.6 doesn't compute
   first-20-LP-swap weighted-avg sniper price (requires per-tx price
   indexing). Current vs Alpha-open multiple still surfaced.
4. **Convergence hub detection** — v0.5 had a `convergence_hubs`
   section that v0.6 hasn't yet wired. Pipeline emits empty stub for
   forward-compat.
5. **Embedding-based META check** — v0.6 uses substring + fuzzy
   matching on the META blacklist corpus. Embedding cosine similarity
   is a v0.7 polish.
6. **Per-tx evidence_graph storage** — evidence_graph holds aggregated
   summaries per actor; raw transfer hashes aren't currently in the
   graph. Provenance traceability is at the section level, not tx level.

## Validator-bypass surfaces removed (paranoid list)

These were all removed at various alpha milestones, **never re-add**:

- `--bypass-validation` flag (v0.5.0-alpha.3, adversarial review round 3)
- `--yaml` / `--corpus` constructor overrides (v0.6.0-alpha.3,
  cross-LLM audit)
- subprocess validator on file paths (v0.6.0-alpha.10, adversarial review alpha.9
  TOCTOU race)
- Silent unknown-tier handling in field_authority.yaml
  (v0.6.0-alpha.11, adversarial review alpha.10 audit)
- Silent skip on locked-paths absent in both skeleton + filled
  (v0.6.0-alpha.11, adversarial review alpha.10 audit)

The validator now hardcodes schema paths + rejects unknown tier names
+ enforces both locked AND derived_locked + requires scalar locked
paths to be present. Construct → fail closed; validate → fail closed.

## Cross-LLM test matrix (target)

The skill targets identical-quality output across:
- **Claude Sonnet 4.6 / Opus 4.7** (reference)
- **adversarial review GPT-5.3** (cross-model bias check)
- **Kimi K2** (lower-cost / non-frontier verification)

E2E pass criteria per LLM:
1. Pipeline runs successfully on a known-bad CA (e.g., BSB
   `0x595deaad1eb5476ff1e649fdb7efc36f1e4679cc`).
2. LLM fills writable slots; validator returns 0 errors.
3. Render produces a 14-20KB report with all 11 H2 sections.
4. `verdict.enum` matches across LLMs (it's derived_locked, so the
   pipeline picks it — divergence here = pipeline bug, not LLM).
5. `verdict.one_liner` content varies (writable) but all 3 mention
   the dominant signal (e.g., quiet wallet size for BSB).

Cross-LLM test runs at major milestones; results in v06/CROSS_LLM_TEST_v06.md.

## Maintainability hooks

- New section helper → add to `helpers/section_*.py` + wire into
  `forensic_pipeline.py` round N + add locked paths to
  `schema/field_authority.yaml` + smoke-test E2E.
- New writable slot → add to `field_authority.yaml` writable list
  (with min_length / semantic_meta_check / provenance_check spec) +
  add `<LLM_NARRATIVE_PLACEHOLDER>` to skeleton emission in pipeline.
- New META pattern → append to `schema/meta_blacklist_corpus.txt`;
  validator picks it up on next construction.
- Locked-field tampering regression → add test case to
  `tests/test_derived_locked_enforcement.py`.

## How to invoke this skill in a Claude / adversarial review / Kimi session

User pastes a 0x address. Skill auto-starts preflight + Section A
(free). Surfaces estimated cost (~$1.5-2.5 for full forensic).
User confirms. Skill runs `forensic_pipeline.py`, then fills writable
slots based on the skeleton, then runs validator + render.

The LLM is responsible for filling the writable slots **only**.
Everything else is pipeline / validator code. If validator fails,
the LLM reads the error code from this doc's error reference and
fixes the offending narrative slot.

End of SKILL_v06.md.
