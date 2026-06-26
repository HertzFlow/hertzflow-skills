#!/usr/bin/env python3
"""v0.6 deterministic report renderer.

Reads:
  --skeleton  Pipeline output (locked + writable placeholders)
  --filled    LLM-filled JSON (writable placeholders replaced)

Runs validate_report_data.py FIRST (mandatory, no opt-out). On pass,
renders the jinja2 template producing a complete report.md.

Inherits v0.5 security hardening verbatim:
- path-traversal / symlink / hardlink guards on out_path
- regular-file check on data paths (FIFO/socket DoS block)
- unpaired-surrogate rejection (UTF-8 round-trip)
- max nesting depth (64) — adversarial JSON DoS
- md_cell pipe + newline escape
- html_escape_finalize — every `{{ ... }}` HTML-entity + markdown-link escape
- mermaid label/id escape — neutralize `"`, `|`, `<>`, `;`, `-->`, etc.

v0.6 schema differences from v0.5:
- evidence_graph (new top-level)
- decision_action_block (new structured immediate_action / stop_loss /
  re_entry_conditions; replaces v0.5 freeform "action narrative")
- holdings_distribution.role_rows now uses role/role_label/n_wallets/
  total_balance/pct_of_total/top_addr_short (no buy/sell columns;
  Phase C+ may add)
- lineage.m6.rows uses addr_short/dumped_pct (no identity/net_buy/exit_pct)
- anomaly.waves uses pipeline-built waves_proposal shape
- v0.5's convergence_hubs / preparation_phase / multihop_verification /
  g_section_notes / hub_detection NOT YET in v0.6 — template skips them
  with `{% if %}` guards (Phase C+ re-introduction)

v0.6 (2026-05-24, Phase D)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from jinja2 import Environment, StrictUndefined

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "helpers"))
from validate_report_data import Validator
import monitoring_export
from i18n import t, set_lang, get_lang   # v0.6.2 i18n


TEMPLATE = """# {{ t("report.title", symbol=meta.symbol, name=meta.name) }}

{# v0.7.24d: 🎯 retail summary section — 4-5 lines of plain Chinese at the
   very top of the report. Neutral tone, no financial advice (no "建议卖出"
   or "不要买"). Derives all numbers from skeleton data — no hard-coded
   recommendations. For LLM-to-LLM consumption + LLM-to-retail explanation
   flow, this gives the AI a clean Chinese summary to read first before
   diving into English-jargon-heavy detail sections. #}
{% set _fa_for_summary = funding_attribution if funding_attribution is defined else None -%}
{% set _mfo_for_summary = (_fa_for_summary.mining_fed_outflows if _fa_for_summary and _fa_for_summary.mining_fed_outflows is defined else None) -%}
{% set _mad_for_summary = (_fa_for_summary.mint_authority_dumps if _fa_for_summary and _fa_for_summary.mint_authority_dumps is defined else None) -%}
{% set _mc_for_summary = (_fa_for_summary.multi_chain if _fa_for_summary and _fa_for_summary.multi_chain is defined else None) -%}
{% set _htd_for_summary = (_fa_for_summary.high_throughput_dumpers if _fa_for_summary and _fa_for_summary.high_throughput_dumpers is defined else None) -%}
{% set _captured_usd_total = (
    (_mfo_for_summary.summary.total_dex_sold_usd if _mfo_for_summary and _mfo_for_summary.summary else 0) +
    (_mad_for_summary.summary.total_dex_sold_usd if _mad_for_summary and _mad_for_summary.summary else 0)
) -%}
{# v0.8.6.6: dump_tracking_mining fallback aliased to dump_tracking.
   Mining fallback insider = m6 + mint_authority + cluster + ht + fanout +
   wcg cluster ≈ 100-200 wallets vs m6 only ≈ 0-50. When mining mode catches
   bigger net_sellout (cluster-heavy / cross-chain / mining tokens), use it.
   BEAT m6=$233K → mining=$37M (159x). JCT m6=$0 → mining=$7.8M. #}
{%- set _dtm = (dump_tracking_mining if (dump_tracking_mining is defined and dump_tracking_mining) else None) -%}
{%- set _dtm_net = (_dtm.get('confirmed_net_sellout_usd') or 0) if _dtm else 0 -%}
{%- set _dt_base = (dump_tracking if (dump_tracking is defined and dump_tracking) else None) -%}
{%- set _dt_base_net = (_dt_base.get('confirmed_net_sellout_usd') or 0) if _dt_base else 0 -%}
{%- if _dtm and _dtm_net > _dt_base_net and not _dtm.get('_error') -%}
  {%- set dump_tracking = _dtm -%}
{%- endif -%}
{% set _captured_tokens_total = (
    (_mfo_for_summary.summary.total_dex_sold_tokens if _mfo_for_summary and _mfo_for_summary.summary else 0) +
    (_mad_for_summary.summary.total_dex_sold_tokens if _mad_for_summary and _mad_for_summary.summary else 0)
) -%}
{% set _captured_pct_supply = ((_captured_tokens_total / meta.total_supply * 100) if (meta.total_supply and _captured_tokens_total) else 0) -%}
{% set _mc_chains_summary = [] -%}
{% if _mc_for_summary -%}
  {% for _chain_name, _mc_data in _mc_for_summary.items() -%}
    {% if _mc_data.get('mint_authorities') or _mc_data.get('high_throughput_dumpers') -%}
      {% set _ = _mc_chains_summary.append(_chain_name) -%}
    {%- endif -%}
  {%- endfor -%}
{%- endif -%}
{% set _has_summary_data = _fa_for_summary and (_captured_usd_total > 0 or _mc_chains_summary or (_htd_for_summary and _htd_for_summary.summary and _htd_for_summary.summary.n_dumpers > 0)) -%}
{% if _has_summary_data %}

{# v0.8.7.0: ## 0. 一屏结论 段 — 6 维度 deterministic TL;DR.
   ChatGPT review (2026-06-12): "第一屏要压成阶段/筹码/最近动 3 个判断".
   helpers/screen_summary.py 算出 6 维度 + 1 句话 deterministic, 这里 render. #}
{% if screen_summary is defined and screen_summary
      and (screen_summary.get('dimensions') or []) | length >= 6 %}
## {{ t("render.screen_summary_h2") }}

> {{ t("render.screen_summary_intro") }}

| {{ t("render.screen_summary_col_dim") }} | {{ t("render.screen_summary_col_conclusion") }} | {{ t("render.screen_summary_col_evidence") }} |
|---|---|---|
{% for _d in (screen_summary.dimensions or []) -%}
| **{{ _d.name }}** | {{ _d.label }} | {{ _d.evidence }} |
{% endfor %}

**{{ t("render.one_sentence_label") }}**: {{ screen_summary.one_sentence }}

{% endif %}
## {{ t("render.tldr_summary_h2") }}

> {{ t("render.tldr_summary_intro") }}

- **{{ t("render.tldr_label_project") }}**: {{ meta.name }} ({{ meta.symbol }}){% if meta.contract_address %}, {{ t("render.tldr_main_contract") }} [`{{ meta.contract_address[:10] }}…`]({{ explorer_url(meta.contract_address) }}){% endif %}

- **{{ t("render.tldr_label_listing") }}**: {{ t("render.tldr_binance_alpha") }} {{ tier_classification.tier }}{% if tier_classification.tier == "S2" %} {{ t("render.tldr_tier_s2_paren") }}{% elif tier_classification.tier == "S3" %} {{ t("render.tldr_tier_s3_paren") }}{% elif tier_classification.tier == "S1" %} {{ t("render.tldr_tier_s1_paren") }}{% endif %} · {{ t("render.tldr_primary_chain", chain=meta.chain) }}

{% if dump_tracking and (dump_tracking.confirmed_total_tokens or 0) > 0 -%}
- {{ t("render.tldr_confirmed_realization", tokens="{:,.0f}".format(dump_tracking.confirmed_total_tokens), pct="%.2f"|format(dump_tracking.confirmed_total_pct or 0), usd="{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd or 0)) }}
{%- endif %}
{% if _captured_tokens_total > 0 -%}
- **{{ t("render.tldr_tge_sold_label") }}**: **{{ "{:,.0f}".format(_captured_tokens_total) }} tokens**{% if _captured_usd_total > 0 %} ≈ **${{ "{:,.0f}".format(_captured_usd_total) }} USD**{% endif %}{% if _captured_pct_supply > 0 %}{% if _captured_pct_supply > 100 %} {{ t("render.tldr_tge_pct_over100", pct="%.0f"|format(_captured_pct_supply)) }}{% else %} {{ t("render.tldr_tge_pct_normal", pct="%.2f"|format(_captured_pct_supply)) }}{% endif %}{% endif %} — {{ t("render.tldr_tge_via") }} {% if _mfo_for_summary and _mfo_for_summary.summary and _mfo_for_summary.summary.n_addrs_with_dex_sells > 0 %}{{ t("render.tldr_tge_via_mining", n=_mfo_for_summary.summary.n_addrs_with_dex_sells) }}{% endif %}{% if (_mfo_for_summary and _mfo_for_summary.summary and _mfo_for_summary.summary.n_addrs_with_dex_sells > 0) and (_mad_for_summary and _mad_for_summary.summary and _mad_for_summary.summary.n_addrs_with_dex_sells > 0) %} + {% endif %}{% if _mad_for_summary and _mad_for_summary.summary and _mad_for_summary.summary.n_addrs_with_dex_sells > 0 %}{{ t("render.tldr_tge_via_mint", n=_mad_for_summary.summary.n_addrs_with_dex_sells) }}{% endif %} {{ t("render.tldr_tge_back_to_market") }}
{%- endif %}

{% if _htd_for_summary and _htd_for_summary.summary and _htd_for_summary.summary.n_dumpers > 0 %}
- {{ t("render.tldr_ht_operators", n=_htd_for_summary.summary.n_dumpers, tokens="{:,.0f}".format(_htd_for_summary.summary.total_throughput)) }}

{% endif %}
{% if _mc_chains_summary %}
- {{ t("render.tldr_cross_chain", chains=(_mc_chains_summary | join(", "))) }}

{% endif %}
- {{ t("render.tldr_completeness_note") }}

- {{ t("render.tldr_how_to_use") }}

{% endif %}
{# v0.7.9.1: narrative_warnings banner removed from user-facing report.
   These are validator NARRATIVE_QUALITY soft warnings (e.g. numeric
   hallucination in templated fill, narrative duplication). They're
   useful for dev validation but pure noise for retail traders reading
   the report. Still emitted to stderr by render_report for debugging.
#}
{% if meta.data_freshness is defined and meta.data_freshness and meta.data_freshness.warning %}
> 📌 **{{ t("report.banner_data_freshness_title") }}**: {{ t("report.banner_data_freshness_body", lag_hours=meta.data_freshness.lag_hours, latest_date=meta.data_freshness.latest_surf_date_utc) }}
{% endif %}
{# v0.7.21.8: skip the "BSC 镜像端 → 主战场" 提示条 on 持币人-snapshot
   chains (Solana). That banner claims pipeline already routes all
   forensic SQL to the primary chain, which is true on EVM but a lie on
   Solana — the SQL detectors are skipped, not routed. The dedicated
   HOLDER_SNAPSHOT banner below carries the correct copy. #}
{% if meta.primary_chain is defined and meta.primary_chain and meta.primary_chain != "binance-smart-chain" and not meta.get('_holder_snapshot_mode') %}
> 📌 **{{ t("report.banner_non_bsc_primary_title") }}**: {{ t("report.banner_non_bsc_primary_body", primary_chain=meta.primary_chain, scope_chains=(meta.coingecko_platforms|default({})|list|reject('eq','binance-smart-chain')|list|join(", ")) ) }}
{% endif %}
{% if meta.primary_chain_derivation is defined and meta.primary_chain_derivation and "unreliable_fetch_failed" in meta.primary_chain_derivation %}
> {{ t("render.banner_primary_chain_unreliable", failed_chain=meta.primary_chain_derivation.split(":")[1]) }}
{% endif %}
{% set _rti_banner = meta.realtime_token_info | default({}) %}
{# v0.7.16: 只要任何一个 source 拿到了价格 (surf project-detail 或 Alpha API),
   下方的"代币行情"表就照常显示, 不再弹 "实时行情未就绪" 警告. 仅当两边都没价格
   (surf NOT_FOUND + alpha API 也没收录) 才提示用户回去 BscScan 手动核对. #}
{% if _rti_banner and _rti_banner.get('fetch_ok') == false and meta.get('alpha_price_usd') is none %}
> {{ t("render.banner_realtime_not_ready") }}
{% endif %}
{# v0.7.21.8: Solana / 任何无 surf onchain-sql 覆盖的链顶部一次性 提示条.
   pre-v0.7.21.8 这些段都显示 "0 命中" 让用户误以为 链上侦测 通过, 实际是 SQL
   层根本没数据. 现在明文告诉用户哪些 链上侦测 段是 chain 限制不是 检测器 结果. #}
{% if meta.get('_holder_snapshot_mode') %}

> {{ t("render.banner_holder_snapshot_line1", chain=meta.chain) }}
> {{ t("render.banner_holder_snapshot_line2", primary_chain=meta.primary_chain) }}
> {{ t("render.banner_holder_snapshot_line3") }}
> {{ t("render.banner_holder_snapshot_skip_intro") }}
> - {{ t("render.banner_holder_snapshot_skip_1") }}
> - {{ t("render.banner_holder_snapshot_skip_2") }}
> - {{ t("render.banner_holder_snapshot_skip_3") }}
> - {{ t("render.banner_holder_snapshot_skip_4") }}
> - {{ t("render.banner_holder_snapshot_skip_5") }}
>
> {{ t("render.banner_holder_snapshot_kept") }}
>
> {{ t("render.banner_holder_snapshot_manual") }}
{% endif %}
{# v0.7.25 unified top callout: 之前 wash_dominated (🚨) + mining-model (⚪)
   + completeness (🟡) 三个独立 提示条 叠在 report 顶部, 散户 直接被劝退,
   每条都要 scroll 看. 现在合并成 1 个统一 "链上侦测限制 / 数据提醒"
   callout, 每条 1 行 + 链接到详细段 锚点. data quality (surf-failure) 提示条
   保持独立, 因为它是 transient surf 问题不是 token 结构.

   3 conditions:
     wash_dominated → 24H vol 被 对敲机器人主导, 不可信
     mining_model → 合约部署地址 placeholder, 标准 内幕 集合空 (非 surf 失败)
     completeness_low → 跨链 / 跨链桥 / CEX 提币阶段 出货 路径结构性不可见

   v0.7.23.2 fix preserved: distinguish "rule_11 m6 empty (mining-token model,
   no insider set to query, NOT a surf failure)" from "surf bucket queries
   actually failed". Real mining tokens have a placeholder deployer detected. #}
{# v0.8.4.9.4: 加 mint_authorities 实证 condition.
   之前 AOP cold-start surf 失败 → m6 trace 空 → 误判矿币模式 (实际是数据残缺).
   真矿币必有 mint_authorities.authorities 非空 (JCT 2 authorities). #}
{%- set _has_mint_authorities = (funding_attribution is defined and funding_attribution
    and ((funding_attribution.get('mint_authorities') or {}).get('authorities') or [])
    | selectattr('is_excluded', 'equalto', false) | list | length > 0) -%}
{% set _dq_mining_model = (
    lineage is defined and lineage and (lineage.get('m6', {}).get('rows')|length == 0)
    and lineage.get('deployer_addr')
    and lineage.get('_status') != 'no_deployer_anchor'
    and dump_tracking is defined and dump_tracking
    and dump_tracking.get('buckets_complete') == false
    and (dump_tracking.get('insider_n_wallets') or 0) == 0
    and _has_mint_authorities
) -%}
{# v0.8.5.2: banner 分级 — adversarial review CLO bug report 2026-06-12:
   push_airdrop_detector 子 SQL fail (max_rows>10K cap) 不该让整个
   dump_tracker 段报"不可信". 真核心 CEX/DEX confirmed 数据完整时, fail
   只是辅助 detector. 用 confirmed_total_tokens > 0 / tree_holds > 0
   信号判断核心数据可用 → suppress banner.
   仍触发 case: insider_n_wallets=0 + 全 0 (真 surf 系统性失败 case). #}
{%- set _has_core_dump_data = (dump_tracking is defined and dump_tracking and (
    (dump_tracking.get('confirmed_total_tokens') or 0) > 0
    or (dump_tracking.get('tree_holds_tokens') or 0) > 0
    or (dump_tracking.get('insider_n_wallets') or 0) > 0
)) -%}
{% set _dq_dump_bad = (
    dump_tracking is defined and dump_tracking
    and dump_tracking.get('buckets_complete') == false
    and not _has_core_dump_data
    and not _dq_mining_model
) -%}
{# v0.8.4.9.4: 矿币模式 — 内幕变现 detector 当前不 quantify mint_authority +
   fake_mining cluster 的 net sell, 显示 $0 误导. Banner 提醒用户看 high_throughput
   段实际 dumper 数 + 链上链路. #}
{% set _dq_mining_no_sellout = (_dq_mining_model
    and dump_tracking is defined and dump_tracking
    and (dump_tracking.get('confirmed_net_sellout_usd') or 0) == 0
    and funding_attribution is defined and funding_attribution
    and ((funding_attribution.get('high_throughput_dumpers') or {}).get('summary') or {}).get('n_dumpers')) -%}
{% set _dq_wash_bad = (wash_infrastructure is defined and wash_infrastructure and wash_infrastructure.get('_truncated')) -%}
{% set _dq_flow_bad = (
    flow_operators is defined and flow_operators
    and (flow_operators.get('_credits_used') or 0) == 0
    and (flow_operators.get('_n_candidates_scanned') or 0) > 0
    and not flow_operators.get('operators')
    and flow_operators.get('_skip_reason') != 'surf_no_sql_solana'
) -%}
{% set _wash_dominated = (dump_tracking is defined and dump_tracking and dump_tracking.get('wash_dominated')) -%}
{% set _completeness_low = (
    dump_tracking is defined and dump_tracking
    and dump_tracking.get('wash_dominated') == true
    and (
        (lineage is defined and lineage and (lineage.get('m6', {}).get('rows')|length == 0))
        or (dump_tracking.get('insider_n_wallets') or 0) < 3
    )
) -%}
{% set _has_top_callout = (_wash_dominated or _dq_mining_model or _completeness_low) -%}
{% if _has_top_callout %}

> {{ t("render.callout_must_read_title") }}
>
{% if _wash_dominated -%}
> - {{ t("render.callout_wash_dominated", n_sellers=(dump_tracking.n_dex_sellers or 0), total_swaps="{:,}".format(dump_tracking.total_dex_swaps or 0), top_swaps="{:,}".format(dump_tracking.top_seller_swaps or 0)) }}{% if dump_tracking.total_dex_swaps and dump_tracking.total_dex_swaps > 0 %} {{ t("render.callout_wash_dominated_share", share="%.1f"|format((dump_tracking.top_seller_swaps or 0) / dump_tracking.total_dex_swaps * 100)) }}{% endif %}. {{ t("render.callout_wash_dominated_tail") }}
{% endif -%}
{% if _dq_mining_model -%}
> - {{ t("render.callout_mining_model") }}
{% endif -%}
{% if _completeness_low -%}
> - {{ t("render.callout_completeness_low") }}
{% endif -%}
{% endif %}{% if _dq_dump_bad or _dq_wash_bad or _dq_flow_bad %}

> {{ t("render.callout_data_incomplete_title") }}
>
{% if _dq_dump_bad -%}
> - {{ t("render.callout_dump_bad") }}
{% endif -%}
{% if _dq_wash_bad -%}
> - {{ t("render.callout_wash_bad", budget=(wash_infrastructure._truncation_meta.wall_clock_budget_seconds | int), processed=wash_infrastructure._truncation_meta.n_candidates_processed, total=wash_infrastructure._truncation_meta.n_candidates_total) }}
{% endif -%}
{% if _dq_flow_bad -%}
> - {{ t("render.callout_flow_bad", n=flow_operators._n_candidates_scanned) }}
{% endif -%}
>
> {{ t("render.callout_data_incomplete_advice") }}
{% endif %}
_{{ t("report.meta_line_1", version=_schema_version, chain=meta.chain, listing_date=meta.alpha_listing_date_utc) }}_

{% if meta.total_supply -%}
_{{ t("report.meta_line_2", total_supply=meta.total_supply, circ_supply=meta.circulating_supply or 0, circ_pct=(meta.circ_ratio * 100) if meta.circ_ratio else 0, token_type=meta.token_type_initial) }}_
{%- else -%}
_{{ t("report.meta_line_2_unknown", token_type=meta.token_type_initial) }}_
{% endif %}

{% if tier_classification.s3_date -%}
_{{ t("report.meta_line_tier_with_s2_s3", tier=tier_classification.tier, s1_date=tier_classification.s1_date or "—", s2_date=tier_classification.s2_date, s3_date=tier_classification.s3_date) }}_
{% elif tier_classification.s2_date -%}
_{{ t("report.meta_line_tier_with_s2", tier=tier_classification.tier, s1_date=tier_classification.s1_date or "—", s2_date=tier_classification.s2_date) }}_
{%- else -%}
_{{ t("report.meta_line_tier", tier=tier_classification.tier, s1_date=tier_classification.s1_date or "—") }}_
{% endif %}

{% set rti = meta.realtime_token_info | default({}) %}
{#  v0.7.16: fallback chain on every field — surf project-detail (rti) is
    primary, Binance Alpha token-list (meta.alpha_*) is the fallback. The
    table renders if EITHER source has a price; previously a single rti
    failure (e.g. surf NOT_FOUND on GUA, 3 months listed but un-indexed)
    hid the whole header. Adds the project NAME, primary chain, and LP
    columns the user asked for so retail-trader readers see "what is this
    token / what's it priced / how active" at a glance.  #}
{# adversarial review HIGH#1: prefer `is not none` over truthiness — vol/LP/mcap can be a
   legitimate 0 on a freshly-listed / illiquid token, and treating 0 as
   missing would wrongly drop it and silently switch to the Alpha API value. #}
{% set _price_usd  = rti.get('price_usd') if rti.get('price_usd') is not none else meta.get('alpha_price_usd') %}
{% set _price_chg  = rti.get('price_change_24h_pct') if rti.get('price_change_24h_pct') is not none else meta.get('alpha_percent_change_24h') %}
{% set _vol_24h    = rti.get('volume_24h_usd') if rti.get('volume_24h_usd') is not none else meta.get('alpha_vol_24h_usd') %}
{% set _lp_usd     = rti.get('liquidity_usd') if rti.get('liquidity_usd') is not none else meta.get('alpha_liquidity_usd') %}
{% set _mcap       = rti.get('market_cap_usd') if rti.get('market_cap_usd') is not none else meta.get('alpha_market_cap_usd') %}
{% set _fdv        = rti.get('fdv_usd') if rti.get('fdv_usd') is not none else meta.get('alpha_fdv_usd') %}
{# adversarial review MEDIUM#1: per-field source flag — price may be from surf while vol
   is from Alpha (or vice versa); previous `_src` only looked at price and
   mislabeled mixed rows. Use a Jinja namespace because `{% set %}` inside
   `{% for %}` does NOT mutate outer-scope variables (loop-local scoping). #}
{% set _ns = namespace(surf=0, alpha=0) %}
{% for _key_pair in [('price_usd','alpha_price_usd'), ('volume_24h_usd','alpha_vol_24h_usd'), ('liquidity_usd','alpha_liquidity_usd'), ('market_cap_usd','alpha_market_cap_usd'), ('fdv_usd','alpha_fdv_usd')] -%}
{%-   if rti.get(_key_pair[0]) is not none -%}{% set _ns.surf = _ns.surf + 1 -%}{% elif meta.get(_key_pair[1]) is not none -%}{% set _ns.alpha = _ns.alpha + 1 -%}{%- endif -%}
{%- endfor -%}
{% set _src = ('surf+Alpha API' if (_ns.surf > 0 and _ns.alpha > 0) else ('surf' if _ns.surf > 0 else ('Alpha API' if _ns.alpha > 0 else 'none'))) %}
{% if _price_usd is not none %}
## {{ t("render.market_h2") }}

| {{ t("render.market_col_item") }} | {{ t("render.market_col_value") }} |
|---|---|
| **{{ t("render.market_project_name") }}** | **{{ meta.name | md_cell }}** ({{ meta.symbol | md_cell }}) |
| Ticker | `{{ meta.symbol | md_cell }}` |
| {{ t("render.market_primary_chain") }} | {{ meta.chain | md_cell }}{% if meta.get('primary_chain') and meta.get('primary_chain') != "binance-smart-chain" %} → {{ t("render.market_actual_primary") }} **{{ meta.get('primary_chain') | md_cell }}**{% if meta.get('_holder_snapshot_mode') %} (HOLDER_SNAPSHOT mode){% else %} {{ t("render.market_bsc_mirror") }}{% endif %}{% endif %} |
| {{ t("render.market_listing") }} | {{ tier_classification.tier }} ({% if tier_classification.tier == "S1" %}{{ t("render.market_tier_s1") }}{% elif tier_classification.tier == "S2" %}{{ t("render.market_tier_s2") }}{% elif tier_classification.tier == "S3" %}{{ t("render.market_tier_s3") }}{% else %}—{% endif %}) · {{ t("render.market_alpha_listed") }} {{ tier_classification.s1_date or "—" }}{% if tier_classification.s2_date %} · {{ t("render.market_perp_listed") }} {{ tier_classification.s2_date }}{% endif %} |
| **{{ t("render.market_current_price") }}** | **${{ "%.4g" | format(_price_usd) }}** ({% if _price_chg is not none and _price_chg < 0 %}🔴 {{ "%.2f" | format(_price_chg) }}%{% elif _price_chg is not none and _price_chg > 0 %}🟢 +{{ "%.2f" | format(_price_chg) }}%{% else %}—{% endif %} 24H) |
| **{{ t("render.market_vol_24h") }}** | {% if _vol_24h is not none %}**${{ "{:,.0f}".format(_vol_24h) }}**{% else %}—{% endif %} |
| {{ t("render.market_lp") }} | {% if _lp_usd is not none %}${{ "{:,.0f}".format(_lp_usd) }}{% else %}—{% endif %} |
| {{ t("render.market_mcap_fdv") }} | {% if _mcap is not none %}${{ "{:,.0f}".format(_mcap) }}{% else %}—{% endif %} / {% if _fdv is not none %}${{ "{:,.0f}".format(_fdv) }}{% else %}—{% endif %} |
| {{ t("render.market_data_source") }} | {{ _src }} ({{ t("render.market_realtime") }}){% if meta.get('alpha_holders') is not none %} · {{ t("render.market_holders", n="{:,.0f}".format(meta.get('alpha_holders'))) }}{% endif %}{% if meta.get('alpha_count_24h') is not none %} · {{ t("render.market_count_24h", n="{:,.0f}".format(meta.get('alpha_count_24h'))) }}{% endif %} |

{% endif %}
{# v0.7.22 P0 #2 (v0.7.25 中性化): 渲染端 判定 5 档 + risk score (1-10) 推导.
   Moved OUTSIDE the `{% if decision_summary %}` block (was inside in
   the first cut) — conclusion section below references `_v.subtype` and
   `_v.risk` unconditionally, and a skeleton without decision_summary
   (legacy / smoke fixtures) made jinja2 StrictUndefined raise. By
   computing _v in the outer scope with safe defaults for every input,
   both the decision-summary table AND the conclusion header can read
   it without scope leaks.
   工作流 现 判定 3 档把 3 个不同时态信号 OR 合一全映射 EXIT_IF_HOLDING,
   90% Alpha 币掉同一档 → 无区分度. 本段从 raw signals 推 5 档子类 + 1-10 风险评分
   不动 工作流 schema.
   v0.7.25: 标签从 EXIT_* (含交易建议含义) 改成 链上侦测-neutral 链上状态:
     CLEAN — 无显著 链上侦测 触发信号
     WATCH — 部分异动但未触发主信号
     OPERATOR_DUMPED — 历史 庄家 已派完 (链上证据: ≥3 个内幕钱包已转出 ≥95%)
     DORMANT_INSIDER_RISK — 潜伏内幕未派 (内幕钱包仍持有 ≥0.5% 总供应)
     RECENT_DISTRIBUTION — 近 72h 大额链上活动 (≥10 笔异常转移) #}
{% set _m6_quiet = (lineage.m6.n_quiet if lineage is defined and lineage and lineage.m6 is defined and lineage.m6 else 0) or 0 -%}
{% set _m6_partial = (lineage.m6.n_partial_dumper if lineage is defined and lineage and lineage.m6 is defined and lineage.m6 else 0) or 0 -%}
{% set _m6_full = (lineage.m6.n_full_dumper if lineage is defined and lineage and lineage.m6 is defined and lineage.m6 else 0) or 0 -%}
{% set _recent_ns = namespace(n=0) -%}
{% if anomaly is defined and anomaly -%}
  {% for d in (anomaly.detector_summary or []) -%}
    {% if d.label and ('72h' in d.label or '近期' in d.label) -%}
      {% set _recent_ns.n = d.count or 0 -%}
    {%- endif -%}
  {%- endfor -%}
{%- endif -%}
{% set _recent_anomaly_n = _recent_ns.n -%}
{% set _wash = dump_tracking.get('wash_dominated', false) if dump_tracking is defined and dump_tracking else false -%}
{% set _pure_pct = (dump_tracking.get('pure_insider_holds_pct_supply') or 0) if dump_tracking is defined and dump_tracking else 0 -%}

{# v0.8.7.3: 加 subtype_zh 中文化 user-facing label. subtype 内部 enum 用作
   logic gate (==, downgrade rules), subtype_zh 仅 display. #}
{% set _v = namespace(risk=0, subtype="CLEAN", subtype_zh=t("render.chain_state_clean_zh"),
                     label=t("render.chain_state_clean_label")) -%}

{# 潜伏内幕未派 — 内幕钱包仍持有 ≥0.5% 总供应 (最高优先级, 因为 时点 不可预测) #}
{% if _m6_quiet > 0 and _pure_pct > 0.5 -%}
  {% set _v.risk = _v.risk + 4 -%}
  {% set _v.subtype = "DORMANT_INSIDER_RISK" -%}
  {% set _v.subtype_zh = t("render.chain_state_dormant_zh") -%}
  {% set _v.label = t("render.chain_state_dormant_label", n=_m6_quiet, pct="%.1f"|format(_pure_pct)) -%}
{%- endif -%}

{# 近期链上活动 — 72h ≥ 10 异常 #}
{% if _recent_anomaly_n >= 10 -%}
  {% set _v.risk = _v.risk + 4 -%}
  {% set _v.subtype = "RECENT_DISTRIBUTION" -%}
  {% set _v.subtype_zh = t("render.chain_state_recent_zh") -%}
  {% set _v.label = t("render.chain_state_recent_label", n=_recent_anomaly_n) -%}
{% elif _recent_anomaly_n >= 3 -%}
  {% set _v.risk = _v.risk + 2 -%}
  {% if _v.subtype == "CLEAN" -%}
    {% set _v.subtype = "WATCH" -%}
    {% set _v.subtype_zh = t("render.chain_state_watch_zh") -%}
    {% set _v.label = t("render.chain_state_watch_label", n=_recent_anomaly_n) -%}
  {%- endif -%}
{%- endif -%}

{# 历史 庄家 已派完 — 内幕大量已分完 #}
{% if _m6_full >= 3 -%}
  {% set _v.risk = _v.risk + 3 -%}
  {% if _v.subtype == "CLEAN" -%}
    {% set _v.subtype = "OPERATOR_DUMPED" -%}
    {% set _v.subtype_zh = t("render.chain_state_dumped_zh") -%}
    {% set _v.label = t("render.chain_state_dumped_label", n=_m6_full) -%}
  {%- endif -%}
{%- endif -%}

{# 对敲主导加 risk #}
{% if _wash -%}{% set _v.risk = _v.risk + 2 -%}{%- endif -%}
{# 纯内幕剩 5%+ 进一步加 risk #}
{% if _pure_pct > 5 -%}{% set _v.risk = _v.risk + 2 -%}{%- endif -%}
{% if _v.risk > 10 -%}{% set _v.risk = 10 -%}{%- endif -%}

{% if decision_summary is defined and decision_summary %}
## {{ t("render.decision_summary_h2") }}

| {{ t("render.market_col_item") }} | {{ t("render.market_col_value") }} |
|---|---|
| **{{ t("render.decision_risk_score") }}** | **{% for _ in range(_v.risk) %}🟥{% endfor %}{% for _ in range(10 - _v.risk) %}⬜{% endfor %} ({{ _v.risk }}/10)** |
| **{{ t("render.decision_chain_state_label") }}** | **{{ _v.subtype_zh }}** — {{ _v.label }} |
| {{ t("render.market_primary_chain") }} | {{ decision_summary.primary_chain or "—" | md_cell }}{% if decision_summary.primary_chain_lp_usd %} ({{ t("render.decision_chain_lp", usd="{:,.0f}".format(decision_summary.primary_chain_lp_usd)) }}){% endif %} |
| **{{ t("render.decision_entry_cap") }}** | **{% if decision_summary.entry_size_cap_usd %}${{ "{:,.0f}".format(decision_summary.entry_size_cap_usd) }}{% else %}—{% endif %}** |
| {{ t("render.decision_short_catalyst") }} | {{ (decision_summary.short_term_catalysts|join("; ")) or t("render.none_word") | md_cell }} |
| {{ t("render.decision_blindspots") }} | {{ (decision_summary.blindspots|join("; ")) or t("render.none_word") | md_cell }} |

> {{ t("render.decision_5tier_title") }}
> - {{ t("render.decision_5tier_clean") }}
> - {{ t("render.decision_5tier_watch") }}
> - {{ t("render.decision_5tier_dumped") }}
> - {{ t("render.decision_5tier_dormant") }}
> - {{ t("render.decision_5tier_recent") }}

> {{ decision_summary.narrative | md_cell }}

{% endif %}

{# v0.7.16: 核心决策信息前置 — 结论 / 真实派发 / 风险信号聚合. 完整异动事件
   列表 (data 出货) 现在沉到 holdings 之前, 让 trader 先看完结论再看明细. #}

{# v0.7.22 (v0.7.25 中性化): 段标题改用 5 档 subtype + risk score (跟决策摘要一致, 避免
   "原 3 档 判定 / 新 5 档" 两套同时出现矛盾). 删除 baseline / downgrade
   那行 — 是 3 档系统的 baseline-AVOID + downgrade-1-tier 衍生品, 5 档不再
   需要这种 "降级路径" 概念.
   v0.7.25: "结论" → "链上状态" 避免 判定 含交易判断含义. #}
## {{ t("render.chain_state_h2", subtype_zh=_v.subtype_zh, risk=_v.risk) }}

**{{ _v.label }}**

{# v0.7.25: hide verdict.one_liner (LLM-filled freeform). LLM filler
   historically includes advice phrases ("建议持仓者择机退出 alpha 头寸",
   "Recommend holders exit Alpha positions") which violate the core
   "no buy/sell advice" constraint. _v.label above already states the
   on-chain state deterministically; one_liner adds nothing without LLM
   inference. v0.7.26 will replace LLM-fill with deterministic narrative
   derived from _v.subtype + key_metrics. Schema slot preserved in
   skeleton.json for AI二次研究. #}

| {{ t("section.decision.anchors_table_header_anchor") }} | {{ t("section.decision.anchors_table_header_value") }} | {{ t("section.decision.anchors_table_header_status") }} |
|---|---|---|
{% for a in decision_anchors %}| {{ a.anchor | md_cell }} | {{ a.value | md_cell }} | {{ a.status | md_cell }} |
{% endfor %}

{# v0.7.25: 删除 advice block (decision_action_block: immediate_action /
   stop_loss / re_entry_conditions). 报告核心约束是"不给买卖建议", advice
   block 整段违反 ("立即在 alpha 分 3 笔抛售 滑点 ≤ 3%" / "止损 $0.005362" /
   "重新进场条件"). decision_action_block 字段在 skeleton.json 保留供 AI
   二次研究使用, 不在 user-facing markdown 渲染.
   被删段: ### 行动方案 + immediate_action + stop_loss + re_entry_conditions
   未删段: ### 决策锚点汇总 (lines above, 确定性 锚点 数字, 非 advice) #}

{# v0.7.26: 当前链上行为画像 — 确定性 behavior_classifier 输出.
   把 10 个 raw 检测器 翻译成 4 大类 / 10 种行为标签, 按 severity
   STRONG/MEDIUM/WEAK 渲染, OFF 折叠. 每条 1 行: emoji + 标签 + 严重度
   badge + 量化 trigger metric + 1 句话人话. 不上 LLM, render 端只取
   classifier 确定性 输出.

   阈值校准来源: v0725_5_CALIBRATION.md (8 token backtest, 2026-06-11).

   多标签 本设计如此: 同一 token 可以同时是 A1+B1+C3+D2. 不要把行为画像
   理解为 "判定", 它跟 判定 是两层 - 判定 是综合状态, 行为画像
   是 检测器 → human translation 中间层. #}
{% if behavior_profile is defined and behavior_profile and behavior_profile.active_labels %}
## {{ t("render.behavior_h2") }}

> {{ t("render.behavior_intro") }}

| {{ t("render.behavior_col_severity") }} | {{ t("render.behavior_col_label") }} | {{ t("render.behavior_col_category") }} | {{ t("render.behavior_col_trigger") }} | {{ t("render.behavior_col_fact") }} |
|:-:|---|---|---|---|
{% for lid in behavior_profile.active_labels %}
{% set info = behavior_profile.by_label[lid] %}
{% set sev_emoji = "🔴" if info.severity == "STRONG" else ("🟠" if info.severity == "MEDIUM" else "🟡") %}
{% set sev_text = info.severity %}
{% set cat = info.category %}
{% set cat_name = behavior_profile.category_names_zh[cat] %}
{% set label_name = behavior_profile.label_names_zh[lid] %}
{% set _metric_parts = [] %}
{% for k, v in (info.trigger_metrics or {}).items() %}{% set _ = _metric_parts.append(k ~ "=" ~ v) %}{% endfor %}
{% set metrics_str = _metric_parts | join(", ") %}
{# v0.7.26.1 adversarial review MED fix: apply md_cell escape to metrics_str. Current
   trigger_metrics are numeric/bool so risk is theoretical, but future
   addr/symbol values could otherwise break table pipes / backtick fences. #}
| {{ sev_emoji }} **{{ sev_text }}** | `{{ lid | md_cell }}` {{ label_name | md_cell }} | {{ cat }} {{ cat_name | md_cell }} | `{{ metrics_str | md_cell }}` | {{ info.human_summary_zh | md_cell }} |
{% endfor %}

> {{ t("render.behavior_footer") }}

{% elif behavior_profile is defined and behavior_profile and behavior_profile.active_labels is iterable %}
## {{ t("render.behavior_h2") }}

> {{ t("render.behavior_none") }}

{% endif %}

{# v0.7.19.4 adversarial review HIGH#1: section guard must use `.get()` for the new
   tree_holds_tokens key (it's absent on pre-v0.7.19.4 skeletons), else
   StrictUndefined raises before the `or` falls back to the alias. The
   earlier test passed only because confirmed_total_tokens > 0 short-
   circuited the OR before the second branch was evaluated. #}
{# v0.7.23 fix: original guard required confirmed_total_tokens > 0 OR
   tree_holds_tokens > 0 to render the section. On a surf-failed
   dump_tracker run (H 2026-06-09) both are zero and the entire section
   would disappear silently, hiding the buckets_complete=false banner
   that lives inside. Now we ALSO render when buckets_complete is
   explicitly false, so the user always sees the failure marker. #}
{% if dump_tracking is defined and dump_tracking and ((dump_tracking.confirmed_total_tokens or 0) > 0 or (dump_tracking.get('tree_holds_tokens') or dump_tracking.get('insider_holds_tokens') or 0) > 0 or dump_tracking.get('buckets_complete') == false) %}
## {{ t("render.dump_tracker_h2") }}

{# v0.8.1.2: 控筹口径汇总表 — 用户要求放在 section 顶部一目了然.
   3 个口径分别口径不同 (纯内幕 / 内幕树含锁仓 / A2 净控筹), 在这里
   统一摆出来跟 tokens / 占总供应 / 占流通 三栏对齐. #}
{%- set _circ = meta.circulating_supply or 0 -%}
{%- set _tot = meta.total_supply or 0 -%}
{%- set _pure_tok = dump_tracking.pure_insider_holds_tokens or 0 -%}
{%- set _pure_pct_tot = dump_tracking.pure_insider_holds_pct_supply or 0 -%}
{%- set _tree_tok = dump_tracking.tree_holds_tokens or 0 -%}
{%- set _tree_pct_tot = dump_tracking.tree_holds_pct_supply or 0 -%}
{%- set _cfh_sum_top = (funding_attribution.cex_fanout_hubs.summary
                       if funding_attribution is defined and funding_attribution
                       and funding_attribution.cex_fanout_hubs is defined
                       and funding_attribution.cex_fanout_hubs
                       and funding_attribution.cex_fanout_hubs.summary
                       else {}) -%}
{%- set _a2_tok = (_cfh_sum_top.net_structured_fanout_tokens_total
                  if _cfh_sum_top.net_structured_fanout_tokens_total is defined
                  else (_cfh_sum_top.net_fanout_tokens_total
                        if _cfh_sum_top.net_fanout_tokens_total is defined
                        else None)) -%}
{# v0.8.6.7 fix: 直接看 net_structured_fanout_tokens_total 是否 > 0.
   v0.8.5.4 per-hub fallback 保证 confirmed_hub recipients 完整即使 bulk
   truncated. 用 net 数字本身判断是否可算 — 算出来就显示 net, 算不出
   (=0) 才标 "不可算". BEAT 案例 recipients_truncated=True 但 net=80M
   实际算出, 不能误标 "不可算". #}
{%- set _a2_net = (_cfh_sum_top.get('net_structured_fanout_tokens_total') or 0) if _cfh_sum_top else 0 -%}
{%- set _a2_stale = (_a2_net <= 0) -%}

{# v0.8.1.3: disjoint 拆分 + 加总. 用户视角:
   "庄家敢不敢拉盘"取决于**非庄家方手里有多少现可砸的筹码**.
   非庄家方抛压 = 流通 - 庄家集团总控筹.
   庄家弹药拆 3 桶:
     - 公开锁仓 (vesting/treasury/中转) = 内幕树 - 纯内幕. 按时间表释放, 拉盘时不立刻砸.
     - m6 可机动 = 纯内幕. 庄家想砸的话用这部分, 但拉盘时庄家不会砸自己.
     - CEX fan-out 外独立 = A2 净控筹. m6 之外通过 CEX→hub→拆散的庄家筹码.
   m6 钱包 (pre-launch 收 from deployer) 跟 A2 hub recipients (post-launch
   收 from hub) 几乎肯定钱包级 disjoint — 直接加总作合理 upper bound. #}
{# v0.8.1.6: 第 5 桶 — 其他庄家足迹钱包当前余额 (m6 / A2 / LP 之外).
   Aggregation 来源:
   - flow_operators: post-launch DEX_ARB_BOT / ASYNC_WASH / CROSS_ALPHA_OPERATOR
     / UNCLASSIFIED_SINGLE_OPERATOR 钱包 (sum net_balance_tokens > 0).
   - cross_sym whales: 跨币种鲸鱼 (sum current balance > 0).
   - high_throughput dumpers: 已识别过账 ≥ 1M tokens 的钱包 (balance > 0
     的部分; 大部分历史庄家 balance ≈ 0 所以不计 — Velvet case).
   排除已在 m6 / A2 / LP 集合的钱包避免双计 — Jinja 没有 set 操作, 改用
   保守做法: 这一桶只算 dump_tracker 已知 insider_addrs **不包含**的部分
   (实测时这些 detector 输出的钱包 99% 是 post-launch 的 EOA 不会在 m6).
   钱包重叠校验严格 disjoint 留 v0.8.2 backlog. #}
{%- set _ops_ns = namespace(bal=0.0, n=0) -%}
{% if flow_operators is defined and flow_operators and flow_operators.operators -%}
  {% for _op in flow_operators.operators -%}
    {%- set _opb = _op.get('net_balance_tokens') or 0 -%}
    {% if _opb > 0 -%}
      {%- set _ops_ns.bal = _ops_ns.bal + _opb -%}
      {%- set _ops_ns.n = _ops_ns.n + 1 -%}
    {% endif -%}
  {% endfor -%}
{% endif -%}
{% if cross_sym is defined and cross_sym and cross_sym.whales -%}
  {% for _w in cross_sym.whales -%}
    {%- set _wb = _w.get('current_balance') or 0 -%}
    {% if _wb > 0 -%}
      {%- set _ops_ns.bal = _ops_ns.bal + _wb -%}
      {%- set _ops_ns.n = _ops_ns.n + 1 -%}
    {% endif -%}
  {% endfor -%}
{% endif -%}
{% if funding_attribution is defined and funding_attribution
      and funding_attribution.high_throughput_dumpers is defined
      and funding_attribution.high_throughput_dumpers -%}
  {% for _d in (funding_attribution.high_throughput_dumpers.dumpers or []) -%}
    {%- set _db = _d.get('balance') or 0 -%}
    {% if _db > 1 -%}
      {%- set _ops_ns.bal = _ops_ns.bal + _db -%}
      {%- set _ops_ns.n = _ops_ns.n + 1 -%}
    {% endif -%}
  {% endfor -%}
{% endif -%}
{%- set _other_op_tok = _ops_ns.bal -%}
{%- set _other_op_n = _ops_ns.n -%}

{# v0.8.4: 先算 _suspected_tok 让 ceiling-clamp 公开锁仓桶时能扣它. #}
{%- set _sus_ns = namespace(bal=0.0, n=0) -%}
{% for _w in (monitoring_wallets or []) -%}
  {% if _w.monitor_role_enum == 'suspected_operator_reserve' -%}
    {%- set _b = _w.balance_tokens or 0 -%}
    {% if _b > 0 -%}
      {%- set _sus_ns.bal = _sus_ns.bal + _b -%}
      {%- set _sus_ns.n = _sus_ns.n + 1 -%}
    {% endif -%}
  {% endif -%}
{% endfor -%}
{%- set _suspected_tok = _sus_ns.bal -%}
{%- set _suspected_n = _sus_ns.n -%}
{%- set _operator_a2 = _a2_tok if (_a2_tok is not none and not _a2_stale) else 0 -%}
{# v0.8.1.5: 所有链上 DEX pool LP 算庄家弹药 — 不只主池. S1/S2/S3
   Alpha token 的 LP 99% 是项目方/MM 提供 (散户 LP 极少). 算法:
   Primary: chain_lp_realtime.<chain>.lp_tokens (surf 实测各 DEX-labeled
            holder 余额, sum across all chains)
   Fallback: alpha_liquidity_usd / 2 / alpha_price_usd (TVL 反推, 仅
             主池 estimate, 当 surf 没拿到 DEX-labeled holder 数据时)
   注: LP pool wallet 一般不在 m6 谱系 (LP create 时间在 trace_floor 前),
   也不在 A2 净控筹 (LP 不是 fan-out hub), 否则会落进"非庄家方抛压"
   错算. #}
{%- set _lp_usd = (meta.alpha_liquidity_usd or 0) -%}
{%- set _alpha_px = (meta.alpha_price_usd or 0) -%}
{%- set _clp = meta.chain_lp_realtime if meta.chain_lp_realtime is defined else {} -%}
{%- set _lp_ns = namespace(measured=0.0, n_pools=0, has_measured=false) -%}
{% for _chain_name, _chain_lp in _clp.items() -%}
  {% if _chain_lp.lp_tokens is not none and _chain_lp.lp_tokens > 0 -%}
    {%- set _lp_ns.measured = _lp_ns.measured + _chain_lp.lp_tokens -%}
    {%- set _lp_ns.n_pools = _lp_ns.n_pools + (_chain_lp.n_dex_pools or 0) -%}
    {%- set _lp_ns.has_measured = true -%}
  {% endif -%}
{% endfor -%}
{%- set _lp_token_side = _lp_ns.measured if _lp_ns.has_measured else ((_lp_usd / 2 / _alpha_px) if (_lp_usd > 0 and _alpha_px > 0) else 0) -%}
{%- set _lp_source = t("render.lp_source_measured", n=_lp_ns.n_pools) if _lp_ns.has_measured else t("render.lp_source_derived") -%}
{# v0.8.3.4 — 矿币/跨链桥模式的 mint 合约 reserve 也算庄家弹药.
   JCT 测试发现: mint_authority_dumps.summary.total_current_balance = 4.25B
   (37% 流通) 是项目方未释放的矿币 reserve, 但 disjoint 5 桶完全没算.
   伪矿币集群 (fake_mining_cluster_member) 的钱包当前余额也应进, 但
   enricher 没查 current balance — v0.8.4 backlog. 当前先把 mint reserve
   接进来, 已经能把 JCT 类 token 的弹药估算从 ~1% 拉到 37%+. #}
{%- set _mint_reserve_tok = ((funding_attribution.mint_authority_dumps.summary.get('total_current_balance') or 0)
                              if funding_attribution is defined and funding_attribution
                              and funding_attribution.mint_authority_dumps is defined
                              and funding_attribution.mint_authority_dumps
                              and funding_attribution.mint_authority_dumps.summary
                              else 0) or 0 -%}
{# v0.8.3.4 — 伪矿币集群已 mint 出去的部分 (累计 minted - 当前 reserve)
   也是项目方控制的庄家弹药, 减去已经被 hidden_operator_activity probe
   surface 出来的"已变现"部分 (转 CEX / DEX 卖). 剩下还在集群钱包里的
   就是潜在弹药. JCT 实测: 累计 mint 10.34B - reserve 4.25B - 已变现
   313.66M ≈ 5.78B 还在 cluster 钱包里. #}
{# v0.8.4: 必须 filter is_excluded=True 的 authority. Excluded 通常是
   deployer 钱包本身 (total_minted = 整个总供应), 不算 inflationary
   mint authority. 不 filter 会让 COLLECT/Velvet (非矿币 token) 误算
   3B/1B 当 "已 mint 给庄家集群", 推 disjoint 表总数超 100% 流通. #}
{%- set _fake_mining_addr_minted = 0.0 -%}
{%- set _mining_ns = namespace(total_minted=0.0) -%}
{% if funding_attribution is defined and funding_attribution
      and funding_attribution.mint_authorities is defined
      and funding_attribution.mint_authorities -%}
  {% for _auth in (funding_attribution.mint_authorities.authorities or []) -%}
    {% if not _auth.is_excluded -%}
      {%- set _mining_ns.total_minted = _mining_ns.total_minted + (_auth.total_minted or 0) -%}
    {% endif -%}
  {% endfor -%}
{% endif -%}
{%- set _hoa_realized = (hidden_operator_activity.confirmed_total_tokens
                         if hidden_operator_activity is defined
                         and hidden_operator_activity
                         and hidden_operator_activity.confirmed_total_tokens is defined
                         else 0) or 0 -%}
{%- set _fake_mining_addr_minted = (_mining_ns.total_minted - _mint_reserve_tok - _hoa_realized) -%}
{% if _fake_mining_addr_minted < 0 %}{%- set _fake_mining_addr_minted = 0 %}{% endif -%}

{# v0.8.4.2: 公开锁仓桶用 max(m6_locked, section_a_locked) 取**全网**
   vesting+multisig+treasury+airdrop_platform 总和, 避免漏算 m6 外的
   vesting wallets (Velvet 案例: SablierLockup `0x6e0bad2c` 471M m6 外,
   旧算法漏算 → 庄家弹药低估).
   再 unminted-subtract gate: 当 _locked_raw > circulating 时, m6/section_a
   内含 unminted supply, 减 unminted_reserve_total. #}
{%- set _unminted_reserve_total = ((meta.total_supply or 0) - _circ) if (meta.total_supply and _circ and meta.total_supply > _circ) else 0 -%}

{# v0.8.4.6: 用 monitoring_wallets[role=deployer] 取 m6 enumerated set,
   按"m6 内 vs m6 外" dedup section_a vesting/multisig. 避免 m6 tree 跟
   ①b 双算 (Velvet `0xd19dce53` Gnosis Safe 107M 同时在 m6 deployer +
   section_a multisig — 不 dedup 重算 107M; COLLECT 4 个 Gnosis Safe
   257M 全在 m6, 不 dedup 重算 257M). #}
{%- set _dpl_ns = namespace(set=[]) -%}
{% for _w in (monitoring_wallets or []) -%}
  {% if _w.monitor_role_enum == 'deployer' -%}
    {%- set _dpl_ns.set = _dpl_ns.set + [(_w.addr_full or '')|lower] -%}
  {% endif -%}
{% endfor -%}
{%- set _m6_deployer_addrs = _dpl_ns.set -%}

{%- set _sa_ns = namespace(
    vesting_out_m6=0.0,
    vesting_in_m6=0.0,
    multisig_out_m6=0.0,
    cex_operator_tok=0.0,
    cex_operator_n=0
) -%}
{%- set _clp_for_locked = meta.chain_lp_realtime if meta.chain_lp_realtime is defined else {} -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc -%}
    {# ①a vesting / treasury / airdrop_platform — m6 外才单独计, m6 内的
       vesting wallet 跟踪给 ② 桶减去 (m6 tree 含 vesting 是 raw 持仓
       不该全算庄家弹药) #}
    {% for _cat in ['vesting', 'treasury', 'airdrop_platform'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {%- set _addr = (_h.addr or '')|lower -%}
        {%- set _bal = _h.balance or 0 -%}
        {% if _addr not in _m6_deployer_addrs -%}
          {%- set _sa_ns.vesting_out_m6 = _sa_ns.vesting_out_m6 + _bal -%}
        {% else -%}
          {%- set _sa_ns.vesting_in_m6 = _sa_ns.vesting_in_m6 + _bal -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
    {# ①b multisig — m6 外才单独计 #}
    {% for _h in ((_thc.get('multisig') or {}).get('top') or []) -%}
      {%- set _addr = (_h.addr or '')|lower -%}
      {%- set _bal = _h.balance or 0 -%}
      {% if _addr not in _m6_deployer_addrs -%}
        {%- set _sa_ns.multisig_out_m6 = _sa_ns.multisig_out_m6 + _bal -%}
      {% endif -%}
    {% endfor -%}
    {# ⑦ CEX 项目方托管: 单 wallet ≥ 3% 流通 + m6 外
       v0.8.4.7: 10% → 3% (用户 review: ≥10% 阈值放过 Bitget Cold 21.6M
       Velvet 4.9% / Binance Wallet Proxy 31M COLLECT 5.8% 等大额单点
       CEX 持仓 — 5% 一个钱包散户充值不现实). #}
    {% for _h in ((_thc.get('cex') or {}).get('top') or []) -%}
      {%- set _addr = (_h.addr or '')|lower -%}
      {%- set _bal = _h.balance or 0 -%}
      {% if _circ and _bal / _circ >= 0.03 and _addr not in _m6_deployer_addrs -%}
        {%- set _sa_ns.cex_operator_tok = _sa_ns.cex_operator_tok + _bal -%}
        {%- set _sa_ns.cex_operator_n = _sa_ns.cex_operator_n + 1 -%}
      {% endif -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}

{# v0.8.4.7: TOP-DOWN retail 算法 — 之前 bottom-up (circ - operator_total)
   因桶 wallet 重叠 leak 严重 (Velvet 102% raw → retail 0 错误).
   现在直接遍历 top 100 holders, 不在 operator union 的算 retail.
   v0.8.4.8: CEX 钱包整段从 retail/operator 双侧刨除 — CEX hot/cold/deposit
   都是散户充值入口, 无法验证 wallet 余额属性 (项目方托管 vs 散户聚合).
   归"中性 CEX 中转池", 速读分 3 个数字: operator / CEX 中转 / retail. #}
{%- set _op_union_ns = namespace(set=_m6_deployer_addrs|list) -%}
{%- set _retail_ns = namespace(tokens=0.0, n=0, top=[]) -%}
{%- set _op_in_circ_ns = namespace(tokens=0.0) -%}
{%- set _vest_unminted_ns = namespace(tokens=0.0) -%}
{%- set _cex_pool_ns = namespace(tokens=0.0, n=0) -%}
{# Build operator union: m6 deployer + section_a multisig / vesting / treasury
   / airdrop_platform / lp + 启发式 / 检测器命中 wallets. NO CEX. #}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc -%}
    {% for _h in ((_thc.get('multisig') or {}).get('top') or []) -%}
      {%- set _op_union_ns.set = _op_union_ns.set + [(_h.addr or '')|lower] -%}
    {% endfor -%}
    {% for _h in ((_thc.get('lp') or {}).get('top') or []) -%}
      {%- set _op_union_ns.set = _op_union_ns.set + [(_h.addr or '')|lower] -%}
    {% endfor -%}
    {% for _h in ((_thc.get('treasury') or {}).get('top') or []) -%}
      {%- set _op_union_ns.set = _op_union_ns.set + [(_h.addr or '')|lower] -%}
    {% endfor -%}
    {% for _h in ((_thc.get('airdrop_platform') or {}).get('top') or []) -%}
      {%- set _op_union_ns.set = _op_union_ns.set + [(_h.addr or '')|lower] -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{# 启发式 + 其他检测器命中的 operator wallets from monitoring_wallets.
   v0.8.4.7.1: JCT review caught — 之前只含 suspected + fake_mining 漏了
   cross_alpha_inactive_whale (JCT `0x26209d9f0dc3` 1.58B = 13.7% 流通!)
   + anomaly_participant + public_cex_hot_wallet (这些都是 detector
   命中的 operator-side, 不是 retail). #}
{# v0.8.4.9.5: revert v0.8.4.9.4 — mint_authority 算 operator, 不算
   vesting_skip. 验证: Alpha API JCT circulating=11.5B 已包含 mint
   authority `0xe0b5ed` 持的 4.15B (已 mint 在它钱包里, 未 distribute).
   是流通中项目方可机动弹药, 该算 operator. v0.8.4.9.4 错改 (用户 catch). #}
{%- set _OPERATOR_ROLES = ['suspected_operator_reserve', 'fake_mining_cluster_member',
                          'cross_alpha_inactive_whale', 'anomaly_participant',
                          'public_cex_hot_wallet', 'cex_fanout_hub',
                          'cex_fanout_recipient', 'flow_operator',
                          'high_throughput_dumper', 'mining_fed_operator',
                          'mint_authority'] -%}
{%- set _UNMINTED_ROLES = [] -%}
{% for _w in (monitoring_wallets or []) -%}
  {% if _w.monitor_role_enum in _OPERATOR_ROLES -%}
    {%- set _op_union_ns.set = _op_union_ns.set + [(_w.addr_full or '')|lower] -%}
  {% endif -%}
{% endfor -%}
{# Build vesting/unminted set (these wallets hold mostly unminted, skip from retail) #}
{%- set _vest_set_ns = namespace(set=[]) -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc -%}
    {% for _h in ((_thc.get('vesting') or {}).get('top') or []) -%}
      {%- set _vest_set_ns.set = _vest_set_ns.set + [(_h.addr or '')|lower] -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{# v0.8.6.1: mint_authority wallets 归 _vest_set_ns (= 流通外锁仓).

   v0.8.6.4: 用户 review (2026-06-12 BEAT 案例) 移除 `is_excluded` filter.
   之前 _exclude_for_auth = mining_fed_addrs | deployer 让 5 个 mint
   authority (含 BEAT 0x75552f8f6785 持 342M = 60% Alpha circ) 被标
   excluded. 但它们仍是 mint authority, 持仓概念上仍是"未释放" — is_excluded
   只是 detector 标 "也是 mining_fed dumper", 不改变持仓本质. 全部 mint
   authorities 加 vest_set 才符合 thesis. #}
{% if funding_attribution is defined and funding_attribution
      and funding_attribution.mint_authorities is defined
      and funding_attribution.mint_authorities -%}
  {% for _auth in (funding_attribution.mint_authorities.authorities or []) -%}
    {%- set _vest_set_ns.set = _vest_set_ns.set + [(_auth.addr or '')|lower] -%}
  {% endfor -%}
{% endif -%}
{# v0.8.6.5.0: wallet_cluster_graph cluster addrs 加进 _op_union_ns.
   Bubblemaps-style cluster detection — wallets transferring 给彼此 高额
   tokens (≥ 0.5% supply per edge) 形成 connected component ≥ 3 nodes.
   = 项目方控筹的非 cex_fanout / 非 mint_authority cluster. 加进 op_union
   让 top-down hit 这些 addrs 时归 operator (不是 retail). #}
{% if wallet_cluster_graph is defined and wallet_cluster_graph -%}
  {% for _cluster in (wallet_cluster_graph.get('clusters') or []) -%}
    {% for _a in (_cluster.get('addrs') or []) -%}
      {%- set _op_union_ns.set = _op_union_ns.set + [_a|lower] -%}
    {% endfor -%}
  {% endfor -%}
{% endif -%}
{# v1.0.5 (ARX 2026-06-22): drop DEX/CEX infra (surf/Arkham-labelled — e.g.
   "PancakeSwap | Vault", "Binance Wallet", routers) from the operator union so
   they are never counted as 项目方可控筹码. `_neutral_infra_addrs` is computed
   ONCE in the pipeline (single source of truth shared with
   screen_summary._compute_chip_3way) so this detail can't diverge from the
   一屏结论 headline. #}
{%- set _neutral_set = (_neutral_infra_addrs | default([])) | map('lower') | list -%}
{%- if _neutral_set -%}
  {%- set _op_union_ns.set = _op_union_ns.set | reject('in', _neutral_set) | list -%}
{%- endif -%}
{# Iterate top 100 across primary chain only, classify each holder into 4 buckets:
   - vesting (unminted)
   - operator (m6 + multisig/vesting/treasury/airdrop_platform/lp + 检测器命中)
   - cex_pool (中性 — 散户充值 vs 项目方托管 无法区分)
   - retail (其他, 可验证非官方控筹)

   v0.8.5.0: 只算 primary_chain. JCT 跨链 case: Ethereum 链上 Gnosis Safe
   持 13.1B JCT, 但 circulating_supply 只 BSC 数 (11.5B) — 混算导致 operator
   raw 撑爆 400%+. 严格分母 / 分子链一致. #}
{%- set _primary_chain_for_classify = meta.get('primary_chain') if meta is defined and meta else None -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {%- set _addr = (_h.addr or '')|lower -%}
        {%- set _bal = _h.balance or 0 -%}
        {%- set _lbl = _h.label_text or '' -%}
        {% if _addr in _vest_set_ns.set -%}
          {%- set _vest_unminted_ns.tokens = _vest_unminted_ns.tokens + _bal -%}
        {% elif _cat == 'cex' -%}
          {# CEX wallet — 整段刨除. v0.8.4.8: 散户充值入口, 无法 attribute
             余额是项目方托管 OR 散户聚合, 归中性 CEX 池, 不影响 retail/operator
             判定. #}
          {%- set _cex_pool_ns.tokens = _cex_pool_ns.tokens + _bal -%}
          {%- set _cex_pool_ns.n = _cex_pool_ns.n + 1 -%}
        {% elif _addr in _op_union_ns.set -%}
          {%- set _op_in_circ_ns.tokens = _op_in_circ_ns.tokens + _bal -%}
        {% else -%}
          {%- set _retail_ns.tokens = _retail_ns.tokens + _bal -%}
          {%- set _retail_ns.n = _retail_ns.n + 1 -%}
          {%- set _retail_ns.top = _retail_ns.top + [{'addr': _addr, 'bal': _bal, 'category': _cat, 'label': _lbl}] -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{%- set _retail_topdown = _retail_ns.tokens -%}
{%- set _retail_topdown_n = _retail_ns.n -%}
{%- set _retail_topdown_pct = (_retail_topdown / _circ * 100) if _circ else 0 -%}
{%- set _retail_top_wallets = _retail_ns.top | sort(attribute='bal', reverse=True) -%}
{# v0.8.5.0: 加 cex_fanout_hubs.summary.net_structured_fanout_tokens_total
   到 operator_in_circ. fan-out hubs + recipients 都是项目方控筹钱包,
   但它们大多不在 top 100 持币人 (hub 转完币 balance ≈ 0, recipients 持仓.

   v0.8.6.1 update: mint authority 持仓不再算 op_in_circ, 而是归 vest_unminted
   (见上方 _vest_set_ns build). op_in_circ 只含 m6 / multisig / lp / 检测器
   命中 / monitoring operator roles. audit 2026-06-12 M3 fix: 之前
   注释说 "mint authority 在 _op_in_circ_ns 已含" 错误 (adversarial review catch). #
   < 0.9% 流通 不进 top 100). top-down 遍历 top_holders 漏算这部分.
   net_structured_fanout_tokens_total = 排除 loopback + 跨 hub shuffle 后
   真实 fan-out tokens 到独立钱包. 直接加 operator_in_circ.

   v0.8.5.1: dedup overlap — 91 fan-out recipients 中部分可能在 top 100
   持币人 (top-down 已算 operator/cex/retail), 直接加 net_total 会双计.
   计算 in-top-100 recipients 持仓 sum 作 overlap 减.

   注: hubs 自己 (hub_addr) 不在 net_structured (那是 recipients 持仓), 不重叠. #}
{%- set _cex_fanout_net = ((funding_attribution.cex_fanout_hubs or {}).get('summary') or {}).get('net_structured_fanout_tokens_total') or 0 if funding_attribution is defined else 0 -%}
{%- set _fanout_recipient_addrs_ns = namespace(set=[]) -%}
{% if funding_attribution is defined and funding_attribution and funding_attribution.cex_fanout_hubs is defined -%}
  {% for _h in (funding_attribution.cex_fanout_hubs.hubs or []) -%}
    {% for _a in (_h.get('_net_structured_recipient_addrs_raw') or []) -%}
      {%- set _fanout_recipient_addrs_ns.set = _fanout_recipient_addrs_ns.set + [_a|lower] -%}
    {% endfor -%}
  {% endfor -%}
{% endif -%}
{%- set _fanout_overlap_ns = namespace(tokens=0.0) -%}
{# v0.8.6.2 adversarial review M1 fix: 加 primary_chain gate. _cex_fanout_net 是 BSC
   only 算的, overlap 也要限 primary_chain. 否则跨链 top_holders 偶然
   碰到 BSC fan-out recipient addr 会错误扣减 BSC fanout tail. #}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {%- set _addr = (_h.addr or '')|lower -%}
        {% if _addr in _fanout_recipient_addrs_ns.set -%}
          {%- set _fanout_overlap_ns.tokens = _fanout_overlap_ns.tokens + (_h.balance or 0) -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{%- set _cex_fanout_tail = _cex_fanout_net - _fanout_overlap_ns.tokens if _cex_fanout_net > _fanout_overlap_ns.tokens else 0 -%}
{# v0.8.6.5.0 adversarial review C2 fix: wallet_cluster_graph cluster wallets 不在 top
   100 时持仓需 inject (跟 cex_fanout_tail 同 pattern). detector 已 emit
   per-addr balance via balance_sql. 这里算 cluster_tail = total cluster
   balance 减 in-top-100 overlap. #}
{%- set _cluster_tail_overlap_ns = namespace(tokens=0.0) -%}
{%- set _cluster_addrs_set_ns = namespace(set=[]) -%}
{% if wallet_cluster_graph is defined and wallet_cluster_graph -%}
  {% for _cluster in (wallet_cluster_graph.get('clusters') or []) -%}
    {% for _a in (_cluster.get('addrs') or []) -%}
      {%- set _cluster_addrs_set_ns.set = _cluster_addrs_set_ns.set + [_a|lower] -%}
    {% endfor -%}
  {% endfor -%}
{% endif -%}
{%- set _cluster_total_balance_ns = namespace(tokens=0.0) -%}
{% if wallet_cluster_graph is defined and wallet_cluster_graph -%}
  {% for _cluster in (wallet_cluster_graph.get('clusters') or []) -%}
    {# adversarial review v1.0.5 R1: subtract neutral-infra cluster members (via per-member
       addr_balances) so an off-top-100 DEX/CEX address can't re-enter operator
       through cluster_tail. Mirrors screen_summary._compute_chip_3way. #}
    {%- set _infra_in_cluster_ns = namespace(tokens=0.0) -%}
    {%- set _cab = _cluster.get('addr_balances') or {} -%}
    {% for _ca in (_cluster.get('addrs') or []) -%}
      {% if (_ca|lower) in _neutral_set -%}
        {%- set _infra_in_cluster_ns.tokens = _infra_in_cluster_ns.tokens + (_cab.get(_ca) or _cab.get(_ca|lower) or 0) -%}
      {% endif -%}
    {% endfor -%}
    {%- set _ct_net = (_cluster.get('cluster_balance_total_tokens') or 0) - _infra_in_cluster_ns.tokens -%}
    {%- set _cluster_total_balance_ns.tokens = _cluster_total_balance_ns.tokens + (_ct_net if _ct_net > 0 else 0) -%}
  {% endfor -%}
{% endif -%}
{# Subtract overlap with top_holders (primary chain only, per adversarial review M1 v0.8.6.2) #}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {% if (_h.addr or '')|lower in _cluster_addrs_set_ns.set -%}
          {%- set _cluster_tail_overlap_ns.tokens = _cluster_tail_overlap_ns.tokens + (_h.balance or 0) -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{%- set _wcg_cluster_tail = _cluster_total_balance_ns.tokens - _cluster_tail_overlap_ns.tokens if _cluster_total_balance_ns.tokens > _cluster_tail_overlap_ns.tokens else 0 -%}
{# v0.8.6: implied_circ = top 100 sum (excl vesting) + cex_fanout tail. 用户
   review (2026-06-12): Alpha API circulating_supply 跟链上实际不一致
   (CLO Alpha 129M vs 链上 309M 2.4x), 速读用 Alpha 作分母让 sum 必然不为
   100%. 改用 implied_circ = "已 mint 进 wallet" 总和:
   - top 100 sum 减 vesting unminted (锁仓不算流通) = op_in_circ + cex + retail
   - 加 cex_fanout tail (= 61 wallets in tail 持仓, 不在 top 100)
   - 速读 用 max(Alpha, implied) 作 effective_circ. sum (op + cex + retail)
     = 100% organic (无 ceiling-clamp 凑数).
   mint authority 持仓在 _op_in_circ_ns 已含 (= 已 mint 进 wallet 部分),
   不再单独减 — per 用户 "mint authority 持仓中已 mint 部分应该算 circ". #}
{%- set _top_100_excl_vesting = _op_in_circ_ns.tokens + _cex_pool_ns.tokens + _retail_ns.tokens -%}
{%- set _implied_circ = _top_100_excl_vesting + _cex_fanout_tail + _wcg_cluster_tail -%}
{%- set _circ_alpha = _circ -%}
{# v0.8.6.1: 直接用 _implied_circ 作 effective. 不用 max(Alpha, implied).
   user wants sum (op + cex + retail) = 100%. vest_unminted (含 mint
   authority 持仓) 单独行不算 sum. Alpha API circ 跟 implied 差距加
   caveat. 例: JCT Alpha 11.5B (含 mint authority 4.26B), implied 7.18B
   (减 mint authority). 用 implied 显示流通 7.18B "可砸盘" 部分.
   CLO Alpha 129M (低估), implied 182M. 用 implied 反映链上实际. #}
{%- set _circ = _implied_circ if _implied_circ > 0 else _circ_alpha -%}
{%- set _implied_vs_alpha_ratio = (_implied_circ / _circ_alpha) if _circ_alpha else 1.0 -%}
{# v0.8.6.5.3 fix: re-compute _retail_topdown_pct with implied_circ. Was
   computed earlier (line ~851) before _circ reassignment, leading to
   inconsistency where 速读 retail_with_tail_pct used implied_circ but
   retail_topdown_pct used Alpha circ — caused "0.3% = 1.5% 内可验证"
   contradiction in COLLECT case (Alpha 537M, implied 2980M, 5.55x). #}
{%- set _retail_topdown_pct = (_retail_topdown / _circ * 100) if _circ else 0 -%}
{%- set _operator_topdown = _op_in_circ_ns.tokens + _cex_fanout_tail + _wcg_cluster_tail -%}
{%- set _operator_topdown_pct = (_operator_topdown / _circ * 100) if _circ else 0 -%}
{# v0.8.5.3: 用户 review (2026-06-12 CLO 案例):
   之前 logic 用 `total_supply - circulating_supply` (= unminted_reserve)
   全减 operator_topdown 错误, 因为 (a) total-circ 含 mint 合约未释放储备
   远超 mint authority 实际持仓, (b) operator_topdown 主体是流通中已
   分发筹码, 不该用未释放储备减.

   CLO 案例: operator_topdown=278M, unminted_reserve=871M (= 1B - 129M),
   278 - 871 = -593M → clamp 0. 速读显示 "庄家弹药 0%" 严重错.

   修法: 用 _mint_authority_balance_in_top_holders (实际持已 mint 但
   未分发部分) 替代 unminted_reserve_total. + ceiling-clamp at circ
   (avoid double-count from cross-bucket overlap).

   _mint_authority_balance_in_top_holders 计算: 遍历 BSC top_holders,
   找 funding_attribution.mint_authorities.authorities 里 addrs, sum
   它们 balance. 这才是 "项目方控制已 mint 未分发" 的真实量. #}
{%- set _ma_set_ns = namespace(set=[]) -%}
{% if funding_attribution is defined and funding_attribution
      and funding_attribution.mint_authorities is defined -%}
  {% for _auth in (funding_attribution.mint_authorities.authorities or []) -%}
    {% if not _auth.is_excluded -%}
      {%- set _ma_set_ns.set = _ma_set_ns.set + [(_auth.addr or '')|lower] -%}
    {% endif -%}
  {% endfor -%}
{% endif -%}
{%- set _ma_held_ns = namespace(tokens=0.0) -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {% if (_h.addr or '')|lower in _ma_set_ns.set -%}
          {%- set _ma_held_ns.tokens = _ma_held_ns.tokens + (_h.balance or 0) -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{# v0.8.6: 删 _ma_held subtract + ceiling-clamp 凑数. mint authority 持仓
   保留在 _operator_topdown (= 已 mint 进 wallet, 算庄家弹药 per 用户决定).
   organic sum: op + cex + retail = 100% (因 effective_circ = implied_circ). #}
{%- set _operator_topdown_in_circ = _operator_topdown -%}
{%- set _operator_topdown_in_circ_pct = (_operator_topdown_in_circ / _circ * 100) if _circ else 0 -%}
{%- set _operator_topdown_has_unminted = _implied_vs_alpha_ratio > 1.1 or _implied_vs_alpha_ratio < 0.9 -%}
{%- set _cex_pool_tokens = _cex_pool_ns.tokens -%}
{# v0.8.4.9.5: tail estimate — surf token-holders 通常返 19-100 个, 真实
   holders 数千. circ 中 operator + CEX + retail_top + vesting_unminted 覆盖
   外的部分 = 散户尾部 (top 100+ holders). 加进 retail 上界.

   v0.8.5.3: cex_fanout 67 recipients 平均 6 个在 top 100, 61 个在 tail.
   用户 review (CLO 2026-06-12): tail 含 fan-out recipients = 庄家藏的筹码
   不是散户. 计算 fan-out_in_tail = recipients NOT in top_holders 的 sum,
   作 庄家 tail 标识, 不算 retail. #}
{%- set _fanout_in_top_addrs_ns = namespace(set=[]) -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {% for _h in ((_thc.get(_cat) or {}).get('top') or []) -%}
        {% if (_h.addr or '')|lower in _fanout_recipient_addrs_ns.set -%}
          {%- set _fanout_in_top_addrs_ns.set = _fanout_in_top_addrs_ns.set + [(_h.addr or '')|lower] -%}
        {% endif -%}
      {% endfor -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{%- set _n_fanout_recipients_total = (_fanout_recipient_addrs_ns.set | list | length) -%}
{%- set _n_fanout_in_top = (_fanout_in_top_addrs_ns.set | list | unique | list | length) -%}
{%- set _n_fanout_in_tail = _n_fanout_recipients_total - _n_fanout_in_top -%}
{# v0.8.6.3: count surf top_holders returned (BSC primary), warn when < 30.
   BEAT case (2026-06-12): Alpha API 报 142k holders 但 surf BSC top 100
   只返 10 个 wallets (全是项目方). 速读 "op 100% / retail 0%" 看似离谱
   实际 surf 数据 thin, 散户 142k 个在 tail 不可见. 加 caveat. #}
{%- set _n_top_holders_returned_ns = namespace(n=0) -%}
{% for _cn, _cd in (_clp_for_locked or {}).items() -%}
  {%- set _thc = _cd.get('top_holders_classified', {}) if _cd is mapping else {} -%}
  {% if _thc and '_error' not in _thc and (not _primary_chain_for_classify or _cn == _primary_chain_for_classify) -%}
    {% for _cat in ['vesting', 'multisig', 'treasury', 'airdrop_platform', 'cex', 'lp', 'unclassified'] -%}
      {%- set _n_top_holders_returned_ns.n = _n_top_holders_returned_ns.n + (((_thc.get(_cat) or {}).get('top') or []) | length) -%}
    {% endfor -%}
  {% endif -%}
{% endfor -%}
{# 阈值 < 15: surf 通常返 20-30, BEAT-like thin case (< 15) 才触发 #}
{%- set _surf_top_thin = _n_top_holders_returned_ns.n < 15 and meta.get('alpha_holders') and meta.alpha_holders > 1000 -%}
{# fan-out tail 持仓估算: net_structured 减 overlap (in_top 部分已算 op_in_circ) #}
{%- set _fanout_tail_tokens = _cex_fanout_net - _fanout_overlap_ns.tokens if _cex_fanout_net > _fanout_overlap_ns.tokens else 0 -%}

{%- set _top_covered = _operator_topdown_in_circ + _cex_pool_tokens + _retail_topdown + _vest_unminted_ns.tokens -%}
{%- set _tail_estimate = (_circ - _top_covered) if _circ > _top_covered else 0 -%}
{%- set _retail_with_tail = _retail_topdown + _tail_estimate -%}
{%- set _retail_with_tail_pct = (_retail_with_tail / _circ * 100) if _circ else 0 -%}
{%- set _tail_pct = (_tail_estimate / _circ * 100) if _circ else 0 -%}
{%- set _cex_pool_n = _cex_pool_ns.n -%}
{%- set _cex_pool_pct = (_cex_pool_tokens / _circ * 100) if _circ else 0 -%}

{# v0.8.4.9.3: Cascade unminted-reserve absorption — 优先级 vesting_in_m6
   → vesting_out_m6 → multisig_out_m6 → m6 tree (minus vesting_in_m6).
   理由: vesting/multisig/m6 deployer 钱包都可能持已 mint 未 release supply
   (尤其 XCX m6 tree=129% / BTX multisig=374% case). 之前只减 vesting
   导致 disjoint 桶 raw > 100% 流通.
   优先级 from highest-likelihood-of-holding-unminted to lowest. #}
{%- set _u_step1 = _sa_ns.vesting_in_m6 if _sa_ns.vesting_in_m6 < _unminted_reserve_total else _unminted_reserve_total -%}
{%- set _u_rem1 = _unminted_reserve_total - _u_step1 -%}
{%- set _u_step2 = _sa_ns.vesting_out_m6 if _sa_ns.vesting_out_m6 < _u_rem1 else _u_rem1 -%}
{%- set _u_rem2 = _u_rem1 - _u_step2 -%}
{%- set _u_step3 = _sa_ns.multisig_out_m6 if _sa_ns.multisig_out_m6 < _u_rem2 else _u_rem2 -%}
{%- set _u_rem3 = _u_rem2 - _u_step3 -%}
{%- set _tree_minus_vest = (_tree_tok - _sa_ns.vesting_in_m6) if _tree_tok > _sa_ns.vesting_in_m6 else 0 -%}
{%- set _u_step4 = _tree_minus_vest if _tree_minus_vest < _u_rem3 else _u_rem3 -%}

{%- set _vesting_in_circ = _sa_ns.vesting_out_m6 - _u_step2 -%}
{%- set _multisig_tok = _sa_ns.multisig_out_m6 - _u_step3 -%}
{%- set _tree_in_circ = _tree_minus_vest - _u_step4 -%}
{% if _vesting_in_circ < 0 %}{%- set _vesting_in_circ = 0 %}{% endif -%}
{% if _multisig_tok < 0 %}{%- set _multisig_tok = 0 %}{% endif -%}
{% if _tree_in_circ < 0 %}{%- set _tree_in_circ = 0 %}{% endif -%}
{%- set _cex_operator_tok = _sa_ns.cex_operator_tok -%}
{%- set _cex_operator_n = _sa_ns.cex_operator_n -%}
{# v0.8.4.8: CEX 全归中性中转池, raw 加总不再含 _cex_operator_tok. #}
{%- set _operator_total_raw = _vesting_in_circ + _multisig_tok + _tree_in_circ + _operator_a2 + _lp_token_side + _other_op_tok + _mint_reserve_tok + _fake_mining_addr_minted + _suspected_tok -%}
{%- set _operator_total = _operator_total_raw if _operator_total_raw < _circ else _circ -%}
{%- set _retail_tok = (_circ - _operator_total_raw) if _circ and _operator_total_raw < _circ else 0 -%}
{%- set _retail_pct_circ = (_retail_tok / _circ * 100) if _circ else 0 -%}
{%- set _operator_pct_raw = (_operator_total_raw / _circ * 100) if _circ else 0 -%}
{%- set _has_bucket_leak = _operator_total_raw > _circ -%}
{#- v0.8.4.9: strip 前面累积的 jinja 块空白行 -#}
### {{ t("render.chip_h3") }}

{# v1.1.0 (CAP): multi-chain supply-overhang banner. When the Alpha listing is a
   MIRROR and the canonical supply lives on another chain, the buckets BELOW are
   only the Alpha-chain slice (CAP BSC 1.4%) and understate operator control. The
   banner surfaces the corrected 真实派发 measured on the canonical supply chain
   (operator/relay/non_operator % of circulating + locked overhang) so the reader
   sees the truth first. Headline (一屏结论) reads the same supply_chain_overhang
   buckets — parity. The Alpha-chain detail stays below, explicitly contextualised
   as the mirror slice. #}
{% if supply_chain_overhang is defined and supply_chain_overhang
      and supply_chain_overhang.get('split') and not supply_chain_overhang.get('_error')
      and supply_chain_overhang.get('operator_pct') is not none -%}
{{ t("render.chip_supply_overhang_banner",
      alpha_chain=(supply_chain_overhang.get('alpha_chain') or '')|upper,
      supply_chain=(supply_chain_overhang.get('supply_chain_label') or supply_chain_overhang.get('supply_chain') or ''),
      supply_pct="%.1f"|format(supply_chain_overhang.get('supply_pct_of_total') or 0),
      op="%.1f"|format(supply_chain_overhang.get('operator_pct') or 0),
      relay="%.1f"|format(supply_chain_overhang.get('relay_pct') or 0),
      nonop="%.1f"|format(supply_chain_overhang.get('non_operator_pct') or 0),
      locked="%.1f"|format(supply_chain_overhang.get('locked_pct_of_total') or 0)) }}

{# adversarial review CRIT#1: switch the 真实派发 speed-read + 3-bucket table to the
   canonical supply-chain buckets so the DETAIL matches the banner + the 一屏结论
   headline (parity). The single-chain Alpha-slice math above this point is
   discarded for the display; the raw sub-breakdown further below stays as the
   Alpha-chain raw reference (it is explicitly the listing-chain classification). #}
{%- set _circ = supply_chain_overhang.get('circulating_classified_tokens') or _circ -%}
{%- set _operator_topdown_in_circ_pct = supply_chain_overhang.get('operator_pct') or 0 -%}
{%- set _operator_topdown_in_circ = (_operator_topdown_in_circ_pct / 100.0) * _circ -%}
{%- set _cex_pool_pct = supply_chain_overhang.get('relay_pct') or 0 -%}
{%- set _cex_pool_tokens = (_cex_pool_pct / 100.0) * _circ -%}
{%- set _cex_pool_n = supply_chain_overhang.get('n_relay_cex') or 0 -%}
{%- set _retail_with_tail_pct = supply_chain_overhang.get('non_operator_pct') or 0 -%}
{%- set _retail_with_tail = (_retail_with_tail_pct / 100.0) * _circ -%}
{%- set _retail_topdown_pct = _retail_with_tail_pct -%}
{%- set _retail_topdown = _retail_with_tail -%}
{%- set _operator_topdown_has_unminted = false -%}
{%- set _tail_pct = 0.0 -%}
{%- set _n_fanout_in_tail = 0 -%}
{# adversarial review re-audit MED: the Alpha-slice raw sub-breakdown (_vesting_in_circ /
   _multisig_tok / _operator_total_raw …) is computed from the listing-chain
   buckets; dividing those Alpha token amounts by the now-canonical _circ would
   be a mixed denominator. Suppress the raw leak note + the <details> fold below
   when split (the canonical 3 buckets above are self-contained). #}
{%- set _has_bucket_leak = false -%}
{%- set _chip_is_supply_override = true -%}
{% endif -%}
{%- if _chip_is_supply_override is not defined -%}{%- set _chip_is_supply_override = false -%}{%- endif -%}

{# v0.8.4.8: 速读 3 个数字 — 庄家弹药 / 交易所中转池 / 可验证非庄家方抛压.
   交易所池中性 (散户 vs 项目方托管无法区分), 不并入任一侧. #}
> **{{ t("render.chip_speedread_prefix") }}**: {{ t("render.chip_speedread_circ", circ="%.1f"|format(_circ / 1_000_000)) }} · **{{ t("render.chip_nonop_pressure") }} {% if _circ %}{{ "%.1f"|format(_retail_with_tail_pct) }}%{% else %}—{% endif %}** ({{ "{:,.0f}".format(_retail_with_tail) }} tokens = {{ t("render.chip_top100_verifiable", pct="%.1f"|format(_retail_topdown_pct)) }}{% if _tail_pct > 0.1 %} + {{ t("render.chip_tail", pct="%.1f"|format(_tail_pct)) }}{% if _n_fanout_in_tail > 5 %} {{ t("render.chip_tail_fanout_warn", n=_n_fanout_in_tail) }}{% endif %}{% endif %}) · {{ t("render.chip_op_ammo") }} {% if _circ %}{{ "%.1f"|format(_operator_topdown_in_circ_pct) }}%{% else %}—{% endif %}{% if _operator_topdown_has_unminted %} {{ t("render.chip_op_ammo_unminted", alpha_circ="%.0f"|format(_circ_alpha / 1_000_000), chain_circ="%.0f"|format(_circ / 1_000_000), ratio="%.2f"|format(_implied_vs_alpha_ratio)) }}{% if _implied_vs_alpha_ratio < 0.9 %}{{ t("render.chip_op_ammo_overest") }}{% else %}{{ t("render.chip_op_ammo_underest") }}{% endif %}){% endif %} · {{ t("render.chip_cex_pool") }} {% if _circ %}{{ "%.1f"|format(_cex_pool_pct) }}%{% else %}—{% endif %} ({{ t("render.chip_cex_pool_n", n=_cex_pool_n) }}) · {{ t("render.chip_confirmed_realized", usd="{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd or 0), pct="%.1f"|format(dump_tracking.confirmed_total_pct or 0)) }}{% if (dump_tracking.confirmed_net_sellout_usd or 0) == 0 %} {{ t("render.chip_no_seller_detected") }}{% endif %}.

{# v0.8.6.8: 三桶 sanity check. 三桶 (op/cex/retail) 任一 = 0% 都不正常,
   说明数据 thin 或 detector 漏算. 自动加排查 banner. 用户 review
   (2026-06-12 BEAT v0.8.6.7): "庄家弹药 / 交易所 / 非庄家 都不太可能是 0,
   如果是 0 就要主动排查". #}
{%- set _zero_buckets = [] -%}
{% if _operator_topdown_in_circ_pct < 0.5 -%}
  {%- set _zero_buckets = _zero_buckets + ['op_ammo'] -%}
{% endif -%}
{% if _cex_pool_pct < 0.5 -%}
  {%- set _zero_buckets = _zero_buckets + ['cex_pool'] -%}
{% endif -%}
{% if _retail_with_tail_pct < 0.5 -%}
  {%- set _zero_buckets = _zero_buckets + ['nonop'] -%}
{% endif -%}
{% if _zero_buckets | length > 0 %}
> {{ t("render.chip_sanity_title") }}
{% for _b in _zero_buckets %}
> - **{{ t("render.chip_bucket_" + _b) }} 0%**: {% if _b == 'op_ammo' %}{{ t("render.chip_sanity_op_ammo") }}
{% elif _b == 'cex_pool' %}{{ t("render.chip_sanity_cex_pool") }}
{% elif _b == 'nonop' %}{{ t("render.chip_sanity_nonop", n=_n_top_holders_returned_ns.n, alpha_holders="{:,.0f}".format(meta.get('alpha_holders') or 0), tail_n=((meta.get('alpha_holders') or 0) - _n_top_holders_returned_ns.n) | int) }}
{% endif %}
{% endfor %}
{% endif %}
> {{ t("render.chip_pump_explainer") }}

{# v0.8.7.1: 筹码三分法主表 + 11 子桶 fold. ChatGPT review (2026-06-12):
   主表只显示 operator / cex / retail 三块 + 关键判断 3 句话, 子桶详情
   全部进 <details>. 不再让 raw 415% 第一眼吓用户. #}
| {{ t("render.chip_table_col_bucket") }} | {{ t("render.chip_table_col_tokens") }} | {{ t("render.chip_table_col_pct_circ") }} | {{ t("render.chip_table_col_interp") }} |
|---|---:|---:|---|
| {{ t("render.chip_row_operator") }} | **{{ "{:,.0f}".format(_operator_topdown_in_circ) }}** | {% if _circ %}**{{ "%.1f"|format(_operator_topdown_in_circ_pct) }}%**{% else %}—{% endif %} | {% if _operator_topdown_in_circ_pct >= 70 %}{{ t("render.chip_op_interp_high") }}{% elif _operator_topdown_in_circ_pct >= 40 %}{{ t("render.chip_op_interp_mid") }}{% else %}{{ t("render.chip_op_interp_low") }}{% endif %} |
| {{ t("render.chip_row_retail") }} | **{{ "{:,.0f}".format(_retail_with_tail) }}** | {% if _circ %}**{{ "%.1f"|format(_retail_with_tail_pct) }}%**{% else %}—{% endif %} | {% if _retail_with_tail_pct < 5 %}{{ t("render.chip_retail_interp_light") }}{% elif _retail_with_tail_pct < 20 %}{{ t("render.chip_retail_interp_mid") }}{% else %}{{ t("render.chip_retail_interp_heavy") }}{% endif %} {{ t("render.chip_retail_interp_note") }} |
| {{ t("render.chip_row_cex") }} | **{{ "{:,.0f}".format(_cex_pool_tokens) }}** | {% if _circ %}**{{ "%.1f"|format(_cex_pool_pct) }}%**{% else %}—{% endif %} | {{ t("render.chip_cex_interp", n=_cex_pool_n) }} |

### {{ t("render.chip_key_judgment_h3") }}

{% if _operator_topdown_in_circ_pct >= 70 and _retail_with_tail_pct < 10 %}{{ t("render.chip_judgment_high") }}
{% elif _operator_topdown_in_circ_pct >= 50 %}{{ t("render.chip_judgment_mid") }}
{% else %}{{ t("render.chip_judgment_low") }}
{% endif %}{% if _has_bucket_leak %}
{{ t("render.chip_raw_leak_note", raw="%.0f"|format(_operator_pct_raw), ammo="%.1f"|format(_operator_topdown_in_circ_pct)) }}
{% endif %}

{% if not _chip_is_supply_override -%}
<details>
<summary>{{ t("render.chip_details_summary") }}</summary>

| {{ t("render.chip_subbucket_col_name") }} | {{ t("render.chip_table_col_tokens") }} | {{ t("render.chip_subbucket_col_pct") }} | {{ t("render.chip_subbucket_col_note") }} |
|---|---:|---:|---|
| {{ t("render.chip_sb_1a") }} | {{ "{:,.0f}".format(_vesting_in_circ) }} | {% if _circ %}{{ "%.1f"|format(_vesting_in_circ / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_1a_note", reserve="{:,.0f}".format(_unminted_reserve_total)) }} |
| {{ t("render.chip_sb_1b") }} | {{ "{:,.0f}".format(_multisig_tok) }} | {% if _circ %}{{ "%.1f"|format(_multisig_tok / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_1b_note") }} |
| {{ t("render.chip_sb_2") }} | {{ "{:,.0f}".format(_tree_in_circ) }} | {% if _circ %}{{ "%.1f"|format(_tree_in_circ / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_2_note", tree="{:,.0f}".format(_tree_tok), locked="{:,.0f}".format(_sa_ns.vesting_in_m6), pure="{:,.0f}".format(_pure_tok)) }} |
{% if _a2_tok is not none and not _a2_stale %}| {{ t("render.chip_sb_3") }} | {{ "{:,.0f}".format(_a2_tok) }} | {% if _circ %}{{ "%.1f"|format(_a2_tok / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_3_note") }} |
{% elif _a2_stale or _a2_tok is none %}| {{ t("render.chip_sb_3_stale") }} | {% if _cfh_sum_top.total_cex_inflow_tokens %}{{ "{:,.0f}".format(_cfh_sum_top.total_cex_inflow_tokens) }}{% else %}—{% endif %} | — | {{ t("render.chip_sb_3_stale_note") }} {% if _cfh_sum_top.total_fanout_recipients %}{{ _cfh_sum_top.total_fanout_recipients }} fan-out recipients{% endif %} |
{% endif %}{% if _lp_token_side > 0 %}| {{ t("render.chip_sb_4") }} | {{ "{:,.0f}".format(_lp_token_side) }} | {% if _circ %}{{ "%.1f"|format(_lp_token_side / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_4_note") }} |
{% endif %}{% if _other_op_tok > 0 %}| {{ t("render.chip_sb_5") }} | {{ "{:,.0f}".format(_other_op_tok) }} | {% if _circ %}{{ "%.1f"|format(_other_op_tok / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_5_note", n=_other_op_n) }} |
{% endif %}{% if _mint_reserve_tok > 0 %}| {{ t("render.chip_sb_6") }} | {{ "{:,.0f}".format(_mint_reserve_tok) }} | {% if _circ %}{{ "%.1f"|format(_mint_reserve_tok / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_6_note") }} |
{% endif %}{% if _fake_mining_addr_minted > 0 %}| {{ t("render.chip_sb_6p") }} | {{ "{:,.0f}".format(_fake_mining_addr_minted) }} | {% if _circ %}{{ "%.1f"|format(_fake_mining_addr_minted / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_6p_note") }} |
{% endif %}{% if _suspected_tok > 0 %}| {{ t("render.chip_sb_6pp") }} | {{ "{:,.0f}".format(_suspected_tok) }} | {% if _circ %}{{ "%.1f"|format(_suspected_tok / _circ * 100) }}%{% else %}—{% endif %} | {{ t("render.chip_sb_6pp_note", n=_suspected_n) }} |
{% endif %}{% if _unminted_reserve_total > 0 %}| {{ t("render.chip_sb_unminted") }} | {{ "{:,.0f}".format(_unminted_reserve_total) }} | _{{ t("render.chip_sb_unminted_pct", pct="%.1f"|format(_unminted_reserve_total / (meta.total_supply or 1) * 100)) }}_ | {{ t("render.chip_sb_unminted_note") }} |
{% endif %}| ━━━━━ | ━━━━━ | ━━━━━ | ━━━━━ |
| {{ t("render.chip_sb_raw_total") }} | {{ "{:,.0f}".format(_operator_total_raw) }} | {% if _circ %}{{ "%.1f"|format(_operator_pct_raw) }}%{% else %}—{% endif %} | {% if _has_bucket_leak %}{{ t("render.chip_sb_raw_total_leak", ammo="%.1f"|format(_operator_topdown_in_circ_pct)) }}{% else %}{{ t("render.chip_sb_raw_total_noleak") }}{% endif %} |

**{{ t("render.chip_explainer_h") }}**:
- {{ t("render.chip_explainer_1") }}
- {{ t("render.chip_explainer_2") }}
- {{ t("render.chip_explainer_3") }}
- {{ t("render.chip_explainer_4") }}
- {{ t("render.chip_explainer_5") }}

</details>

#### {{ t("render.chip_nonop_detail_h4") }}

> {{ t("render.chip_nonop_detail_intro") }}

| {{ t("render.chip_nonop_col_n") }} | {{ t("render.chip_nonop_col_wallet") }} | {{ t("render.chip_nonop_col_balance") }} | {{ t("render.chip_nonop_col_pct") }} | {{ t("render.chip_nonop_col_type") }} | {{ t("render.chip_nonop_col_arkham") }} |
|---:|---|---:|---:|---|---|
{% set _CAT_ZH = {'vesting': t("render.chip_cat_vesting"), 'multisig': t("render.chip_cat_multisig"), 'treasury': t("render.chip_cat_treasury"), 'airdrop_platform': t("render.chip_cat_airdrop"), 'cex': t("render.chip_cat_cex"), 'lp': t("render.chip_cat_lp"), 'unclassified': t("render.chip_cat_unclassified")} %}
{% for _w in _retail_top_wallets[:20] %}| {{ loop.index }} | [`{{ _w.addr[:14] }}`](https://bscscan.com/address/{{ _w.addr }}) | {{ "{:,.0f}".format(_w.bal) }} | {{ "%.2f"|format(_w.bal / _circ * 100) if _circ else 0 }}% | {{ _CAT_ZH.get(_w.category, _w.category) }} | {{ _w.label or '—' }} |
{% endfor %}
{% if _retail_topdown_n > 20 %}| ... | {{ t("render.chip_nonop_remainder", n=(_retail_topdown_n - 20), tokens="{:,.0f}".format(_retail_topdown - (_retail_top_wallets[:20] | sum(attribute='bal')))) }} | | | | |
{% endif %}| ━━━━━━━━━━━━━━━━━ | ━━━━━━━━━━━━━━━━━ | ━━━━━━━━━ | ━━━━━━━ | ━━━━━━━━━ | ━━━━━━━━━ |
| **{{ t("render.chip_nonop_total_label") }}** | {{ t("render.chip_nonop_total_wallets", n=_retail_topdown_n) }} | **{{ "{:,.0f}".format(_retail_topdown) }}** | **{{ "%.1f"|format(_retail_topdown_pct) }}%** | — | — |

> {{ t("render.chip_nonop_nature_note") }}

{% set _24h_chg = meta.alpha_percent_change_24h or 0 %}
{% if _24h_chg > 30 and _retail_pct_circ > 40 %}> {{ t("render.chip_pump_mismatch", chg="%.0f"|format(_24h_chg), retail="%.0f"|format(_retail_pct_circ)) }}

{% endif %}{% endif %}---

{# v0.7.23.4: surface mining-fed wallet stock + flow directly in the
   dump_tracker table when funding_attribution.mining_fed_outflows produced
   data. mining-fed wallets ARE insiders in the operator sense (received
   tokens via mint contract → dumped via DEX); they should count toward
   tracked-wallet + holdings + (a)(b) rows rather than being relegated to
   a separate (c) row. _mfo / _mfo_sum aliases for compact template. #}
{% set _mfo = (funding_attribution.mining_fed_outflows
                if funding_attribution is defined and funding_attribution
                and funding_attribution.mining_fed_outflows is defined
                and funding_attribution.mining_fed_outflows
                else None) -%}
{% set _mfo_sum = (_mfo.summary if _mfo and _mfo.summary else None) -%}
{# v0.8.4.9.2: AOP cold-start case — mfo.summary is {} from pipeline
   when no mining-fed wallets found. Use .get() to avoid StrictUndefined. #}
{% set _mfo_n = (_mfo_sum.get('n_addrs') or 0) if _mfo_sum else 0 -%}
{% set _mfo_bal = (_mfo_sum.get('total_current_balance') or 0) if _mfo_sum else 0 -%}
{% set _mfo_sold = (_mfo_sum.get('total_dex_sold_tokens') or 0) if _mfo_sum else 0 -%}
{% set _mfo_sold_usd = (_mfo_sum.get('total_dex_sold_usd') or 0) if _mfo_sum else 0 -%}
{% set _mfo_swaps = (_mfo_sum.get('n_addrs_with_dex_sells') or 0) if _mfo_sum else 0 -%}
{# Jinja {% set %} inside {% for %} only mutates within loop scope; use
   namespace() to accumulate across iterations. v0.7.23.4 first revision
   had this bug → (b) showed "0 笔" instead of 10,569. #}
{% set _ns = namespace(swaps=0) -%}
{% if _mfo and _mfo.per_addr -%}
  {% for _k, _v in _mfo.per_addr.items() -%}
    {% set _ns.swaps = _ns.swaps + (_v.dex_sells.n_swaps or 0) -%}
  {%- endfor -%}
{%- endif -%}
{% set _mfo_n_total_swaps = _ns.swaps -%}
{# Floating-point cleanup: in - out completely balanced can yield ~-3e-8
   from numerical drift; clamp tiny |bal| to 0 so display reads cleanly. #}
{% set _mfo_bal_clamped = (0 if (_mfo_sum and ((_mfo_sum.get('total_current_balance') or 0) | abs) < 1) else ((_mfo_sum.get('total_current_balance') or 0) if _mfo_sum else 0)) -%}
{% set _has_mfo = _mfo_sum and (_mfo_sold > 0 or _mfo_bal > 0) -%}
{% set _ts = meta.total_supply if meta is defined and meta and meta.total_supply else 0 -%}
{# Use clamped balance for pct calc — keep tiny float noise out of display. #}
{% set _mfo_bal_eff = (0 if (_mfo_bal | abs) < 1 else _mfo_bal) -%}
{% set _mfo_bal_pct = (_mfo_bal_eff / _ts * 100) if (_ts and _has_mfo) else 0 -%}
{# v0.7.24a: mint authority dumps — same shape as mining_fed_outflows so
   we can augment the dump_tracker table in parallel. mint_authorities is
   a NEW concept (the contracts that mint, not the wallets that receive
   mint) so their dump is additive to mining_fed dump. #}
{% set _mad = (funding_attribution.mint_authority_dumps
                if funding_attribution is defined and funding_attribution
                and funding_attribution.mint_authority_dumps is defined
                and funding_attribution.mint_authority_dumps
                else None) -%}
{% set _mad_sum = (_mad.summary if _mad and _mad.summary else None) -%}
{# v0.8.4.9.2: AOP cold-start case — partial mad.summary dict #}
{% set _mad_n = (_mad_sum.get('n_addrs') or 0) if _mad_sum else 0 -%}
{% set _mad_bal = (_mad_sum.get('total_current_balance') or 0) if _mad_sum else 0 -%}
{% set _mad_bal_eff = (0 if (_mad_bal | abs) < 1 else _mad_bal) -%}
{% set _mad_sold = (_mad_sum.get('total_dex_sold_tokens') or 0) if _mad_sum else 0 -%}
{% set _mad_sold_usd = (_mad_sum.get('total_dex_sold_usd') or 0) if _mad_sum else 0 -%}
{% set _has_mad = _mad_sum and (_mad_sold > 0 or _mad_bal_eff > 0) -%}
{% set _ns_mad = namespace(swaps=0) -%}
{% if _mad and _mad.per_addr -%}
  {% for _k, _v in _mad.per_addr.items() -%}
    {% set _ns_mad.swaps = _ns_mad.swaps + (_v.dex_sells.n_swaps or 0) -%}
  {%- endfor -%}
{%- endif -%}
{% set _mad_n_swaps = _ns_mad.swaps -%}
{% set _mad_bal_pct = (_mad_bal_eff / _ts * 100) if (_ts and _has_mad) else 0 -%}
| {{ t("render.market_col_item") }} | {{ t("render.market_col_value") }} |
|---|---|
{# v0.8.4.9: 主数字用 m6 谱系 raw count (lineage.m6.rows|length) 跟下面
   m6 表/关键解读统一. 旧 dump_tracking.insider_n_wallets 排除 CEX/DEX
   infra 给出 48 当 secondary, footnote 解释口径差.
   矿币 case (JCT): m6 谱系空 → fallback 用 insider_standard. #}
{%- set _m6_raw_count_only = lineage.m6.rows | length if lineage is defined and lineage and lineage.m6 is defined else 0 -%}
{%- set _insider_standard = dump_tracking.insider_n_wallets + (_mfo_n if _has_mfo else 0) + (_mad_n if _has_mad else 0) -%}
{%- set _m6_raw_count = _m6_raw_count_only if _m6_raw_count_only > 0 else _insider_standard -%}
{% if _m6_raw_count_only > 0 %}| {{ t("render.dt_tracked_wallets_m6") }} | **{{ _m6_raw_count }}** ({{ t("render.dt_standard_insider", n=_insider_standard) }}{% if _has_mfo %} + **{{ t("render.dt_mining_fed", n=_mfo_n) }}**{% endif %}{% if _has_mad %} + **{{ t("render.dt_mint_authority", n=_mad_n) }}**{% endif %}{% if _m6_raw_count > _insider_standard %} + {{ t("render.dt_custody_dust", n=(_m6_raw_count - _insider_standard)) }}{% endif %}) |
{% else %}| {{ t("render.dt_tracked_wallets") }} | **{{ _insider_standard }}** ({{ t("render.dt_standard_insider", n=dump_tracking.insider_n_wallets) }}{% if _has_mfo %} + **{{ t("render.dt_mining_fed", n=_mfo_n) }}**{% endif %}{% if _has_mad %} + **{{ t("render.dt_mint_authority", n=_mad_n) }}**{% endif %}; {{ t("render.dt_no_m6_lineage") }}) |
{% endif %}
{# v0.7.19.4: defensive `.get()` access so the template renders cleanly
   against a pre-v0.7.19.4 skeleton.json (old skeletons only carry
   insider_holds_*, not the new split fields). `.get()` returns None on
   missing key (no StrictUndefined raise), and `is none` filters cleanly.
   `is defined` does NOT work for dict attribute presence under
   StrictUndefined — use `.get()` + `is not none`. #}
{% set _pure_pct = dump_tracking.get('pure_insider_holds_pct_supply') %}
{% set _pure_tok = dump_tracking.get('pure_insider_holds_tokens') %}
{% set _tree_pct = dump_tracking.get('tree_holds_pct_supply') %}
{% set _tree_tok = dump_tracking.get('tree_holds_tokens') %}
{% set _alias_pct = dump_tracking.get('insider_holds_pct_supply') %}
{% set _alias_tok = dump_tracking.get('insider_holds_tokens') %}
{# v0.7.23.4: 纯内幕 / 内幕树 augment with 挖矿机制取得钱包 current
   balance (stock). For mining-token model the mining-fed operators ARE
   the insider set; their unwound balance ≈ 0 means dumped clean, balance
   > 0 means still sitting on un-sold mint. #}
{% set _augmented_pure_tok = (_pure_tok or 0) + (_mfo_bal_eff if _has_mfo else 0) + (_mad_bal_eff if _has_mad else 0) -%}
{% set _augmented_pure_pct = (_pure_pct or 0) + _mfo_bal_pct + _mad_bal_pct -%}
{% if _pure_pct is not none or _has_mfo or _has_mad %}
| **{{ t("render.dt_pure_insider_label") }}** | **{{ t("render.dt_pure_insider_value", pct="%.4f"|format(_augmented_pure_pct), tokens="{:,.0f}".format(_augmented_pure_tok)) }}{% if _has_mfo %}{{ t("render.dt_pure_incl_mfo") }}{% endif %}{% if _has_mad %}{{ t("render.dt_pure_incl_mad") }}{% endif %}){% if _has_mfo and _mfo_bal_eff == 0 %} {{ t("render.dt_mfo_dumped_clean") }}{% elif _has_mfo and _mfo_bal_eff > 0 %} {{ t("render.dt_mfo_still_sit", tokens="{:,.0f}".format(_mfo_bal_eff)) }}{% endif %}{% if _has_mad and _mad_bal_eff == 0 %} {{ t("render.dt_mad_dumped_clean") }}{% elif _has_mad and _mad_bal_eff > 0 %} {{ t("render.dt_mad_still_sit", tokens="{:,.0f}".format(_mad_bal_eff)) }}{% endif %} |
{% endif %}
{% set _augmented_tree_tok = ((_tree_tok if _tree_tok is not none else (_alias_tok or 0))) + (_mfo_bal_eff if _has_mfo else 0) + (_mad_bal_eff if _has_mad else 0) -%}
{% set _augmented_tree_pct = ((_tree_pct if _tree_pct is not none else _alias_pct) or 0) + _mfo_bal_pct + _mad_bal_pct -%}
| {{ t("render.dt_tree_label") }} | {{ t("render.dt_tree_value", pct="%.4f"|format(_augmented_tree_pct), tokens="{:,.0f}".format(_augmented_tree_tok)) }}{% if _has_mfo or _has_mad %}{{ t("render.dt_tree_mining") }}{% if _has_mad %}{{ t("render.dt_tree_mining_mad") }}{% endif %}{{ t("render.dt_tree_mining_tail") }}{% else %}{{ t("render.dt_tree_standard") }}{% endif %}) |
{# v0.7.23.4: (a) CEX deposit row. Mining-fed wallets may also push to CEX;
   when we get destination labels from surf_labels_probe we can decompose
   top_destinations into CEX-deposit subset + DEX-router subset + unlabeled.
   v0.7.23.4 minimal: keep dump_tracker (a) figure (insider→CEX subset =
   0 for mining model where insider_addrs is empty), no augment here since
   we don't have CEX destination labels in mining_fed_outflows yet. #}
{# v0.7.24a.1: augment (a) CEX row with destination label evidence.
   destination_label_summary aggregates top destinations across mining-fed
   + mint-authority dumps and classifies via Arkham. If cex_deposit_tokens
   > 0 we add it to (a); otherwise we surface "verified 0" with the
   inline reasoning (operator chose DEX path, not CEX deposit).
   Eleve note: the CEX 提币 phase Eleve described is CEX → 钱包
   (off-chain side), opposite direction from (a) which tracks
   wallet → CEX. Off-chain CEX withdraws are structurally outside the
   on-chain forensic. #}
{% set _dest_sum = (funding_attribution.destination_label_summary
                    if funding_attribution is defined and funding_attribution
                    and funding_attribution.destination_label_summary is defined
                    else None) -%}
{% set _aug_cex_tok = (dump_tracking.confirmed_cex_tokens or 0) + (_dest_sum.cex_deposit_tokens if _dest_sum else 0) -%}
| {{ t("render.dt_row_a_label") }} | {{ "{:,.0f}".format(_aug_cex_tok) }}{% if dump_tracking.confirmed_cex_labels %} → {{ dump_tracking.confirmed_cex_labels|join(", ") | md_cell }}{% endif %}{% if _dest_sum and _dest_sum.cex_deposit_tokens > 0 %} {{ t("render.dt_row_a_incl_cex", tokens="{:,.0f}".format(_dest_sum.cex_deposit_tokens)) }}{% elif (_has_mfo or _has_mad) and _aug_cex_tok == 0 %} {{ t("render.dt_row_a_all_dex") }}{% endif %} |
{# Caveat: explain why this row might still understate vs Twitter forensic
   when the dump phase included CEX withdrawals (the reverse direction). #}
{% if (_has_mfo or _has_mad) %}
> {{ t("render.dt_row_a_caveat") }}
{% endif %}
{# v0.7.23.4: (b) DEX swap (本钱包) — 挖矿机制取得 wallets ARE 本钱包 in
   the operator-insider sense. Merge their dex_sells into (b) row instead
   of relegating to a separate (c) row (v0.7.23.3 design mistake — they're
   not a new category, they're the actual content of (b) for mining
   tokens). #}
{% set _augmented_dex_tok = dump_tracking.confirmed_dex_tokens + _mfo_sold + _mad_sold -%}
{% set _augmented_dex_swaps = dump_tracking.confirmed_dex_swaps + _mfo_n_total_swaps + _mad_n_swaps -%}
| {{ t("render.dt_row_b_label") }} | {{ "{:,.0f}".format(_augmented_dex_tok) }} ({{ t("render.dt_row_b_swaps", n="{:,}".format(_augmented_dex_swaps)) }}{% if _has_mfo and _mfo_sold > 0 %}{{ t("render.dt_row_b_mfo", tokens="{:,.0f}".format(_mfo_sold), swaps="{:,}".format(_mfo_n_total_swaps), usd="{:,.0f}".format(_mfo_sold_usd)) }}{% endif %}{% if _has_mad and _mad_sold > 0 %}{{ t("render.dt_row_b_mad", tokens="{:,.0f}".format(_mad_sold), swaps="{:,}".format(_mad_n_swaps), usd="{:,.0f}".format(_mad_sold_usd)) }}{% endif %}{% if _has_mfo or _has_mad %} {{ t("render.dt_row_b_via_dex") }}{% endif %}) |
| **{{ t("render.dt_gross_label") }}** | **{% if dump_tracking.confirmed_capped %}≈{% else %}≥{% endif %} {{ "{:,.0f}".format(dump_tracking.confirmed_total_tokens + _mfo_sold + _mad_sold) }}{% if dump_tracking.confirmed_total_pct is not none or _has_mfo or _has_mad %} {{ t("render.dt_gross_circ", pct="%.1f"|format((dump_tracking.confirmed_total_pct or 0) + ((((_mfo_sold + _mad_sold) / (meta.total_supply or 1)) * 100) if (meta.total_supply and (_has_mfo or _has_mad)) else 0))) }}{% else %} {{ t("render.dt_gross_circ_unknown") }}{% endif %}**{% if (dump_tracking.confirmed_est_profit_usd is not none) or _mfo_sold_usd > 0 or _mad_sold_usd > 0 %}, USD ≈ ${{ "{:,.0f}".format((dump_tracking.confirmed_est_profit_usd or 0) + _mfo_sold_usd + _mad_sold_usd) }}{% endif %} |
{# v0.7.21.10: 净卖出 row — apparatus' time-weighted estimate.
   Only render when the helper produced a value; on holder-snapshot chains
   (Solana) and dump_tracker failures the field is None and we skip. #}
{# v0.8.4.9.8: 净卖出 fallback — confirmed_net_sellout_usd 是 None (矿币 m6
   谱系空时), 用 ht_dumpers throughput 算只给参考 (不当真数, 含 wash). #}
{%- set _ht_dumpers_list = (funding_attribution.high_throughput_dumpers.dumpers if funding_attribution is defined and funding_attribution and funding_attribution.high_throughput_dumpers is defined and funding_attribution.high_throughput_dumpers else []) -%}
{%- set _ht_ns = namespace(total_out=0.0) -%}
{% for _d in (_ht_dumpers_list or []) -%}{%- set _ht_ns.total_out = _ht_ns.total_out + (_d.get('total_out') or 0) -%}{% endfor -%}
{%- set _ht_median_px = dump_tracking.get('median_price_usd') or 0 -%}
{%- set _ht_throughput_usd = _ht_ns.total_out * _ht_median_px if _ht_median_px else 0 -%}
| **{{ t("render.dt_net_label") }}** | {% if dump_tracking.get('confirmed_net_sellout_usd') is not none %}**${{ "{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd) }}**{% if dump_tracking.get('apparatus_dex_twap_usd_per_token') is not none %} {{ t("render.dt_net_twap", twap="%.4g"|format(dump_tracking.apparatus_dex_twap_usd_per_token)) }}{% endif %}{% if dump_tracking.get('confirmed_dex_real_usd') is not none and dump_tracking.get('confirmed_cex_estimated_usd') is not none %}{{ t("render.dt_net_dex_cex", dex_usd="{:,.0f}".format(dump_tracking.confirmed_dex_real_usd), cex_usd="{:,.0f}".format(dump_tracking.confirmed_cex_estimated_usd)) }}{% endif %}{% if dump_tracking.get('net_above_gross_pct') is not none and dump_tracking.net_above_gross_pct > 5 %} {{ t("render.dt_net_above_gross", pct="%.0f"|format(dump_tracking.net_above_gross_pct)) }}{% endif %}{% else %}{{ t("render.dt_net_unreliable", tokens="{:,.0f}".format(_ht_ns.total_out), circ_x="%.1fx"|format(_ht_ns.total_out / (meta.circulating_supply or 1))) }}{% endif %} |

{% if dump_tracking.confirmed_capped %}
> {{ t("render.dt_capped_note") }}
{% endif %}

{# v0.9.2: per-window 时间窗拆分 — EmberCN-style 短期 alarm 对账. SQL
   CASE WHEN 取 7d/30d/累计 三个窗口, 0 额外 surf credit. 累计 = dump
   tracker 用的 date_floor (老 token surf_safe 364d, 新 token listing
   date). #}
{% set _has_window = dump_tracking.get('confirmed_net_sellout_usd_7d') is not none or dump_tracking.get('confirmed_total_tokens_7d') %}
{% if _has_window %}

> {{ t("render.dt_window_intro") }}

| {{ t("render.dt_window_col_window") }} | {{ t("render.dt_window_col_gross") }} | {{ t("render.dt_window_col_pct") }} | {{ t("render.dt_window_col_net") }} | {{ t("render.dt_window_col_dex") }} | {{ t("render.dt_window_col_cex") }} |
|---|---:|---:|---:|---:|---:|
| **{{ t("render.dt_window_7d") }}** | {{ "{:,.0f}".format(dump_tracking.get('confirmed_total_tokens_7d') or 0) }} | {% if dump_tracking.get('confirmed_total_pct_7d') is not none %}{{ "%.2f"|format(dump_tracking.confirmed_total_pct_7d) }}%{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_net_sellout_usd_7d') is not none %}**${{ "{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd_7d) }}**{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_dex_real_usd_7d') is not none %}${{ "{:,.0f}".format(dump_tracking.confirmed_dex_real_usd_7d) }}{% else %}—{% endif %} | {{ "{:,.0f}".format(dump_tracking.get('confirmed_cex_tokens_7d') or 0) }} |
| {{ t("render.dt_window_30d") }} | {{ "{:,.0f}".format(dump_tracking.get('confirmed_total_tokens_30d') or 0) }} | {% if dump_tracking.get('confirmed_total_pct_30d') is not none %}{{ "%.2f"|format(dump_tracking.confirmed_total_pct_30d) }}%{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_net_sellout_usd_30d') is not none %}${{ "{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd_30d) }}{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_dex_real_usd_30d') is not none %}${{ "{:,.0f}".format(dump_tracking.confirmed_dex_real_usd_30d) }}{% else %}—{% endif %} | {{ "{:,.0f}".format(dump_tracking.get('confirmed_cex_tokens_30d') or 0) }} |
| {{ t("render.dt_window_cumulative") }} | {{ "{:,.0f}".format(dump_tracking.confirmed_total_tokens or 0) }} | {% if dump_tracking.confirmed_total_pct is not none %}{{ "%.2f"|format(dump_tracking.confirmed_total_pct) }}%{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_net_sellout_usd') is not none %}${{ "{:,.0f}".format(dump_tracking.confirmed_net_sellout_usd) }}{% else %}—{% endif %} | {% if dump_tracking.get('confirmed_dex_real_usd') is not none %}${{ "{:,.0f}".format(dump_tracking.confirmed_dex_real_usd) }}{% else %}—{% endif %} | {{ "{:,.0f}".format(dump_tracking.get('confirmed_cex_tokens') or 0) }} |

> {{ t("render.dt_window_explainer") }}

{% endif %}

{# v0.8.3: 隐藏庄家弹药的历史动作 — 用 hidden_operator_activity probe 跑
   (a)/(b) 同算法但 input 集合换 suspected_operator_reserve +
   fake_mining_cluster_member 钱包. 只在有变现行为时显示 (避免噪音).
   v0.8.3.1 audit fixes:
   - HIGH #2: 用 .get() 不直接 .attr, 避免 partial dict 触发 StrictUndefined
   - MED #3: 叠加 claim 软化, 加 "需扣除重叠" 注解
   - MED #4: USD 算法 source 注明 (hidden_own_dex / m6_insider_twap)
   - LOW #7: 时间窗用实际 date_floor, 不写"365d"
#}
{% set _hoa = hidden_operator_activity if hidden_operator_activity is defined else None %}
{% set _hoa_n = (_hoa.get('n_hidden_wallets_tracked') if _hoa else 0) or 0 %}
{% set _hoa_total = (_hoa.get('confirmed_total_tokens') if _hoa else 0) or 0 %}
{% set _hoa_err = (_hoa.get('_error') if _hoa else None) %}
{% set _hoa_floor = (_hoa.get('date_floor') if _hoa else None) %}
{% if _hoa and _hoa_total > 0 %}{% set _hoa_src = _hoa.get('confirmed_est_usd_source') or 'none' %}
> {{ t("render.hoa_observed_prefix", n=_hoa_n, cex_tokens="{:,.0f}".format(_hoa.confirmed_cex_tokens), n_cex=_hoa.n_distinct_cex_destinations, cex_brands=(_hoa.cex_destination_brands | join(", ") if _hoa.cex_destination_brands else "—"), dex_tokens="{:,.0f}".format(_hoa.confirmed_dex_tokens), n_swaps=_hoa.n_dex_swaps, total="{:,.0f}".format(_hoa_total)) }}{% if _hoa.confirmed_total_pct_circ is not none %} {{ t("render.hoa_pct_circ", pct="%.2f"|format(_hoa.confirmed_total_pct_circ)) }}{% endif %}{% if _hoa.confirmed_est_usd %}, USD ≈ **${{ "{:,.0f}".format(_hoa.confirmed_est_usd) }}**{% if _hoa_src == 'hidden_own_dex' %} {{ t("render.hoa_usd_src_own_dex") }}{% elif _hoa_src == 'hidden_own_dex_only' %} {{ t("render.hoa_usd_src_own_dex_only") }}{% elif _hoa_src == 'm6_insider_twap' %} {{ t("render.hoa_usd_src_m6_twap") }}{% endif %}{% endif %}. {{ t("render.hoa_observed_tail") }}{% if _hoa_floor %} {{ t("render.hoa_time_window", floor=_hoa_floor) }}{% endif %}
{% elif _hoa and _hoa_n > 0 and not _hoa_err %}
> {{ t("render.hoa_none_prefix", n=_hoa_n) }} **{% if _hoa_floor %}{{ t("render.hoa_none_since", floor=_hoa_floor) }}{% else %}{{ t("render.hoa_none_window") }}{% endif %}{{ t("render.hoa_none_tail") }}**{{ t("render.hoa_none_accumulating") }}
{% elif _hoa and _hoa_err %}
> {{ t("render.hoa_err", err=(_hoa_err | md_cell)) }}
{% endif %}
{# v0.7.23.3: distinguish mining-token mode from real surf failure inside
   the dump_tracker section body. _dq_mining_model is computed at the top
   of the template; reuse it here so the in-section banner doesn't mislead
   the reader with "surf 失败 重跑" when the actual issue is that the
   token's distribution model bypasses rule_11 (and the (c) row above
   shows what we recovered via the mining-fed path). #}
{% if dump_tracking.buckets_complete == false %}
{% if _dq_mining_model %}
> {{ t("render.dt_mining_model_note_prefix") }} ({% if _mfo_sum and _mfo_sum.total_dex_sold_usd > 0 %}{{ t("render.dt_mining_model_note_usd", usd="{:,.0f}".format(_mfo_sum.total_dex_sold_usd)) }}{% else %}{{ t("render.dt_mining_model_note_seedetail") }}{% endif %}). {{ t("render.dt_mining_model_note_norerun") }}
{% else %}
> {{ t("render.dt_incomplete_note") }}
{% endif %}
{% endif %}
{% if dump_tracking.wash_dominated %}
> {{ t("render.dt_wash_dominated_note", n_sellers=dump_tracking.n_dex_sellers, total_swaps="{:,}".format(dump_tracking.total_dex_swaps), top_swaps="{:,}".format(dump_tracking.top_seller_swaps)) }}
{% endif %}

{% endif %}

<a id="section-recent-anomaly"></a>
## {{ t("render.risk_signal_h2") }}

### {{ t("section.anomaly.detector_summary_h3") }}

| {{ t("section.anomaly.detector_table_header_emoji") }} | {{ t("section.anomaly.detector_table_header_label") }} | {{ t("section.anomaly.detector_table_header_count") }} | {{ t("section.anomaly.detector_table_header_detail") }} |
|---|---|---|---|
{% for d in anomaly.detector_summary %}| {{ d.emoji }} | {{ d.label | md_cell }} | {{ d.count }} | {{ d.detail | md_cell }} |
{% endfor %}

### {{ t("section.anomaly.rhythm_h3") }}

**{{ anomaly.rhythm.title | md_cell }}**

{% for w in anomaly.rhythm.waves -%}
- {{ w.name | md_cell }} ({{ w.ts_text | md_cell }}): {{ w.detail | md_cell }}
{% endfor %}

{# v0.7.25: hide 异常.verdict_impact (LLM-filled). 同 判定.one_liner
   原因 — LLM 填的文案含 "触发 EXIT_IF_HOLDING" / "建议..." 类交易判断词,
   违反 "no advice" 约束. 检测器汇总 + 节奏识别表已 确定性 给出
   全部链上事实数字, verdict_impact 段不增加 链上侦测价值. v0.7.26+
   会用 确定性 behavior_classifier 输出替代. #}

{# v0.7.22 P0 #3: 完整异动事件列表默认折叠 (散户 不会逐行读). 顶部加 1 行
   汇总 让 散户 看到分波统计; 详细 evt_xxx 表 click 展开. #}
<details{% if mode == 'deep' %} open{% endif %}>
<summary>📂 <strong>{{ t("section.anomaly.title") }}</strong> — {% set _ev_ns = namespace(n=0) %}{% for w in anomaly.waves %}{% set _ev_ns.n = _ev_ns.n + (w.events|length) %}{% endfor %}{{ t("render.anomaly_summary", n_waves=anomaly.waves|length, n_events=_ev_ns.n) }}</summary>

{% for wave in anomaly.waves %}
### {{ wave.emoji }} {{ wave.title | md_cell }} ({{ wave.ts_range | md_cell }}, **{{ wave.status_text | md_cell }}**)

| {{ t("section.anomaly.table_header_evt") }} | {{ t("section.anomaly.table_header_utc") }} | {{ t("section.anomaly.table_header_ago") }} | {{ t("section.anomaly.table_header_from_to") }} | {{ t("section.anomaly.table_header_nature") }} | {{ t("section.anomaly.table_header_amount") }} |
|---|---|---|---|---|---|
{% for ev in wave.events %}| `{{ ev.evt_ref }}` | {{ ev.ts | md_cell }} | {{ ev.hours_ago_text | md_cell }} | {{ ev.from_to | md_cell }} | {{ ev.nature | md_cell }} | {{ ev.amount | md_cell }} |
{% endfor %}

{% endfor %}

</details>

{# v0.7.16: detector_summary + rhythm + verdict_impact moved up to
   "📊 风险信号聚合" right after 真实派发, so traders see aggregated risk
   signals next to the verdict, not buried under the events dump. #}

## {{ t("section.multi_chain.title") }}

| {{ t("section.multi_chain.table_header_item") }} | {{ t("section.multi_chain.table_header_value") }} |
|---|---|
{% for row in multi_chain.rows %}| {{ row.item | md_cell }} | {{ row.value | md_cell }} |
{% endfor %}

{{ multi_chain.gate_note | md_cell }}

**{{ t("section.multi_chain.interpretation_label") }}**: {{ multi_chain.interpretation | md_cell }}

## {{ t("section.tge.title") }}

| {{ t("section.tge.table_header_anchor") }} | {{ t("section.tge.table_header_utc") }} | {{ t("section.tge.table_header_price") }} | {{ t("section.tge.table_header_vs_current") }} |
|---|---|---|---|
{% for row in tge.rows %}| {{ row.label | md_cell }} | {{ row.time | md_cell }} | {{ row.price | md_cell }} | {{ row.vs_current | md_cell }} |
{% endfor %}

**{{ t("section.multi_chain.interpretation_label") }}**: {{ tge.interpretation | md_cell }}

<a id="section-alloc"></a>
## {{ t("section.alloc.title") }}

| {{ t("section.alloc.table_header_item") }} | {{ t("section.alloc.table_header_value") }} | {{ t("section.alloc.table_header_source") }} |
|---|---|---|
{% for row in alloc.rows %}| {{ row.item | md_cell }} | {{ row.value | md_cell }} | {{ row.source | md_cell }} |
{% endfor %}

**{{ t("section.multi_chain.interpretation_label") }}**: {{ alloc.interpretation | md_cell }}

{# v0.7.16: 🔴 真实派发 moved up to right after 判定 — see top of report. #}
## {{ t("section.cex_trace.title") }}

| {{ t("section.cex_trace.table_header_exchange") }} | {{ t("section.cex_trace.table_header_status") }} | {{ t("section.cex_trace.table_header_ts") }} | {{ t("section.cex_trace.table_header_since") }} |
|---|---|---|---|
{% for row in cex_trace.rows %}| {{ row.exchange | md_cell }} | {{ row.status | md_cell }} | {{ row.ts | md_cell }} | {{ row.since | md_cell }} |
{% endfor %}

{{ cex_trace.new_catalyst | md_cell }}. {{ cex_trace.tier_explanation | md_cell }}.

**{{ t("section.multi_chain.interpretation_label") }}**: {{ cex_trace.interpretation | md_cell }}

<a id="section-liq"></a>
## {{ t("section.liq.title") }}

| {{ t("section.liq.table_header_anchor") }} | {{ t("section.liq.table_header_value") }} | {{ t("section.liq.table_header_note") }} |
|---|---|---|
{% for row in liq.rows %}| {{ row.anchor | md_cell }} | {{ row.value | md_cell }} | {{ row.note | md_cell }} |
{% endfor %}

**{{ t("section.multi_chain.interpretation_label") }}**: {{ liq.interpretation | md_cell }}

{# v0.7.16: verdict / decision_anchors / decision_action_block moved up to
   right after 决策摘要 — see top of report. #}
<a id="section-holdings"></a>
## {{ t("section.holdings.title") }}

{# v0.7.21.6: detect "Alpha API totalSupply 滞后 / inflationary token" case.
   OLAS surfaced this — its top-50 holders sum 504.97M > Alpha-API-reported
   473.48M total_supply, producing a per-role pct > 100% that confused
   users. When the sum of all role balances exceeds the locked total_supply
   by > 5%, banner a warning before the bars so the reader knows the % is
   a Alpha-snapshot artefact, not a real overflow. #}
{% set _alpha_supply = meta.total_supply if meta is defined and meta and meta.total_supply else 0 %}
{# Jinja2 gotcha: variables set inside {% for %} are scoped to the loop
   and disappear after; using `namespace()` lets us mutate across iterations. #}
{% set ns = namespace(holders_sum=0) %}
{% for row in holdings_distribution.role_rows %}{% set ns.holders_sum = ns.holders_sum + (row.total_balance or 0) %}{% endfor %}
{% if _alpha_supply and ns.holders_sum > _alpha_supply * 1.05 %}
> {{ t("render.holdings_inflationary_banner", holders_sum="{:,.0f}".format(ns.holders_sum), alpha_supply="{:,.0f}".format(_alpha_supply), pct="%.2f"|format(ns.holders_sum / _alpha_supply * 100)) }}

{% endif %}
{# v0.8.0.4 methodology fix: ASCII bar chart was rendered inside ```...```
   code block with `{%- for` newline-stripping = all bars collapsed
   onto one unreadable line. User explicitly asked for table form.
   The "持仓分布表" below already presents the same data in clean
   markdown table form; dropping the ASCII chart avoids both redundancy
   and the {% for newline bug. Future re-introduction of a visual
   chart should use markdown table or embedded image, not pre-block
   ASCII art (the latter is unrenderable on monospace-stripping
   viewers like GitHub mobile / Notion). #}
{{ t("section.holdings.table_h3") }}:

| {{ t("section.holdings.table_header_role") }} | {{ t("section.holdings.table_header_n_wallets") }} | {{ t("section.holdings.table_header_balance") }} | {{ t("section.holdings.table_header_pct") }} | {{ t("section.holdings.table_header_top_wallet") }} |
|---|---|---|---|---|
{% for row in holdings_distribution.role_rows %}| {{ row.role_label | md_cell }} | {{ row.n_wallets }} | {{ "{:,.0f}".format(row.total_balance) }} | {{ "%.4f"|format(row.pct_of_total) if row.pct_of_total else "—" }}% | {% if row.top_addr_full %}[`{{ row.top_addr_short | md_cell }}`]({{ explorer_url(row.top_addr_full) }}){% else %}—{% endif %} |
{% endfor %}

{{ t("section.holdings.key_takeaways_h3") }}:
{# v0.8.4.9: 用 render-time 真实 m6 raw count, 不用 LLM key_takeaways
   (LLM 数 43+5+1=49 漏 2 个 vesting custody / dust wallet, 跟下面表里
   51 行 m6_xxx 对不上). 真实 = lineage.m6.rows|length. #}
{%- set _m6_total = lineage.m6.rows | length if lineage is defined and lineage and lineage.m6 is defined else 0 -%}
{%- set _dt_safe = dump_tracking if dump_tracking is defined and dump_tracking else {} -%}
{%- set _tree_pct = (_dt_safe.get('tree_holds_pct_supply') or 0) -%}
{%- set _net_sellout_usd = (_dt_safe.get('confirmed_net_sellout_usd') or 0) -%}
{%- set _sell_pct_circ = (_dt_safe.get('confirmed_total_pct') or 0) -%}
{%- set _wash_summary = (wash_infrastructure.get('summary') if wash_infrastructure is defined and wash_infrastructure else None) -%}
{%- set _wash_share_pct = ((_wash_summary.get('top_bot_share') or 0) * 100) if _wash_summary else 0 -%}
{%- set _m6_other_top = _m6_total - _m6_full - _m6_partial - _m6_quiet -%}
{# v0.8.4.9.1: 矿币 fallback (JCT 类) — m6 谱系空时关键解读用 insider_standard 数字 #}
{% if _m6_total > 0 %}- {{ t("render.holdings_takeaway_m6", total=_m6_total, tree_pct="%.1f"|format(_tree_pct), full=_m6_full, partial=_m6_partial, quiet=_m6_quiet) }}{% if _m6_other_top > 0 %} {{ t("render.holdings_takeaway_m6_other", n=_m6_other_top) }}{% endif %}.
{% else %}- {{ t("render.holdings_takeaway_mining", n=_insider_standard, tree_pct="%.1f"|format(_tree_pct)) }}{% if _has_mfo %}{{ t("render.holdings_takeaway_mining_mfo", n=_mfo_n) }}{% endif %}{% if _has_mad %}{{ t("render.holdings_takeaway_mining_mad", n=_mad_n) }}{% endif %} {{ t("render.holdings_takeaway_mining_tail") }}
{% endif %}
- {{ t("render.holdings_takeaway_outflow", usd="{:,.1f}".format(_net_sellout_usd / 1_000_000), pct="%.2f"|format(_sell_pct_circ)) }}
{% if _wash_share_pct > 0 %}- {{ t("render.holdings_takeaway_wash", pct="%.1f"|format(_wash_share_pct)) }}
{% endif %}

{# v0.7.22 P0 #3: lineage 谱系默认折叠. 散户 不需要逐行看 41 个内幕钱包,
   汇总 行给"项目方 → N 个一级钱包 + N 已分完 / N 分发中 / N 潜伏"概要. #}
<details{% if mode == 'deep' %} open{% endif %}>
<summary>📂 <strong>{{ t("section.lineage.title") }}</strong> — {{ t("render.lineage_summary", n=lineage.m6.rows|length, full=lineage.m6.n_full_dumper or 0, partial=lineage.m6.n_partial_dumper or 0, quiet=lineage.m6.n_quiet or 0) }}</summary>

{{ t("section.lineage.table_h3") }}:

| {{ t("section.lineage.table_header_id") }} | {{ t("section.lineage.table_header_addr") }} | {{ t("section.lineage.table_header_recv") }} | {{ t("section.lineage.table_header_balance") }} | {{ t("section.lineage.table_header_dumped") }} |
|---|---|---|---|---|
{% for r in lineage.m6.rows %}| `{{ r.m6_ref }}` | [`{{ r.addr_short | md_cell }}`]({{ explorer_url(r.addr_full) }}) | {{ "{:,.0f}".format(r.received_from_deployer) }} | {{ "{:,.0f}".format(r.current_balance) if r.current_balance is not none else "—" }} | {{ ("%.1f"|format(r.dumped_pct) ~ "%") if r.dumped_pct is not none else "—" }} |
{% endfor %}

{%- set _m6_total_lineage = lineage.m6.rows | length -%}
{%- set _m6_other = _m6_total_lineage - (lineage.m6.n_quiet or 0) - (lineage.m6.n_partial_dumper or 0) - (lineage.m6.n_full_dumper or 0) -%}
_{{ t("render.lineage_stats", total=_m6_total_lineage, quiet=lineage.m6.n_quiet or 0, partial=lineage.m6.n_partial_dumper or 0, full=lineage.m6.n_full_dumper or 0) }}{% if _m6_other > 0 %}{{ t("render.lineage_stats_other", n=_m6_other) }}{% endif %}_

{# v0.8.4.9.1: m4_notes 是 LLM fill 生成, 可能含跟 v0.8.4.9 数字统一
   口径不符的 wallet count (老 fill 写 49 vs 真实 51). render-time
   regex 替换"N 个内幕钱包"为 hardcoded _m6_total_lineage. #}
{{ t("section.lineage.m4_notes_h3") }}:
{% for n in lineage.m4_notes %}
- {{ (n | md_cell) | regex_replace('\\d+ 个内幕钱包', (_m6_total_lineage|string) + ' 个内幕钱包') | regex_replace('\\d+ 个内幕地址', (_m6_total_lineage|string) + ' 个内幕地址') }}
{% endfor %}

{# v0.9.6 Fix #3 (adversarial review Windows EVAA 2026-06-15 feedback): surface
   step4 dumpers skipped due to chunk errors. Pre-v0.9.6 these were
   only logged to stderr; users had no in-report signal that part of
   the trace was incomplete. The skip itself is correct (any chunk
   error → drop dumper to avoid undercount), but silently losing data
   without showing it in the report violates the "user knows what's
   in vs out" principle. #}
{# v0.9.6 Fix #3: guard with `.get(..., 0)` so old fixtures / skeletons
   missing the field render cleanly. #}
{%- set _n_step4_skipped = (lineage.get('n_step4_skipped_dumpers', 0) if lineage is mapping else 0) or 0 -%}
{% if _n_step4_skipped > 0 %}

{{ t("render.step4_gap_intro", n=_n_step4_skipped) }}
{% for sd in lineage.get('step4_skipped_dumpers', []) %}
- [`{{ sd.addr[:10] }}…`]({{ explorer_url(sd.addr) }}) — d{{ sd.depth }} — {{ sd.errored_chunks }}/{{ sd.total_chunks }} chunks errored
{% endfor %}
_{{ t("render.step4_gap_action") }}_
{% endif %}

{# v0.9.7 adversarial review R1 Finding 6 (HIGH): step4 budget-cap truncation. When
   the dispersal tree is wider than MAX_PROMOTED_SUBDUMPERS (default 12),
   the largest N sub-dumpers are expanded + the rest skipped. The verdict
   is then a LOWER BOUND — disclose the skipped count + aggregate token
   size so the reader knows the operator tree is under-counted (NOT a
   surf failure — an intentional budget cap; rerun with
   BINANCE_ALPHA_STEP4_MAX_DUMPERS=40 for full depth). #}
{%- set _n_cap_skipped = (lineage.get('n_sub_dumpers_skipped', 0) if lineage is mapping else 0) or 0 -%}
{%- set _cap_skipped_tokens = (lineage.get('n_sub_dumpers_skipped_tokens', 0) if lineage is mapping else 0) or 0 -%}
{% if _n_cap_skipped > 0 %}

{{ t("render.step4_cap_intro", n=_n_cap_skipped, tokens="{:,.0f}".format(_cap_skipped_tokens)) }}
_{{ t("render.step4_cap_action") }}_
{% endif %}

</details>

{# v0.8.4.9: cross_sym 段整段删除. 用户 review (2026-06-11): 抓到的多是
   router / MEV bot / 套利 bot, 真"跨币种庄家"罕见 (< 5%). 用户决策
   不依赖此段. cross_sym_registry refresh 也从 pipeline disable.
   节省 ~30 credits/run + cold-start 190 credits (7 天 TTL). #}
{# v0.8.4.9.9: wash_infra 段整段删除. 用户 review (2026-06-11): Alpha 类
   token 默认含 wash, 用户 expect, "对敲占 X%" 数字对决策无价值. 庄家
   筹码状况 / 内幕变现 / mint_authority 持仓全跟 wash 无关. 节省
   ~350 credits/token (~70% wash budget) ≈ $1.75. detector 也从
   pipeline disable. 跟 v0.8.4.9 删 flow_operators + cross_sym 同 pattern. #}
{# v0.8.4.9: flow_operators 段整段删除. 用户 review (2026-06-11): 实际
   抓到的 wallet 多是 PancakeSwap router 上的 MEV / sandwich bot (单一
   签名 + 高频 router 交互 + 0 持仓), 不是项目方操盘, 对用户决策无价值.
   real "跨币种 operator" case 占比 < 5%. detector 也从 pipeline disable. #}
{# audit M2 fix: render gate must fire on error / skipped state too,
   otherwise surf-failed / Solana-skipped runs silently drop the entire
   section and retail loses the failure banner. The inner branches handle
   error / skipped / has-data dispatch. #}
{% if funding_attribution is defined and funding_attribution and funding_attribution.get('summary') %}
{% set _fa = funding_attribution %}
{% set _fa_sum = _fa.summary %}
{% if (_fa_sum.get('n_addrs_with_data') or 0) > 0 or _fa.get('_error') or _fa.get('_skipped') %}
{# v0.7.23.1: reverse-direction funding source attribution table. Surfaces
   the high-value addresses with their mint% vs dex_buy% vs p2p% so the
   reader can tell mining-fed wallets (= operators / sockpuppet airdrop
   farms) apart from dex-fed wallets (= real retail buyers). Works the
   same for standard deployer-anchored tokens and for mining / bridge /
   airdrop tokens where rule_11's standard m6 trace returns empty. #}
## {{ t("section.funding_attribution.title") }}

{# v0.8.0.2 render fix — same as wash_infra/flow_operators above. #}
{{ t("section.funding_attribution.how_to_read") | safe }}

{% if _fa.get('_error') %}
> {{ t("render.fa_error", err=(_fa._error | md_cell), n=_fa_sum.n_addrs_queried) }}

{% elif _fa.get('_skipped') %}
> {{ t("render.fa_skipped", reason=(_fa._skipped | md_cell)) }}

{% else %}
> {{ t("section.funding_attribution.summary_line", n_queried=_fa_sum.n_addrs_queried, n_data=_fa_sum.n_addrs_with_data, n_mining=_fa_sum.n_mining_fed, n_dex=_fa_sum.n_dex_fed, n_p2p=_fa_sum.n_p2p_fed) }}

{# audit M3 fix: ratio threshold instead of absolute count. The
   intent is "mining is the dominant funding mode" — for a 6-addr token
   3/6 mining-fed (50%) should warn; for a 60-addr token 5/60 (8%) should
   not. Threshold: mining-fed share of addr-with-data ≥ 30%. #}
{% set _ratio = (_fa_sum.n_mining_fed * 1.0) / (_fa_sum.n_addrs_with_data) if _fa_sum.n_addrs_with_data else 0 %}
{% if _ratio >= 0.30 %}
> {{ t("render.fa_mining_dominant", n_mining=_fa_sum.n_mining_fed, n_data=_fa_sum.n_addrs_with_data, pct="%.0f"|format(_ratio * 100)) }}
{% endif %}

| {{ t("section.funding_attribution.col_addr") }} | {{ t("section.funding_attribution.col_role") }} | {{ t("section.funding_attribution.col_total") }} | {{ t("section.funding_attribution.col_mint_pct") }} | {{ t("section.funding_attribution.col_dex_pct") }} | {{ t("section.funding_attribution.col_p2p_pct") }} |
|---|---|---:|---:|---:|---:|
{% set _ns = namespace(rows=0) %}
{% for _addr, _v in (_fa.attributions.items() | sort(attribute='1.total', reverse=true)) %}
{% if _v.total > 0 and _ns.rows < 30 %}
{% set _ns.rows = _ns.rows + 1 %}
| [`{{ _addr[:10] }}…`]({{ explorer_url(_addr) }}) | {{ t("section.funding_attribution.primary_label." + (_v.primary_source or 'unknown')) }} | {{ "{:,.0f}".format(_v.total) }} | {% if _v.mint_pct is not none %}{{ "%.1f"|format(_v.mint_pct * 100) }}%{% else %}—{% endif %} | {% if _v.dex_buy_pct is not none %}{{ "%.1f"|format(_v.dex_buy_pct * 100) }}%{% else %}—{% endif %} | {% if _v.p2p_pct is not none %}{{ "%.1f"|format(_v.p2p_pct * 100) }}%{% else %}—{% endif %} |
{% endif %}
{% endfor %}

{% if _fa._debug and (_fa._debug.get('sql_truncated_addr_n') or _fa._debug.get('pipeline_truncated_n')) %}
> _{{ t("render.fa_scan_cap", total=(_fa._debug.pipeline_input_total if _fa._debug.get('pipeline_input_total') else (_fa_sum.n_addrs_queried + (_fa._debug.get('sql_truncated_addr_n') or 0))), queried=_fa_sum.n_addrs_queried, truncated=(_fa._debug.get('pipeline_truncated_n') or _fa._debug.get('sql_truncated_addr_n') or 0)) }}_
{% endif %}

> _{{ t("render.fa_cex_withdraw_note") }}_

{# v0.7.23.2: mining-fed wallets' actual DEX dump + top outflow destinations.
   This is the data dump_tracker (a)(b) would have produced if rule_11's
   m6 trace had been populated; for mining/bridge tokens (rule_11 m6 empty)
   the dump signal lives here instead. #}
{% if _fa.mining_fed_outflows is defined and _fa.mining_fed_outflows and _fa.mining_fed_outflows.get('per_addr') %}
{% set _mfo = _fa.mining_fed_outflows %}
{% set _mfo_sum = _mfo.summary %}

### {{ t("render.mfo_h3") }}

{% if _mfo.get('_error') %}
> {{ t("render.mfo_error", err=(_mfo._error | md_cell)) }}

{% else %}
> {{ t("render.mfo_intro", n=_mfo.per_addr | length, sold_tokens="{:,.0f}".format(_mfo_sum.total_dex_sold_tokens), sold_usd="{:,.0f}".format(_mfo_sum.total_dex_sold_usd), outflow="{:,.0f}".format(_mfo_sum.total_outflow_tokens)) }}

{% for _addr, _v in (_mfo.per_addr.items() | sort(attribute='1.dex_sells.sold_usd', reverse=true)) %}
{% if _v.dex_sells.sold_usd > 0 or _v.total_outflow_tokens > 0 %}
**[`{{ _addr[:14] }}…`]({{ explorer_url(_addr) }})** —
{% if _v.dex_sells.sold_usd > 0 %} {{ t("render.mfo_addr_sold", tokens="{:,.0f}".format(_v.dex_sells.tokens_sold), swaps="{:,}".format(_v.dex_sells.n_swaps), usd="{:,.0f}".format(_v.dex_sells.sold_usd)) }}{% else %} {{ t("render.mfo_addr_no_sell") }}{% endif %}.
{% if _v.top_destinations %} {{ t("render.mfo_top_outflow") }}
{% for _d in _v.top_destinations %}
> - [`{{ _d.dest[:14] }}…`]({{ explorer_url(_d.dest) }}) ← {{ "{:,.0f}".format(_d.amt) }} tokens {{ t("render.dest_n_tx", n=_d.n_tx) }}{% if _d.arkham_entity_name %} · 🏷️ **{{ _d.arkham_entity_name | md_cell }}**{% if _d.arkham_label %} ({{ _d.arkham_label | md_cell }}){% endif %}{% elif _d.arkham_label %} · 🏷️ {{ _d.arkham_label | md_cell }}{% endif %}
{% endfor %}
{% endif %}

{% endif %}
{% endfor %}
{% endif %}{# end mfo _error branch #}
{% endif %}{# end mining_fed_outflows defined #}

{# v0.7.24a: 🌉 Bridge / Mint Authority self-dump subsection. Parallel to
   ⛏️ Mining-fed: mint authorities are the bridge/staking/airdrop contracts
   that physically issue new supply (receive from 0x0). They are missed by
   mining-fed pathway because they DON'T receive from anyone — they ARE the
   mint source. For H: 0x6aa22cb8 minted 132.5B (1325% nominal supply!)
   and self-DEX-dumped 19.8B over 30d, fully invisible until v0.7.24a. #}
{% if _fa.mint_authorities is defined and _fa.mint_authorities and _fa.mint_authorities.get('authorities') %}
{% set _mauth = _fa.mint_authorities %}
{% set _mauth_sum = _mauth.summary %}
{% set _mad = _fa.mint_authority_dumps if _fa.mint_authority_dumps is defined else None %}
{% set _mad_sum = _mad.summary if _mad and _mad.summary else None %}

<a id="section-bridge-mint"></a>
### {{ t("render.mauth_h3") }}

{% if _mauth.get('_error') %}
> {{ t("render.mauth_error", err=(_mauth._error | md_cell)) }}

{% else %}
> {{ t("render.mauth_intro", n=_mauth_sum.n_authorities) }}

{% set _ns_mauth = namespace(rows=0) %}
| {{ t("render.mauth_col_addr") }} | {{ t("render.mauth_col_arkham") }} | {{ t("render.mauth_col_mint") }} | {{ t("render.mauth_col_pct") }} | {{ t("render.mauth_col_selfdex") }} | USD ≈ |
|---|---|---:|---:|---|---:|
{% for _a in _mauth.authorities %}
{% if not _a.is_excluded and _ns_mauth.rows < 10 %}
{% set _ns_mauth.rows = _ns_mauth.rows + 1 %}
{% set _v = _mad.per_addr.get(_a.addr) if _mad and _mad.per_addr else None %}
| [`{{ _a.addr[:14] }}…`]({{ explorer_url(_a.addr) }}) | {% if _a.arkham_entity_name %}{{ _a.arkham_entity_name | md_cell }}{% if _a.arkham_label %} ({{ _a.arkham_label | md_cell }}){% endif %}{% elif _a.arkham_label %}{{ _a.arkham_label | md_cell }}{% else %}_{{ t("render.label_unlabeled_new") }}{% endif %} | {{ "{:,.0f}".format(_a.total_minted) }} | {% if _a.mint_pct_supply is not none %}{{ "%.2f"|format(_a.mint_pct_supply) }}%{% else %}—{% endif %} | {% if _v and _v.dex_sells.n_swaps > 0 %}{{ t("render.mauth_dex_swaps", tokens="{:,.0f}".format(_v.dex_sells.tokens_sold), swaps="{:,}".format(_v.dex_sells.n_swaps)) }}{% else %}{{ t("render.mauth_no_selfdex") }}{% endif %} | {% if _v and _v.dex_sells.sold_usd > 0 %}**${{ "{:,.0f}".format(_v.dex_sells.sold_usd) }}**{% else %}—{% endif %} |
{% endif %}
{% endfor %}

{% if _mauth_sum.total_minted_aggregate > meta.total_supply %}
> {{ t("render.mauth_inflationary", minted="{:,.0f}".format(_mauth_sum.total_minted_aggregate), supply="{:,.0f}".format(meta.total_supply)) }}
{% endif %}

{% if _mad_sum and _mad_sum.total_dex_sold_usd > 0 %}
> {{ t("render.mauth_selfdex_summary", tokens="{:,.0f}".format(_mad_sum.total_dex_sold_tokens), usd="{:,.0f}".format(_mad_sum.total_dex_sold_usd)) }}
{% endif %}

{# Per-authority top destinations — keep brief, only show authorities with
   meaningful DEX self-dump activity #}
{% if _mad and _mad.per_addr %}
{% for _addr, _v in (_mad.per_addr.items() | sort(attribute='1.dex_sells.sold_usd', reverse=true)) %}
{% if _v.dex_sells.sold_usd > 0 and _v.top_destinations %}

**[`{{ _addr[:14] }}…`]({{ explorer_url(_addr) }})** {{ t("render.mauth_selfdex_per_addr", usd="{:,.0f}".format(_v.dex_sells.sold_usd)) }}
{% for _d in _v.top_destinations[:3] %}
> - [`{{ _d.dest[:14] }}…`]({{ explorer_url(_d.dest) }}) ← {{ "{:,.0f}".format(_d.amt) }} tokens {{ t("render.dest_n_tx", n=_d.n_tx) }}{% if _d.arkham_entity_name %} · 🏷️ **{{ _d.arkham_entity_name | md_cell }}**{% if _d.arkham_label %} ({{ _d.arkham_label | md_cell }}){% endif %}{% elif _d.arkham_label %} · 🏷️ {{ _d.arkham_label | md_cell }}{% endif %}
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}
{% endif %}{# end mint_authorities _error branch #}
{% endif %}{# end mint_authorities defined #}

{# v0.7.24b: 🌊 High-throughput dump trace — operator wallets that ingested
   a meaningful allocation (1M-5% nominal supply) and cleared out (balance
   ≈ 0) via >= 1000 txs. Catches the sss_crypto Twitter thread profile
   (0x47a6e4e1: 30M / 79k tx cleared) which all v0.7.23.x detectors miss
   (60d window flow_operators / inflated balance threshold mining-fed /
   wash_infra not atomic). Already-labeled infra (DEX_POOL / CEX_HOT) is
   filtered upstream in forensic_pipeline. #}
{% if _fa.high_throughput_dumpers is defined and _fa.high_throughput_dumpers and _fa.high_throughput_dumpers.get('dumpers') %}
{% set _htd = _fa.high_throughput_dumpers %}
{% set _htd_sum = _htd.summary %}

<a id="section-high-throughput"></a>
### {{ t("render.htd_h3") }}

{% if _htd.get('_error') %}
> {{ t("render.htd_error", err=(_htd._error | md_cell)) }}

{% else %}
> {{ t("render.htd_intro", n=_htd_sum.n_dumpers) }}

{# v0.7.28 selective dedupe: if a dumper's primary_role is NOT
   high_throughput_operator (i.e. it lives in CEX fan-out hub or
   mint authority as primary), show a compact cross-link row with
   key metrics (balance / throughput) instead of the full operator
   detail row. This trims ~15-20% off JCT-class reports where ~3-5
   HT entries are also fan-out hubs that already have full cards
   in the fan-out section. address_role_index lookup is O(1). #}
{% set _ari = address_role_index | default({}) %}
{% set _ns_htd = namespace(rows=0, dedup=0) %}
| {{ t("render.htd_col_addr") }} | {{ t("render.htd_col_role") }} | {{ t("render.mauth_col_arkham") }} | {{ t("render.htd_col_in") }} | {{ t("render.htd_col_out") }} | {{ t("render.htd_col_balance") }} | {{ t("render.htd_col_ntx") }} |
|---|---|---|---:|---:|---:|---:|
{% for _d in _htd.dumpers %}
{% if not _d.get('is_excluded') and not _d.get('is_infra') and _ns_htd.rows < 20 %}
{% set _ns_htd.rows = _ns_htd.rows + 1 %}
{% set _addr_lower = (_d.addr or '') | lower %}
{% set _ari_e = _ari.get(_addr_lower) %}
{% set _is_primary_here = (not _ari_e) or (_ari_e.primary_role == 'high_throughput_operator') %}
{% if _is_primary_here %}| [`{{ _d.addr[:14] }}…`]({{ explorer_url(_d.addr) }}) | {{ t("render.htd_role_primary") }} | {% if _d.get('arkham_entity_name') %}{{ _d.arkham_entity_name | md_cell }}{% if _d.get('arkham_label') %} ({{ _d.arkham_label | md_cell }}){% endif %}{% elif _d.get('arkham_label') %}{{ _d.arkham_label | md_cell }}{% else %}_{{ t("render.label_unlabeled_eoa") }}{% endif %} | {{ "{:,.0f}".format(_d.total_in) }} | {{ "{:,.0f}".format(_d.total_out) }} | {{ "{:,.0f}".format(_d.balance) }} | {{ "{:,}".format(_d.n_tx) }} |
{% else %}{% set _ns_htd.dedup = _ns_htd.dedup + 1 %}| [`{{ _d.addr[:14] }}…`]({{ explorer_url(_d.addr) }}) | [{{ t("render.htd_role_seeprimary", label=(_ari_e.primary_section_label_zh | md_cell)) }}](#{{ _ari_e.primary_section_anchor }}) | _{{ t("render.htd_dedupe") }}_ | {{ "{:,.0f}".format(_d.total_in) }} | _{{ t("render.htd_see_primary") }}_ | {{ "{:,.0f}".format(_d.balance) }} | {{ "{:,}".format(_d.n_tx) }} |
{% endif %}
{% endif %}
{% endfor %}
{% if _ns_htd.dedup > 0 %}

> _{{ t("render.htd_dedup_note", n=_ns_htd.dedup) }}_
{% endif %}

{% if _htd_sum.n_dumpers > 20 %}
> _{{ t("render.htd_top20_note", n=_htd_sum.n_dumpers) }}_
{% endif %}

> {{ t("render.htd_footer", throughput="{:,.0f}".format(_htd_sum.total_throughput)) }}

{% endif %}{# end high_throughput _error branch #}
{% endif %}{# end high_throughput_dumpers defined #}

{# v0.7.24e: 🎯 CEX 提币 大规模分发 控筹 detection. sss_crypto Twitter thread
   profile (BEAT 2026-05-21: Gate hot wallet → 1 hub → 10 sub-wallets each
   0.1%+ supply, designed to disperse top100 concentration signal). The hub
   pattern: 5-50 fan-out recipients each receiving ≥ 100K tokens, where the
   hub's biggest sender is Arkham-confirmed CEX_DEPOSIT / CEX_HOT_WALLET. #}
{% if _fa.cex_fanout_hubs is defined and _fa.cex_fanout_hubs and _fa.cex_fanout_hubs.get('hubs') %}
{% set _cfh = _fa.cex_fanout_hubs %}
{% set _cfh_sum = _cfh.summary %}

<a id="section-cex-fanout"></a>
### {{ t("render.cfh_h3") }}

{% if _cfh.get('_error') %}
> {{ t("render.cfh_error", err=(_cfh._error | md_cell)) }}

{% else %}
> {{ t("render.cfh_intro", n=_cfh_sum.n_confirmed_hubs) }}

> {{ t("render.cfh_threshold", n_candidate=_cfh_sum.n_candidate_hubs, n_confirmed=_cfh_sum.n_confirmed_hubs) }}

{% if _cfh_sum.net_structured_fanout_tokens_total is defined or _cfh_sum.net_fanout_tokens_total is defined %}{% set _net_total = _cfh_sum.net_structured_fanout_tokens_total if _cfh_sum.net_structured_fanout_tokens_total is defined else _cfh_sum.net_fanout_tokens_total %}{% set _net_recip = _cfh_sum.net_structured_unique_recipients if _cfh_sum.net_structured_unique_recipients is defined else _cfh_sum.net_fanout_unique_recipients %}
> {{ t("render.cfh_net_total_prefix", tokens="{:,.0f}".format(_net_total)) }}{% if meta.circulating_supply and meta.circulating_supply > 0 %} {{ t("render.cfh_pct_circ", pct="%.2f"|format(_net_total / meta.circulating_supply * 100)) }}{% endif %}{% if meta.total_supply and meta.total_supply > 0 %} {{ t("render.cfh_pct_supply", pct="%.2f"|format(_net_total / meta.total_supply * 100)) }}{% endif %} {{ t("render.cfh_net_total_tail", n=_net_recip) }}

{% endif %}{% for _h in _cfh.hubs %}

#### {{ t("render.cfh_hub_h4") }} [`{{ _h.addr[:14] }}…`]({{ explorer_url(_h.addr) }})

| {{ t("render.field_label") }} | {{ t("render.field_value") }} |
|---|---|
| {{ t("render.cfh_field_cex_source") }} | **{{ _h.cex_source_entity or _h.cex_source_label or _h.cex_source }}** ({{ _h.cex_source_classification }}) — [`{{ _h.cex_source[:14] }}…`]({{ explorer_url(_h.cex_source) }}) |
| {{ t("render.cfh_field_cex_inflow") }} | **{{ "{:,.0f}".format(_h.cex_source_inflow_tokens) }} tokens** ({{ t("render.cfh_n_tx", n=_h.cex_source_n_tx) }}) |
| {{ t("render.cfh_field_recipients") }} | {{ t("render.cfh_field_recipients_val", n=_h.n_recipients) }} |
{% if _h.net_fanout_tokens is defined %}| **{{ t("render.cfh_field_net") }}** | **{{ "{:,.0f}".format(_h.net_fanout_tokens) }} tokens**{% if meta.circulating_supply and meta.circulating_supply > 0 %} {{ t("render.cfh_pct_circ", pct="%.2f"|format(_h.net_fanout_tokens / meta.circulating_supply * 100)) }}{% endif %}{% if meta.total_supply and meta.total_supply > 0 %} {{ t("render.cfh_pct_supply_paren", pct="%.2f"|format(_h.net_fanout_tokens / meta.total_supply * 100)) }}{% endif %} {{ t("render.cfh_net_recipients", n=_h.net_fanout_recipients) }} |
{% if _h.loopback_to_cex_tokens > 0 %}| {{ t("render.cfh_field_loopback") }} | {{ t("render.cfh_field_loopback_val", tokens="{:,.0f}".format(_h.loopback_to_cex_tokens)) }} |
{% endif %}{% if _h.inter_hub_shuffle_tokens > 0 %}| {{ t("render.cfh_field_shuffle") }} | {{ t("render.cfh_field_shuffle_val", tokens="{:,.0f}".format(_h.inter_hub_shuffle_tokens)) }} |
{% endif %}| {{ t("render.cfh_field_phase1_deprecated") }} | ~~{{ "{:,.0f}".format(_h.total_out_tokens) }} tokens~~ {{ t("render.cfh_phase1_deprecated_note") }} |
{% else %}| {{ t("render.cfh_field_phase1_broken") }} | **{{ "{:,.0f}".format(_h.total_out_tokens) }} tokens** {{ t("render.cfh_phase1_broken_val", avg="{:,.0f}".format(_h.avg_per_recipient), min="{:,.0f}".format(_h.min_per_recipient)) }} |
{% endif %}

**{{ t("render.cfh_recipients_h", n=_h.top_recipients | length) }}**:

| {{ t("render.cfh_recip_col_wallet") }} | {{ t("render.cfh_recip_col_received") }} | n_tx |
|---|---:|---:|
{% for _r in _h.top_recipients %}| [`{{ _r.addr[:14] }}…`]({{ explorer_url(_r.addr) }}) | {{ "{:,.0f}".format(_r.amt) }} | {{ _r.n_tx }} |
{% endfor %}

{% endfor %}

> _{{ t("render.cfh_retail_note") }}_
{% endif %}{# end cex_fanout _error branch #}
{% endif %}{# end cex_fanout_hubs defined #}

{# v0.7.24c: 🔗 Multi-chain dump trace. For tokens deployed on multiple
   chains (H = BSC + Ethereum), surface per-chain mint authorities + high-
   throughput dumpers from the OTHER chains. Catches Eleve's H finding:
   0x9e995952 on Ethereum dumped 140M H. Primary chain (= the one whose
   results are in the main funding_attribution body) is not repeated here. #}
{% if _fa.multi_chain is defined and _fa.multi_chain %}

### {{ t("render.mc_h3") }}

> {{ t("render.mc_intro", chain=meta.chain) }}

{% for _chain_name, _mc in _fa.multi_chain.items() %}

#### 🔗 {{ _chain_name | upper }} (CA: [`{{ _mc.ca[:14] }}…`]({{ explorer_url(_mc.ca) }}))

{% if _mc.get('_error') %}
> {{ t("render.mc_chain_error", chain=_chain_name, err=(_mc._error | md_cell)) }}

{% elif _mc.get('_skipped') %}
> {{ t("render.mc_chain_skipped", chain=_chain_name, reason=(_mc._skipped | md_cell)) }}

{% else %}
{% set _mc_auth = _mc.mint_authorities %}
{% set _mc_ht = _mc.high_throughput_dumpers %}
{% set _mc_auth_sum = _mc_auth.summary if _mc_auth else None %}
{% set _mc_ht_sum = _mc_ht.summary if _mc_ht else None %}

{% if _mc_auth_sum and _mc_auth_sum.n_authorities > 0 %}
**{{ t("render.mc_auth_h", n=_mc_auth_sum.n_authorities, minted="{:,.0f}".format(_mc_auth_sum.total_minted_aggregate)) }}**

{% set _ns_mc_auth = namespace(rows=0) %}
| {{ t("render.mauth_col_addr") }} | {{ t("render.mauth_col_arkham") }} | {{ t("render.mc_auth_col_mint") }} | {{ t("render.mauth_col_pct") }} |
|---|---|---:|---:|
{% for _a in _mc_auth.authorities %}
{% if not _a.is_excluded and _ns_mc_auth.rows < 5 %}
{% set _ns_mc_auth.rows = _ns_mc_auth.rows + 1 %}
| [`{{ _a.addr[:14] }}…`]({{ explorer_url(_a.addr) }}) | {% if _a.get('arkham_entity_name') %}{{ _a.arkham_entity_name | md_cell }}{% if _a.get('arkham_label') %} ({{ _a.arkham_label | md_cell }}){% endif %}{% elif _a.get('arkham_label') %}{{ _a.arkham_label | md_cell }}{% else %}_{{ t("render.label_unlabeled") }}{% endif %} | {{ "{:,.0f}".format(_a.total_minted) }} | {% if _a.mint_pct_supply is not none %}{{ "%.2f"|format(_a.mint_pct_supply) }}%{% else %}—{% endif %} |
{% endif %}
{% endfor %}
{% endif %}

{% if _mc_ht_sum and _mc_ht_sum.n_dumpers > 0 %}
**{{ t("render.mc_ht_h", n=_mc_ht_sum.n_dumpers, throughput="{:,.0f}".format(_mc_ht_sum.total_throughput)) }}**

{% set _ns_mc_ht = namespace(rows=0) %}
| {{ t("render.htd_col_addr") }} | {{ t("render.mauth_col_arkham") }} | {{ t("render.mc_ht_col_in") }} | {{ t("render.htd_col_balance") }} | n_tx |
|---|---|---:|---:|---:|
{% for _d in _mc_ht.dumpers %}
{% if not _d.get('is_excluded') and not _d.get('is_infra') and _ns_mc_ht.rows < 10 %}
{% set _ns_mc_ht.rows = _ns_mc_ht.rows + 1 %}
| [`{{ _d.addr[:14] }}…`]({{ explorer_url(_d.addr) }}) | {% if _d.get('arkham_entity_name') %}{{ _d.arkham_entity_name | md_cell }}{% if _d.get('arkham_label') %} ({{ _d.arkham_label | md_cell }}){% endif %}{% elif _d.get('arkham_label') %}{{ _d.arkham_label | md_cell }}{% else %}_{{ t("render.label_unlabeled") }}{% endif %} | {{ "{:,.0f}".format(_d.total_in) }} | {{ "{:,.0f}".format(_d.balance) }} | {{ "{:,}".format(_d.n_tx) }} |
{% endif %}
{% endfor %}
{% endif %}

{% if (not _mc_auth_sum or _mc_auth_sum.n_authorities == 0) and (not _mc_ht_sum or _mc_ht_sum.n_dumpers == 0) %}
> _{{ t("render.mc_no_detection") }}_
{% endif %}
{% endif %}{# end _mc._error / _skipped #}

{% endfor %}

> _{{ t("render.mc_footer") }}_
{% endif %}{# end multi_chain defined #}

{% endif %}{# end _fa._error / _skipped branches #}
{% endif %}{# end render gate (data-or-error-or-skipped) #}
{% endif %}{# end funding_attribution defined #}

{# v0.8.6.7: wallet_cluster_graph 单独段 — Bubblemaps-style cluster
   detector. 显示项目方 wallet ↔ wallet 直接转账形成的 cluster (非 CEX
   route / 非 mint route / 非 m6 lineage). v0.8.6.5.0 detector 已跑,
   但之前没单独段, 用户看不到具体 cluster wallets 是哪些. 现在加. #}
{% if wallet_cluster_graph is defined and wallet_cluster_graph
      and (wallet_cluster_graph.get('clusters') or []) %}
<a id="section-wallet-cluster-graph"></a>
## {{ t("render.wcg_h2") }}

> {{ t("render.wcg_intro") }}

{%- set _wcg_sum = wallet_cluster_graph.get('summary') or {} -%}
| {{ t("render.wcg_col_metric") }} | {{ t("render.field_value") }} |
|---|---|
| {{ t("render.wcg_n_clusters") }} | **{{ _wcg_sum.get('n_clusters') or 0 }}** |
| {{ t("render.wcg_n_cluster_addrs") }} | **{{ _wcg_sum.get('n_cluster_addrs_total') or 0 }}** |
| {{ t("render.wcg_n_candidates") }} | {{ _wcg_sum.get('n_candidates_input') or 0 }} |
| {{ t("render.wcg_n_filtered_l1") }} | {{ _wcg_sum.get('n_filtered_by_l1') or 0 }} |
| {{ t("render.wcg_n_edges") }} | {{ _wcg_sum.get('n_edges_total') or 0 }} |
| {{ t("render.wcg_n_new") }} | {{ _wcg_sum.get('n_new_in_op_union') or 0 }} |
| {{ t("render.wcg_n_chunks") }} | {{ _wcg_sum.get('n_chunks_run') or 0 }} |

{% for _c in (wallet_cluster_graph.get('clusters') or []) %}
#### {{ t("render.wcg_cluster_h4", n=loop.index, wallets=_c.get('addrs') | length) }}

| {{ t("render.field_label") }} | {{ t("render.field_value") }} |
|---|---|
| {{ t("render.wcg_cluster_wallets") }} | {{ t("render.wcg_n_wallets", n=_c.get('addrs') | length) }} |
| {{ t("render.wcg_cluster_edges") }} | {{ _c.get('n_edges') }} |
| {{ t("render.wcg_total_weight") }} | {{ "{:,.0f}".format(_c.get('total_weight_tokens') or 0) }} tokens |
| {{ t("render.wcg_max_edge") }} | {{ "{:,.0f}".format(_c.get('max_edge_weight_tokens') or 0) }} tokens |
| {{ t("render.wcg_cluster_balance") }} | {{ "{:,.0f}".format(_c.get('cluster_balance_total_tokens') or 0) }} tokens |
| Arkham UNLABELED % | {{ "%.0f"|format(_c.get('arkham_unlabeled_pct') or 0) }}% |
{% if _c.get('time_window_days') is not none %}| {{ t("render.wcg_time_window") }} | {{ t("render.wcg_time_window_val", days=_c.get('time_window_days'), min_t=_c.get('min_block_time'), max_t=_c.get('max_block_time')) }} |
{% endif %}{% if _c.get('source_overlap_counts') %}| {{ t("render.wcg_source_dist") }} | {% for _s, _n in _c.get('source_overlap_counts').items() %}{{ _s }}: {{ _n }}{% if not loop.last %}, {% endif %}{% endfor %} |
{% endif %}

**{{ t("render.wcg_wallets_h") }}**:

| {{ t("render.wcg_wallet_col_n") }} | {{ t("render.cfh_recip_col_wallet") }} | {{ t("render.wcg_wallet_col_balance") }} |
|---:|---|---:|
{% for _a in (_c.get('addrs') or [])[:30] %}| {{ loop.index }} | [`{{ _a[:14] }}`]({{ explorer_url(_a) }}) | {{ "{:,.0f}".format((_c.get('addr_balances') or {}).get(_a) or 0) }} |
{% endfor %}{% if _c.get('addrs') | length > 30 %}| ... | {{ t("render.wcg_remainder", n=(_c.get('addrs') | length - 30)) }} | |
{% endif %}

{% endfor %}
{% endif %}
<a id="section-monitoring"></a>
## {{ t("section.monitoring.title") }}

{# v0.7.27 monitoring_ranker summary — 4-tier level tally from
   deterministic Python score formula. Helps retail prioritize the
   paste.json entries (CRITICAL > HIGH > NORMAL > NOT_TRACKED) instead
   of treating 50+ addresses as equal-weight. NOT_TRACKED hidden by
   default (infra / public CEX). See helpers/monitoring_ranker.py for
   formula + ChatGPT v0.8 spec section 4. #}
{% if monitoring_summary is defined and monitoring_summary and monitoring_summary.level_counts %}
{% set _lc = monitoring_summary.level_counts %}
{% set _critical_n = _lc.get("CRITICAL") or 0 %}
{% set _high_n = _lc.get("HIGH") or 0 %}
{% set _normal_n = _lc.get("NORMAL") or 0 %}
{% set _nottracked_n = _lc.get("NOT_TRACKED") or 0 %}
{% set _active_n = _critical_n + _high_n + _normal_n %}

> {{ t("render.mon_priority_line1", critical=_critical_n, high=_high_n, normal=_normal_n) }}{% if _nottracked_n > 0 %} {{ t("render.mon_priority_nottracked", n=_nottracked_n) }}{% endif %}
>
> {{ t("render.mon_priority_line2", critical_high=(_critical_n + _high_n), normal=_normal_n) }}

{% endif %}
{% if monitoring_wallets|length > 10 -%}
_{{ t("render.mon_top10_note", n=monitoring_wallets|length) }}_
{% endif %}

{# v0.7.28 monitoring section: keep ALL entries (retail needs to import
   the whole list to set up tracking) but add a primary_role badge so
   "wait, I've seen this address in another section" can be answered at
   a glance. Address_role_index lookup is O(1). #}
{% set _ari_mon = address_role_index | default({}) %}
| {{ t("section.monitoring.table_header_n") }} | {{ t("render.mon_col_level") }} | {{ t("section.monitoring.table_header_wallet") }} | {{ t("section.monitoring.table_header_role") }} | {{ t("render.mon_col_primary_section") }} | {{ t("render.mon_col_trigger") }} | {{ t("section.monitoring.table_header_status") }} |
|---|:-:|---|---|---|---|---|
{% for w in monitoring_wallets[:10] %}
{% set _ml = w.monitor_level | default("NORMAL") %}
{% set _ml_emoji = "🚨" if _ml == "CRITICAL" else ("🔥" if _ml == "HIGH" else ("👀" if _ml == "NORMAL" else "💤")) %}
{% set _addr_low = (w.addr_full or '') | lower %}
{% set _ari_e = _ari_mon.get(_addr_low) %}
{# v0.7.28.1 adversarial review MED fix: don't run md_cell on the assembled
   `[label](#anchor)` link — md_cell escapes `[` and `]` so the link
   would render as literal text. Instead apply md_cell to the label
   ONLY, then build markdown link syntax inline at render time. #}
| {{ w.n }} | {{ _ml_emoji }} {{ _ml | md_cell }} | [`{{ w.addr_short | md_cell }}`]({{ explorer_url(w.addr_full) }}) | {{ w.role | md_cell }} | {% if _ari_e %}[{{ _ari_e.primary_section_label_zh | md_cell }}](#{{ _ari_e.primary_section_anchor }}){% else %}—{% endif %} | {{ (w.trigger_summary or w.alert) | md_cell }} | {{ w.status_emoji }} |
{% endfor %}

{{ monitoring_footer | md_cell }}

{# v0.7.28.1 adversarial review MED fix: LLM safety-net was previously ONLY in the
   machine_readable_json fence (which LLM 二次解读 might skip). Render a
   compact markdown "role overlap index" for addresses appearing in 2+
   detector segments, so a reader scrolling the prose body also sees the
   cross-reference. Capped at 30 entries (sorted by all_roles length
   desc) to keep markdown body bounded. #}
{% set _ari_render = address_role_index | default({}) %}
{% set _multi_role_entries = [] %}
{% for _addr, _info in _ari_render.items() -%}
{% if (_info.all_roles | length) > 1 -%}
{% set _ = _multi_role_entries.append((_addr, _info)) -%}
{%- endif -%}
{% endfor %}
{% if _multi_role_entries | length > 0 %}
## {{ t("render.mra_h2") }}

> {{ t("render.mra_intro") }}

| {{ t("render.cfh_recip_col_wallet") }} | {{ t("render.mra_col_primary") }} | {{ t("render.mra_col_all_roles") }} |
|---|---|---|
{% set _ROLE_ZH_SHORT = {
    "mint_authority": t("render.role_short_mint_authority"),
    "cex_fanout_hub": t("render.role_short_cex_fanout_hub"),
    "fanout_recipient": t("render.role_short_fanout_recipient"),
    "direct_dumper": t("render.role_short_direct_dumper"),
    "high_throughput_operator": t("render.role_short_ht_operator"),
    "anomaly_participant": t("render.role_short_anomaly"),
    "wash_operator": t("render.role_short_wash"),
    "cross_alpha_whale": t("render.role_short_cross_alpha_whale"),
    "top_holder": t("render.role_short_top_holder"),
    "public_cex_hot_wallet": t("render.role_short_cex_hot"),
    "public_cex_deposit": t("render.role_short_cex_deposit"),
} %}
{% for _addr, _info in (_multi_role_entries | sort(attribute='1.all_roles', reverse=true))[:30] -%}
{# Sort key falls back lexicographically when length ties; cap 30 for size. #}
{% set _short = _info.addr_short or (_addr[:10] if _addr.startswith('0x') else _addr[:8]) %}
{% set _roles_zh = _info.all_roles | map('lower') | list %}
{% set _roles_display = [] %}
{% for _r in _info.all_roles %}{% set _ = _roles_display.append(_ROLE_ZH_SHORT.get(_r, _r)) %}{% endfor %}
| [`{{ _short | md_cell }}`]({{ explorer_url(_addr) }}) | [{{ _info.primary_section_label_zh | md_cell }}](#{{ _info.primary_section_anchor }}) | {{ _roles_display | join(", ") | md_cell }} |
{% endfor %}

> _{{ t("render.mra_footer", n=_multi_role_entries | length) }}_

{% endif %}
## {{ t("section.machine_readable.title") }}

```json
{{ machine_readable_json }}
```

---

**{{ t("section.footer.disclaimer", n=evidence_count) }}**
"""


# ============================================================
# Security helpers (verbatim from v0.5)
# ============================================================

def escape_md_cell(s):
    """Escape markdown table-cell sensitive chars (pipe + newlines)."""
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def html_escape_finalize(s):
    """Default finalize for jinja2 Environment — HTML escape + markdown-link
    neutralize on every `{{ ... }}` expression output. Stops user-controlled
    fields rendering as HTML, clickable links, or images.

    v0.8.0.5 fix: pass `Markup`-wrapped strings through unchanged. The
    template uses `{{ t("...") | safe }}` to inject i18n strings that
    contain markdown blockquote `>` literals. Without this guard, the
    chained `Markup.replace(">", "&gt;")` re-escaped the `&` in `&gt;`
    to `&amp;gt;` (double escape, broke flow_operators / wash_infra /
    funding_attribution how_to_read_block sections).
    """
    if s is None:
        return ""
    # Markup-marked strings (via `| safe`) are explicitly safe; never re-escape.
    from markupsafe import Markup
    if isinstance(s, Markup):
        return str(s)
    if not isinstance(s, str):
        s = str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace("[", "\\[")
         .replace("]", "\\]")
         .replace("!", "\\!")
    )


def escape_mermaid_label(s):
    """Neutralize mermaid label injection: `"`, `|`, backtick, `[]`, `<>`,
    `;`, edge tokens, newlines.
    """
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    out = (
        s.replace('"', "'")
         .replace("|", "·")
         .replace("`", "")
         .replace("[", "(")
         .replace("]", ")")
         .replace("<", "‹")
         .replace(">", "›")
         .replace(";", ",")
         .replace("\n", " ")
         .replace("\r", " ")
    )
    for token in ("-->", "---", "==>", "==="):
        out = out.replace(token, " ")
    return out


def _normalize_for_width(s):
    """Strip zero-width / control / format chars before width calc.

    adversarial review beta.6 9th-audit MED: combining marks (U+0300+), variation
    selectors (U+FE0F emoji modifier), zero-width joiners (U+200D in ZWJ
    sequences), and control chars miscount when each codepoint is treated
    independently. We don't implement full grapheme clustering (would need
    `regex` package); instead strip the obvious zero-width codepoints
    before measuring. Known limitation: ZWJ emoji sequences like 👨‍👩‍👧
    (5 codepoints, 1 grapheme) will still over-measure as 6 cols vs true
    2 cols. Acceptable for our use case (Chinese labels rarely have ZWJ).
    """
    import unicodedata
    out = []
    for ch in s or "":
        cat = unicodedata.category(ch)
        # Cc=Control, Cf=Format (incl. ZWJ U+200D), Mn=NonspacingMark (combining)
        if cat in ("Cc", "Cf", "Mn", "Me"):
            continue
        # Variation selectors (U+FE00-U+FE0F, U+E0100-U+E01EF) — width 0
        if 0xFE00 <= ord(ch) <= 0xFE0F or 0xE0100 <= ord(ch) <= 0xE01EF:
            continue
        out.append(ch)
    return "".join(out)


def _display_width(s):
    """Visual column width — CJK + emoji count as 2, others as 1.

    v0.6.0-beta.6 fix: progress bar label `%-32s` used char count, but
    Chinese chars render as 2 columns in monospace → labels misaligned.
    """
    import unicodedata
    width = 0
    for ch in _normalize_for_width(s):
        ea = unicodedata.east_asian_width(ch)
        if ea in ("F", "W") or unicodedata.category(ch) == "So":
            width += 2
        else:
            width += 1
    return width


def pad_display(s, target_width):
    """Left-align by display column width (CJK-safe)."""
    if s is None:
        s = ""
    s = str(s)
    pad = max(0, int(target_width) - _display_width(s))
    return s + (" " * pad)


def truncate_display(s, max_width):
    """Truncate to max display columns (CJK-safe), add ellipsis.

    `…` (U+2026) is itself 1 column. Reserve room. adversarial review beta.6
    9th-audit MED: if remaining budget is 1 and we're about to add a
    2-col char, we'd append `…` then return — but the result is still
    within budget. Verified: `out + "…"` length stays ≤ max_width
    because we exit BEFORE appending the 2-col char. OK.
    """
    if s is None:
        return ""
    s = str(s)
    if _display_width(s) <= max_width:
        return s
    if max_width < 1:
        return ""
    out = ""
    w = 0
    for ch in _normalize_for_width(s):
        cw = _display_width(ch)
        # Reserve 1 col for `…`. If adding this char would push us past
        # max_width-1 (= room for `…`), stop and append ellipsis.
        if w + cw > max_width - 1:
            return out + "…"
        out += ch
        w += cw
    return out + "…"   # consumed all chars but still over budget edge case


def role_to_cn(s):
    """Translate role enum → localized flowchart node label.

    v0.6.2 (was v0.6.0-beta.8): now reads from i18n YAML
    (`role.<ENUM>.flowchart_node_label`) instead of hardcoded dict.
    Fallback chain: flowchart_node_label → short → label. Some roles
    (DEPLOYER, DEX_POOL, OTHER) don't have a dedicated flowchart label
    in i18n; we use their `short` field. Unmapped UPPERCASE enum →
    "未知角色" / "Unknown role" (fail-closed).
    """
    if s is None:
        return ""
    key = str(s)
    # Try i18n lookup chain
    for field in ("flowchart_node_label", "short", "label"):
        val = t(f"role.{key}.{field}")
        if not val.startswith("[MISSING:"):
            return val
    # All 3 fields missing → check if it looks like an enum
    import re
    if re.match(r"^[A-Z][A-Z0-9_]{2,}$", key):
        return t("role.unknown.label")
    # Free-text already-localized — pass through.
    return key


def escape_mermaid_id(s):
    """Mermaid node IDs must be alphanumeric-ish."""
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    cleaned = "".join(c for c in s if c.isalnum() or c in "_")
    return cleaned or "_node"


# ============================================================
# Machine-readable footer
# ============================================================

def _derive_chain_state_neutral_5tier(data: dict) -> dict:
    """v0.7.25: Python mirror of the jinja2 5-tier derivation (see render
    template ~line 322-365). Same trigger rules — produces neutral
    forensic-state label for machine-readable JSON footer.

    Returns: {"subtype": str, "label": str, "risk": int}
    where subtype ∈ {CLEAN, WATCH, OPERATOR_DUMPED, DORMANT_INSIDER_RISK,
    RECENT_DISTRIBUTION}.
    """
    lineage = data.get("lineage") or {}
    m6 = lineage.get("m6") or {}
    m6_quiet = m6.get("n_quiet") or 0
    m6_full = m6.get("n_full_dumper") or 0

    anomaly = data.get("anomaly") or {}
    recent_n = 0
    for d in anomaly.get("detector_summary") or []:
        lbl = d.get("label") or ""
        if "72h" in lbl or "近期" in lbl:
            recent_n = d.get("count") or 0
            break

    dump_tracking = data.get("dump_tracking") or {}
    wash = dump_tracking.get("wash_dominated") or False
    pure_pct = dump_tracking.get("pure_insider_holds_pct_supply") or 0

    risk = 0
    subtype = "CLEAN"
    label = t("render.chain_state_clean_label")

    if m6_quiet > 0 and pure_pct > 0.5:
        risk += 4
        subtype = "DORMANT_INSIDER_RISK"
        label = t("render.chain_state_dormant_label", n=m6_quiet, pct=f"{pure_pct:.1f}")

    if recent_n >= 10:
        risk += 4
        subtype = "RECENT_DISTRIBUTION"
        label = t("render.chain_state_recent_label", n=recent_n)
    elif recent_n >= 3:
        risk += 2
        if subtype == "CLEAN":
            subtype = "WATCH"
            label = t("render.chain_state_watch_label", n=recent_n)

    if m6_full >= 3:
        risk += 3
        if subtype == "CLEAN":
            subtype = "OPERATOR_DUMPED"
            label = t("render.chain_state_dumped_label", n=m6_full)

    if wash:
        risk += 2
    if pure_pct > 5:
        risk += 2
    risk = min(risk, 10)
    return {"subtype": subtype, "label": label, "risk": risk}


def compute_machine_readable_json(data: dict) -> str:
    """v0.6 machine-readable footer: counts + verdict pulled from data,
    no hardcoded "guarantees" (audit v0.5 alpha.1 Critical 2 fix).
    """
    meta = data.get("meta", {})
    verdict = data.get("verdict", {})
    tier = data.get("tier_classification", {})
    chain_state = _derive_chain_state_neutral_5tier(data)
    counts = {
        "anomaly_waves": len((data.get("anomaly") or {}).get("waves") or []),
        "evidence_graph_entries": len(data.get("evidence_graph") or {}),
        "holdings_role_rows": len((data.get("holdings_distribution") or {}).get("role_rows") or []),
        "holdings_progress_bars": len((data.get("holdings_distribution") or {}).get("progress_bars") or []),
        "monitoring_wallets": len(data.get("monitoring_wallets") or []),
        "lineage_flowchart_nodes": len((data.get("lineage") or {}).get("flowchart_nodes") or []),
        "lineage_flowchart_edges": len((data.get("lineage") or {}).get("flowchart_edges") or []),
        "m6_rows": len(((data.get("lineage") or {}).get("m6") or {}).get("rows") or []),
        "decision_anchors": len(data.get("decision_anchors") or []),
        "decision_re_entry_conditions": len(
            (data.get("decision_action_block") or {}).get("re_entry_conditions") or []
        ),
    }
    out = {
        "schema_version": data.get("_schema_version"),
        "symbol": meta.get("symbol"),
        # v0.7.25: legacy 3-tier verdict (EXIT_IF_HOLDING etc) kept for
        # downstream schema compat. v0.8.0 will deprecate; prefer
        # `chain_state` / `chain_state_label` (neutral 5-tier) for new
        # parsers. AI parsing should treat `verdict` as legacy.
        "verdict": verdict.get("enum"),
        "verdict_zh": verdict.get("cn_label"),
        "verdict_downgrade_applied": verdict.get("downgrade_applied", 0),
        # v0.7.25: render-side derived neutral 5-tier label, deterministic
        # from raw signals (m6_quiet / pure_pct / recent_anomaly_n / m6_full).
        # Pure on-chain state description, no buy/sell judgment.
        # 5 tiers: CLEAN / WATCH / OPERATOR_DUMPED / DORMANT_INSIDER_RISK /
        # RECENT_DISTRIBUTION.
        "chain_state": chain_state["subtype"],
        "chain_state_label": chain_state["label"],
        "chain_state_risk_score": chain_state["risk"],
        "alpha_listing_tier": tier.get("tier"),
        "any_anomaly_firing": counts["anomaly_waves"] > 0,
        "render_provenance": {
            "rendered_by": "render_report.py (v0.6, jinja2)",
            "data_source": "report_data.json (LLM-filled, Python-validated)",
            "deterministic": True,
        },
        "structural_counts": counts,
        # v0.7.28 LLM safety-net: dump address_role_index so AI
        # 二次解读 can cross-reference duplicate-rendered addresses
        # without following markdown anchors. Compact form per entry
        # (skip the addr_short / primary_section_label_zh duplicates
        # of what's in the dict key) — just primary_role + all_roles
        # + anchor. For large reports (JCT 162 addrs), this is ~5KB.
        "address_role_index": {
            addr: {
                "primary_role": v.get("primary_role"),
                "all_roles": v.get("all_roles") or [],
                "primary_section_anchor": v.get("primary_section_anchor"),
            }
            for addr, v in (data.get("address_role_index") or {}).items()
        },
    }
    return json.dumps(out, ensure_ascii=False, indent=2)


# ============================================================
# Path / data hardening (verbatim from v0.5)
# ============================================================

def _guard_out_path(out_path: str) -> Path:
    refuse_backslash = (os.name != "nt") and ("\\" in out_path)
    if ".." in out_path or refuse_backslash or "\x00" in out_path:
        print(
            f"REFUSED: out_path={out_path!r} contains '..', a POSIX-illegal "
            "'\\\\', or NUL byte.",
            file=sys.stderr,
        )
        sys.exit(1)
    out_p = Path(out_path)
    if out_p.is_symlink():
        print(f"REFUSED: out_path={out_path!r} is itself a symlink.", file=sys.stderr)
        sys.exit(1)
    if out_p.exists() and out_p.is_file():
        try:
            if out_p.stat().st_nlink > 1:
                print(
                    f"REFUSED: out_path={out_path!r} is a hardlink "
                    "(st_nlink > 1).",
                    file=sys.stderr,
                )
                sys.exit(1)
        except OSError:
            pass
    return out_p


def _load_json_hardened(path: str, label: str) -> dict:
    if not Path(path).is_file():
        print(
            f"REFUSED: {label}={path!r} is not a regular file "
            "(FIFO/socket/dir blocked).",
            file=sys.stderr,
        )
        sys.exit(1)
    raw_bytes = Path(path).read_bytes()
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        print(f"REFUSED: {label} is not valid UTF-8 — {e}", file=sys.stderr)
        sys.exit(1)
    try:
        raw_text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        print(
            f"REFUSED: {label} contains unpaired surrogate / invalid codepoint — {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(
            f"REFUSED: {label} not valid JSON — {e.msg} at line {e.lineno} col {e.colno}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Iterative depth-cap walk
    MAX_NEST_DEPTH = 64
    stack = [(data, "$", 0)]
    while stack:
        node, p, depth = stack.pop()
        if depth > MAX_NEST_DEPTH:
            print(
                f"REFUSED: {label} exceeds max nesting depth ({MAX_NEST_DEPTH}) at {p}.",
                file=sys.stderr,
            )
            sys.exit(1)
        if isinstance(node, str):
            for ch in node:
                cp = ord(ch)
                if 0xD800 <= cp <= 0xDFFF:
                    print(
                        f"REFUSED: {label} contains unpaired surrogate U+{cp:04X} at {p}.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append((v, f"{p}.{k}", depth + 1))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((v, f"{p}[{i}]", depth + 1))
    return data


# ============================================================
# v0.7.2 smoke fixture fingerprint
# ============================================================

# NATO phonetic alphabet (lowercase) — exactly the set used by
# tests/smoke_fill.py to suffix per-index variants like "(alpha variant)".
_SMOKE_NATO_WORDS = frozenset((
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
    "golf", "hotel", "india", "juliet", "kilo", "lima",
    "mike", "november", "oscar", "papa", "quebec", "romeo",
    "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu",
))

# Match the literal "(word variant)" pattern smoke_fill writes.
# v0.7.2 hardening (adversarial-review audit finding #1): tolerate adversarial
# formatting variants — uppercase, mixed case, extra/missing whitespace
# around the parens and word, NBSP, Unicode confusables. Strings are
# NFKC-normalized + casefolded before regex match, so:
#   "(Alpha variant)"           → matches alpha
#   "(ALPHA  VARIANT)"          → matches alpha
#   "( alpha\tvariant )"        → matches alpha
#   "(αlpha variant)" (Greek)   → NFKC keeps the Greek α, regex still
#                                  fails to match — but `_NORMALIZE`
#                                  treats it as the same visual class
#                                  via the confusable substitution map.
# Regex itself uses \s+ for whitespace and is case-insensitive (paranoid
# belt+suspenders even though casefold() already lowered).
import re as _re  # noqa: E402  (local re alias keeps the symbol private)
import unicodedata as _unicodedata  # noqa: E402

_SMOKE_NATO_RE = _re.compile(
    r"\(\s*([a-z]+)\s+variant\s*\)",
    _re.IGNORECASE,
)

# Confusable letter substitutions — homoglyphs commonly used to evade
# pattern matching. Maps Unicode visual-equivalents to their ASCII Latin
# counterparts so e.g. "αlpha" (Greek α + "lpha") collapses to "alpha".
# Curated to the lookalikes that actually appear in adversarial text
# generators; not exhaustive, but defends the obvious bypass class.
_SMOKE_CONFUSABLE_MAP = str.maketrans({
    " ": " ",   # NBSP → space
    " ": " ",   # figure space
    " ": " ",   # thin space
    "​": "",    # zero-width space → strip
    "‌": "",    # ZWNJ → strip
    "‍": "",    # ZWJ → strip
    "﻿": "",    # BOM → strip
    # Latin lookalikes for ASCII letters that appear in NATO words.
    "α": "a",   # Greek small alpha
    "а": "a",   # Cyrillic small a
    "е": "e",   # Cyrillic small e
    "ο": "o",   # Greek small omicron
    "о": "o",   # Cyrillic small o
    "і": "i",   # Cyrillic small i
    "ι": "i",   # Greek small iota
    "р": "p",   # Cyrillic small er
    "с": "c",   # Cyrillic small es
    "х": "x",   # Cyrillic small ha
    "у": "y",   # Cyrillic small u
})


def _normalize_for_fingerprint(s: str) -> str:
    """NFKC + casefold + confusable substitution. Idempotent."""
    return _unicodedata.normalize("NFKC", s).translate(_SMOKE_CONFUSABLE_MAP).casefold()


def _count_nato_smoke_fingerprints(obj) -> int:
    """Walk `obj` recursively and count *distinct* NATO words that appear
    inside a `(<word> variant)` suffix. Returns the count.

    De-duping by word means a single repeated stub doesn't trip the gate
    (e.g. 5 copies of `(alpha variant)` count as 1); the gate fires when
    multiple distinct NATO words appear, which is the signature of
    smoke_fill walking through indexed lists.

    v0.7.2 hardening: input strings are NFKC-normalized + casefolded +
    confusable-substituted before matching, so uppercase / whitespace /
    homoglyph / NBSP bypasses are caught. Only dict VALUES are walked;
    dict keys are skipped (smoke_fill never targets keys).
    """
    found: set[str] = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            normalized = _normalize_for_fingerprint(node)
            for word in _SMOKE_NATO_RE.findall(normalized):
                if word in _SMOKE_NATO_WORDS:
                    found.add(word)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return len(found)


# ============================================================
# Render pipeline
# ============================================================

# v0.7.21.6: human-readable explanation per abort reason. Keys match the
# `_reason` strings written by forensic_pipeline.build_skeleton — keep in
# sync when adding new abort paths. Each entry is (title, body_md) where
# body_md uses {ca} and {detail} placeholders.
# v0.6.2 i18n: abort explainer titles + bodies are looked up at render time
# via t() so they localize. Keyed by reason → (title_key, body_key).
_ABORT_EXPLAINER_KEYS = {
    "INVALID_CA": ("render.abort_invalid_ca_title", "render.abort_invalid_ca_body"),
    "SPOT_GRADUATED": ("render.abort_spot_graduated_title", "render.abort_spot_graduated_body"),
    "NEVER_ALPHA": ("render.abort_never_alpha_title", "render.abort_never_alpha_body"),
    "unsupported_chain": ("render.abort_unsupported_chain_title", "render.abort_unsupported_chain_body"),
    "missing_chain_id": ("render.abort_missing_chain_id_title", "render.abort_missing_chain_id_body"),
}


def _render_abort_report(skel: dict, out_p) -> int:
    """v0.7.21.6: write a short human-readable report.md for abort skeletons.

    Skeleton schema: `_status="abort", _reason=<key>, _detail=<text>,
    _timings={...}`. We map `_reason` through `_ABORT_EXPLAINER_KEYS` to
    i18n title + body keys, render markdown, prepend the UTF-8 BOM (same convention
    as the normal report path), and write to the output file.

    Returns 0 (success). The user gets a tangible file artifact even when
    the pipeline couldn't actually run forensic SQL.
    """
    reason_key = skel.get("_reason") or "UNKNOWN"
    detail = skel.get("_detail") or "(no detail available)"
    timings = skel.get("_timings") or {}
    title_key, body_key = _ABORT_EXPLAINER_KEYS.get(reason_key, (None, None))
    if title_key:
        title = t(title_key)
        body = t(body_key)
    else:
        title = t("render.abort_unknown_title", reason=reason_key)
        body = t("render.abort_unknown_body")

    lines = [
        f"# 🚫 {title}",
        "",
        f"> {t('render.abort_intro')}",
        "",
        f"## {t('render.abort_detail_h2')}",
        "",
        f"- **{t('render.abort_reason_label')}**: `{reason_key}`",
        f"- **{t('render.abort_detail_label')}**: {detail}",
        f"- **{t('render.abort_section_a_time')}**: {timings.get('section_a', 0)*1000:.2f} ms",
        "",
        f"## {t('render.abort_interpretation_h2')}",
        "",
        body,
        "",
        "---",
        "",
        f"_{t('render.abort_footer')}_",
        "",
    ]
    bom = "﻿"
    md = bom + "\n".join(lines)
    out_p.write_bytes(md.encode("utf-8"))
    print(f"OK: rendered abort report {out_p} ({len(md)} bytes, reason={reason_key})")
    return 0


# ============================================================
# v0.8.0 TLDR mode template — minimal战情摘要 (4-6KB target).
# Independent from the full TEMPLATE constant above; reuses the same
# Jinja2 environment + filters. ChatGPT v0.8 spec section 7.4.
# Sections (5):
#   1. 一句话状态 (chain_state_label)
#   2. Top 3 active behaviors (from behavior_profile, sorted by severity)
#   3. 监控等级 汇总 (level_counts)
#   4. Top 10 CRITICAL wallets (filtered from monitoring_wallets)
#   5. 主要盲区 (1-line 汇总 of 链上侦测 limits)
# Use case: Discord/Telegram bot forwarding, mobile preview, TL;DR.
# Trade-off: omits all detector detail — readers needing forensic
# evidence should use --mode=default.
# ============================================================
_TLDR_TEMPLATE = """\
# {{ meta.symbol or "—" }} ({{ meta.name | md_cell }}) — {{ t("render.tldr_title_suffix") }}

_v{{ _schema_version }} · {{ meta.chain }} · {{ t("render.market_alpha_listed") }} {{ meta.alpha_listing_date_utc or "—" }}_

## {{ t("render.tldr_chain_state_h2") }}

**`{{ _v.subtype }}`** ({{ _v.risk }}/10) — {{ _v.label | md_cell }}

{# v0.8.0 fix: use dict.get() instead of attribute access since
   StrictUndefined raises on absent keys (ZEST fixture only has subset
   of meta fields). Falls back gracefully to "—" when both rti +
   alpha_* are missing. #}
{% set rti = meta.get('realtime_token_info') or {} %}
{% set _price = rti.get('price_usd') or meta.get('alpha_price_usd') %}
{% set _vol = rti.get('volume_24h_usd') or meta.get('alpha_vol_24h_usd') %}
{% set _lp = rti.get('liquidity_usd') or meta.get('alpha_liquidity_usd') %}
- {{ t("render.tldr_current_price") }}: **${% if _price is not none %}{{ "%.4g" | format(_price) }}{% else %}—{% endif %}**
- {{ t("render.tldr_vol") }}: **${% if _vol is not none %}{{ "{:,.0f}".format(_vol) }}{% else %}—{% endif %}**
- {{ t("render.tldr_lp") }}: **${% if _lp is not none %}{{ "{:,.0f}".format(_lp) }}{% else %}—{% endif %}**

## {{ t("render.tldr_behavior_h2") }}

{# v0.8.0.1 adversarial review MED fix: nested .get() guards for behavior_profile
   sub-dicts (active_labels / by_label / label_names_zh) so malformed
   profile doesn't crash render. #}
{% if behavior_profile is defined and behavior_profile and behavior_profile.get('active_labels') %}
{% set _top3 = behavior_profile.active_labels[:3] %}
| {{ t("render.behavior_col_label") }} | {{ t("render.behavior_col_severity") }} | {{ t("render.behavior_col_fact") }} |
|---|:-:|---|
{% for lid in _top3 %}
{% set info = (behavior_profile.get('by_label') or {}).get(lid) or {} %}
{% set sev_emoji = "🔴" if info.get('severity') == "STRONG" else ("🟠" if info.get('severity') == "MEDIUM" else "🟡") %}
| `{{ lid }}` {{ (behavior_profile.get('label_names_zh') or {}).get(lid) or lid }} | {{ sev_emoji }} {{ info.get('severity') or "—" }} | {{ (info.get('human_summary_zh') or "—") | md_cell }} |
{% endfor %}
{% if behavior_profile.active_labels | length > 3 %}

_{{ t("render.tldr_more_behaviors", n=(behavior_profile.active_labels | length - 3)) }}_
{% endif %}
{% else %}
> {{ t("render.tldr_behavior_none") }}
{% endif %}

## {{ t("render.tldr_mon_h2") }}

{% if monitoring_summary is defined and monitoring_summary and monitoring_summary.level_counts %}
{% set _lc = monitoring_summary.level_counts %}
- 🚨 **CRITICAL**: {{ _lc.get("CRITICAL") or 0 }} {{ t("render.tldr_mon_critical") }}
- 🔥 **HIGH**: {{ _lc.get("HIGH") or 0 }} {{ t("render.tldr_mon_high") }}
- 👀 **NORMAL**: {{ _lc.get("NORMAL") or 0 }} {{ t("render.tldr_mon_normal") }}
- 💤 **NOT_TRACKED**: {{ _lc.get("NOT_TRACKED") or 0 }} {{ t("render.tldr_mon_nottracked") }}

_{{ t("render.tldr_mon_paste") }}_
{% else %}
_{{ t("render.tldr_mon_nodata") }}_
{% endif %}

## {{ t("render.tldr_critical_wallets_h2") }}

{# v0.8.0.1 adversarial review MED fix: defensive guard. StrictUndefined raises
   if monitoring_wallets is absent (e.g. malformed skeleton). #}
{% set _critical_wallets = [] %}
{% if monitoring_wallets is defined and monitoring_wallets %}
{% for w in monitoring_wallets %}
{% if (w.get("monitor_level") or "") == "CRITICAL" %}
{% set _ = _critical_wallets.append(w) %}
{% endif %}
{% endfor %}
{% endif %}
{% if _critical_wallets | length > 0 %}
| {{ t("render.cfh_recip_col_wallet") }} | {{ t("section.monitoring.table_header_role") }} | {{ t("render.mon_col_trigger") }} |
|---|---|---|
{% for w in _critical_wallets[:10] %}| [`{{ w.addr_short | md_cell }}`]({{ explorer_url(w.addr_full) }}) | {{ w.monitor_role_enum or w.role | md_cell }} | {{ (w.trigger_summary or w.alert) | md_cell }} |
{% endfor %}
{% if _critical_wallets | length > 10 %}

_{{ t("render.tldr_more_critical", n=(_critical_wallets | length - 10)) }}_
{% endif %}
{% else %}
_{{ t("render.tldr_no_critical") }}_
{% endif %}

## {{ t("render.tldr_blindspot_h2") }}

{# v0.8.0.1 adversarial review MED fix: defensive .get() chains throughout —
   `lineage.m6` may be explicitly None per adversarial review repro, not just absent. #}
{% set _caveat_parts = [] %}
{% if dump_tracking is defined and dump_tracking and dump_tracking.get('wash_dominated') %}
{% set _ = _caveat_parts.append(t("render.tldr_caveat_wash")) %}
{% endif %}
{% set _m6_for_caveat = (lineage.get('m6') or {}) if (lineage is defined and lineage) else {} %}
{% if _m6_for_caveat and (_m6_for_caveat.get('rows') or []) | length == 0 and lineage.get('deployer_addr') %}
{% set _ = _caveat_parts.append(t("render.tldr_caveat_mining")) %}
{% endif %}
{% set _mc_chains_summary = [] -%}
{% set _mc_for_caveat = (funding_attribution.get('multi_chain') or {}) if (funding_attribution is defined and funding_attribution) else {} -%}
{% for _c in (_mc_for_caveat.keys() | list) if not _c.startswith("_") -%}
{% set _ = _mc_chains_summary.append(_c) -%}
{%- endfor -%}
{% if _mc_chains_summary %}
{% set _ = _caveat_parts.append(t("render.tldr_caveat_cross_chain", chains=(_mc_chains_summary | join(", ")))) %}
{% endif %}
{% if _caveat_parts | length > 0 %}
{% for c in _caveat_parts %}
- {{ c | md_cell }}
{% endfor %}
{% else %}
- {{ t("render.tldr_caveat_none") }}
{% endif %}

{{ t("render.tldr_blindspot_footer") }}

---

_{{ t("render.tldr_mode_footer") }}_

{# v0.8.0.1 adversarial review HIGH fix: disclaimer wording previously contained
   "建议" (banned word). Rephrased to neutral 链上侦测-only language. #}
**{{ t("render.tldr_disclaimer") }}**
"""


def render(skeleton_path: str, filled_path: str, out_path: str, mode: str = "default") -> int:
    """Render report.md from validated v0.6 filled report_data.json.

    Validator is MANDATORY pre-render — invokes validate_report_data.py
    as a subprocess (matches v0.5 audit pattern: validator is the gate,
    renderer trusts validated data).

    v0.8.0 mode parameter:
      - "default" (current behavior, full forensic 18-28KB)
      - "tldr"    (5-section minimal 4-6KB)
      - "deep"    (default template + `<details open>` everywhere)
    """
    # v0.8.0.1 adversarial review MED fix: argparse choices=() guards the CLI path,
    # but direct Python callers could pass a typo and silently fall
    # through to the default template. Fail loud on invalid mode.
    if mode not in ("tldr", "default", "deep"):
        raise ValueError(
            f"render(mode={mode!r}) invalid; must be one of "
            f"'tldr' / 'default' / 'deep'"
        )
    out_p = _guard_out_path(out_path)
    skel = _load_json_hardened(skeleton_path, "skeleton")

    # v0.7.21.6: short-circuit on abort skeleton. forensic_pipeline writes
    # a 200-byte abort marker for INVALID_CA / SPOT_GRADUATED / NEVER_ALPHA
    # / UNSUPPORTED_CHAIN cases (Solana base58 CAs go here today). Pre-
    # v0.7.21.6 the user got no report file at all — only a stdout banner
    # they'd have to scroll back to read. Now we always emit a short
    # human-readable explanation so the file artifact is the source of
    # truth. No filled.json required; no validator run; minimal cost.
    if isinstance(skel, dict) and skel.get("_status") == "abort":
        return _render_abort_report(skel, out_p)

    filled = _load_json_hardened(filled_path, "filled")

    # v0.7.2 SMOKE FIXTURE GATE — bash-level enforcement (cannot be
    # bypassed by docs/SKILL.md guidance alone). Two layers:
    #
    #   1. Flag check: tests/smoke_fill.py writes `_smoke_test_fixture: true`
    #      at top level. Render refuses (exit 3) if present.
    #
    #   2. Fingerprint check: even if the flag is stripped, smoke_fill stubs
    #      use NATO-alphabet suffixes (e.g. "(alpha variant)", "(bravo
    #      variant)") that are vanishingly unlikely in real narrative.
    #      Threshold: ≥3 distinct NATO suffixes across narrative strings.
    #      Strings are NFKC-normalized + casefolded + confusable-substituted
    #      before matching, so case/whitespace/homoglyph bypasses fail.
    #
    # Override (adversarial-review audit finding #3 hardening): both env vars
    # required — single-flag override was too easy to set accidentally.
    #     BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1
    #     BINANCE_ALPHA_SMOKE_OVERRIDE_REASON="<short justification>"
    # The reason text is logged to stderr verbatim so override invocations
    # are visible in audit trails. CI scripts must set both; the legacy
    # single-flag form now emits a "REFUSED override missing reason" error
    # rather than silently allowing the bypass.
    #
    # Motivation: cross-LLM acceptance testing on v0.7.1 revealed that
    # agents (adversarial review, claude) default to invoking tests/smoke_fill.py as
    # a production fill step instead of authoring narrative directly,
    # producing reports full of placeholder stubs that look "filled" but
    # carry no analytical content. SKILL.md guidance alone proved
    # insufficient — agents read code paths over prose. So we gate at
    # the renderer level instead.
    smoke_override_flag = os.environ.get("BINANCE_ALPHA_ALLOW_SMOKE_RENDER") == "1"
    smoke_override_reason = os.environ.get("BINANCE_ALPHA_SMOKE_OVERRIDE_REASON", "").strip()
    smoke_override = smoke_override_flag and bool(smoke_override_reason)
    if smoke_override_flag and not smoke_override_reason:
        print(
            "REFUSED: BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 was set without "
            "BINANCE_ALPHA_SMOKE_OVERRIDE_REASON. Both env vars are "
            "required to bypass the smoke gate (audit-trail enforcement).",
            file=sys.stderr,
        )
        sys.exit(3)
    if filled.get("_smoke_test_fixture") is True:
        if not smoke_override:
            print(
                "REFUSED: filled.json is a smoke test fixture "
                "(_smoke_test_fixture=true). Render will not produce a "
                "production report from test fixtures.",
                file=sys.stderr,
            )
            print(
                "  → If this is a real forensic run, author narrative into "
                "the writable slots of skeleton.json directly (do NOT "
                "invoke tests/smoke_fill.py).",
                file=sys.stderr,
            )
            print(
                "  → If this is an intentional CI/E2E test, set BOTH "
                "BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 and "
                "BINANCE_ALPHA_SMOKE_OVERRIDE_REASON='<reason>' in env.",
                file=sys.stderr,
            )
            sys.exit(3)
        print(
            f"WARNING: rendering smoke test fixture under override "
            f"(reason: {smoke_override_reason}; output is NOT a real report).",
            file=sys.stderr,
        )
    else:
        # Fingerprint check — counts NATO-suffix patterns across all
        # narrative strings in `filled`. Real narrative effectively never
        # produces these.
        nato_hits = _count_nato_smoke_fingerprints(filled)
        if nato_hits >= 3 and not smoke_override:
            print(
                f"REFUSED: filled.json appears to be smoke test output "
                f"with the _smoke_test_fixture flag stripped "
                f"({nato_hits} NATO suffix fingerprints detected, e.g. "
                f"'(alpha variant)', '(bravo variant)').",
                file=sys.stderr,
            )
            print(
                "  → Stripping the flag does not bypass the gate. Author "
                "real narrative or set both override env vars "
                "(BINANCE_ALPHA_ALLOW_SMOKE_RENDER=1 + "
                "BINANCE_ALPHA_SMOKE_OVERRIDE_REASON='<reason>').",
                file=sys.stderr,
            )
            sys.exit(3)

    # v0.6.2 audit HIGH #2: pipeline lang vs render lang must match.
    # Mismatch = visible-fail (refuse render) instead of silent
    # "English shell + Chinese narrative core" pollution.
    skel_lang = (skel.get("meta") or {}).get("report_lang_locked")
    cur_lang = get_lang()
    if skel_lang and skel_lang != cur_lang:
        print(
            f"REFUSED: skeleton --lang ({skel_lang}) != render --lang ({cur_lang}). "
            f"Re-run pipeline with --lang {cur_lang} OR render with --lang {skel_lang}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # v0.7.20.1: route the chain_router to the chain the pipeline ran on.
    # render_report.py is a fresh process — without this, `_active_chain`
    # is the module default ("bsc") and every `explorer_url(...)` call
    # in the jinja template links to BSCScan even for a Base / Arbitrum
    # token. We read meta.chain_id (Alpha API value, locked at Section
    # A time) rather than meta.primary_chain because chain_id is the
    # canonical chain_router input and round-trips through the same
    # mapping the pipeline used.
    meta_for_chain = filled.get("meta", {})
    chain_id_from_meta = meta_for_chain.get("chain_id")
    if chain_id_from_meta:
        try:
            from chain_router import set_active_chain, UnsupportedChainError
            set_active_chain(chain_id_from_meta)
        except UnsupportedChainError as e:
            print(
                f"WARN: render unable to route to chain_id={chain_id_from_meta!r} "
                f"({e}); explorer links will fall back to BSC default.",
                file=sys.stderr,
            )

    # MANDATORY validator — invoked on the EXACT in-memory objects that will
    # be rendered. Earlier alpha.8 ran the validator as a subprocess against
    # file paths AFTER loading skel/filled, which let an attacker swap the
    # file between load + validate and ship malicious content with a passing
    # validator — cross-LLM audit on alpha.8 caught this TOCTOU race.
    # Calling Validator() directly on `skel` / `filled` binds validation to
    # the exact bytes we will render. No opt-out path.
    validator = Validator()
    errors = validator.validate(skel, filled)
    narrative_warnings: list[str] = []
    if errors:
        # v0.7.1 architectural fix (was hard-abort blowing surf credits with
        # no report.md): split errors into structural (LLM tampered locked
        # data — never render) vs narrative quality (recoverable — render
        # with warning, agent can retry the specific slot if it wants).
        from validate_report_data import categorize_errors
        structural, narrative_warnings = categorize_errors(errors)
        if structural:
            print(
                f"V_SEMANTIC_VALIDATION STRUCTURAL FAIL — render aborted: "
                f"{len(structural)} blocking issue(s):",
                file=sys.stderr,
            )
            for i, e in enumerate(structural, 1):
                print(f"  {i}. {e}", file=sys.stderr)
            sys.exit(1)
        # Only narrative-quality errors: print to stderr but proceed to render.
        if narrative_warnings:
            print(
                f"V_SEMANTIC_VALIDATION NARRATIVE_QUALITY: {len(narrative_warnings)} "
                f"recoverable issue(s) — rendering with warning footer:",
                file=sys.stderr,
            )
            for i, e in enumerate(narrative_warnings, 1):
                print(f"  {i}. {e}", file=sys.stderr)

    filled["machine_readable_json"] = compute_machine_readable_json(filled)
    filled["evidence_count"] = len(filled.get("evidence_graph") or {})
    # Pass warnings into template so renderer can add a footer if narrative
    # quality issues are present.
    filled["_narrative_warnings"] = narrative_warnings

    # v0.7.19: trim_blocks=True strips the newline immediately following a
    # `{% %}` block tag, so a false `{% if %}{% endif %}` no longer leaves
    # a phantom blank line in the rendered markdown. lstrip_blocks=True
    # additionally strips leading whitespace on lines that contain only
    # a block tag. Together they fix the ~5 leading blank lines that
    # COLLECT / BEAT / GUA reports had at the top (5 banner blocks all
    # evaluating false stacks 5 blank lines under the H1 title).
    env = Environment(
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
        finalize=html_escape_finalize,
    )
    env.filters["md_cell"] = escape_md_cell
    env.filters["mermaid_label"] = escape_mermaid_label
    env.filters["mermaid_id"] = escape_mermaid_id
    env.filters["role_to_cn"] = role_to_cn
    env.filters["pad_display"] = pad_display
    env.filters["truncate_display"] = truncate_display
    # v0.8.4.9.1: regex_replace filter for in-template substitution of
    # stale LLM-emitted numbers (e.g. m4_notes "49 个内幕钱包" → "51").
    import re as _re
    env.filters["regex_replace"] = lambda s, pattern, repl: _re.sub(pattern, repl, s) if isinstance(s, str) else s
    # v0.6.2: register t() as Jinja global so template can use {{ t("...") }}
    # for lang-aware labels. set_lang() must be called earlier in main().
    #
    # v1.0.1 i18n-completion fix: the static curated i18n strings legitimately
    # contain raw markdown (blockquote `>`, `**bold**`, `[links]`, `< / >`
    # comparators) that MUST render verbatim — exactly as the pre-i18n inline
    # template literals did. Under `finalize=html_escape_finalize`, a bare
    # `{{ t("...") }}` would HTML-escape those (`>`→`&gt;`), silently degrading
    # the report vs the pre-i18n output. Wrapping the result in Markup makes
    # the trusted i18n string render raw (finalize passes Markup through, see
    # html_escape_finalize). We still escape any STRING kwargs first, because
    # those are data (token symbol/name, chain ids, addresses) and remain
    # user-controlled — preserving the original behavior where data rendered
    # via `{{ var }}` was escaped. Only ~2 of 540 template t() calls had the
    # explicit `| safe`; this makes all of them faithful without per-call edits.
    from markupsafe import Markup as _Markup

    def _t_template(_key, **_kwargs):
        _safe = {
            _k: (html_escape_finalize(_v) if isinstance(_v, str) else _v)
            for _k, _v in _kwargs.items()
        }
        return _Markup(t(_key, **_safe))

    env.globals["t"] = _t_template
    # v0.7.20.1: explorer URL helper. Templates call `explorer_url(addr)`
    # instead of hardcoding `https://bscscan.com/address/...`. The router
    # is set by forensic_pipeline → section_a chain_id, so a Base PLAY
    # report links to basescan.org, an Arbitrum token to arbiscan.io, etc.
    from chain_router import explorer_url, explorer_name
    env.globals["explorer_url"] = explorer_url
    env.globals["explorer_name"] = explorer_name
    # v0.8.0: TLDR mode uses independent compact template. DEEP mode
    # uses the same default TEMPLATE but with `mode == 'deep'` available
    # in the Jinja context so `<details>` blocks can pass `open` attr.
    # Default mode is unchanged from v0.7.28 behavior.
    _context = dict(filled)
    _context["mode"] = mode
    if mode == "tldr":
        template = env.from_string(_TLDR_TEMPLATE)
        # TLDR template references `_v.subtype/label/risk` for parity
        # with the full template's namespace shape. Pre-compute in
        # Python since TLDR template doesn't carry the jinja-side
        # namespace derivation block from the full TEMPLATE.
        _chain_state = _derive_chain_state_neutral_5tier(filled)
        _context["_v"] = {
            "subtype": _chain_state["subtype"],
            "label": _chain_state["label"],
            "risk": _chain_state["risk"],
        }
    else:
        template = env.from_string(TEMPLATE)
    rendered = template.render(**_context)

    # v0.6.4: prepend UTF-8 BOM (U+FEFF) so downstream viewers / wrappers
    # that auto-detect encoding don't misread UTF-8 as cp1252 / Latin-1.
    # Empirical: 3/3 cross-LLM testers (Claude / adversarial review / Kimi) produced
    # mojibake in their wrapper-rendered output when no BOM was present.
    # BOM is a no-op for any UTF-8-aware viewer (GitHub, VSCode, most
    # markdown renderers strip it silently) and a strong signal to
    # legacy / heuristic viewers to decode as UTF-8.
    bom = "﻿"
    out_p.write_bytes((bom + rendered).encode("utf-8"))
    print(f"OK: rendered {out_path} ({len(rendered)} bytes, UTF-8 + BOM)")

    # v0.6.0-beta.3: re-emit monitoring_wallets export with LLM-filled
    # alert text. Pipeline-time emit had placeholder masked to empty;
    # this pass writes the final usable files.
    meta = filled.get("meta", {})
    mw_export = monitoring_export.write_all(
        symbol=meta.get("symbol", "UNKNOWN"),
        chain=meta.get("chain", "BSC"),
        contract_address=meta.get("contract_address", ""),
        monitoring_wallets=filled.get("monitoring_wallets", []),
        out_dir=out_p.parent,
        lang=get_lang(),   # v0.6.2 audit MED #3: pass through current lang
    )
    print(
        f"OK: monitoring re-emitted ({mw_export['n_wallets']} wallets) → "
        f"{mw_export['dir']}"
    )

    # v0.7.1: caller signals via exit code whether render was clean (0) or
    # had narrative-quality warnings (2). Structural failures (exit 1)
    # already returned earlier via sys.exit(1).
    if narrative_warnings:
        return 2
    return 0


def main() -> int:
    # Beta.15: force UTF-8 stdout/stderr so prints with '→' / emoji /
    # 中文 work on Windows console (default cp1252 can't encode U+2192
    # and most non-Latin codepoints). Symptom: render succeeds (writes
    # report.md fine) then exit 1 inside the post-render `print(...)`
    # at line 635 because `→` doesn't round-trip through cp1252.
    # `errors="replace"` falls back to `?` rather than crashing on
    # any remaining edge case.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--skeleton", required=True, help="Pipeline output (pre-LLM-fill)")
    ap.add_argument("--filled", required=True, help="LLM-filled JSON")
    ap.add_argument("--out", required=True, help="Output report.md path")
    ap.add_argument("--lang", default="zh", choices=("zh", "en"),
                    help="Report language. Default: zh. Must match pipeline --lang.")
    # v0.8.0: 3-tier report mode (ChatGPT v0.8 spec section 7).
    # - tldr     ~4-6KB minimal战情摘要 — Discord/移动端/preview 用 (5 段)
    # - default  ~18-28KB full forensic简报 (current template, all 15+ sections)
    # - deep     same as default but `<details>` 块默认展开, no collapse —
    #            链上侦测 全展开 + AI 深挖友好
    ap.add_argument("--mode", default="default", choices=("tldr", "default", "deep"),
                    help="Report mode. tldr=minimal 4-6KB, default=full 18-28KB, "
                         "deep=full + all <details> expanded. Default: default.")
    args = ap.parse_args()
    # v0.6.2: set lang BEFORE render() so all t() lookups use it.
    set_lang(args.lang)
    rc = render(args.skeleton, args.filled, args.out, mode=args.mode)
    return rc if rc is not None else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
