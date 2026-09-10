"""Render the management briefing dashboard from out/data/*.csv.

Audience: China HQ security / tech management. This is a self-contained briefing --
a reader should finish it without needing the 9 technical reports or a background
explainer on what SMS pumping is.

Design system is fixed and documented in docs/02_看板设计说明.md -- do not reinvent it.
Charts are hand-authored inline SVG (the Artifact CSP forbids external JS/CSS).

    python -m sms_attack.dashboard
"""
import os

import pandas as pd

from . import figures as F

OUT_HTML = os.path.join(F.OUT, "mgmt_dashboard.html")
UNIT_LO, UNIT_HI = 0.03, 0.13     # USD per international OTP SMS -- ASSUMPTION, see docs/03


def _f(n):
    return f"{n:,.0f}"


def load_all():
    D = F.OUT_DATA
    r = lambda n: pd.read_csv(os.path.join(D, n))
    up = r("06_upush_daily.csv")
    up = up[up["日期"] < "2026-09-10"].reset_index(drop=True)   # drop the partial final day
    rc = r("02_recall.csv")
    cand = r("04_candidates.csv").set_index("策略")
    coh = r("03_cohort_profile.csv").set_index("cohort")
    dv = r("01_daily_overview.csv")

    atk = dv[(dv.date_utc >= "2026-09-03") & (dv.date_utc <= "2026-09-09")].copy()
    atk["rej"] = atk["非1_86调用"] - atk["非1_86_PASS"]
    # 攻击前窗 = the same 25 days every backtest uses (see report._baseline)
    base = up[(up["日期"] >= "2026-08-09") & (up["日期"] <= "2026-09-02")]["其他区号发送"]
    last = up.iloc[-1]

    m = {
        "up": up, "curve": r("04_threshold_curve.csv"), "evas": r("04_threshold_evasion_by_cc.csv"),
        "byday": r("02_recall_by_day.csv"), "src": r("07_source_country.csv"),
        "dev": r("07_device_profile.csv"), "tl": r("06_measures_timeline.csv"),
        "cc": r("05_black_sample_by_cc.csv"), "leak": r("02_leak_breakdown.csv"),
        "today_attack": int(last["其他区号发送"]),
        "today_fill": float(last["其他区号填充率%"]),
        "today_us_fill": float(last["+1填充率%"]),
        "today_us_send": int(last["+1发送"]),
        "baseline": float(base.mean()), "base_lo": int(base.min()), "base_hi": int(base.max()),
        "sent_cum": int(up[up["日期"] >= "2026-09-03"]["其他区号发送"].sum()),
        "sent_since_cfg": int(up[up["日期"] >= "2026-09-04"]["其他区号发送"].sum()),
        "blocked_cum": int(atk["rej"].sum()),
        "recall_now": float(rc.iloc[1]["ONLINE召回%"]),
        "leak_now": int(rc.iloc[1]["漏召回(PASS)"]),
        "black_total": int(rc.iloc[1]["黑产总量"]),
        "recall_after": 95.2,
        "cand_a": cand.loc["strategy_MGj5bfGOijOi"], "cand_b": cand.loc["strategy_x37TInaHsvPQ"],
        "us_req": int(coh.loc["美国IP·非+1/+86", "请求数"]),
        "nonus_req": int(coh.loc["非美国IP·非+1/+86", "请求数"]),
        "us_ip_multi": float(coh.loc["美国IP·非+1/+86", "IP>3手机号占比%"]),
        "p1_ip_multi": float(coh.loc["+1 正常基线", "IP>3手机号占比%"]),
        "us_pushonly": float(coh.loc["美国IP·非+1/+86", "仅调短信uid%"]),
        "p1_pushonly": float(coh.loc["+1 正常基线", "仅调短信uid%"]),
    }
    m["multiple"] = round(m["today_attack"] / m["baseline"], 1)
    m["us_ip_share"] = round(m["us_req"] / (m["us_req"] + m["nonus_req"]) * 100, 1)
    m["cost_day"] = (m["today_attack"] * UNIT_LO, m["today_attack"] * UNIT_HI)
    m["cost_cum"] = (m["sent_cum"] * UNIT_LO, m["sent_cum"] * UNIT_HI)
    m["cost_saved"] = (m["blocked_cum"] * UNIT_LO, m["blocked_cum"] * UNIT_HI)
    m["cost_month"] = (m["today_attack"] * 30 * UNIT_LO, m["today_attack"] * 30 * UNIT_HI)
    resid = m["today_attack"] * (1 - m["recall_after"] / 100) / (1 - m["recall_now"] / 100)
    m["resid_day"] = resid
    m["save_month"] = ((m["today_attack"] - resid) * 30 * UNIT_LO,
                       (m["today_attack"] - resid) * 30 * UNIT_HI)
    ip = m["dev"][m["dev"].机型 == "__iPhone合计__"].set_index("分组")["占比%"]
    m["iphone_atk"], m["iphone_p1"] = float(ip["攻击流量"]), float(ip["正常美国用户"])
    return m


# ----------------------------------------------------------------- design system
# Colours match docs/02_看板设计说明.md. Chrome uses the company navy; data marks use
# the validated categorical pair. Every colour is a token so the three theme states
# (unstamped / data-theme=light / data-theme=dark) all resolve as a set.
CSS = """
:root {
  --ground:#F2F4F7; --surface:#FFFFFF; --surface-2:#F7F9FB;
  --ink:#16243A; --ink-2:#5A6678; --ink-3:#8A94A3;
  --line:#DFE4EB; --navy:#1F3864; --on-navy:#FFFFFF;
  --crit:#C0342E; --good:#1E7A4C; --warn:#B8730F;
  --blue:#2a78d6; --orange:#eb6834;
  --crit-bg:#FBEDEC; --good-bg:#EAF5EF; --warn-bg:#FDF4E6; --blue-bg:#ECF3FC;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground:#11151C; --surface:#181D26; --surface-2:#1E242F;
    --ink:#EEF2F7; --ink-2:#A7B2C1; --ink-3:#77828F;
    --line:#2C3542; --navy:#8FB0E0; --on-navy:#0E1319;
    --crit:#F08C86; --good:#63C795; --warn:#E5A548;
    --blue:#3987e5; --orange:#d95926;
    --crit-bg:#2E1B1A; --good-bg:#152B21; --warn-bg:#2C2213; --blue-bg:#16202E;
  }
}
:root[data-theme="dark"] {
  --ground:#11151C; --surface:#181D26; --surface-2:#1E242F;
  --ink:#EEF2F7; --ink-2:#A7B2C1; --ink-3:#77828F;
  --line:#2C3542; --navy:#8FB0E0; --on-navy:#0E1319;
  --crit:#F08C86; --good:#63C795; --warn:#E5A548;
  --blue:#3987e5; --orange:#d95926;
  --crit-bg:#2E1B1A; --good-bg:#152B21; --warn-bg:#2C2213; --blue-bg:#16202E;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
body{margin:0;background:var(--ground);color:var(--ink);
  font-family:"Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
.num{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums}

/* sticky section nav */
.nav{position:sticky;top:0;z-index:20;background:var(--surface);border-bottom:1px solid var(--line)}
.nav-in{max-width:1120px;margin:0 auto;padding:0 20px;display:flex;gap:2px;overflow-x:auto;
  -webkit-overflow-scrolling:touch;scrollbar-width:thin}
.nav a{flex:0 0 auto;padding:12px 11px;font-size:13px;color:var(--ink-2);text-decoration:none;
  border-bottom:2px solid transparent;white-space:nowrap}
.nav a:hover{color:var(--ink);border-bottom-color:var(--line)}
.nav a:focus-visible{outline:2px solid var(--blue);outline-offset:-2px;border-radius:3px}

.wrap{max-width:1120px;margin:0 auto;padding:24px 20px 72px;display:flex;flex-direction:column;gap:22px}
section{scroll-margin-top:64px}
h2.sec{margin:14px 0 2px;font-size:20px;font-weight:900;letter-spacing:-.01em;
  padding-left:12px;border-left:4px solid var(--navy)}
p.seclede{margin:6px 0 14px 16px;color:var(--ink-2);font-size:14px;max-width:72ch}

.ribbon{display:flex;flex-wrap:wrap;align-items:center;gap:12px;background:var(--crit-bg);
  border:1px solid var(--crit);border-left-width:5px;border-radius:8px;padding:14px 18px}
.ribbon .tag{font-weight:900;color:var(--crit);font-size:15px}
.ribbon .day{margin-left:auto;color:var(--ink-2);font-size:13px}
header h1{margin:0;font-size:28px;font-weight:900;letter-spacing:-.01em;text-wrap:balance}
header .lede{margin:10px 0 0;font-size:16px;color:var(--ink-2);max-width:66ch}
header .lede b{color:var(--ink);font-weight:700}
.meta{margin-top:10px;font-size:12.5px;color:var(--ink-3)}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.kpi .k{font-size:12px;color:var(--ink-2);letter-spacing:.04em}
.kpi .v{font-size:27px;font-weight:700;margin-top:6px;line-height:1.15}
.kpi .s{font-size:12.5px;color:var(--ink-3);margin-top:4px}
.v.crit{color:var(--crit)} .v.good{color:var(--good)} .v.warn{color:var(--warn)}

.card{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:20px 22px}
.card h3{margin:0 0 4px;font-size:16px;font-weight:700}
.card .sub{margin:0 0 16px;font-size:13px;color:var(--ink-2)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}
figure{margin:0}
figcaption{margin-top:10px;font-size:12.5px;color:var(--ink-2);line-height:1.6}
.chart{width:100%;height:auto;display:block;max-width:100%}
.grid{stroke:var(--line);stroke-width:1}
.ax{fill:var(--ink-3);font-size:11px;font-family:"IBM Plex Mono",monospace}
.mark{stroke:var(--ink-3);stroke-width:1;stroke-dasharray:3 3}
.markt{fill:var(--ink-2);font-size:11px}
.s-blue{fill:none;stroke:var(--blue);stroke-width:2;stroke-linejoin:round}
.s-orange{fill:none;stroke:var(--orange);stroke-width:2.5;stroke-linejoin:round}
.dot-orange{fill:var(--orange);stroke:var(--surface);stroke-width:2}
.endlab{fill:var(--ink);font-size:13px;font-weight:700;font-family:"IBM Plex Mono",monospace}
.track{fill:var(--surface-2);stroke:var(--line)}
.bar-blue{fill:var(--blue)} .bar-orange{fill:var(--orange)} .bar-good{fill:var(--good)}
.blab{fill:var(--ink-2);font-size:12.5px}
.bval{fill:var(--ink);font-size:12.5px;font-weight:700;font-family:"IBM Plex Mono",monospace}
.bval-blue{fill:var(--blue);font-size:19px;font-weight:700;font-family:"IBM Plex Mono",monospace}
.bval-orange{fill:var(--orange);font-size:19px;font-weight:700;font-family:"IBM Plex Mono",monospace}
.legend{display:flex;gap:18px;margin-top:12px;font-size:12.5px;color:var(--ink-2);flex-wrap:wrap}
.legend i{display:inline-block;width:14px;height:3px;border-radius:2px;vertical-align:middle;margin-right:6px}

/* mechanism diagram */
.dgm{color:var(--ink-2)}
.dgm .box{fill:var(--surface-2);stroke:currentColor;stroke-width:1.2}
.dgm .box-us{fill:var(--blue-bg);stroke:var(--blue);stroke-width:1.6}
.dgm .box-atk{fill:var(--crit-bg);stroke:var(--crit);stroke-width:1.4}
.dgm .t{fill:var(--ink);font-size:13px;font-weight:700}
.dgm .t2{fill:var(--ink-2);font-size:11.5px}
.dgm .flow{stroke:currentColor;stroke-width:1.6;fill:none}
.dgm .money{stroke:var(--orange);stroke-width:2;fill:none;stroke-dasharray:5 4}
.dgm .lab{fill:var(--ink-2);font-size:11.5px}
.dgm .lab-m{fill:var(--orange);font-size:12px;font-weight:700}

.why{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.why .w{background:var(--surface-2);border:1px solid var(--line);border-radius:8px;padding:15px 16px}
.why .wn{font-size:22px;font-weight:700;color:var(--orange);font-family:"IBM Plex Mono",monospace}
.why .wt{font-weight:700;margin:6px 0 5px;font-size:14.5px}
.why .wd{font-size:13px;color:var(--ink-2);line-height:1.6}

/* solution cards */
.sol{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--navy);
  border-radius:8px;padding:16px 18px;margin-bottom:12px}
.sol h4{margin:0 0 8px;font-size:15.5px;font-weight:700;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.sol dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:6px 14px;font-size:13.5px}
.sol dt{color:var(--ink-3);white-space:nowrap;font-size:12.5px;padding-top:1px}
.sol dd{margin:0;color:var(--ink-2)}
.sol dd b{color:var(--ink)}

/* timeline */
.tl{list-style:none;margin:0;padding:0 0 0 22px;border-left:2px solid var(--line)}
.tl li{position:relative;padding:0 0 16px 16px}
.tl li::before{content:"";position:absolute;left:-25px;top:6px;width:8px;height:8px;border-radius:50%;
  background:var(--ink-3);box-shadow:0 0 0 3px var(--ground)}
.tl li.hot::before{background:var(--crit)}
.tl li.ok::before{background:var(--good)}
.tl .d{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--ink-3)}
.tl .h{font-weight:700;font-size:14.5px;margin:1px 0 3px}
.tl .b{font-size:13.5px;color:var(--ink-2)}

.tblwrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13.5px;min-width:660px}
th{background:var(--navy);color:var(--on-navy);text-align:left;padding:10px 12px;font-weight:700;
  font-size:13px;white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11.5px;font-weight:700;white-space:nowrap}
.p-now{background:var(--crit-bg);color:var(--crit)}
.p-next{background:var(--warn-bg);color:var(--warn)}
.p-ok{background:var(--good-bg);color:var(--good)}
.p-info{background:var(--blue-bg);color:var(--blue)}

.note{background:var(--surface-2);border:1px dashed var(--line);border-radius:8px;padding:14px 18px;
  font-size:13px;color:var(--ink-2)}
.note b{color:var(--ink)}
details{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:0 20px}
details[open]{padding-bottom:16px}
summary{cursor:pointer;padding:15px 0;font-weight:700;font-size:14.5px}
summary:focus-visible{outline:2px solid var(--blue);outline-offset:3px;border-radius:4px}
details ul{margin:0;padding-left:20px;color:var(--ink-2);font-size:13.5px;line-height:1.8}
footer{color:var(--ink-3);font-size:12px;text-align:center;padding-top:6px}

/* ---- print / PDF ---------------------------------------------------- */
@page{size:A4;margin:14mm 12mm}
@media print{
  :root,:root[data-theme="dark"]{
    --ground:#FFFFFF; --surface:#FFFFFF; --surface-2:#F6F8FA;
    --ink:#16243A; --ink-2:#4A5666; --ink-3:#6E7885;
    --line:#C9D0DA; --navy:#1F3864; --on-navy:#FFFFFF;
    --crit:#B02A24; --good:#176B42; --warn:#9A6008;
    --blue:#1F63BC; --orange:#C9501F;
    --crit-bg:#FBEDEC; --good-bg:#EAF5EF; --warn-bg:#FDF4E6; --blue-bg:#ECF3FC;
  }
  body{background:#fff;font-size:10.2pt;line-height:1.55}
  .nav{display:none}
  .wrap{max-width:none;padding:0;gap:12px}
  h2.sec{break-after:avoid;font-size:14pt;margin-top:8px}
  p.seclede{font-size:9.4pt}
  .card,.sol,.kpi,.why .w,.note,details,figure{break-inside:avoid}
  section{break-inside:auto}
  #background,#solution,#decide{break-before:page}
  tr,li{break-inside:avoid}
  thead{display:table-header-group}
  table{min-width:0!important;font-size:9pt}
  .tblwrap{overflow:visible}
  .kpis{grid-template-columns:repeat(5,1fr)}
  .kpi .v{font-size:16pt}
  header h1{font-size:19pt}
  header .lede{font-size:10.6pt}
  summary{list-style:none}
  a{color:inherit;text-decoration:none}
  footer{margin-top:10px}
}
@media (max-width:640px){
  header h1{font-size:22px} .kpi .v{font-size:23px} .wrap{padding:16px 14px 52px}
  .card{padding:16px 15px} h2.sec{font-size:18px}
  .sol dl{grid-template-columns:1fr;gap:2px 0} .sol dt{padding-top:6px}
}
"""


def mechanism_svg():
    """The one picture that answers '我们被黑了吗'. Claim: nothing was breached --
    the attacker profits from the SMS being *sent*, via carrier revenue share."""
    return '''<figure>
<svg viewBox="0 0 880 292" class="chart dgm" role="img"
     aria-label="攻击获利链条：攻击脚本刷验证码接口，我们付费给短信服务商，服务商结算给目的国运营商，运营商把话务分成返给攻击方">
  <defs>
    <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="currentColor"/>
    </marker>
    <marker id="arm" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="var(--orange)"/>
    </marker>
  </defs>

  <rect x="14" y="54" width="152" height="64" rx="7" class="box-atk"/>
  <text x="90" y="80" class="t" text-anchor="middle">攻击方脚本</text>
  <text x="90" y="99" class="t2" text-anchor="middle">批量请求验证码</text>

  <rect x="238" y="54" width="176" height="64" rx="7" class="box-us"/>
  <text x="326" y="80" class="t" text-anchor="middle">瑞幸 App 验证码接口</text>
  <text x="326" y="99" class="t2" text-anchor="middle">正常功能，未被攻破</text>

  <rect x="486" y="54" width="152" height="64" rx="7" class="box"/>
  <text x="562" y="80" class="t" text-anchor="middle">短信服务商</text>
  <text x="562" y="99" class="t2" text-anchor="middle">我们按条付费</text>

  <rect x="710" y="54" width="156" height="64" rx="7" class="box"/>
  <text x="788" y="80" class="t" text-anchor="middle">目的国运营商</text>
  <text x="788" y="99" class="t2" text-anchor="middle">高结算价国家</text>

  <line x1="166" y1="86" x2="232" y2="86" class="flow" marker-end="url(#ar)"/>
  <text x="199" y="76" class="lab" text-anchor="middle">刷请求</text>
  <line x1="414" y1="86" x2="480" y2="86" class="flow" marker-end="url(#ar)"/>
  <text x="447" y="76" class="lab" text-anchor="middle">下发短信</text>
  <line x1="638" y1="86" x2="704" y2="86" class="flow" marker-end="url(#ar)"/>
  <text x="671" y="76" class="lab" text-anchor="middle">国际结算</text>

  <text x="562" y="140" class="lab-m" text-anchor="middle">▲ 成本落在我们这里</text>

  <path d="M788,118 L788,196 L90,196 L90,124" class="money" marker-end="url(#arm)"/>
  <text x="439" y="187" class="lab-m" text-anchor="middle">话务分成回流 —— 这就是攻击方的收入来源</text>

  <line x1="14" y1="228" x2="866" y2="228" class="grid"/>
  <text x="14" y="252" class="t2">关键点一：短信「被发出」本身就是攻击方的目的，验证码内容对他们毫无用处 ——</text>
  <text x="14" y="271" class="t2">这解释了为什么这些短信的验证码填充率只有 0.6%，而正常美国用户是 95%。</text>
</svg>
<figcaption><b>攻击方没有攻破任何系统。</b>他们与部分国家的终端运营商存在话务分成，
通过脚本让我们向高结算价国家发出大量短信，费用由公司承担、分成由攻击方获得。
因此这不是入侵事件，而是对一个正常业务功能的滥用。</figcaption>
</figure>'''


def _fig(svg, caption):
    return f'<figure>{svg}\n<figcaption>{caption}</figcaption></figure>'


def trend_svg(up):
    W, H, ml, mr, mt, mb = 760, 300, 54, 16, 18, 40
    pw, ph = W - ml - mr, H - mt - mb
    ymax = max(list(up["+1发送"]) + list(up["其他区号发送"])) * 1.12
    n = len(up)
    xs = [ml + pw * i / (n - 1) for i in range(n)]
    y = lambda v: mt + ph - ph * v / ymax
    path = lambda c: " ".join(("M" if i == 0 else "L") + f"{xs[i]:.1f},{y(v):.1f}"
                              for i, v in enumerate(up[c]))
    g = "".join(f'<line x1="{ml}" y1="{y(v):.1f}" x2="{W-mr}" y2="{y(v):.1f}" class="grid"/>'
                f'<text x="{ml-10}" y="{y(v)+4:.1f}" class="ax" text-anchor="end">{v:,}</text>'
                for v in range(500, int(ymax), 500))
    keep = list(range(0, n, 3))
    if n - 1 - keep[-1] >= 2:
        keep.append(n - 1)
    tk = "".join(f'<text x="{xs[i]:.1f}" y="{H-mb+20}" class="ax" text-anchor="middle">'
                 f'{up["日期"].iloc[i][5:]}</text>' for i in keep)
    mk = ""
    for day, txt, anch in [("2026-09-03", "9/3 攻击起量", "start"), ("2026-09-09", "9/9 新策略生效", "end")]:
        i = list(up["日期"]).index(day)
        dx = 6 if anch == "start" else -6
        mk += (f'<line x1="{xs[i]:.1f}" y1="{mt}" x2="{xs[i]:.1f}" y2="{mt+ph}" class="mark"/>'
               f'<text x="{xs[i]+dx:.1f}" y="{mt+12}" class="markt" text-anchor="{anch}">{txt}</text>')
    lv = up["其他区号发送"].iloc[-1]
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="每日实发短信趋势，攻击流量自9月3日起飙升且未见拐点">
{g}{tk}{mk}<path d="{path('+1发送')}" class="s-blue"/><path d="{path('其他区号发送')}" class="s-orange"/>
<circle cx="{xs[-1]:.1f}" cy="{y(lv):.1f}" r="4.5" class="dot-orange"/>
<text x="{xs[-1]-8:.1f}" y="{y(lv)-12:.1f}" class="endlab" text-anchor="end">{lv:,}</text></svg>'''


def fill_svg(m):
    W, H, ml = 760, 150, 130
    bw = W - ml - 96
    out = []
    for i, (lab, v, c) in enumerate([("正常美国用户", m["today_us_fill"], "blue"),
                                     ("攻击目标区号", m["today_fill"], "orange")]):
        yy = 34 + i * 62
        out.append(f'<text x="{ml-16}" y="{yy+21}" class="blab" text-anchor="end">{lab}</text>'
                   f'<rect x="{ml}" y="{yy}" width="{bw}" height="30" rx="4" class="track"/>'
                   f'<rect x="{ml}" y="{yy}" width="{max(bw*v/100,3):.1f}" height="30" rx="4" class="bar-{c}"/>'
                   f'<text x="{ml+bw+14}" y="{yy+21}" class="bval-{c}">{v}%</text>')
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="验证码填充率对比，正常用户95%，攻击目标区号0.6%">{''.join(out)}</svg>'''


def _hbar(rows, W=760, ml=124, rlab=104, unit="", cls="bar-orange", hi=None):
    """Generic horizontal bar chart: rows = [(label, value, right_text)]."""
    bw = W - ml - rlab
    mx = max(r[1] for r in rows) or 1
    H = 18 + len(rows) * 30
    out = []
    for i, (lab, v, rt) in enumerate(rows):
        yy = 10 + i * 30
        c = cls if (hi is None or lab in hi) else "bar-blue"
        out.append(f'<text x="{ml-14}" y="{yy+16}" class="blab" text-anchor="end">{lab}</text>'
                   f'<rect x="{ml}" y="{yy}" width="{max(bw*v/mx,2):.1f}" height="21" rx="3" class="{c}"/>'
                   f'<text x="{ml+max(bw*v/mx,2)+9:.1f}" y="{yy+16}" class="bval">{rt}</text>')
    return W, H, "".join(out)


def source_svg(src):
    rows = [(r["来源国家"], r["请求数"], f'{r["请求数"]:,}　{r["占比%"]}%') for _, r in src.iterrows()]
    W, H, body = _hbar(rows, hi={"美国"})
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="攻击来源IP国家分布，巴基斯坦德国美国为前三">{body}</svg>'''


def device_svg(dev, m):
    a = dev[(dev.分组 == "攻击流量") & (dev.机型 != "__iPhone合计__")].head(6)
    rows = [(r["机型"], r["请求数"], f'{r["占比%"]}%') for _, r in a.iterrows()]
    W, H, body = _hbar(rows, ml=132)
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="攻击流量的设备机型全部为低价安卓机，无iPhone">{body}</svg>'''


def daily_recall_svg(byday):
    W, H, ml, mr, mt, mb = 760, 260, 54, 16, 20, 44
    pw, ph = W - ml - mr, H - mt - mb
    n = len(byday)
    ymax = max(byday["黑产(SOP标签)"]) * 1.18
    slot = pw / n
    y = lambda v: mt + ph - ph * v / ymax
    out = []
    for i, r in byday.iterrows():
        cx = ml + slot * (i + .5)
        w = slot * .30
        out.append(f'<rect x="{cx-w-1.5:.1f}" y="{y(r["已拦截"]):.1f}" width="{w:.1f}" height="{mt+ph-y(r["已拦截"]):.1f}" class="bar-good"/>'
                   f'<rect x="{cx+1.5:.1f}" y="{y(r["漏召回(PASS)"]):.1f}" width="{w:.1f}" height="{mt+ph-y(r["漏召回(PASS)"]):.1f}" class="bar-orange"/>'
                   f'<text x="{cx:.1f}" y="{H-mb+18}" class="ax" text-anchor="middle">{r["日期(UTC)"][5:]}</text>'
                   f'<text x="{cx:.1f}" y="{min(y(r["已拦截"]),y(r["漏召回(PASS)"]))-7:.1f}" class="bval" text-anchor="middle">{r["召回%"]}%</text>')
    g = "".join(f'<line x1="{ml}" y1="{y(v):.1f}" x2="{W-mr}" y2="{y(v):.1f}" class="grid"/>'
                f'<text x="{ml-10}" y="{y(v)+4:.1f}" class="ax" text-anchor="end">{v:,}</text>'
                for v in range(1000, int(ymax), 1000))
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="逐日拦截与漏过对比，拦截率长期停在五成上下">{g}{''.join(out)}</svg>'''


def threshold_svg(evas):
    e = evas.sort_values("中位").head(10)
    W, H, ml, mr = 760, 40 + len(e) * 27, 92, 92
    pw = W - ml - mr
    mx = 40.0
    out = []
    for i, (_, r) in enumerate(e.iterrows()):
        yy = 12 + i * 27
        w = pw * r["中位"] / mx
        out.append(f'<text x="{ml-14}" y="{yy+15}" class="blab" text-anchor="end">+{int(r["cc"])}</text>'
                   f'<rect x="{ml}" y="{yy}" width="{w:.1f}" height="19" rx="3" class="bar-blue"/>'
                   f'<text x="{ml+w+9:.1f}" y="{yy+15}" class="bval">中位 {r["中位"]:.0f}</text>')
    tx = ml + pw * 30 / mx
    out.append(f'<line x1="{tx:.1f}" y1="6" x2="{tx:.1f}" y2="{H-24}" stroke="var(--orange)" stroke-width="2"/>'
               f'<text x="{tx+7:.1f}" y="{H-10}" class="lab-m" style="fill:var(--orange);font-size:12px;font-weight:700">现网阈值 &gt;30</text>')
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="各目的区号每小时请求量中位数紧贴现网阈值30">{''.join(out)}</svg>'''


def _pdf_font_css():
    d = os.path.expanduser("~/.fonts")
    return PDF_FONTS % (d, d, d)


NAV = [("summary", "执行摘要"), ("background", "问题背景"), ("timeline", "事件经过"),
       ("impact", "影响评估"), ("evidence", "判定依据"), ("actions", "已采取措施"),
       ("why", "为什么没压住"), ("solution", "解决方案"), ("decide", "待决事项"),
       ("process", "流程改进"), ("caveat", "口径与缺口")]


PDF_FONTS = """
@font-face{font-family:'NotoSC';font-weight:400;src:url('file://%s/NotoSansSC-Regular.otf')}
@font-face{font-family:'NotoSC';font-weight:700;src:url('file://%s/NotoSansSC-Bold.otf')}
@font-face{font-family:'NotoSC';font-weight:900;src:url('file://%s/NotoSansSC-Bold.otf')}
body,.num,.ax,.bval,.endlab,.bval-blue,.bval-orange,.tl .d,.why .wn{font-family:'NotoSC',sans-serif!important}
.nav{display:none}
"""


def render(m, pdf=False, standalone=False):
    up, ca, cb = m["up"], m["cand_a"], m["cand_b"]
    lo, hi = m["cost_day"]
    nav = "".join(f'<a href="#{i}">{t}</a>' for i, t in NAV)
    pre_hits = int(ca["攻击前窗命中"]) + int(cb["攻击前窗命中"])

    part1 = f'''<title>LKUS 短信攻击处置看板</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700;900&family=IBM+Plex+Mono:wght@500;600&display=swap">
<style>{CSS}{_pdf_font_css() if pdf else ""}</style>

<nav class="nav"><div class="nav-in">{nav}</div></nav>
<div class="wrap">

<section id="summary">
  <div class="ribbon">
    <span class="tag">🔴 尚未压制</span>
    <span style="color:var(--ink-2);font-size:14px">攻击仍在上行，未出现拐点</span>
    <span class="day">数据窗口至 2026-09-10 06:32 UTC（北京 14:32）</span>
  </div>
  <header style="margin-top:20px">
    <h1>短信验证码遭黑产刷量 · 第 8 天处置简报</h1>
    <p class="lede">攻击方持续向<b>我们没有客户的国家</b>刷取验证码短信，每条都由公司真实付费。
      当前每天仍有 <b class="num">{_f(m['today_attack'])}</b> 条攻击短信发出，是攻击前日均的
      <b class="num">{m['multiple']}</b> 倍。<b>正常美国用户完全未受影响。</b>
      两条策略已配置完成、等待审批，<b>上线即可把拦截率从 {m['recall_now']}% 提到 {m['recall_after']}%</b>，
      且攻击前 25 天回测对美国真实用户零命中。</p>
    <div class="meta">数据来源：风控请求日志（64 分片源库）+ 短信发送记录，全程只读 · 共 76,764 条风控请求</div>
  </header>
  <div class="kpis" style="margin-top:18px">
    <div class="kpi"><div class="k">每日攻击短信</div><div class="v crit num">{_f(m['today_attack'])}</div>
      <div class="s">攻击前日均 {_f(m['baseline'])} 条 · <b>↑{m['multiple']}倍</b></div></div>
    <div class="kpi"><div class="k">当前拦截率</div><div class="v warn num">{m['recall_now']}%</div>
      <div class="s">仍有 {_f(m['leak_now'])} 条/日漏过</div></div>
    <div class="kpi"><div class="k">估算日损耗</div><div class="v crit num">${_f(lo)}~{_f(hi)}</div>
      <div class="s">估算值 · 口径见文末</div></div>
    <div class="kpi"><div class="k">正常用户影响</div><div class="v good num">0</div>
      <div class="s">验证码填充率稳定 {m['today_us_fill']}%</div></div>
    <div class="kpi"><div class="k">已避免损耗</div><div class="v good num">${_f(m['cost_saved'][0])}~{_f(m['cost_saved'][1])}</div>
      <div class="s">已拦下 {_f(m['blocked_cum'])} 条</div></div>
  </div>
</section>

<section id="background">
  <h2 class="sec">一、问题背景：这是什么攻击</h2>
  <p class="seclede">先回答最容易被误解的一个问题——<b>我们没有被入侵</b>。这是一类叫「短信刷量」
    （SMS Pumping / 话务人为增量 AIT）的欺诈，攻击方滥用的是一个完全正常的业务功能。</p>
  <div class="card">{mechanism_svg()}</div>
  <div class="grid2" style="margin-top:16px">
    <div class="card"><h3>为什么打这些国家</h3>
      <p class="sub" style="margin-bottom:10px">攻击目标高度集中在阿尔及利亚、马拉维、白俄罗斯、塔吉克斯坦、
        纳米比亚、加纳、马里等地——这些不是随机噪音，而是精心挑选的：</p>
      <ul style="margin:0;padding-left:18px;color:var(--ink-2);font-size:13.5px;line-height:1.85">
        <li><b>国际短信结算价高</b>，分成空间大；</li>
        <li><b>电信监管相对宽松</b>，话务分成安排不易被追责；</li>
        <li><b>我们在这些国家没有任何业务</b>，正常情况下几乎不会有验证码请求——
          攻击前这些区号合计每天只有 {_f(m['baseline'])} 条。</li>
      </ul></div>
    <div class="card"><h3>行业背景：这不是个案</h3>
      <p class="sub" style="margin-bottom:10px">用于判断这是行业性风险还是我们独有的运维失误：</p>
      <ul style="margin:0;padding-left:18px;color:var(--ink-2);font-size:13.5px;line-height:1.85">
        <li>国际电信联盟（ITU）已于 <b>2026 年 2 月通过 E.371 建议书</b>，正式定义此类
          「话务人为增量」欺诈；</li>
        <li>行业公开数据显示，约 <b>八分之一的验证码请求为欺诈流量</b>；</li>
        <li>主流短信服务商已把「短信刷量防护」作为独立产品能力提供，
          说明这是普遍存在、需要专门防护的攻击面。</li>
      </ul></div>
  </div>
</section>

<section id="timeline">
  <h2 class="sec">二、事件经过</h2>
  <p class="seclede">时间为 UTC。措施时间取自风控策略表的实际变更记录，不是回忆。</p>
  <div class="card"><ul class="tl">
    <li><div class="d">08-09 ~ 09-02</div><div class="h">攻击前基线（25 天）</div>
      <div class="b">非 +1/+86 区号日均发送 {_f(m['baseline'])} 条（区间 {m['base_lo']}~{m['base_hi']}），
        验证码填充率约 24%，属正常水平。</div></li>
    <li class="hot"><div class="d">09-03</div><div class="h">攻击起量</div>
      <div class="b">非 +1/+86 发送量跳到 273 条，为基线的 {273/m['baseline']:.1f} 倍。填充率同步掉到 8.1%。</div></li>
    <li><div class="d">09-03 ~ 09-04</div><div class="h">上调既有速度类策略</div>
      <div class="b">09-03 有 8 条频次类策略被启用，09-04 再启用 1 条；同日把两条最有效的
        「单区号日频次」策略配置为<b>观察状态（已配置但未生效）</b>。</div></li>
    <li class="hot"><div class="d">09-04 ~ 09-05</div><div class="h">攻击量翻倍</div>
      <div class="b">日发送量 1,211 → 1,648 条，填充率跌破 2%，确认为刷量而非真实需求。</div></li>
    <li class="hot"><div class="d">09-05 ~ 09-08</div><div class="h">新增上线策略 0 条</div>
      <div class="b">这 4 天内没有新的防护策略生效，攻击量继续爬升至 2,076 条/日。</div></li>
    <li><div class="d">09-09</div><div class="h">上线 2 条新策略</div>
      <div class="b">其中一条按「来源国家不是美国」过滤——但攻击方已有 {m['us_ip_share']}% 的流量走美国机房代理，
        这部分被设计性放过。当日攻击量仍创新高 {_f(m['today_attack'])} 条。</div></li>
    <li class="hot"><div class="d">09-10（当前）</div><div class="h">尚未压制</div>
      <div class="b">拦截率 {m['recall_now']}%，每日仍有 {_f(m['leak_now'])} 条漏过并实际发出。</div></li>
  </ul></div>
</section>

<section id="impact">
  <h2 class="sec">三、影响评估</h2>
  <p class="seclede">两个维度：花了多少钱，以及有没有伤到真实用户。</p>
  <div class="card">
    <h3>攻击短信量仍在上行</h3>
    <p class="sub">每日实际发出的验证码短信条数。9/9 新策略生效当天，攻击量仍创新高。</p>
    {trend_svg(up)}
    <div class="legend"><span><i style="background:var(--blue)"></i>正常美国用户（+1）</span>
      <span><i style="background:var(--orange)"></i>攻击目标区号（其他国家）</span></div>
  </div>
  <div class="grid2" style="margin-top:16px">
    <div class="card"><h3>成本影响（估算）</h3>
      <div class="tblwrap"><table style="min-width:auto"><tbody>
        <tr><td>当前日损耗</td><td class="num" style="text-align:right;color:var(--crit);font-weight:700">${_f(lo)} ~ ${_f(hi)}</td></tr>
        <tr><td>09-03 起累计已发出（{_f(m['sent_cum'])} 条）</td><td class="num" style="text-align:right">${_f(m['cost_cum'][0])} ~ ${_f(m['cost_cum'][1])}</td></tr>
        <tr><td>同期已拦截（{_f(m['blocked_cum'])} 条）</td><td class="num" style="text-align:right;color:var(--good);font-weight:700">已避免 ${_f(m['cost_saved'][0])} ~ ${_f(m['cost_saved'][1])}</td></tr>
        <tr><td>若不处置，按当前量续 30 天</td><td class="num" style="text-align:right;color:var(--crit);font-weight:700">${_f(m['cost_month'][0])} ~ ${_f(m['cost_month'][1])}</td></tr>
        <tr><td>启用待批策略后，每月可减少</td><td class="num" style="text-align:right;color:var(--good);font-weight:700">${_f(m['save_month'][0])} ~ ${_f(m['save_month'][1])}</td></tr>
      </tbody></table></div>
      <p style="margin:12px 0 0;font-size:12.5px;color:var(--ink-3)">金额为<b>估算值</b>，单价假设 ${UNIT_LO}~${UNIT_HI}/条，详见文末口径说明。</p>
    </div>
    <div class="card"><h3>用户影响：无</h3>
      <p class="sub">正常美国用户的发送量与验证码填充率在整个攻击期间保持稳定，
        当前拦截策略也未误拦任何正常用户。</p>
      <div class="tblwrap"><table style="min-width:auto"><tbody>
        <tr><td>+1 用户日发送量</td><td class="num" style="text-align:right">{_f(m['today_us_send'])} 条（稳定 900~1,400）</td></tr>
        <tr><td>+1 验证码填充率</td><td class="num" style="text-align:right;color:var(--good);font-weight:700">{m['today_us_fill']}%（全程 94~98%）</td></tr>
        <tr><td>命中样本中误拦正常用户</td><td class="num" style="text-align:right;color:var(--good);font-weight:700">0 条</td></tr>
        <tr><td>待批策略攻击前 25 天回测</td><td class="num" style="text-align:right;color:var(--good);font-weight:700">命中 {_f(pre_hits)} 条，美国用户 0 条</td></tr>
      </tbody></table></div>
    </div>
  </div>
</section>
'''

    part2 = f'''
<section id="evidence">
  <h2 class="sec">四、判定依据：凭什么确定是黑产</h2>
  <p class="seclede">按风控 SOP，<b>不得凭单一特征定性，需 ≥2 类独立特征交叉印证</b>。
    本次命中样本满足 4 类，逐项列出如下。命中样本中判为「正常用户」的为 0 条。</p>

  <div class="grid2">
    <div class="card"><h3>证据一：短信发出去没有任何人使用</h3>
      <p class="sub">「填充率」＝ 收到短信后真正输入了验证码的比例。这是最直接的一条：
        正常用户几乎都会输入，攻击方从不输入——因为他们要的不是验证码本身。</p>
      {fill_svg(m)}
      <div class="legend"><span>数据日期 2026-09-09 · 攻击前该指标约 24%，攻击开始后塌到 1% 以下</span></div>
    </div>
    <div class="card"><h3>证据二：设备画像与真实用户完全不同</h3>
      <p class="sub">攻击流量的机型清一色是在美国市场几乎没有零售存在的低价安卓机；
        而真实美国用户中 iPhone 占 <b>{m['iphone_p1']}%</b>，攻击流量中只有 <b>{m['iphone_atk']}%</b>。</p>
      {device_svg(m['dev'], m)}
      <div class="legend"><span>攻击流量机型 TOP6 · 同期正常美国用户 iPhone 占 {m['iphone_p1']}%</span></div>
    </div>
  </div>

  <div class="grid2" style="margin-top:16px">
    <div class="card"><h3>证据三：来源集中在少数几个境外出口</h3>
      <p class="sub">按来源 IP 国家统计（09-04 起）。值得注意的是<b>美国机房代理已占 {m['us_ip_share']}%</b>——
        攻击方在换出口，这也是 9/9 那条按国家过滤的策略失效的原因。</p>
      {source_svg(m['src'])}
      <div class="legend"><span><i style="background:var(--blue)"></i>美国机房代理（被现有策略设计性放过）
        　<i style="background:var(--orange)"></i>其他来源</span></div>
    </div>
    <div class="card"><h3>证据四：资源聚集与行为异常</h3>
      <p class="sub">同一台机器批量操作多个号码，且从不做验证码之外的任何事。</p>
      <div class="tblwrap"><table style="min-width:auto">
        <thead><tr><th>特征</th><th style="text-align:right">攻击流量</th><th style="text-align:right">正常用户</th></tr></thead>
        <tbody>
          <tr><td>一个 IP 关联 &gt;3 个手机号的比例</td>
            <td class="num" style="text-align:right;color:var(--crit);font-weight:700">{m['us_ip_multi']}%</td>
            <td class="num" style="text-align:right;color:var(--good)">{m['p1_ip_multi']}%</td></tr>
          <tr><td>只调短信接口、从不登录下单的比例</td>
            <td class="num" style="text-align:right;color:var(--crit);font-weight:700">{m['us_pushonly']}%</td>
            <td class="num" style="text-align:right;color:var(--good)">{m['p1_pushonly']}%</td></tr>
          <tr><td>iPhone 占比</td>
            <td class="num" style="text-align:right;color:var(--crit);font-weight:700">{m['iphone_atk']}%</td>
            <td class="num" style="text-align:right;color:var(--good)">{m['iphone_p1']}%</td></tr>
          <tr><td>验证码填充率</td>
            <td class="num" style="text-align:right;color:var(--crit);font-weight:700">{m['today_fill']}%</td>
            <td class="num" style="text-align:right;color:var(--good)">{m['today_us_fill']}%</td></tr>
        </tbody></table></div>
      <p style="margin:12px 0 0;font-size:12.5px;color:var(--ink-3)">
        另有：32.6% 的号码在 24 小时内被 ≥2 个不同国家的 IP 请求过；
        美国侧 IP 集中在德州 Plano / Richardson 等机房网段，非住宅宽带。</p>
    </div>
  </div>
</section>

<section id="actions">
  <h2 class="sec">五、已采取的措施与当前效果</h2>
  <p class="seclede">措施是有效果的——已拦下 {_f(m['blocked_cum'])} 条，避免了对应成本。
    但拦截率长期停在五成上下，没有随时间改善。</p>
  <div class="card">
    <h3>逐日拦截与漏过</h3>
    <p class="sub">柱上百分比为当日拦截率。可以看到 09-05 之后拦截率基本横盘，说明现有规则已经到顶。</p>
    {daily_recall_svg(m['byday'])}
    <div class="legend"><span><i style="background:var(--good)"></i>已拦截</span>
      <span><i style="background:var(--orange)"></i>漏过并实际发出</span></div>
  </div>
</section>

<section id="why">
  <h2 class="sec">六、为什么还没压住</h2>
  <p class="seclede">三条原因都来自数据核查，按影响排序。</p>
  <div class="why">
    <div class="w"><div class="wn">30.1%</div><div class="wt">攻击贴着我们的阈值跑</div>
      <div class="wd">现网主力规则是「单区号每小时超过 30 次」才拦。实测攻击把每个区号每小时压在
        24~33 次，紧贴阈值——三成攻击请求根本碰不到这条规则。<b>把阈值降到 15 即可压到 5.3%。</b></div></div>
    <div class="w"><div class="wn">{m['us_ip_share']}%</div><div class="wt">新策略方向漏掉了美国 IP</div>
      <div class="wd">9/9 上线的策略按「来源国家不是美国」过滤，而攻击方已有 {m['us_ip_share']}% 的请求
        来自美国机房代理，<b>被设计性放过</b>。经四类特征交叉确认，是同一伙攻击方换了出口。</div></div>
    <div class="w"><div class="wn">6 天</div><div class="wt">最有效的策略一直没生效</div>
      <div class="wd">两条最有效的策略 9/4 就已配置完成，但一直停在<b>「已配置但未生效」</b>的观察状态。
        它们一条就能补回 {ca['占漏召回%']}% 的漏拦量，且攻击前回测零误拦。</div></div>
  </div>
  <div class="card" style="margin-top:16px">
    <h3>攻击是按我们的阈值校准过的</h3>
    <p class="sub">各目的区号每小时请求量的中位数，与现网阈值 30 的关系。这种贴合不是巧合。</p>
    {threshold_svg(m['evas'])}
    <div class="legend"><span>48.4% 的（区号,小时）组合 ≤30 次，承载了 30.1% 的攻击请求</span></div>
  </div>
</section>
'''

    part3 = f'''
<section id="solution">
  <h2 class="sec">七、解决方案详解</h2>
  <p class="seclede">每条措施说明<b>做什么、针对攻击的哪个特征、预期效果、风险</b>，
    便于判断该不该批。前两条不需要新开发，策略已经配置好了。</p>

  <div class="sol">
    <h4><span class="pill p-now">立即</span> 方案一 · 启用两条已配置的「单区号日频次」策略</h4>
    <dl>
      <dt>做什么</dt><dd>把两条已配置但停在观察状态的策略正式启用：对<b>单个国家区号一天内请求次数超过阈值</b>的流量直接拦截（分别覆盖高风险名单内与名单外的区号）。</dd>
      <dt>为什么有效</dt><dd>攻击方能把<b>每小时</b>频次压到阈值以下，但<b>一整天</b>的总量压不下来——他们要的就是量。这条规则打的正是这个软肋，且与来源 IP 国家无关，<b>美国机房代理同样会被拦到</b>。</dd>
      <dt>预期效果</dt><dd>拦截率 <b class="num">{m['recall_now']}% → {m['recall_after']}%</b>；每日漏出从 {_f(m['leak_now'])} 条降到约 <b class="num">{_f(m['resid_day'])}</b> 条；每月减少损耗约 <b class="num">${_f(m['save_month'][0])}~{_f(m['save_month'][1])}</b>。</dd>
      <dt>风险</dt><dd><b>极低。</b>用攻击前 25 天的真实流量回测，两条策略合计命中 {_f(pre_hits)} 条，其中<b>美国真实用户 0 条</b>、判为正常用户 2 条。</dd>
      <dt>需要谁</dt><dd>田志鲔配置 · <b>段枝宏审批</b>（因场景调用量低于 SOP 绝对门槛，需走应急审批）</dd>
    </dl>
  </div>

  <div class="sol">
    <h4><span class="pill p-now">立即</span> 方案二 · 下调单区号小时频次阈值（30 → 15）</h4>
    <dl>
      <dt>做什么</dt><dd>把现网两条主力规则的触发阈值从「每小时 &gt;30 次」下调到「&gt;15 次」。</dd>
      <dt>为什么有效</dt><dd>实测攻击方把每区号每小时刻意压在 <b>24~33 次</b>，正好骑在 30 这条线上。阈值不动，这部分流量永远碰不到规则。</dd>
      <dt>预期效果</dt><dd>可规避该规则的攻击请求从 <b class="num">30.1% → 5.3%</b>。</dd>
      <dt>风险</dt><dd><b>低。</b>攻击前正常流量中，单区号每小时请求量的 P99 远低于 15，正常用户几乎不可能触及。</dd>
      <dt>需要谁</dt><dd>田志鲔配置 · <b>段枝宏审批</b></dd>
    </dl>
  </div>

  <div class="sol" style="border-left-color:var(--warn)">
    <h4><span class="pill p-next">24 小时内</span> 方案三 · 短信通道加地域权限与限额</h4>
    <dl>
      <dt>做什么</dt><dd>在短信服务商侧，对<b>我们没有业务的国家</b>关闭国际下发权限，或设置每日发送上限。</dd>
      <dt>为什么有效</dt><dd>这是<b>唯一不依赖风控命中率的措施</b>。风控是概率性的，总会有漏网；通道限额是确定性的，超了就是发不出去。</dd>
      <dt>预期效果</dt><dd>对已关闭的国家，成本<b>直接归零</b>，且不受攻击方后续变换手法影响。</dd>
      <dt>风险</dt><dd>需业务侧确认这些国家确无真实用户。可先设日限额（而非直接关闭）作为过渡。</dd>
      <dt>需要谁</dt><dd>upush 侧执行 · <b>需跨团队协调</b></dd>
    </dl>
  </div>

  <div class="sol" style="border-left-color:var(--ink-3)">
    <h4><span class="pill p-ok">排期</span> 方案四 · 补齐设备与网关维度的识别能力</h4>
    <dl>
      <dt>做什么</dt><dd>新增两类风控特征：同一网关标识近 60 分钟关联的手机号个数、同一 IP 段近 60 分钟关联的手机号个数。</dd>
      <dt>为什么有效</dt><dd>现有规则<b>完全没有设备/网关维度</b>，攻击方正是靠单点频次压低、横向铺开来规避。实测最大的一个网关标识关联了 277 个手机号、93 个 IP、跨 3 个国家——现有规则对此毫无感知。</dd>
      <dt>预期效果</dt><dd>覆盖「低频但横向铺开」这一整类规避手法，属长期能力建设。</dd>
      <dt>风险</dt><dd>无（新增观察指标，先观察后启用）。</dd>
      <dt>需要谁</dt><dd>风控平台研发排期</dd>
    </dl>
  </div>
</section>

<section id="decide">
  <h2 class="sec">八、待决事项</h2>
  <p class="seclede">这是需要管理层动作的部分。前两项批准后 2 小时内即可生效。</p>
  <div class="card"><div class="tblwrap"><table>
    <thead><tr><th>优先级</th><th>动作</th><th>预期效果</th><th>误拦正常用户风险</th><th>执行 / 审批</th></tr></thead>
    <tbody>
      <tr><td><span class="pill p-now">立即</span></td>
        <td><b>启用两条已配置策略</b><br><span style="color:var(--ink-2)">「单区号日频次」规则</span></td>
        <td>拦截率 <b class="num">{m['recall_now']}% → {m['recall_after']}%</b><br>日漏出降至约 <span class="num">{_f(m['resid_day'])}</span> 条</td>
        <td><b>极低</b>：攻击前 25 天回测命中 <span class="num">{_f(pre_hits)}</span> 条，美国真实用户 <b class="num">0</b> 条</td>
        <td>田志鲔配置<br><b>段枝宏审批</b></td></tr>
      <tr><td><span class="pill p-now">立即</span></td>
        <td><b>下调单区号频次阈值</b><br><span style="color:var(--ink-2)">每小时 30 次 → 15 次</span></td>
        <td>可规避流量 <b class="num">30.1% → 5.3%</b></td>
        <td><b>低</b>：攻击前正常流量几乎从未触及 15 次/小时</td>
        <td>田志鲔配置<br><b>段枝宏审批</b></td></tr>
      <tr><td><span class="pill p-next">24 小时内</span></td>
        <td><b>短信通道加地域限制</b><br><span style="color:var(--ink-2)">对零业务量国家关闭国际下发或设日限额</span></td>
        <td><b>唯一能把成本直接压到 0 的动作</b><br>不依赖风控命中率</td>
        <td>需业务确认这些国家确无真实用户</td>
        <td>upush 侧<br><b>需协调</b></td></tr>
      <tr><td><span class="pill p-next">24 小时内</span></td>
        <td>配置攻击复发告警</td>
        <td>复发后 1 小时内发现<br><span style="color:var(--ink-2)">三条阈值：小时请求量 &gt;300、非美区号占比 &gt;90%、日发送量 &gt;150</span></td>
        <td>无</td><td>DBA 团队</td></tr>
      <tr><td><span class="pill p-ok">排期</span></td>
        <td>补充设备与网关维度识别能力</td>
        <td>覆盖「低频横向铺开」整类手法</td><td>无</td><td>风控平台研发</td></tr>
    </tbody></table></div></div>
</section>

<section id="process">
  <h2 class="sec">九、流程改进建议</h2>
  <p class="seclede">以下为对事不对人的机制性建议——本次处置中，技术判断没有出错，
    但有几个环节让有效措施迟迟没能落地。</p>
  <div class="card"><div class="tblwrap"><table>
    <thead><tr><th>观察到的现象</th><th>影响</th><th>建议</th></tr></thead>
    <tbody>
      <tr><td>两条最有效的策略在「已配置但未生效」状态停留 <b>6 天</b></td>
        <td>自 09-04 配置完成起，累计发出约 {_f(m['sent_since_cfg'])} 条攻击短信</td>
        <td>应急期为观察状态设定<b>时长上限与到期自动提醒</b>，超时未决需上报</td></tr>
      <tr><td>09-05 ~ 09-08 连续 <b>4 天</b>新增生效策略 0 条</td>
        <td>攻击量在这 4 天从 1,648 爬到 2,076 条/日，与国内「24 小时内压制」的标准存在差距</td>
        <td>明确应急响应的<b>时限与授权路径</b>，应急期可先降级为观察拦截再补审批</td></tr>
      <tr><td>风控特征名在攻击期间被改动，<b>无变更留痕</b></td>
        <td>按名字取数会静默丢数据，本次分析首轮即因此得出过错误结论</td>
        <td>特征目录纳入<b>变更管理</b>，改名需通知下游分析与策略配置方</td></tr>
      <tr><td>短信通道的<b>单条价格未入库</b>（仅部分通道有）</td>
        <td>成本只能估算，无法精确核算损失与 ROI</td>
        <td>补齐计费字段，或建立与服务商账单的定期对账</td></tr>
      <tr><td>攻击持续 8 天，<b>无自动告警</b>，靠人工发现</td>
        <td>发现与响应都滞后</td>
        <td>落地上表中的三条监控阈值（已列入待决事项）</td></tr>
    </tbody></table></div></div>
</section>

<section id="caveat">
  <h2 class="sec">十、口径说明与已知缺口</h2>
  <div class="note">
    <b>关于成本数字（请注意）：</b>攻击流量全部走 Twilio 通道，而<b>该通道的每条单价数据库中未记录</b>
    （仅 AWS 通道有记录），因此本文所有金额为<b>估算值</b>，按<b>单价 ${UNIT_LO}~${UNIT_HI}/条</b>测算。
    上限参考行业公开基准（某防护厂商 2025 年数据集拦截 2,430 万条黑产验证码请求、避免约 326 万美元成本，
    折合约 $0.134/条）。<b>精确金额需以 Twilio 账单为准，建议同步向财务 / upush 侧调取 9 月账单核实。</b>
  </div>
  <div class="card" style="margin-top:14px">
    <h3>已知缺口（如实列出）</h3>
    <ul style="margin:0;padding-left:18px;color:var(--ink-2);font-size:13.5px;line-height:1.85">
      <li><b>数据为快照</b>：截至 2026-09-10 06:32 UTC。若待批策略已上线，「尚未压制」这一结论需重新评估。</li>
      <li><b>成本为估算</b>：见上方口径说明，拿到账单后应替换。</li>
      <li><b>客诉信号未核实</b>：本次分析无法接触客诉系统，「零误拦」结论基于风控样本判定与回测，
        未与真实客诉数据交叉验证。</li>
      <li><b>攻击方可能继续变换手法</b>：本次已观察到从境外 IP 转向美国机房代理，
        后续可能转向新的区号、通道或客户端版本，需持续观察。</li>
    </ul>
  </div>
  <details style="margin-top:14px" open>
    <summary>附录：技术细节与详细报告（供风控 / DBA 下钻）</summary>
    <ul>
      <li><b>判定标准</b>：遵循风控 SOP —— 需 ≥2 类独立特征交叉印证；单一特征一律标注「暂无法判断」，
        未计入黑产。命中样本 {_f(m['black_total'])} 条中误拦正常用户 0 条。</li>
      <li><b>涉及策略</b>：建议启用的两条为 <code>strategy_MGj5bfGOijOi</code>、<code>strategy_x37TInaHsvPQ</code>；
        9/9 已上线的为 <code>strategy_uKSgJAVWhWlU</code>；待评估的为 <code>strategy_ARqkLD7E3JaK</code>。
        另有一条 <code>strategy_aEw2XWL4QIYx</code> 看似增量召回高，但无区号护栏、
        攻击前窗口会打到 881 个真实美国用户，<b>已明确不建议上线</b>。</li>
      <li><b>「攻击集中在非营业时段」这一说法已撤回</b>：实测攻击 7×24 全天候，
        美东 14–18 点低谷仍占 8.8%。已改为三条监控告警阈值。</li>
      <li><b>数据口径提醒</b>：风控特征名在 8/27–9/5 期间被改动过，按字面名字取数会静默丢失整段数据。
        分析管道已改为按结构取数。</li>
      <li><b>详细报告</b>：9 份技术报告 + 7 张图 + 19 份明细 CSV，见 <code>github.com/xiangyuzeng/info</code>。
        评估管道可复跑：<code>python -m sms_attack.evaluate --strategy &lt;策略ID&gt; --window 5h</code>。</li>
    </ul>
  </details>
</section>

<footer>瑞幸咖啡北美 · 信息安全 / 数据库团队 · 本看板由风控源库数据自动生成，数字可追溯至明细 CSV</footer>
</div>'''
    doc = part1 + part2 + part3
    if standalone:
        head, _, tail = doc.partition("<nav class=")
        doc = ('<!doctype html>\n<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n'
               '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
               + head + "</head>\n<body>\n<nav class=" + tail
               + "\n</body>\n</html>")
    return doc


def main():
    m = load_all()
    html = render(m)
    with open(OUT_HTML, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote {OUT_HTML}  ({len(html):,} chars)")
    print(f"  攻击 {m['today_attack']:,}/天 · 基线 {m['baseline']:.0f} · {m['multiple']}x · "
          f"拦截 {m['recall_now']}% · 漏 {m['leak_now']:,}")


if __name__ == "__main__":
    main()


def build_standalone(path=None):
    """A single self-contained .html the user can attach to an email / Feishu message.

    Deliberately NOT a PDF: this container has no browser and its text stack cannot
    shape CJK, so every PDF it renders drops Chinese glyphs. Opening this file and
    pressing Ctrl/Cmd+P produces a correct PDF in one step -- print CSS is included.
    Chinese renders offline via the system stack (PingFang SC / Microsoft YaHei);
    the Google Fonts link is only an online upgrade.
    """
    m = load_all()
    html = render(m, standalone=True)
    path = path or os.path.join(F.OUT, "LKUS短信攻击处置简报.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote {path}  ({os.path.getsize(path):,} bytes)")
    return path
