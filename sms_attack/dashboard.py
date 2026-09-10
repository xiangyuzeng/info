"""Render the management-facing one-page dashboard from out/data/*.csv.

Audience: China HQ security / tech management. They read four things:
how much is it costing, are real users hurt, is it contained, what do I approve.
Everything else belongs in the technical reports.

    python -m sms_attack.dashboard
"""
import os

import pandas as pd

from . import figures as F

OUT_HTML = os.path.join(F.OUT, "mgmt_dashboard.html")

# Data colours: validated categorical slots (light/dark pairs).
BLUE, BLUE_D = "#2a78d6", "#3987e5"      # 正常用户
ORANGE, ORANGE_D = "#eb6834", "#d95926"  # 攻击流量

UNIT_LO, UNIT_HI = 0.03, 0.13            # USD per international OTP SMS (assumption)


def _f(n):
    return f"{n:,.0f}"


def load_all():
    up = pd.read_csv(os.path.join(F.OUT_DATA, "06_upush_daily.csv"))
    up = up[up["日期"] < "2026-09-10"].reset_index(drop=True)      # drop partial day
    rc = pd.read_csv(os.path.join(F.OUT_DATA, "02_recall.csv"))
    cand = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv")).set_index("策略")
    coh = pd.read_csv(os.path.join(F.OUT_DATA, "03_cohort_profile.csv")).set_index("cohort")
    dv = pd.read_csv(os.path.join(F.OUT_DATA, "01_daily_overview.csv"))
    curve = pd.read_csv(os.path.join(F.OUT_DATA, "04_threshold_curve.csv"))

    atk = dv[(dv.date_utc >= "2026-09-03") & (dv.date_utc <= "2026-09-09")].copy()
    atk["rej"] = atk["非1_86调用"] - atk["非1_86_PASS"]
    base = up[(up["日期"] >= "2026-08-27") & (up["日期"] <= "2026-09-02")]["其他区号发送"]
    last = up.iloc[-1]

    m = {
        "up": up, "curve": curve,
        "today_attack": int(last["其他区号发送"]),
        "today_fill": float(last["其他区号填充率%"]),
        "today_us_fill": float(last["+1填充率%"]),
        "today_us_send": int(last["+1发送"]),
        "baseline": float(base.mean()),
        "baseline_lo": int(base.min()), "baseline_hi": int(base.max()),
        "sent_cum": int(up[(up["日期"] >= "2026-09-03")]["其他区号发送"].sum()),
        "blocked_cum": int(atk["rej"].sum()),
        "recall_now": float(rc.iloc[1]["ONLINE召回%"]),
        "leak_now": int(rc.iloc[1]["漏召回(PASS)"]),
        "recall_after": 95.2,
        "us_ip_share": round(coh.loc["美国IP·非+1/+86", "请求数"] /
                             (coh.loc["美国IP·非+1/+86", "请求数"] +
                              coh.loc["非美国IP·非+1/+86", "请求数"]) * 100, 1),
        "cand_a": cand.loc["strategy_MGj5bfGOijOi"],
        "cand_b": cand.loc["strategy_x37TInaHsvPQ"],
    }
    m["multiple"] = round(m["today_attack"] / m["baseline"], 1)
    m["cost_day"] = (m["today_attack"] * UNIT_LO, m["today_attack"] * UNIT_HI)
    m["cost_cum"] = (m["sent_cum"] * UNIT_LO, m["sent_cum"] * UNIT_HI)
    m["cost_saved"] = (m["blocked_cum"] * UNIT_LO, m["blocked_cum"] * UNIT_HI)
    m["cost_month"] = (m["today_attack"] * 30 * UNIT_LO, m["today_attack"] * 30 * UNIT_HI)
    resid = m["today_attack"] * (1 - m["recall_after"] / 100) / (1 - m["recall_now"] / 100)
    m["resid_day"] = resid
    m["save_month"] = ((m["today_attack"] - resid) * 30 * UNIT_LO,
                       (m["today_attack"] - resid) * 30 * UNIT_HI)
    return m


# ---------------------------------------------------------------- charts
def trend_svg(up):
    """Daily SMS actually delivered: legitimate +1 vs attack traffic."""
    W, H = 720, 290
    ml, mr, mt, mb = 52, 16, 18, 40
    pw, ph = W - ml - mr, H - mt - mb
    ys = list(up["+1发送"]) + list(up["其他区号发送"])
    ymax = max(ys) * 1.12
    n = len(up)
    xs = [ml + pw * i / (n - 1) for i in range(n)]

    def y(v):
        return mt + ph - ph * v / ymax

    def path(col):
        return " ".join(("M" if i == 0 else "L") + f"{xs[i]:.1f},{y(v):.1f}"
                        for i, v in enumerate(up[col]))

    grid, labels = [], []
    for gv in range(0, int(ymax), 500):
        if gv == 0:
            continue
        grid.append(f'<line x1="{ml}" y1="{y(gv):.1f}" x2="{W-mr}" y2="{y(gv):.1f}" class="grid"/>')
        labels.append(f'<text x="{ml-10}" y="{y(gv)+4:.1f}" class="ax" text-anchor="end">{gv:,}</text>')
    xticks = []
    for i, d in enumerate(up["日期"]):
        if i % 3 == 0 or i == n - 1:
            xticks.append(f'<text x="{xs[i]:.1f}" y="{H-mb+20}" class="ax" text-anchor="middle">{d[5:]}</text>')

    marks = []
    for day, txt in [("2026-09-03", "9/3 攻击起量"), ("2026-09-09", "9/9 新策略生效")]:
        if day in list(up["日期"]):
            i = list(up["日期"]).index(day)
            marks.append(f'<line x1="{xs[i]:.1f}" y1="{mt}" x2="{xs[i]:.1f}" y2="{mt+ph}" class="mark"/>')
            anchor = "end" if day.endswith("09") else "start"
            dx = -6 if anchor == "end" else 6
            marks.append(f'<text x="{xs[i]+dx:.1f}" y="{mt+12}" class="markt" text-anchor="{anchor}">{txt}</text>')

    last_i, last_v = n - 1, up["其他区号发送"].iloc[-1]
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="每日实发短信趋势：攻击流量自 9/3 起飙升">
  {''.join(grid)}{''.join(labels)}{''.join(xticks)}{''.join(marks)}
  <path d="{path('+1发送')}" class="s-blue"/>
  <path d="{path('其他区号发送')}" class="s-orange"/>
  <circle cx="{xs[last_i]:.1f}" cy="{y(last_v):.1f}" r="4.5" class="dot-orange"/>
  <text x="{xs[last_i]-8:.1f}" y="{y(last_v)-12:.1f}" class="endlab" text-anchor="end">{last_v:,}</text>
</svg>'''


def fill_svg(m):
    """Verification-code fill rate: the single clearest proof this is fraud, not demand."""
    W, H = 720, 150
    ml = 128
    bw = W - ml - 96
    rows = [("正常美国用户", m["today_us_fill"], "blue"), ("攻击目标区号", m["today_fill"], "orange")]
    out = []
    for i, (lab, v, c) in enumerate(rows):
        yy = 34 + i * 62
        out.append(f'<text x="{ml-16}" y="{yy+21}" class="blab" text-anchor="end">{lab}</text>')
        out.append(f'<rect x="{ml}" y="{yy}" width="{bw}" height="30" rx="4" class="track"/>')
        out.append(f'<rect x="{ml}" y="{yy}" width="{max(bw*v/100,3):.1f}" height="30" rx="4" class="bar-{c}"/>')
        out.append(f'<text x="{ml+bw+14}" y="{yy+21}" class="bval-{c}">{v}%</text>')
    return f'''<svg viewBox="0 0 {W} {H}" class="chart" role="img" aria-label="验证码填充率对比：正常用户 95%，攻击目标区号 0.6%">
  {''.join(out)}
</svg>'''


# ---------------------------------------------------------------- page
def render(m):
    up = m["up"]
    ca, cb = m["cand_a"], m["cand_b"]
    lo, hi = m["cost_day"]
    return f'''<title>LKUS 短信攻击处置看板</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700;900&family=IBM+Plex+Mono:wght@500;600&display=swap">
<style>
:root {{
  --ground:#F2F4F7; --surface:#FFFFFF; --surface-2:#F7F9FB;
  --ink:#16243A; --ink-2:#5A6678; --ink-3:#8A94A3;
  --line:#DFE4EB; --navy:#1F3864; --on-navy:#FFFFFF;
  --crit:#C0342E; --good:#1E7A4C; --warn:#B8730F;
  --blue:{BLUE}; --orange:{ORANGE};
  --crit-bg:#FBEDEC; --good-bg:#EAF5EF; --warn-bg:#FDF4E6;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --ground:#11151C; --surface:#181D26; --surface-2:#1E242F;
    --ink:#EEF2F7; --ink-2:#A7B2C1; --ink-3:#77828F;
    --line:#2C3542; --navy:#8FB0E0; --on-navy:#0E1319;
    --crit:#F08C86; --good:#63C795; --warn:#E5A548;
    --blue:{BLUE_D}; --orange:{ORANGE_D};
    --crit-bg:#2E1B1A; --good-bg:#152B21; --warn-bg:#2C2213;
  }}
}}
:root[data-theme="dark"] {{
  --ground:#11151C; --surface:#181D26; --surface-2:#1E242F;
  --ink:#EEF2F7; --ink-2:#A7B2C1; --ink-3:#77828F;
  --line:#2C3542; --navy:#8FB0E0; --on-navy:#0E1319;
  --crit:#F08C86; --good:#63C795; --warn:#E5A548;
  --blue:{BLUE_D}; --orange:{ORANGE_D};
  --crit-bg:#2E1B1A; --good-bg:#152B21; --warn-bg:#2C2213;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--ground);color:var(--ink);
  font-family:"Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px 20px 64px;display:flex;flex-direction:column;gap:20px}}
.num{{font-family:"IBM Plex Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums}}

.ribbon{{display:flex;flex-wrap:wrap;align-items:center;gap:12px;
  background:var(--crit-bg);border:1px solid var(--crit);border-left-width:5px;
  border-radius:8px;padding:14px 18px}}
.ribbon .tag{{font-weight:900;color:var(--crit);font-size:15px;letter-spacing:.02em}}
.ribbon .day{{margin-left:auto;color:var(--ink-2);font-size:13px}}

header h1{{margin:0;font-size:27px;font-weight:900;letter-spacing:-.01em;text-wrap:balance}}
header .lede{{margin:10px 0 0;font-size:16px;color:var(--ink-2);max-width:64ch}}
header .lede b{{color:var(--ink);font-weight:700}}
.meta{{margin-top:10px;font-size:12.5px;color:var(--ink-3)}}

.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));gap:12px}}
.kpi{{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:14px 16px}}
.kpi .k{{font-size:12px;color:var(--ink-2);letter-spacing:.04em}}
.kpi .v{{font-size:27px;font-weight:700;margin-top:6px;line-height:1.15}}
.kpi .s{{font-size:12.5px;color:var(--ink-3);margin-top:4px}}
.v.crit{{color:var(--crit)}} .v.good{{color:var(--good)}} .v.warn{{color:var(--warn)}}

.card{{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:20px 22px}}
.card h2{{margin:0 0 4px;font-size:17px;font-weight:700}}
.card .sub{{margin:0 0 16px;font-size:13px;color:var(--ink-2)}}
.chart{{width:100%;height:auto;display:block}}
.grid{{stroke:var(--line);stroke-width:1}}
.ax{{fill:var(--ink-3);font-size:11px;font-family:"IBM Plex Mono",monospace}}
.mark{{stroke:var(--ink-3);stroke-width:1;stroke-dasharray:3 3}}
.markt{{fill:var(--ink-2);font-size:11px}}
.s-blue{{fill:none;stroke:var(--blue);stroke-width:2;stroke-linejoin:round}}
.s-orange{{fill:none;stroke:var(--orange);stroke-width:2.5;stroke-linejoin:round}}
.dot-orange{{fill:var(--orange);stroke:var(--surface);stroke-width:2}}
.endlab{{fill:var(--ink);font-size:13px;font-weight:700;font-family:"IBM Plex Mono",monospace}}
.track{{fill:var(--surface-2);stroke:var(--line)}}
.bar-blue{{fill:var(--blue)}} .bar-orange{{fill:var(--orange)}}
.blab{{fill:var(--ink-2);font-size:13px}}
.bval-blue{{fill:var(--blue);font-size:19px;font-weight:700;font-family:"IBM Plex Mono",monospace}}
.bval-orange{{fill:var(--orange);font-size:19px;font-weight:700;font-family:"IBM Plex Mono",monospace}}
.legend{{display:flex;gap:18px;margin-top:12px;font-size:12.5px;color:var(--ink-2);flex-wrap:wrap}}
.legend i{{display:inline-block;width:14px;height:3px;border-radius:2px;vertical-align:middle;margin-right:6px}}

.why{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}}
.why .w{{background:var(--surface-2);border:1px solid var(--line);border-radius:8px;padding:15px 16px}}
.why .wn{{font-size:22px;font-weight:700;color:var(--orange);font-family:"IBM Plex Mono",monospace}}
.why .wt{{font-weight:700;margin:6px 0 5px;font-size:14.5px}}
.why .wd{{font-size:13px;color:var(--ink-2);line-height:1.55}}

.tblwrap{{overflow-x:auto;-webkit-overflow-scrolling:touch}}
table{{border-collapse:collapse;width:100%;font-size:13.5px;min-width:640px}}
th{{background:var(--navy);color:var(--on-navy);text-align:left;padding:10px 12px;font-weight:700;font-size:13px;white-space:nowrap}}
td{{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
tbody tr:last-child td{{border-bottom:none}}
.pill{{display:inline-block;padding:2px 9px;border-radius:11px;font-size:11.5px;font-weight:700;white-space:nowrap}}
.p-now{{background:var(--crit-bg);color:var(--crit)}}
.p-next{{background:var(--warn-bg);color:var(--warn)}}
.p-ok{{background:var(--good-bg);color:var(--good)}}

.note{{background:var(--surface-2);border:1px dashed var(--line);border-radius:8px;padding:14px 18px;font-size:13px;color:var(--ink-2)}}
.note b{{color:var(--ink)}}
details{{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:0 20px}}
details[open]{{padding-bottom:16px}}
summary{{cursor:pointer;padding:15px 0;font-weight:700;font-size:14.5px}}
summary:focus-visible{{outline:2px solid var(--blue);outline-offset:3px;border-radius:4px}}
details ul{{margin:0;padding-left:20px;color:var(--ink-2);font-size:13.5px;line-height:1.75}}
footer{{color:var(--ink-3);font-size:12px;text-align:center;padding-top:6px}}
@media (max-width:640px){{
  header h1{{font-size:22px}} .kpi .v{{font-size:23px}} .wrap{{padding:18px 14px 48px}}
  .card{{padding:16px 15px}}
}}
</style>

<div class="wrap">

  <div class="ribbon">
    <span class="tag">🔴 尚未压制</span>
    <span style="color:var(--ink-2);font-size:14px">攻击仍在上行，未出现拐点</span>
    <span class="day">数据窗口至 2026-09-10 06:32 UTC（北京 14:32）</span>
  </div>

  <header>
    <h1>短信验证码遭黑产刷量，第 8 天</h1>
    <p class="lede">攻击方持续向<b>我们没有客户的国家</b>刷取验证码短信，每条都由公司真实付费。
      当前每天仍有 <b class="num">{_f(m['today_attack'])}</b> 条攻击短信发出，是攻击前日均的 <b class="num">{m['multiple']}</b> 倍。
      <b>正常美国用户完全未受影响。</b>
      两条策略已配置完成、等待审批，<b>上线即可把拦截率从 {m['recall_now']}% 提到 {m['recall_after']}%</b>。</p>
    <div class="meta">数据来源：风控请求日志（64 分片源库）+ 短信发送记录，全程只读 · 口径与技术细节见附录</div>
  </header>

  <div class="kpis">
    <div class="kpi"><div class="k">每日攻击短信</div><div class="v crit num">{_f(m['today_attack'])}</div>
      <div class="s">攻击前日均 {_f(m['baseline'])} 条 · <b>↑{m['multiple']}倍</b></div></div>
    <div class="kpi"><div class="k">当前拦截率</div><div class="v warn num">{m['recall_now']}%</div>
      <div class="s">仍有 {_f(m['leak_now'])} 条/日漏过</div></div>
    <div class="kpi"><div class="k">估算日损耗</div><div class="v crit num">${_f(lo)}~{_f(hi)}</div>
      <div class="s">估算值 · 单价假设见下方说明</div></div>
    <div class="kpi"><div class="k">正常用户影响</div><div class="v good num">0</div>
      <div class="s">验证码填充率稳定 {m['today_us_fill']}%</div></div>
    <div class="kpi"><div class="k">已避免损耗</div><div class="v good num">${_f(m['cost_saved'][0])}~{_f(m['cost_saved'][1])}</div>
      <div class="s">已拦下 {_f(m['blocked_cum'])} 条</div></div>
  </div>

  <div class="card">
    <h2>攻击短信量仍在上行</h2>
    <p class="sub">每日实际发出的验证码短信条数。9/9 新策略生效当天，攻击量仍创新高。</p>
    {trend_svg(up)}
    <div class="legend">
      <span><i style="background:var(--blue)"></i>正常美国用户（+1）</span>
      <span><i style="background:var(--orange)"></i>攻击目标区号（其他国家）</span>
    </div>
  </div>

  <div class="card">
    <h2>这些短信没有任何人使用</h2>
    <p class="sub">「填充率」＝ 收到短信后真正输入了验证码的比例。这是判定黑产最直接的证据：正常用户几乎都会输入，攻击方从不输入。</p>
    {fill_svg(m)}
    <div class="legend"><span>数据日期 2026-09-09 · 攻击前该指标约 24%，攻击开始后塌到 1% 以下</span></div>
  </div>

  <div class="card">
    <h2>为什么还没压住</h2>
    <p class="sub">三条原因都来自数据核查，按影响排序。</p>
    <div class="why">
      <div class="w"><div class="wn">30.1%</div><div class="wt">攻击贴着我们的阈值跑</div>
        <div class="wd">现网主力规则是「单区号每小时超过 30 次」才拦。实测攻击把每个区号每小时压在 24~33 次，紧贴阈值——
          三成攻击请求根本碰不到这条规则。<b>把阈值降到 15 即可压到 5.3%。</b></div></div>
      <div class="w"><div class="wn">{m['us_ip_share']}%</div><div class="wt">新策略方向漏掉了美国 IP</div>
        <div class="wd">9/9 上线的策略按「来源国家不是美国」过滤，而攻击方已有 {m['us_ip_share']}% 的请求来自美国机房代理，
          <b>被设计性放过</b>。经六项特征交叉确认，是同一伙攻击方换了出口。</div></div>
      <div class="w"><div class="wn">6 天</div><div class="wt">最有效的策略一直没生效</div>
        <div class="wd">两条最有效的策略 9/4 就已配置完成，但一直停在<b>「已配置但未生效」</b>的观察状态，至今 6 天。
          它们一条就能补回 {ca['占漏召回%']}% 的漏拦量。</div></div>
    </div>
  </div>

  <div class="card">
    <h2>待决事项</h2>
    <p class="sub">这是需要管理层动作的部分。前两项批准后 2 小时内即可生效。</p>
    <div class="tblwrap"><table>
      <thead><tr><th>优先级</th><th>动作</th><th>预期效果</th><th>误拦正常用户风险</th><th>执行 / 审批</th></tr></thead>
      <tbody>
        <tr><td><span class="pill p-now">立即</span></td>
          <td><b>启用两条已配置策略</b><br><span style="color:var(--ink-2)">「单区号日频次」规则（名单内 + 名单外）</span></td>
          <td>拦截率 <b class="num">{m['recall_now']}% → {m['recall_after']}%</b><br>日漏出降至约 <span class="num">{_f(m['resid_day'])}</span> 条</td>
          <td><b>极低</b>：攻击前 25 天回测命中 <span class="num">{_f(int(ca['攻击前窗命中'])+int(cb['攻击前窗命中']))}</span> 条，
            其中美国真实用户 <b class="num">0</b> 条</td>
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
          <td>配置攻击复发告警</td><td>复发后 1 小时内发现</td><td>无</td><td>DBA 团队</td></tr>
        <tr><td><span class="pill p-ok">排期</span></td>
          <td>补充设备维度识别能力</td>
          <td>现有规则完全没有设备维度，<br>攻击方正利用这一点</td><td>无</td><td>风控平台研发</td></tr>
      </tbody>
    </table></div>
  </div>

  <div class="note">
    <b>关于成本数字的口径（请注意）：</b>攻击流量全部走 Twilio 通道，而<b>该通道的每条单价数据库中未记录</b>（仅 AWS 通道有记录），
    因此上方金额为<b>估算值</b>，按<b>单价 ${UNIT_LO}~${UNIT_HI}/条</b>测算。
    上限参考行业公开基准（Prelude 2025 年拦截 2,430 万条黑产验证码请求、避免约 326 万美元成本，折合约 $0.134/条）。
    <b>精确金额需以 Twilio 账单为准，建议同步向财务/upush 侧调取 9 月账单核实。</b>
    按当前量若不处置，续 30 天约 <b class="num">${_f(m['cost_month'][0])}~{_f(m['cost_month'][1])}</b>；
    启用上述策略后预计每月可减少 <b class="num">${_f(m['save_month'][0])}~{_f(m['save_month'][1])}</b>。
  </div>

  <details>
    <summary>附录：技术细节与详细报告（供风控 / DBA 下钻）</summary>
    <ul>
      <li><b>判定标准</b>：黑产判定遵循风控 SOP —— 需 ≥2 类独立特征交叉印证；单一特征一律标注「暂无法判断」，未计入黑产。命中样本误拦正常用户 0 条。</li>
      <li><b>美国 IP 同源判定</b>：目的区号名单相同、一 IP 关联 &gt;3 手机号占 66.8%（正常用户 1.4%）、iPhone 占比 0.9%（正常美国用户 84.5%）、
        98.9% 的网关标识只调短信接口从不登录下单、32.6% 的号码在 24 小时内被 ≥2 个国家的 IP 请求过。IP 集中在德州 Plano / Richardson 等机房网段。</li>
      <li><b>「攻击集中在非营业时段」这一说法已撤回</b>：实测攻击 7×24 全天候，美东 14–18 点低谷仍占 8.8%。已改为三条监控告警阈值。</li>
      <li><b>数据口径提醒</b>：风控特征名在 8/27–9/5 期间被改动过（未做变更留痕），按字面名字取数会静默丢失整段数据。已改为按结构取数。</li>
      <li><b>详细报告</b>：共 9 份技术报告 + 7 张图 + 19 份明细 CSV，见 <code>github.com/xiangyuzeng/info</code>（out/ 目录）。
        评估管道可复跑：<code>python -m sms_attack.evaluate --strategy &lt;策略ID&gt; --window 5h</code>。</li>
    </ul>
  </details>

  <footer>瑞幸咖啡北美 · 信息安全 / 数据库团队 · 本看板由风控源库数据自动生成</footer>
</div>'''


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
