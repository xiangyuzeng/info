"""Charts for out/charts/.

Palette + mark specs follow the dataviz method: categorical hues assigned in fixed
order (never cycled), one axis per chart (no dual-axis), 2px lines, recessive
grid/axes, legend whenever >=2 series, text in ink tokens rather than series colour.
Palette validated with scripts/validate_palette.js (light, surface #fcfcfb): ALL PASS.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
import pandas as pd

from . import figures as F

FONT = os.path.expanduser("~/.fonts/NotoSansSC-Regular.otf")
if os.path.exists(FONT):
    fm.fontManager.addfont(FONT)
    plt.rcParams["font.family"] = "Noto Sans SC"
plt.rcParams["axes.unicode_minus"] = False

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e3e2df"
S1, S2, S3 = "#2a78d6", "#eb6834", "#1baf7a"   # blue / orange / aqua, fixed order
CHARTS = os.path.join(F.OUT, "charts")


def _full_days(df, col):
    """Drop the trailing partial day -- the extract ends mid-day, which would otherwise
    render as a fake cliff at the right edge of every daily series."""
    return df[pd.to_datetime(df[col]) < pd.Timestamp("2026-09-10")].reset_index(drop=True)


def _ax(figsize=(10, 4.6)):
    fig, ax = plt.subplots(figsize=figsize, dpi=150)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)
    ax.grid(True, axis="y", color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9, length=0)
    return fig, ax


def _save(fig, ax, title, sub, name):
    ax.text(0, 1.16, title, transform=ax.transAxes, color=INK, fontsize=13,
            fontweight="bold", va="bottom")
    if sub:
        ax.text(0, 1.055, sub, transform=ax.transAxes, color=INK2, fontsize=9.5, va="bottom")
    os.makedirs(CHARTS, exist_ok=True)
    fig.tight_layout()
    p = os.path.join(CHARTS, name)
    fig.savefig(p, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    print(f"  chart {p}")


def suppression_curve():
    up = _full_days(F.upush_series(), "日期")
    x = pd.to_datetime(up["日期"])
    fig, ax = _ax()
    ax.plot(x, up["+1发送"], color=S1, linewidth=2, marker="o", markersize=4, label="+1（正常美国用户）")
    ax.plot(x, up["其他区号发送"], color=S2, linewidth=2, marker="o", markersize=4, label="其他区号（攻击）")
    for when, lbl in [("2026-09-03", "9/3 攻击起量"), ("2026-09-09", "9/9 上线 172")]:
        ax.axvline(pd.Timestamp(when), color=INK2, linewidth=1, linestyle=":", zorder=1)
        ax.text(pd.Timestamp(when), ax.get_ylim()[1] * 0.97, "  " + lbl, color=INK2,
                fontsize=8.5, rotation=90, va="top")
    last = up.iloc[-1]
    ax.annotate(f"{int(last['其他区号发送']):,}", (x.iloc[-1], last["其他区号发送"]),
                textcoords="offset points", xytext=(6, 4), color=INK, fontsize=10, fontweight="bold")
    ax.set_ylabel("每日实发短信条数", color=INK2, fontsize=10)
    ax.legend(frameon=False, fontsize=9.5, labelcolor=INK2, loc="upper left")
    _save(fig, ax, "其他区号短信发送量仍在上行，未见压制拐点",
          "upush 实发短信（t_sent_verifycode_sms），LKUS 租户 · UTC 日", "01_suppression_curve.png")


def fill_rate():
    up = _full_days(F.upush_series(), "日期")
    x = pd.to_datetime(up["日期"])
    fig, ax = _ax()
    ax.plot(x, up["+1填充率%"], color=S1, linewidth=2, marker="o", markersize=4, label="+1（正常美国用户）")
    ax.plot(x, up["其他区号填充率%"], color=S2, linewidth=2, marker="o", markersize=4, label="其他区号（攻击）")
    ax.set_ylim(0, 100)
    ax.annotate("95~96% 稳定", (x.iloc[-4], up["+1填充率%"].iloc[-4]),
                textcoords="offset points", xytext=(-30, 8), color=INK, fontsize=9.5)
    ax.annotate(f"{up['其他区号填充率%'].iloc[-1]}%", (x.iloc[-1], up["其他区号填充率%"].iloc[-1]),
                textcoords="offset points", xytext=(4, 10), color=INK, fontsize=10, fontweight="bold")
    ax.set_ylabel("验证码填充率 %", color=INK2, fontsize=10)
    ax.legend(frameon=False, fontsize=9.5, labelcolor=INK2, loc="center left")
    _save(fig, ax, "发出去的短信没人用：其他区号填充率塌到 1% 以下",
          "「填充」= 用户真的输入了验证码。这是 SMS pumping 最硬的判据", "02_fill_rate.png")


def threshold_evasion():
    """The attack sits deliberately just under the online 30/hour area-code rule."""
    per = pd.read_csv(os.path.join(F.OUT_DATA, "04_threshold_evasion_by_cc.csv"))
    per = per.sort_values("中位")
    fig, ax = _ax(figsize=(10, 5))
    ax.barh(per["cc"].astype(str), per["中位"], color=S1, height=0.62, zorder=2)
    ax.axvline(30, color=S2, linewidth=2, zorder=3)
    ax.text(30.6, -0.7, "现网阈值 >30", color=S2, fontsize=10, fontweight="bold")
    for i, (m, mx) in enumerate(zip(per["中位"], per["峰值"])):
        ax.text(m + 0.6, i, f"中位 {m:.0f}", va="center", color=INK, fontsize=9)
    ax.set_xlim(0, max(46, per["中位"].max() * 1.5))
    ax.set_ylabel("目的区号", color=INK2, fontsize=10)
    ax.set_xlabel("每小时请求量中位数（09-05 起，按区号）", color=INK2, fontsize=10)
    _save(fig, ax, "攻击贴着阈值跑：各区号每小时请求量中位数紧贴 30",
          "单序列，无需图例 · 48.4% 的(区号,小时)格子 ≤30，承载 30.1% 的攻击请求",
          "03_threshold_evasion.png")


def threshold_curve():
    c = pd.read_csv(os.path.join(F.OUT_DATA, "04_threshold_curve.csv"))
    fig, ax = _ax(figsize=(9, 4.4))
    ax.plot(c["阈值(区号近60分钟>N)"], c["占攻击请求%"], color=S1, linewidth=2,
            marker="o", markersize=8, zorder=3)
    for x_, y_ in zip(c["阈值(区号近60分钟>N)"], c["占攻击请求%"]):
        ax.annotate(f"{y_}%", (x_, y_), textcoords="offset points", xytext=(0, 10),
                    ha="center", color=INK, fontsize=10,
                    fontweight="bold" if x_ in (15, 30) else "normal")
    ax.set_xticks(c["阈值(区号近60分钟>N)"])
    ax.set_ylim(0, c["占攻击请求%"].max() * 1.3)
    ax.set_xlabel("区号近60分钟的访问次数 阈值 N", color=INK2, fontsize=10)
    ax.set_ylabel("仍可规避该规则的攻击请求占比 %", color=INK2, fontsize=10)
    _save(fig, ax, "阈值从 30 下调到 15，可规避的攻击请求从 30.1% 降到 5.3%",
          "单序列，无需图例 · 攻击前 25 天该指标 P99 远低于 15，下调对真实用户影响极小",
          "07_threshold_curve.png")


def edt_profile():
    e = pd.read_csv(os.path.join(F.OUT_DATA, "05_edt_hour_profile.csv"))
    fig, ax = _ax()
    ax.plot(e["hour_edt"], e["+1"], color=S1, linewidth=2, marker="o", markersize=4, label="+1（正常美国用户）")
    ax.plot(e["hour_edt"], e["非+1/+86"], color=S2, linewidth=2, marker="o", markersize=4, label="非+1/+86（攻击）")
    ax.axvspan(14, 18, color=GRID, alpha=0.55, zorder=0)
    ax.text(16, ax.get_ylim()[1] * 0.92, "EDT 14–18 低谷\n仍占 8.8%，不为 0",
            ha="center", color=INK, fontsize=9.5)
    ax.set_xticks(range(0, 24, 2))
    ax.set_xlabel("美东时间 EDT（小时）", color=INK2, fontsize=10)
    ax.set_ylabel("请求数（09-05 起累计）", color=INK2, fontsize=10)
    ax.legend(frameon=False, fontsize=9.5, labelcolor=INK2, loc="upper right")
    _save(fig, ax, "攻击是 7×24 的，「集中在非营业时段」这个说法需要修正",
          "低谷时段仍有 347~583 请求/小时；正常 +1 流量则集中在 EDT 08–16", "04_edt_hour_profile.png")


def candidate_recall():
    c = pd.read_csv(os.path.join(F.OUT_DATA, "04_candidates.csv"))
    c = c[c.增量召回 > 0].sort_values("增量召回").tail(8)
    lbl = [s.replace("strategy_", "") for s in c["策略"]]
    risky = c["攻击前命中中+1"] > 50
    colors = [S2 if r else S1 for r in risky]
    fig, ax = _ax(figsize=(10, 5))
    b = ax.barh(lbl, c["增量召回"], color=colors, height=0.62, zorder=2)
    for rect, v, p, r in zip(b, c["增量召回"], c["占漏召回%"], risky):
        ax.text(rect.get_width() + 18, rect.get_y() + rect.get_height() / 2,
                f"{int(v):,}  ({p}%)" + ("  ⚠ 攻击前误伤真实用户" if r else ""),
                va="center", color=INK if not r else "#a8380f", fontsize=9.5)
    ax.set_xlim(0, c["增量召回"].max() * 1.55)
    ax.set_xlabel("在当前 ONLINE 之外可新增拦截的黑产条数（最近 24h，引擎实测）", color=INK2, fontsize=10)
    handles = [plt.Line2D([0], [0], color=S1, linewidth=8, label="攻击前窗口零误伤，可上线"),
               plt.Line2D([0], [0], color=S2, linewidth=8, label="攻击前窗口打到真实 +1 用户，不建议")]
    ax.legend(handles=handles, frameon=False, fontsize=9.5, labelcolor=INK2, loc="lower right")
    _save(fig, ax, "增量召回最高的两条策略，已经在预上线里躺了 6 天",
          "MGj5bfGOijOi / x37TInaHsvPQ 自 09-04 起配置为预上线，未推进上线", "05_candidate_recall.png")


def daily_recall():
    r = _full_days(pd.read_csv(os.path.join(F.OUT_DATA, "02_recall_by_day.csv")), "日期(UTC)")
    fig, ax = _ax()
    x = range(len(r))
    ax.bar([i - 0.19 for i in x], r["已拦截"], width=0.38, color=S1, label="已拦截 REJECT", zorder=2)
    ax.bar([i + 0.19 for i in x], r["漏召回(PASS)"], width=0.38, color=S2, label="漏召回 PASS", zorder=2)
    for i, v in zip(x, r["召回%"]):
        ax.text(i, max(r["已拦截"].iloc[i], r["漏召回(PASS)"].iloc[i]) + 60, f"{v}%",
                ha="center", color=INK, fontsize=9)
    ax.set_xticks(list(x))
    ax.set_xticklabels([d[5:] for d in r["日期(UTC)"]])
    ax.set_ylabel("黑产请求条数（SOP 标签）", color=INK2, fontsize=10)
    ax.legend(frameon=False, fontsize=9.5, labelcolor=INK2, loc="upper left")
    _save(fig, ax, "逐日召回：仍有近一半黑产请求被放行",
          "标签为 SOP §3.7 ≥2 类特征交叉认定；百分比为当日召回率", "06_daily_recall.png")


def all_charts():
    suppression_curve(); fill_rate(); threshold_evasion(); threshold_curve()
    edt_profile(); candidate_recall(); daily_recall()


if __name__ == "__main__":
    all_charts()
