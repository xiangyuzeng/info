# START HERE · 在新 session 里继续改这块看板

## 30 秒速览

| 项 | 值 |
|---|---|
| 这是什么 | 瑞幸北美（LKUS）**短信验证码遭黑产刷量**的管理层一页看板 |
| 已发布链接 | https://claude.ai/code/artifact/a33b2e56-f7b2-471c-9100-b24ccc020adb |
| 当前结论 | 攻击第 8 天**尚未压制**；正常美国用户零影响；两条策略待批，上线即可把拦截率 53.8% → 95.2% |
| 数据窗口 | 2026-08-09 ~ **2026-09-10 06:32 UTC**（快照，可能已过期） |
| 汇报对象 | 中国总部安全 / 技术管理层 |
| 看板生成器 | `sms_attack/dashboard.py`（从 `out/data/*.csv` 读数，数字不硬编码） |

重新生成看板：

```bash
cd /app/lkus-sms-dashboard-handoff && python3 -m sms_attack.dashboard
```

## 阅读顺序

1. **`docs/04_红线与已知缺口.md` — 先读这份。** 5 条红线，破了会出事（尤其是 Artifact 更新方式）。
2. `docs/01_项目背景与结论.md` — 这件事是什么、5 条关键结论、相关人。
3. `docs/02_看板设计说明.md` — 色板 / 字体 / 主题三态 / 版式 / **中文翻译对照表**，每条都写了"为什么"。
4. `docs/03_数字口径与来源.md` — 看板上每个数字对应哪个 CSV 哪一列，以及 4 条踩过的口径坑。

---

## 续作提示词（整段复制到新 session）

把下面整段粘进新 session，并把倒数第二段的 `<在这里写你的具体需求>` 换成你要改的东西。

```text
我要继续修改一个已经交付的管理层看板（瑞幸北美 LKUS 短信黑产攻击处置看板）。

【动手前必须先读上下文】全部在 /app/lkus-sms-dashboard-handoff/ ：
  1. docs/04_红线与已知缺口.md  ← 先读这份，5 条红线
  2. docs/01_项目背景与结论.md  ← 这件事是什么、5 条关键结论
  3. docs/02_看板设计说明.md    ← 色板/字体/主题/版式/中文翻译对照表，每条都写了为什么
  4. docs/03_数字口径与来源.md  ← 每个数字对应哪个 CSV、哪些口径踩过坑
看板源码在 sms_attack/dashboard.py（从 out/data/*.csv 读数渲染，数字不硬编码在 HTML 里），
当前产出在 out/mgmt_dashboard.html。
重新生成：cd /app/lkus-sms-dashboard-handoff && python3 -m sms_attack.dashboard

【已发布的 Artifact —— 必须更新它，不要新建】
  https://claude.ai/code/artifact/a33b2e56-f7b2-471c-9100-b24ccc020adb
重新发布时必须把这个 URL 作为 url 参数传给 Artifact 工具。不传 url 会新建一个 artifact，
而管理层手上的旧链接不会更新，你会以为改好了其实没有。这是本项目最容易犯、后果最大的错。

【受众与文风】中国总部安全/技术管理层。简体中文，结论先行，一页看完，用业务语言不要风控黑话
（对照表在 docs/02：召回率→拦截率、误伤→误拦正常用户、预上线→已配置但未生效）。
这是一块被扫视、据以决策的看板，不是一篇被通读的报告；待决事项表是整块看板的目的地。

【四条红线】
 1. 成本必须标注为估算值。Twilio 通道的单条价格数据库里没有记录（只有 AWS 通道有），
    现用单价假设 $0.03~$0.13/条，必须保留"估算值 · 待 Twilio 账单核实"的说明，不能写成实测值。
 2. 正文不出现策略 ID（strategy_XXXX），要用业务名称（如「单区号日频次」策略），ID 只能进折叠附录。
 3. 不出现手机号、完整 IP、内网地址；IP 最多写到 /24 段或城市名。
 4. 基线/倍数/拦截率这类数字同时出现在 out/summary.md、out/06_*.md、out/07_群消息.md 和看板里，
    改一处必须四处同步（改 sms_attack/report.py 后重跑，不要手改 md 文件）。

【注意数据时效】包内数据是 2026-09-10 06:32 UTC 的快照。"尚未压制"这个结论可能已经过期——
如果那两条待批策略已经上线，待决事项表和整个结论都要重写。先确认当前状态，别照抄旧结论。
若要重新取数：export MCP_DB_GATEWAY_SSE=... 后跑 python3 -m sms_attack.extract（64 分片，约 11 分钟），
取数三个坑写在 sms_attack/README.md 里。

【我想改的是】
<在这里写你的具体需求>

【改完自查】
 - grep -oE "strategy_[A-Za-z0-9]+" out/mgmt_dashboard.html          → 应为空
 - grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" out/mgmt_dashboard.html → 应为空
 - 重跑生成器，确认看板数字与 out/summary.md 逐项一致
 - 用同一个 URL 重新发布 Artifact，确认返回的链接没变
```

---

## 可选的改进方向（挑一条填进上面的「我想改的是」）

这些是已知还没做、但值得做的：

| 方向 | 说明 |
|---|---|
| **加一张「拦截率随时间变化」图** | 现在只能看到当前值 53.8%，看不出措施生效后的改善。逐日数据现成：`out/data/02_recall_by_day.csv` |
| **用真实 Twilio 账单替换成本区间** | 拿到 9 月账单后改 `dashboard.py` 里的 `UNIT_LO/UNIT_HI`，并把成本口径那段虚线框改写成实测口径 |
| **策略若已上线，重写待决事项表** | 表里"立即"那两行会过期；当前状态见 `out/data/06_measures_timeline.csv` 或重新查库 |
| **在真实浏览器里核对渲染** | 原环境没有 headless browser，窄屏布局与暗色模式只做了代码层校验，**从未肉眼看过** |
| **补一张目的地国家分布图** | `out/data/05_black_sample_by_cc.csv` 有按区号的攻击量，可做条形图 |
| **加"如果不处置"的成本外推曲线** | 让管理层直观看到不批的代价 |

---

## 目录结构

```
lkus-sms-dashboard-handoff/
├── START_HERE.md              ← 本文件
├── docs/
│   ├── 01_项目背景与结论.md
│   ├── 02_看板设计说明.md
│   ├── 03_数字口径与来源.md
│   └── 04_红线与已知缺口.md
├── sms_attack/                ← 完整管道（可直接运行）
│   ├── dashboard.py           ← 看板生成器
│   ├── report.py figures.py common.py label.py evaluate.py extract.py charts.py countries.py
│   ├── mcp_client.py          ← 连数据库网关（地址走环境变量）
│   ├── README.md              ← 取数的三个坑
│   └── sql/                   ← 6 份取数 SQL
└── out/
    ├── mgmt_dashboard.html    ← 当前看板产出
    ├── summary.md             ← 技术侧一页纸
    ├── 00~07_*.md             ← 9 份技术报告（数字权威来源）
    ├── data/                  ← 18 份 CSV（看板只读其中 6 份）
    └── charts/                ← 7 张 PNG
```

**不在包内**：`risk_log.parquet` / `risk_labeled.parquet` / `otp_filled.csv` / `uid_scenes.csv` —— 
含未脱敏手机号与完整 IP，改看板用不到；需要时按上面的命令重新取数。
