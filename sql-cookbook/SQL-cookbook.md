# LKUS 风控日志取数 SQL 手册

> 场景：`t_iriskcontrol_log` / `LKUS_push` 的明细取数。
> 本手册解决的核心问题：**为什么加上 `featureDetail` 查询就卡死，以及正确写法。**
> 数据截至 2026-09-10 · 北美安全 / DBA

| 文件 | 状态 | 用途 |
|---|---|---|
| `sql/01_mysql_源库_近20天.sql` | ✅ **已实测跑通**（本次 64,931 行即由它产出） | 走上游 MySQL 源库，64 分片逐个跑 |
| `sql/02_doris_近20天_宽表.sql` | ⚠️ **未实测**（无 Doris 账号） | 走数仓，一条 SQL 出宽表 |

---

## 一、为什么原来那条 query 慢

瓶颈**不在扫描，在结果回传**。

`extend.respDetailStrategyEngine.re.featureDetail` 实测**平均 20,641 字节/行**——
里面绝大部分是 reCAPTCHA token 原文和 Google 返回体，而真正要用的只有二十几个计数值。

近 20 天约 6.5 万行，直接 `SELECT` 这个字段 ≈ **1.3 GB** 往客户端搬。

**正确做法：在服务端把它摊平，只回传标量。** 每行约 500 字节，**小 40 倍**。
- Doris：`LATERAL VIEW EXPLODE_JSON_ARRAY_JSON(...)` 炸成行 → `MAX(CASE WHEN 特征名=... )` 透视回来
- MySQL 8：`JSON_TABLE(...)` 摊平（Doris 没有这个函数）

> 一句话：**永远不要 `SELECT` 整个 featureDetail 串。**

---

## 二、性能杠杆（按收益排序）

| # | 动作 | 收益 |
|---|---|---|
| 1 | 不 SELECT featureDetail 原串，改服务端摊平 | 回传量 ↓ 40 倍 —— 主因 |
| 2 | 炸开后立刻用特征名白名单过滤 | 约 230 万行 → 150 万行 |
| 3 | `access_time` 谓词保证分区裁剪；若 `NOW() - INTERVAL` 裁剪不掉，改写成字面日期 | 视分区设计 |
| 4 | 仍慢：拆两步——先跑不带特征的轻量版拿基础列，再单独跑特征长表，客户端 join | 避免宽 GROUP BY |

---

## 三、四个坑（都踩过）

### 坑 1 · 特征名会变，按字面名取数会静默丢整段数据
`reCAPTCHA V3 token是否有效` 在 **2026-08-27 ～ 09-05** 被改名为 `reCAPTCHA V3风险分`
（09-06/07 两名并存，09-08 改回），**没有变更留痕**。

按字面名字取分数，那段时间会**整段取不到值，现象和「reCAPTCHA 彻底故障」一模一样**——
本项目第一轮分析就因此得出过错误结论。

同一次改名还造成：`一分钟请求量` ↔ `一小时请求量`、`同IP近5分钟的访问次数` ↔ `同IP近10分钟的访问次数`
成对出现（**窗口语义不同，不可合并**）。

**解法**：分数用前缀匹配 `... LIKE 'reCAPTCHA V3%'`，或按结构取
（apiResp 能解析成含 `riskAnalysis.score` 的对象）。两份 SQL 都已这样写。

### 坑 2 · GROUP BY 必须带每请求唯一键，否则静默合并行
实测（源库单分片 912 行）：仅按「时间 + 号码 + IP」聚合只剩 **899 个唯一值 —— 13 行（1.4%）
被静默合并**。放到 6.5 万行上约 900 行。

**解法**：Doris 版用 `requestId`（`$.respDetailStrategyEngine.re.requestId`）作分组主键，
实测唯一（907 唯一 + 5 空 / 912）。MySQL 版用主键 `id`，且用相关子查询、不做 GROUP BY，天然无此问题。

### 坑 3 · `LATERAL VIEW` 是 inner 语义，会丢行
featureDetail 为空的请求会被**整行丢掉**。若必须保留，用 `EXPLODE_JSON_ARRAY_JSON_OUTER`
（若该 Doris 版本支持），或先跑轻量版再 LEFT JOIN。
MySQL 版用相关子查询，**行全保留**。

### 坑 4 · 网关把含 `REPLACE(` 的 SELECT 判成写操作
走 `mcp-db-gateway` 时，`REPLACE(x,'+','')` 会被拒（`Permission denied for operation`）。
改用 `TRIM(LEADING '+' FROM x)`。仅影响 MySQL 版。

---

## 四、字段映射：Doris 侧 vs MySQL 源库

大部分字段两边同名同义，**以下三处不同，务必注意**：

| 字段 | Doris（数仓） | MySQL（源库） |
|---|---|---|
| `l2_scene` | ✅ 有这一列，可直接取 | ❌ **源库无此字段**（派生于数仓），只能置 NULL |
| `ip_country` / `ip_province` / `ip_city` | ✅ 该列有值 | ❌ 同名基础列**全为 NULL**，必须取 `request_strategy_engine.para.realIpCountry/Province/City` |
| `country_code` | 不带 `+`（如 `92`） | **带 `+`**（如 `+92`），MySQL 版已去前缀对齐 |

其余对应关系：

| Doris | MySQL 源库 |
|---|---|
| `access_time` | `create_time`（实测 UTC） |
| `l1_scene = '1000'` | `scene_id = 'LKUS_push'`（**等价**，已核实） |
| `resp_detail` | `response` 列（`{code, detail, message, result}`） |
| `extend.respDetailStrategyEngine.re.*` | `response_strategy_engine.re.*` |
| `cid` / `version` / `phone_no` | `request_strategy_engine.para` |

---

## 五、验收基准

在 Doris 上跑完后**逐项对照**，对不上说明有偏差（窗口：近 20 天滚动，截至 2026-09-10 20:09 UTC）：

| 指标 | 源库实测值 |
|---|---|
| 总行数 | **64,931** |
| `result` 分布 | PASS 41,629 · REJECT 23,121 · REVIEW 181 |
| `country_code` top6 | 1=23,130 · 92=5,359 · 265=5,223 · 375=4,499 · 213=4,465 · 386=4,384 |
| `recaptcha_score` 非空 | 55,333 |
| 特征名总数 | 23 个（见白名单） |

> 若 Doris 版行数**少于** 64,931，优先怀疑坑 3（LATERAL VIEW 丢行）；
> 若**少得多且是整数倍关系**，怀疑坑 2（GROUP BY 缺唯一键）。

---

## 六、MySQL 源库版怎么跑

单条 SQL 只覆盖一张分片表，需对 `t_access_log_0000` ～ `t_access_log_0063` 逐个执行再合并。
已封装成脚本：

```bash
MCP_DB_GATEWAY_SSE=http://<网关>:8080/sse python -m sms_attack.pull_20d --days 20
```

64 分片约 7 分钟，直接产出 CSV(UTF-8-BOM) + parquet。
代码：`sms_attack/pull_20d.py` + `sms_attack/sql/08_riskcontrol_20d.sql`。

**为什么有时只能走源库**：Doris `t_iriskcontrol_log` 需要只读账号，`databasecheck` 没有
（`1045 Access denied`，见 `doris_check/`）。源库就是数仓那张表的 ODS 上游。
