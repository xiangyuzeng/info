# 近 20 天风控日志取数说明

**窗口**：2026-08-21 20:09:26 ～ 2026-09-10 20:08:57 UTC（滚动 20 天，与原查询的
`NOW() - INTERVAL 20 DAY` 完全一致，非自然日）
**行数**：64,931　**列数**：52　**生成**：2026-09-10

| 文件 | 大小 | 用途 |
|---|---|---|
| `lkus_riskcontrol_20d_20260910.csv` | 98.8 MB | UTF-8-BOM，Excel / WPS 双击直接打开不乱码 |
| `lkus_riskcontrol_20d_20260910.csv.gz` | 见目录 | 同上，压缩版，便于传输 |
| `lkus_riskcontrol_20d_20260910.parquet` | 10.9 MB | 带类型，pandas / Doris 导入用 |

复跑：`MCP_DB_GATEWAY_SSE=http://<网关>:8080/sse python -m sms_attack.pull_20d --days 20`

---

## 一、数据源不是 Doris，是它的上游源库

Doris 的 `t_iriskcontrol_log` 取不了：`idorisjdbc.luckincoffee.us:9030` 网络可达，
但 `databasecheck` **没有只读账号**（`1045 Access denied`）。

本次改从**上游 MySQL 源库** `luckyus_iriskcontrolservice.t_access_log_0000..0063`
（64 张 Sharding-JDBC 分片表）取数。数仓那张表就是这批表的 ODS 镜像。

## 二、为什么原来那条 query 慢，以及这里怎么解决

`extend.respDetailStrategyEngine.re.featureDetail` **平均 20,641 字节/行**（实测）。
20 天 6.5 万行直接拉原串 ≈ **1.3 GB**，绝大部分是用不上的 token 原文和 Google 返回体。

本次把 featureDetail **在服务端用 `JSON_TABLE` 摊平**，只把标量传回来：
每行约 500 字节，**小 40 倍**，64 分片全量 7 分钟跑完。

> 如果以后还要在 Doris 上跑，同样的思路可用 `LATERAL VIEW EXPLODE_JSON_ARRAY_JSON`
> 只取需要的特征名，不要 `SELECT` 整个 featureDetail 字符串。

## 三、字段映射（逐条实测，非推断）

| 原查询字段 | 本文件来源 | 说明 |
|---|---|---|
| `access_time` | `create_time` | 实测 UTC（`NOW()==UTC_TIMESTAMP()`，`@@time_zone='UTC'`） |
| `l1_scene='1000'` | `scene_id='LKUS_push'` | **等价**。Doris 导出显示 LKUS_push 全部行 l1_scene 均为 1000；`t_scene.scene_type`(1001/1002) 即 l2_scene，且都落在 LKUS_push 下 |
| `cid` `version` `country_code` `phone_no` | `request_strategy_engine.para` | |
| `ip` | `para.realIp`（回退 `ip` 列） | 两者一致率 100% |
| `ip_country` `ip_province` `ip_city` | `para.realIpCountry / Province / City` | ⚠️ 见下第 2 条 |
| `user_no` | `user_no` | 97.1% 为空（短信场景在登录前，本就没有用户编号） |
| `result` | `result` | 与 `risk_resp_result` 100% 一致（已校验） |
| `risk_resp_code/detail/message/result` | `response` 列 | 实测即 `{"code":0,"detail":"验证通过","message":"验证通过","result":"PASS"}` |
| `featureDetail` | `response_strategy_engine.re.featureDetail` | 摊平为 23 个 `f_*` 列 + `recaptcha_score` + `feats_json` |

## 四、⚠️ 三条必须知道的差异

**1. `l2_scene` 全为空 —— 源库没有这个字段。**
它是数仓 ODS 层的派生列。源库里 `request_strategy_engine.sceneid` 是字符串 `LKUS_push`、
`type`=1 是日志类型，都不是 l2_scene。Doris 导出显示该列在 LKUS_push 下
7,744 行为 1001、1 行为 1002 —— 但**无法逐行还原**，所以这里留空，
没有填一个猜出来的常量进数据文件。

**2. `ip_country` / `ip_province` / `ip_city` 取的是 `para` 里的值，不是同名基础列。**
源库同名的 `ip_country`/`ip_province`/`ip_city` 三列**全为 NULL**。
`para.realIpCountry` 才是引擎实际用于策略判定的值——也就是说这个值比数仓那列更贴近
"策略当时看到的是什么"。本文件该列空值率 0.0%。

**3. `country_code` 已去掉 `+` 前缀，与 Doris 侧对齐。**
源库存的是 `+92` 这种带加号的形式，数仓侧不带。已统一去前缀（实测 0 行残留 `+`）。

## 五、特征列

23 个频次类特征各一列（`f_` 开头），命名沿用项目里已有的 `common.FEATURE_COLS` 映射：

`f_phone_1d/1m/5m/30m`（手机号各时间窗访问次数）、`f_ac_1m/5m/60m/1d`（区号）、
`f_ip_1m`、`f_ip_5m_same`、`f_ip_10m_same`、`f_ip_phone_1m/5m/10m/60m`（IP 关联手机号数）、
`f_ipc_phone_1m/10m`（IPC 段关联手机号数）、`f_ip_cc_60m`（IP 关联国家区号数）、
`f_phone_ipcity`、`f_ac_nonus_60m`、`f_ac_notoken_60m`、`f_req_1m`、`f_req_1h`

另有：
- `recaptcha_score` —— 人机识别风险分（0.0~1.0），空值率 14.8%（＝用户端本就没带 token）
- `feats_json` —— name→value 紧凑 JSON 兜底，保留全部特征名，可自行解析
- `hit_online` / `hit_preonline` / `best_strategy_id` —— 命中的线上 / 预上线策略 ID

> ⚠️ **特征名会变。** `reCAPTCHA V3 token是否有效` 在 2026-08-27～09-05 期间被改名为
> `reCAPTCHA V3风险分`（09-06/07 两名并存，09-08 改回），且没有变更留痕。
> **按字面名字取分数会静默丢掉整段数据，现象和「reCAPTCHA 彻底故障」一模一样。**
> 本次按结构取（apiResp 能解析成含 `riskAnalysis.score` 的 JSON 对象），不按名字取。
> `f_req_1m`/`f_req_1h`、`f_ip_5m_same`/`f_ip_10m_same` 成对出现也是同一次改名造成的，
> 两个窗口语义不同，未合并。

## 六、校验结果

| 检查 | 结果 |
|---|---|
| 逐日行数 vs 既有 33 天抽取（8/22～9/9 共 19 个完整重叠日） | **逐日完全一致，差值全为 0** |
| 摊平特征 vs 独立解析原始 featureDetail（12 项抽检） | 全部一致 |
| `result` == `risk_resp_result` | 1.0000 |
| `country_code` 残留 `+` | 0 行 |
| `ip_country` 空值率 | 0.0%（若接近 100% 说明误取了基础列） |
| CSV 前三字节 | `EF BB BF`（UTF-8 BOM，Excel 不乱码） |
| 窗口跨度 | 20.00 天 |

## 七、口径提醒

- 时间为 **UTC**。美东 EDT = UTC−4，北京 = UTC+8。
- `result` 三值：PASS 41,629 / REJECT 23,121 / REVIEW 181。
- 该窗口横跨攻击前后（攻击自 09-03 起量），做基线对比时注意分段。
