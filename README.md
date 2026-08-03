> **本仓库是 fork。** 下面先写清楚我在上游基础上改了什么，
> [原作者文档](#以下为上游原文)在后半部分原样保留。
>
> 上游：[LingJingMaster/Shadowrocket-Rules](https://github.com/LingJingMaster/Shadowrocket-Rules)

# 本 fork 的改动

导入链接（注意是本 fork，不是上游）：

```
https://raw.githubusercontent.com/WSure00/Shadowrocket-Rules/refs/heads/main/Shadowrocket.conf
```

## 节点自动化：只管开关，不选节点

上游的 `🚀 节点选择` 默认落在 `PROXY`，需要手动挑节点。本 fork 加了一层自动兜底：

| 策略组 | 类型 | 说明 |
|--------|------|------|
| `♻️ 自动` | fallback | 按 香港 → 台湾 → 日本 → 美国 → 其他 → DIRECT 顺序自动故障转移 |
| `🚀 节点选择` | select | 默认项改为 `♻️ 自动`（上游是 `PROXY`） |

配合测速参数收紧，切换更快：

| 参数 | 上游 | 本 fork |
|------|------|---------|
| `interval` | 600 | **450** |
| `tolerance` | 0 | **50** |
| `timeout` | 5 | **2** |

`🌍 非中国` 和 `🐟 漏网之鱼` 的默认项也从 `PROXY` 改成 `🚀 节点选择`，
让它们跟着主策略走，不用分别设置。

## 其他改动

| 项 | 上游 | 本 fork | 为什么 |
|----|------|---------|--------|
| 头部注释 | `可分享版` + 固定的 `更新时间` | `自用版` + `生成时间` + `Author` | `生成时间`**每次同步都会刷新**，记录这份配置对齐到上游的时刻 |
| `update-url` | 指向上游 | **指向本 fork** | 指向上游的话，App 每次更新配置都会拉回原版，把所有个人改动覆盖掉 |
| `ipv6` | `false` | **`true`** | 启用 IPv6 |
| 台湾节点组名 | `🇹🇼 台湾节点` | **`🇨🇳 台湾节点`** | 仅改组名；`policy-regex-filter` 里的 `🇹🇼` 保持不动，它要匹配机场给出的真实节点名 |
| `[MITM]` | 只有 `hostname` | 补 **`h2 = true`**、**`enable = true`** | 开启 MITM 与 HTTP/2 解密 |

新增分流：

- **`🎧 Spotify`** 策略组（默认 `DIRECT`）+ blackmatrix7 Spotify 规则集
- **个人直连表** [`WSure00/ProxyResource`](https://github.com/WSure00/ProxyResource) 置于 `[Rule]` 靠前位置
- **`LinuxDo.list`**（见下节），置于个人直连表**之前**

## 自带规则表：LinuxDo.list

只干一件事：让 [Dexo](https://github.com/Eilgnaw/dexo)（iOS 的 Discourse 客户端）能访问
`linux.do`。论坛本身和客户端里配的三个 DoH 端点都在这份表里，统一走 `DIRECT`。

```
DOMAIN-SUFFIX,linux.do
DOMAIN,edge.47258.xyz
DOMAIN,wsu.ddd.oaifree.com
DOMAIN,gameapi.47258.xyz
```

### 光有规则不够，必须配合 `[Host]` 段

走 `DIRECT` 意味着由 Shadowrocket 用 `[General]` 里的 `dns-server` 自己解析，
而那几个国内 DNS 对 `linux.do` 污染得很彻底（2026-08-02 实测）：

| 解析源 | 返回 | 能否连通 |
|--------|------|----------|
| alidns DoH | `108.160.167.174`（Dropbox 段） | 连不通 |
| `119.29.29.29` | `31.13.75.12`（Facebook 段） | 连不通 |
| `223.5.5.5` | `108.160.167.174` | 连不通 |
| 干净 DoH | `172.66.166.61` / `104.20.16.234` | 真实 Cloudflare |

所以只把规则设成 `DIRECT`、不改解析的话，会出现**规则确实命中了 DIRECT，但页面还是
打不开** —— 解析拿到的是假 IP。overlay 因此会同时往 `[Host]` 段写两行：

```
linux.do   = server:https://wsu.ddd.oaifree.com/query-dns
*.linux.do = server:https://wsu.ddd.oaifree.com/query-dns
```

让 Shadowrocket 自己也用干净 DoH 解析这个域名。`verify()` 会检查这两行在不在 ——
少了它们，规则看着对但打不开，很难查。

真实 IP 是 Cloudflare anycast 会漂，所以规则按域名写、解析交给 DoH，不往 `[Host]`
里钉死 IP。

### 顺序约束

```
1. LinuxDo.list             -> DIRECT
2. shadowrocket-direct.list -> DIRECT   个人直连表（ProxyResource）
```

个人直连表里本来就有 `DOMAIN-SUFFIX,linux.do,China`，策略同样是 `DIRECT`，所以第 1 条
不影响结果；固定顺序只是为了不因上游改动而漂。

同时必须早于 `BlockHttpDNS.list`：那份表每天现拉 blackmatrix7 上游，一旦哪天收录了
表里这类社区 DoH，就会落进默认 `REJECT` 的 `🧱 DNS 防泄露`，表现为静默断网。

### 三个 DoH 端点的实测状态

| 端点 | 2026-08-02 直连实测 |
|------|---------------------|
| `edge.47258.xyz` | HTTP/2 200，0.22s，稳定。**只认 wireformat**，发 dns-json 返回 400 |
| `wsu.ddd.oaifree.com` | HTTP/2 200，0.3~1.8s。wireformat 和 dns-json 都支持，`[Host]` 里用的是它 |
| `gameapi.47258.xyz` | **三个 IP 全不通**，TLS 握完后服务端不协商 ALPN、0 字节超时，源站疑似已死 |

它们本来国内直连就通，走 `DIRECT` 顺带避开了两条只对代理生效的开关
（`block-quic = all-proxy`、`udp-policy-not-supported-behaviour = REJECT`）。

保持上游原样的地方：`AI.list` 等 5 份规则表的 URL 仍指向上游 main（有意如此），
blackmatrix7 等第三方规则集 URL 不动。

## 自动同步上游

每天 03:30（UTC+8）自动同步，直接提交到本 fork 的 main，不走 PR。

`Shadowrocket.conf` 是**生成物**，直接编辑会被下一次同步覆盖。个人改动写在
`tools/overlay.py` 里 —— 它把上游原文经过一串幂等变换生成自用版。仓库不跟踪上游那份
原文，CI 每天现拉现用，所以 git 层面不存在共同修改的文件，永远不会有合并冲突。

```
上游有新提交？──否──> 直接结束
       │
       是
       v
按 SHA 下载 ──> overlay.py ──> 自检 ──> 提交到 fork main
```

| 想做的事 | 怎么做 |
|----------|--------|
| 调整策略组、规则、DNS 等 | 改 `tools/overlay.py` 里的 patch 函数，**同时更新本节以上的改动说明** |
| 本地预览生成结果 | `python3 tools/overlay.py --fetch` |
| 校验现有产物 | `python3 tools/overlay.py --check` |
| 跑回归测试 | `python3 tools/test_overlay.py` |
| 立即同步一次 | Actions → 同步上游 → Run workflow |
| 强制重新生成 | 同上，勾选 `force` |

几个设计约束：

- **上游没新提交就直接结束**。`.upstream-sha` 记着已同步到哪个 commit，
  跟上游 HEAD 一致就不下载、不生成。
- **真同步了就刷时间戳**。上游有新提交但生成结果一字节没变时（比如上游只改了自己的
  README），配置里仍会更新 `生成时间` 并提交 —— 这样从配置就能看出最后一次对齐上游是什么时候。
- **每个 patch 都绑一个锚点**，上游结构变了锚点找不到就直接让 CI 失败。宁可红，
  也不要静默生成一份看着正常但少了规则的配置。
- **按 commit SHA 下载**而不是按分支：上游在下载途中推新提交的话，按分支会拿到一份
  前后不一致的混合版本。
- **CA 私钥永不进入本仓库**。`ca-p12` / `ca-passphrase` 是设备 MITM 根 CA 的私钥，
  公开等于任何人都能为任意域名签发该设备信任的证书。`overlay.py` 的 `verify()` 和
  workflow 的 grep 扫描两道防线都会拦住它。需要 MITM 时在 App 内本地生成并信任证书即可。

### GitHub 页面上的「落后 N 个提交」可以无视

fork 页面会一直显示 `This branch is N commits behind LingJingMaster:main`，
**这个数字永远不会归零，而且会随上游每次推送持续增长。它不代表同步失败。**

GitHub 比的是**提交图谱** —— 问的是"上游那个 commit 对象在不在你的历史里"。
本仓库走的是重新生成的路线：把上游的**内容**经 overlay 生成一遍，从不把上游的
commit 对象合并进来。所以内容是同步的，图谱是分叉的（`status=diverged`）。

> ⚠️ **不要点页面上的 "Sync fork" 按钮。** 那会把上游原版 `Shadowrocket.conf`
> 合并进来，和 overlay 生成的版本正面冲突，个人改动会被搅乱。同步一律交给
> `sync-upstream.yml`。

判断是否真的同步到位，看 `.upstream-sha` 和上游 HEAD 是否一致：

```bash
[ "$(cat .upstream-sha)" = "$(gh api repos/LingJingMaster/Shadowrocket-Rules/commits/main --jq .sha)" ] \
  && echo 已是最新 || echo 有待同步的上游提交
```

或者更省事：看 Actions 里最近一次「同步上游」是不是绿的。

---

# 以下为上游原文

> 下面是原作者 README 的原样保留，描述的是**上游配置**。
> 与本 fork 的差异见上文，不再在此重复标注。

# Shadowrocket 配置文件

一份开箱即用的 Shadowrocket 规则配置，导入后添加自己的节点或订阅即可使用。

## 当前重点

- 优化 DNS 防泄露
   - 上游 DNS 仅使用 DNSPod / AliDNS 的 DoH
   - 备用 DNS 不再回退系统 DNS
   - 直连域名解析不再强制使用系统 DNS
   - 扩展常见硬编码 DNS 劫持范围
   - 新增 blackmatrix7 `BlockHttpDNS`，拦截 App 内置 HTTPDNS
- 新增 `HK_Broker.list`
   - 补充富途 / moomoo / 长桥券商域名
   - 合并老虎证券域名，不再依赖外部券商规则
   - 补充富途交易相关域名：`futuapi.com`、`futuin.com`、`futuhk1.com`、`futuhongkong.com`、`qtlcdn.com`
   - 补充长桥交易相关域名：`lbkrs.com`、`longbridge.app`、`longportapp.com`
   - 合并 Arthur-vx Broker 规则中的精确 API / 交易域名、IP 段、TradeUP 和 Schwab 域名
- Google AI 相关规则已并入 `Google.list`
- `🔍 谷歌服务` 默认走日本节点，同时提供香港节点作为手动可选分区，便于在不同网络环境下切换。
- 新增 `ApplePush.list`
   - 将 Apple Push Notification service 相关域名优先归入 `🍎 苹果推送`
   - 改善 X、Telegram 等 App 在部分网络环境下无法及时收到推送的问题。
- 本仓库维护 `Apple.list`
   - 基于 blackmatrix7 的 Apple 规则
   - 补充 iCloud Photos、CloudKit、Apple CDN 相关域名，优化 iCloud 照片同步。

## 默认策略

| 服务 | 默认策略 | 可选策略 |
|------|----------|----------|
| 🧱 DNS 防泄露 | REJECT | 节点选择、DIRECT |
| 🔍 谷歌服务 | 🇯🇵 日本节点 | 🇭🇰 香港节点、节点选择、PROXY、DIRECT |
| 🤖 AI 服务 | 🇺🇸 美国节点 | 节点选择、PROXY、DIRECT |
| 🍎 苹果推送 | 🚀 节点选择 | PROXY、DIRECT |
| 🍏 苹果服务 | DIRECT | 节点选择、PROXY |
| 📈 券商服务 | 🇭🇰 香港节点 | DIRECT、节点选择、PROXY |
| 🌍 非中国 | PROXY | 节点选择、DIRECT、日本节点 |
| 🐟 漏网之鱼 | PROXY | 节点选择、DIRECT、日本节点 |

## 快速开始

1. 复制配置文件的 Raw 链接：
   `https://raw.githubusercontent.com/LingJingMaster/Shadowrocket-Rules/refs/heads/main/Shadowrocket.conf`
2. 打开 Shadowrocket → 配置 → 右上角 `+` → 粘贴链接 → 下载
3. 点击已下载的配置，设为使用中（✔️）
4. 首页添加你自己的节点或订阅
5. 连通性测试，选择可用节点连接

或者扫描二维码

<img width="200" height="200" alt="ctool-2026-02-26-17-13-16" src="https://github.com/user-attachments/assets/22f1b4f7-3265-493c-9e5a-2b662924ed2f" />

## 策略组说明

| 策略组 | 类型 | 说明 |
|--------|------|------|
| 🚀 节点选择 | 手动选择 | 主策略，可选内置代理、地区分组或直连 |
| 🇭🇰 香港节点 | 自动测速 | 按节点名关键词匹配香港节点 |
| 🇹🇼 台湾节点 | 自动测速 | 按节点名关键词匹配台湾节点 |
| 🇯🇵 日本节点 | 自动测速 | 按节点名关键词匹配日本节点 |
| 🇺🇸 美国节点 | 自动测速 | 按节点名关键词匹配美国节点 |
| 🌐 其他节点 | 自动测速 | 匹配不属于以上地区的节点 |

## 分流规则

规则从上到下依次匹配。`🔍 谷歌服务` 优先级高于 `🤖 AI 服务`，因此 Gemini 会走谷歌服务策略组。

| 优先级 | 服务 | 默认策略 |
|--------|------|----------|
| 1 | 🧱 DNS 防泄露（HTTPDNS） | REJECT |
| 2 | 🛑 广告拦截 | REJECT |
| 3 | 🔍 谷歌服务（含 Gemini） | 日本节点，可手动切香港节点 |
| 4 | 🤖 AI 服务（ChatGPT、Claude 等） | 美国节点 |
| 5 | 📹 油管视频 | 节点选择 |
| 6 | 🔒 哔哩哔哩 | DIRECT |
| 7 | 🏠 私有网络 / 局域网 | DIRECT |
| 8 | 📲 电报消息 | 节点选择 |
| 9 | 🐱 代码托管（GitHub、GitLab、Atlassian） | 节点选择 |
| 10 | Ⓜ️ 微软服务 | 节点选择 |
| 11 | 📈 券商服务（富途 / moomoo / 长桥 / 老虎） | 香港节点 |
| 12 | 🍎 苹果推送 | 节点选择 |
| 13 | 🍏 苹果服务 | DIRECT |
| 14 | 🔒 国内服务 | DIRECT |
| 15 | 🌍 非中国（境外流量） | PROXY |
| 16 | GEOIP CN | DIRECT |
| 17 | 🐟 漏网之鱼（兜底） | PROXY |

## 规则集来源

- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) — 主要规则集
- [iab0x00/ProxyRules](https://github.com/iab0x00/ProxyRules) — AI 服务补充规则
- `Apple.list` 基于 blackmatrix7 Apple 规则，并补充 iCloud Photos / Apple CDN 直连域名
- `HK_Broker.list` 补充富途 / moomoo / 长桥 / 老虎 / TradeUP / Schwab 证券域名及交易 IP 段

## 其他特性

- DNS：DoH（DNSPod + AliDNS），备用 DNS 仍使用 DoH，不回退系统 DNS
- DNS 劫持：拦截常见硬编码 53 端口 DNS，防止应用绕过规则
- HTTPDNS 拦截：引用 blackmatrix7 `BlockHttpDNS`，阻止 App 通过内置 HTTPDNS 绕过系统解析
- QUIC 屏蔽：对代理连接屏蔽 UDP/443，强制回退 HTTP/2
- 本地服务保护：`localhost.weixin.qq.com` 固定解析到 `127.0.0.1` 并强制直连，避免 fake-IP 影响微信本地回调
- 腾讯云 IM：`shortconn.im.qcloud.com` 前置归入国内服务，避免被券商分流规则误挂到香港节点
- TUN 直连优化：iCloud Photos / CloudKit / Apple CDN 域名使用系统 DNS 并跳过代理，保留 Apple Push 走代理
- DNS 上游：移除 `doh.pub`，默认使用 AliDNS DoH + 腾讯 DNS / AliDNS 普通 DNS，减少 DoH 长尾超时
- 局域网解析保护：`*.in-addr.arpa`、`*.ip6.arpa`、`*.local` 前置直连并交给系统解析，补充常见 DNS-SD 反查模式，避免 Bonjour / PTR 反查打到公共 DoH
- TUN 边界：保留 `198.18.0.0/15` 给 fake-IP / TUN 内部使用，不加入排除路由，私网桥接网段仍通过 `10.0.0.0/8`、`192.168.0.0/16` 等排除
- Apple 推送：默认走代理
   - `push.apple.com`
   - `gateway.push.apple.com`
   - `api.push.apple.com`
   - `sandbox.push.apple.com` 
- Google 防跳转：`google.cn` / `g.cn` 自动 302 到 `google.com`
- MITM：仅解密 `*.google.cn`

## 注意事项

- 地区分组通过节点名称关键词自动匹配，请确保你的节点名称包含地区标识（如 🇭🇰、HK、香港等）
- Google、AI、非中国和漏网之鱼的默认出口可在 App 内手动切换
- 如需 HTTPS 解密功能，请在 Shadowrocket 中生成并安装 CA 证书

## License

MIT
