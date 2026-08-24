#!/usr/bin/env python3
"""把上游 Shadowrocket.conf 变换成本 fork 的自用版。

设计要点：
- 仓库不跟踪上游原文，CI 每天现拉现用，所以 git 层面不存在共同修改的文件，冲突量为零。
- 每个补丁都绑一个锚点，锚点消失就抛 AnchorMissing 让 CI 红掉。宁可失败，
  也不要静默生成一份看着正常但少了规则的配置。
- 所有补丁幂等：对自己的产物再跑一次结果不变（tools/test_overlay.py 有回归测试）。

改了这里的任何补丁，**同时要更新 README 开头的「本 fork 的改动」一节** ——
那是这个 fork 相对上游做了什么的唯一说明，README 后半部分是上游原文，不要动。

用法：
    python3 tools/overlay.py --fetch                    # 本地调试：现拉上游并生成
    python3 tools/overlay.py --upstream up.conf --sha abc1234
    python3 tools/overlay.py --check                    # 只校验现有产物
    python3 tools/overlay.py --synced-sha               # 打印已同步到的上游 commit
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

UPSTREAM_REPO = "LingJingMaster/Shadowrocket-Rules"
FORK_REPO = "WSure00/Shadowrocket-Rules"
UPSTREAM_RAW = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/refs/heads/main/"
FORK_RAW = f"https://raw.githubusercontent.com/{FORK_REPO}/refs/heads/main/"
FORK_CONF_URL = FORK_RAW + "Shadowrocket.conf"

# 跟着配置一起同步进本仓库的上游规则表
SYNCED_LISTS = ("AI.list", "Apple.list", "ApplePush.list", "Google.list", "HK_Broker.list")

# True = 生成配置里这 5 份规则的 URL 指向本 fork（手机读到的就是同步 commit 里的版本，
# 而不是上游可变的 main）。默认 False，保持当前线上配置的行为不变。
POINT_SYNCED_LISTS_AT_FORK = False

# CA 私钥字段：**永不**出现在这个公开仓库的任何产物里。
# 故意写得宽松（任意缩进/Tab/等号旁无空格/大小写），只匹配 "ca-p12 = " 的话，
# 上游哪天换成 "ca-p12=" 就绕过去了。
CA_FIELD_RE = re.compile(r"(?im)^[ \t]*ca-(?:p12|passphrase)[ \t]*=.*$\n?")

TS_PLACEHOLDER = "@@TIMESTAMP@@"
TS_LINE_RE = re.compile(r"(?m)^# 生成时间: .*$")

HEADER = """# Shadowrocket 配置（自用版）
# 上游: {repo}
# 生成时间: {ts}
# Author: WSure
"""

# 记录已同步到的上游 commit。定时任务靠它判断要不要干活；
# 故意放在配置外面，这样 Shadowrocket.conf 的内容完全由 overlay 决定。
SHA_FILE = ".upstream-sha"

AUTO_GROUP = "♻️ 自动"
URL_TEST_TUNING = {"interval": "450", "tolerance": "50", "timeout": "2"}
# ♻️ 自动：单层 url-test，直接对全部节点测速。
# 不用 fallback 嵌套地区组：Shadowrocket 只测当前生效的策略链，
# fallback 切换时不会触发子组重新测速，非生效子组永远"不可用"，
# 最后静默落到永远可用的 DIRECT —— 国外流量直连还不易察觉。
# timeout=5：经代理访问 gstatic，2s 太紧，网络一抖就整组误判不可用。
# 正则排除机场的信息节点（剩余流量/官网之类），它们不是可用代理。
AUTO_URL_TEST = (
    f"{AUTO_GROUP} = url-test,url=http://www.gstatic.com/generate_204,"
    "interval=300,tolerance=50,timeout=5,"
    "policy-regex-filter=^(?!.*(直连|剩余|流量|官网|试用|到期)).*$"
)
SPOTIFY_GROUP = "🎧 Spotify = select,DIRECT,🚀 节点选择,🇺🇸 美国节点,policy-select-name=DIRECT"
SPOTIFY_RULESET = (
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master"
    "/rule/Shadowrocket/Spotify/Spotify.list,🎧 Spotify"
)
DIRECT_RULESET = (
    f"RULE-SET,https://raw.githubusercontent.com/{FORK_REPO.split('/')[0]}/ProxyResource"
    "/refs/heads/main/Rule/shadowrocket-direct.list,DIRECT"
)

# 本仓库自带的规则表（论坛本身 + 客户端里配的 DoH 端点，同一个策略）。
# URL 指向 fork —— 它只存在于这里，上游没有。
LINUXDO_LIST = "LinuxDo.list"
LINUXDO_POLICY = "DIRECT"
LINUXDO_RULESET = f"RULE-SET,{FORK_RAW}{LINUXDO_LIST},{LINUXDO_POLICY}"

# linux.do 走 DIRECT，但国内 DNS 对它污染极彻底：alidns / 119.29.29.29 /
# 223.5.5.5 分别给 108.160.167.174(Dropbox 段)、31.13.75.12(Facebook 段) 等，
# 全部连不通。只改规则不改解析，DIRECT 拿到污染 IP 照样上不去 —— 这正是
# 之前"命中了 DIRECT 但还是打不开"的原因。
# 这里把它的解析钉到干净 DoH（wsu 两种格式都支持，实测返回真实 Cloudflare IP）。
HOST_DOH_SERVER = "https://wsu.ddd.oaifree.com/query-dns"
HOST_DOH_DOMAINS = ("linux.do", "*.linux.do")
HOST_DOH_LINES = tuple(f"{d} = server:{HOST_DOH_SERVER}" for d in HOST_DOH_DOMAINS)

MITM_FIELDS = (("h2", "true"), ("enable", "true"))

class AnchorMissing(RuntimeError):
    """上游结构变了，锚点找不到。CI 应该直接失败。"""


def _section_bounds(text: str, name: str) -> tuple[int, int]:
    """返回 [name] 段正文的 (start, end) 偏移，不含段头本身。"""
    head = re.search(rf"(?m)^\[{re.escape(name)}\][ \t]*$", text)
    if not head:
        raise AnchorMissing(f"找不到段 [{name}]")
    start = head.end()
    nxt = re.search(r"(?m)^\[[^\]]+\][ \t]*$", text[start:])
    return start, start + nxt.start() if nxt else len(text)


def _sub_in_section(text: str, name: str, pattern: str, repl, *, count: int = 0) -> tuple[str, int]:
    """只在某个段内做替换，避免误伤同名字样出现在别的段。"""
    start, end = _section_bounds(text, name)
    body, n = re.subn(pattern, repl, text[start:end], count=count)
    return text[:start] + body + text[end:], n


def patch_header(text: str) -> str:
    """替换开头的注释块。时间戳先写占位符，最后再决定要不要落盘。"""
    header = HEADER.format(repo=UPSTREAM_REPO, ts=TS_PLACEHOLDER)
    new, n = re.subn(r"\A(?:#.*\n)+", header, text, count=1)
    if not n:
        raise AnchorMissing("文件开头没有注释块可替换")
    return new


def patch_update_url(text: str) -> str:
    """update-url 必须指向本 fork。指向上游的话 App 每次更新配置都会拉回原版，
    把所有个人改动覆盖掉。"""
    if f"update-url = {FORK_CONF_URL}" in text:
        return text
    new, n = _sub_in_section(
        text, "General", r"(?m)^update-url\s*=.*$",
        lambda _: f"update-url = {FORK_CONF_URL}", count=1,
    )
    if not n:
        raise AnchorMissing("[General] 里没有 update-url")
    return new


def patch_ipv6(text: str) -> str:
    new, n = _sub_in_section(
        text, "General", r"(?m)^ipv6\s*=.*$", lambda _: "ipv6 = true", count=1
    )
    if not n:
        raise AnchorMissing("[General] 里没有 ipv6")
    return new


def patch_taiwan_name(text: str) -> str:
    """组名 🇹🇼 台湾节点 -> 🇨🇳 台湾节点。

    只改组名整串，policy-regex-filter 里裸的 🇹🇼 不动 —— 那个要匹配机场给出的
    真实节点名，改了就一个台湾节点都选不中。
    """
    if "🇨🇳 台湾节点" in text:
        return text
    new, n = re.subn("🇹🇼 台湾节点", "🇨🇳 台湾节点", text)
    if not n:
        raise AnchorMissing("找不到 🇹🇼 台湾节点")
    return new


def _is_url_test(line: str) -> bool:
    _, eq, value = line.partition("=")
    return bool(eq) and value.split(",")[0].strip() == "url-test"


def url_test_params(line: str) -> dict[str, str]:
    """按逗号精确拆出 url-test 行的参数表。

    不用子串匹配：'interval=600' 是 'check-interval=600' 的子串，
    上游改个参数名就能悄悄绕过校验。
    """
    _, _, value = line.partition("=")
    params: dict[str, str] = {}
    for token in value.split(","):
        key, eq, val = token.partition("=")
        if eq:
            params[key.strip()] = val.strip()
    return params


def patch_url_test_tuning(text: str) -> str:
    """收紧所有 url-test 组的测速参数。

    逐行按参数名精确替换，而不是逐组列举：上游以后加了新地区组也会自动跟着调。
    """
    start, end = _section_bounds(text, "Proxy Group")
    lines = text[start:end].splitlines(keepends=True)
    if not any(_is_url_test(line) for line in lines):
        raise AnchorMissing("[Proxy Group] 里没有 url-test 组")

    out_lines = []
    for line in lines:
        if not _is_url_test(line):
            out_lines.append(line)
            continue
        name, sep, value = line.partition("=")
        # 只动命中的参数，其余 token 原样回填，所以拆开再拼是无损的
        tokens = [
            f"{k}={URL_TEST_TUNING[k]}" if (k := t.split("=", 1)[0].strip()) in URL_TEST_TUNING else t
            for t in value.split(",")
        ]
        tuned = name + sep + ",".join(tokens)
        params = url_test_params(tuned)
        for key, val in URL_TEST_TUNING.items():
            if params.get(key) != val:
                raise AnchorMissing(
                    f"url-test 组没能套上 {key}={val}（上游可能改了参数名）: {name.strip()}"
                )
        out_lines.append(tuned)
    return text[:start] + "".join(out_lines) + text[end:]


def _region_groups(text: str) -> list[str]:
    """按出现顺序取出所有 url-test 地区组的组名。

    要排除 ♻️ 自动 自身：它也是 url-test 组，二次跑 overlay 时会混进来，
    幂等性就破了。
    """
    start, end = _section_bounds(text, "Proxy Group")
    names = [
        line.partition("=")[0].strip()
        for line in text[start:end].splitlines()
        if _is_url_test(line) and line.partition("=")[0].strip() != AUTO_GROUP
    ]
    if not names:
        raise AnchorMissing("[Proxy Group] 里没有地区组")
    return names


def patch_select_and_auto(text: str) -> str:
    """节点选择默认走 ♻️ 自动；♻️ 自动是单层 url-test，直接测全部节点。

    用户的节点自动化目标是"只管开关、不选节点"。
    """
    regions = _region_groups(text)  # 必须在台湾改名之后调用
    select = (
        "🚀 节点选择 = select," + AUTO_GROUP + ",PROXY,DIRECT,REJECT,"
        + ",".join(regions) + f",policy-select-name={AUTO_GROUP}"
    )
    auto = AUTO_URL_TEST

    new, n = _sub_in_section(
        text, "Proxy Group", r"(?m)^🚀 节点选择\s*=.*$", lambda _: select, count=1
    )
    if not n:
        raise AnchorMissing("[Proxy Group] 里没有 🚀 节点选择")

    if re.search(rf"(?m)^{re.escape(AUTO_GROUP)}\s*=", new):
        new, _ = _sub_in_section(
            new, "Proxy Group", rf"(?m)^{re.escape(AUTO_GROUP)}\s*=.*$",
            lambda _: auto, count=1,
        )
    else:
        new, _ = _sub_in_section(
            new, "Proxy Group", r"(?m)^(🚀 节点选择\s*=.*)$",
            lambda m: m.group(1) + "\n" + auto, count=1,
        )
    return new


def patch_spotify_group(text: str) -> str:
    if SPOTIFY_GROUP in text:
        return text
    new, n = _sub_in_section(
        text, "Proxy Group", r"(?m)^(🧱 DNS 防泄露\s*=.*)$",
        lambda m: m.group(1) + "\n\n" + SPOTIFY_GROUP, count=1,
    )
    if not n:
        raise AnchorMissing("[Proxy Group] 里没有 🧱 DNS 防泄露，Spotify 组没有落点")
    return new


def patch_fallback_policy(text: str) -> str:
    """🌍 非中国 / 🐟 漏网之鱼 的默认项从 PROXY 改成 🚀 节点选择。"""
    for group in ("🌍 非中国", "🐟 漏网之鱼"):
        text, n = _sub_in_section(
            text, "Proxy Group",
            rf"(?m)^({re.escape(group)}\s*=.*policy-select-name=).*$",
            lambda m: m.group(1) + "🚀 节点选择", count=1,
        )
        if not n:
            raise AnchorMissing(f"[Proxy Group] 里没有带 policy-select-name 的 {group}")
    return text


def patch_direct_ruleset(text: str) -> str:
    """个人直连表放在 [Rule] 最前面 —— 它要能压过后面所有规则。"""
    if DIRECT_RULESET in text:
        return text
    start, _ = _section_bounds(text, "Rule")
    return text[:start] + "\n\n" + DIRECT_RULESET + "\n\n" + text[start:].lstrip("\n")


def patch_linuxdo_ruleset(text: str) -> str:
    """LinuxDo.list 插到 [Rule] 最前面，压过个人直连表。

    必须排在 patch_direct_ruleset 之后跑：那个函数也往 [Rule] 开头插，
    后插的会顶到更前面，正好是需要的顺序。
    """
    if LINUXDO_RULESET in text:
        return text
    if LINUXDO_POLICY not in text:
        raise AnchorMissing(
            f"[Proxy Group] 里没有 {LINUXDO_POLICY}，{LINUXDO_LIST} 规则没有落点"
        )
    start, _ = _section_bounds(text, "Rule")
    return text[:start] + "\n\n" + LINUXDO_RULESET + "\n\n" + text[start:].lstrip("\n")


def patch_host_doh(text: str) -> str:
    """把 linux.do 的解析钉到干净 DoH。

    它走 DIRECT，而 DIRECT 由 Shadowrocket 用 [General] 里的国内 dns-server
    自己解析 —— 那几个对 linux.do 污染得很彻底，拿到的 IP 全连不通。
    只改规则策略不改这里，DIRECT 照样打不开。
    """
    start, end = _section_bounds(text, "Host")
    body = text[start:end]
    # 按整行比，不用子串 —— "linux.do = server:X" 是 "*.linux.do = server:X"
    # 的子串，子串比法会让前者永远被判成"已存在"而漏插。
    existing = {l.strip() for l in body.splitlines()}
    add = [l for l in HOST_DOH_LINES if l not in existing]
    if not add:
        return text
    return text[:start] + "\n" + "\n".join(add) + "\n" + body.lstrip("\n") + text[end:]


def patch_spotify_ruleset(text: str) -> str:
    if SPOTIFY_RULESET in text:
        return text
    # 依次尝试一组锚点：上游 2026-08-22 删了 Advertising 规则（连带广告拦截组），
    # 单一锚点太脆。顺序按原来的插入位置排，靠前的还在就用靠前的。
    # 都是插入位置而非关键内容，缺哪个都行，全没了才算真出事。
    anchors = [
        (r"(?m)^(RULE-SET,\S+/Advertising/Advertising\.list,.*)$", "after"),
        (r"(?m)^(RULE-SET,\S+/YouTube/YouTube\.list,.*)$", "after"),
        (r"(?m)^(RULE-SET,\S+/China/China\.list,.*)$", "before"),
    ]
    for pattern, where in anchors:
        if where == "after":
            repl = lambda m: m.group(1) + "\n\n" + SPOTIFY_RULESET  # noqa: E731
        else:
            repl = lambda m: SPOTIFY_RULESET + "\n\n" + m.group(1)  # noqa: E731
        new, n = _sub_in_section(text, "Rule", pattern, repl, count=1)
        if n:
            return new
    raise AnchorMissing("[Rule] 里找不到任何可用锚点，Spotify 规则没有落点")


def patch_mitm(text: str) -> str:
    start, end = _section_bounds(text, "MITM")
    body = text[start:end]
    add = [f"{k} = {v}" for k, v in MITM_FIELDS if not re.search(rf"(?m)^{k}\s*=", body)]
    if not add:
        return text
    return text[:start] + "\n" + "\n".join(add) + "\n" + body.lstrip("\n")


def patch_list_urls(text: str) -> str:
    """把同步进本仓库的 5 份规则表 URL 指向 fork。

    不这么做的话，手机会绕过每日同步 commit 直读上游可变的 main，
    同步进来的文件就白同步了。blackmatrix7 等第三方规则不同步，URL 保持原样。
    """
    for name in SYNCED_LISTS:
        if UPSTREAM_RAW + name not in text and FORK_RAW + name not in text:
            raise AnchorMissing(f"[Rule] 里找不到 {name} 的 RULE-SET")
    if not POINT_SYNCED_LISTS_AT_FORK:
        return text
    for name in SYNCED_LISTS:
        text = text.replace(UPSTREAM_RAW + name, FORK_RAW + name)
    return text


def strip_ca(text: str) -> str:
    """兜底：上游哪天带了 CA 私钥字段进来，这里剥掉。"""
    return CA_FIELD_RE.sub("", text)


PATCHES = (
    patch_update_url,
    patch_ipv6,
    patch_taiwan_name,
    patch_url_test_tuning,
    patch_select_and_auto,
    patch_spotify_group,
    patch_fallback_policy,
    patch_direct_ruleset,
    patch_linuxdo_ruleset,
    patch_host_doh,
    patch_spotify_ruleset,
    patch_mitm,
    patch_list_urls,
    strip_ca,
)


def render(upstream: str) -> str:
    """跑完整条 overlay。返回的文本里时间戳还是占位符。"""
    text = patch_header(upstream)
    for patch in PATCHES:
        text = patch(text)
    verify(text)
    return text


def verify(text: str) -> None:
    """产物自检。任何一条不过就抛 AnchorMissing。"""
    if CA_FIELD_RE.search(text):
        raise AnchorMissing("产物里出现了 CA 私钥字段，绝不允许提交")
    required = [
        f"update-url = {FORK_CONF_URL}",
        "FINAL,",
        "GEOIP,CN,",
        AUTO_GROUP + " = url-test,",
        "🇨🇳 台湾节点 =",
    ]
    for token in required:
        if token not in text:
            raise AnchorMissing(f"产物缺少必需内容: {token}")
    base = FORK_RAW if POINT_SYNCED_LISTS_AT_FORK else UPSTREAM_RAW
    for name in SYNCED_LISTS:
        if base + name not in text:
            raise AnchorMissing(f"产物缺少 {name} 的 RULE-SET")
    if "🇹🇼 台湾节点" in text:
        raise AnchorMissing("产物里还有旧组名 🇹🇼 台湾节点")

    # LinuxDo.list 的存在性 + 顺序。顺序错了规则就不起作用，且是静默的，必须查。
    if LINUXDO_RULESET not in text:
        raise AnchorMissing(f"产物缺少 {LINUXDO_RULESET}")
    if text.index(LINUXDO_RULESET) > text.index(DIRECT_RULESET):
        raise AnchorMissing(
            f"{LINUXDO_LIST} 必须早于个人直连表 —— 两边都是 DIRECT，"
            "但顺序固定下来才不会因为上游改动而漂"
        )
    blockdns = re.search(r"(?m)^RULE-SET,\S+/BlockHttpDNS/BlockHttpDNS\.list,.*$", text)
    if blockdns and text.index(LINUXDO_RULESET) > blockdns.start():
        raise AnchorMissing(
            f"{LINUXDO_LIST} 必须早于 BlockHttpDNS.list，否则里面的 DoH 可能被 REJECT"
        )

    # linux.do 走 DIRECT 时由 Shadowrocket 自己解析，国内 dns-server 对它污染
    # 极彻底（拿到的 IP 全连不通）。少了这几行，规则是对的但照样打不开。
    host_start, host_end = _section_bounds(text, "Host")
    # 按整行比，不用子串 —— "linux.do = server:X" 是 "*.linux.do = server:X"
    # 的子串，子串比法会让前者漏检。
    host_lines = {l.strip() for l in text[host_start:host_end].splitlines()}
    for line in HOST_DOH_LINES:
        if line not in host_lines:
            raise AnchorMissing(f"[Host] 段缺少 DoH 钉定: {line}")

    # 指向本 fork 的规则表必须真的存在于仓库里，否则手机拉到 404，规则静默失效。
    # 这条挡的是"删掉某个 patch 后，拿旧产物当输入重新生成"——旧产物里的 RULE-SET
    # 没有任何 patch 会去删，会一路留下来。
    allowed = {LINUXDO_LIST}
    if POINT_SYNCED_LISTS_AT_FORK:
        allowed |= set(SYNCED_LISTS)
    referenced = re.findall(rf"{re.escape(FORK_RAW)}(\S+?\.list)", text)
    for name in referenced:
        if name not in allowed:
            raise AnchorMissing(f"产物引用了本 fork 不存在的规则表: {name}")

    # 同一份表只能出现一次。改了某个 patch 的策略后拿旧产物当输入重新生成时，
    # 旧那条不会被删，新那条会插在前面 —— 两条策略冲突，靠前的生效，
    # 表面上看不出问题。开发中踩到过两次。
    for name in set(referenced):
        n = referenced.count(name)
        if n > 1:
            raise AnchorMissing(f"{name} 在产物里出现 {n} 次，应当只有一条")


def _now_ts() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S (UTC+8)")


def _fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - 固定的 https 常量
        return resp.read().decode("utf-8")


def write_output(rendered: str, out: Path) -> None:
    """落盘，头部时间戳一律刷成当前时间。

    跑到这一步就说明上游确实有新提交（没有的话 workflow 的 check job 已经早退了），
    所以哪怕生成内容一个字节没变，也把时间戳更新掉 —— 它记录的是"这份配置对齐到
    上游的时刻"，不是"内容上次变化的时刻"。
    """
    out.write_text(rendered.replace(TS_PLACEHOLDER, _now_ts()), encoding="utf-8")


def read_synced_sha(path: Path) -> str:
    """读出已同步到的上游 commit。文件不存在或为空时返回 ""，让定时任务照常同步一次。"""
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="生成本 fork 的 Shadowrocket.conf")
    ap.add_argument("--upstream", type=Path, help="上游 Shadowrocket.conf 路径")
    ap.add_argument("--fetch", action="store_true", help="现拉上游 main（本地调试用）")
    ap.add_argument("--sha", help="本次同步的上游 commit，成功后记到 .upstream-sha")
    ap.add_argument("--out", type=Path, default=Path("Shadowrocket.conf"))
    ap.add_argument("--sha-file", type=Path, default=Path(SHA_FILE))
    ap.add_argument("--check", action="store_true", help="只校验 --out 现有产物，不生成")
    ap.add_argument(
        "--synced-sha", action="store_true", help="打印已同步的上游 commit 后退出"
    )
    args = ap.parse_args(argv)

    if args.synced_sha:
        print(read_synced_sha(args.sha_file))
        return 0

    if args.check:
        verify(args.out.read_text(encoding="utf-8"))
        print(f"OK  {args.out} 自检通过")
        return 0

    if args.fetch:
        upstream = _fetch(UPSTREAM_RAW + "Shadowrocket.conf")
    elif args.upstream:
        upstream = args.upstream.read_text(encoding="utf-8")
    else:
        ap.error("需要 --upstream 或 --fetch")

    write_output(render(upstream), args.out)
    print(f"已写入（时间戳已刷新）  {args.out}")
    if args.sha:
        # 无条件记账：这次确实照着这个 commit 生成过了，配置有没有变是另一回事。
        args.sha_file.write_text(args.sha.strip() + "\n", encoding="utf-8")
        print(f"已同步到 {args.sha.strip()[:7]}  ->  {args.sha_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
