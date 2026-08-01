#!/usr/bin/env python3
"""overlay.py 的回归测试。跑法：python3 tools/test_overlay.py"""

from __future__ import annotations

import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import overlay  # noqa: E402
from overlay import AnchorMissing  # noqa: E402

HERE = Path(__file__).resolve().parent
UPSTREAM = (HERE / "testdata" / "upstream-2026-06-12.conf").read_text(encoding="utf-8")
EXPECTED = (HERE / "testdata" / "expected.conf").read_text(encoding="utf-8")


def _strip_ts(text: str) -> str:
    """抹掉时间戳那行，用来比较"除时间戳之外是否一致"。"""
    return overlay.TS_LINE_RE.sub("# 生成时间: -", text)


class TestGolden(unittest.TestCase):
    def test_matches_expected_output(self):
        """对着冻结的上游快照，产物必须逐字节等于 expected.conf。"""
        self.assertEqual(overlay.render(UPSTREAM), EXPECTED)

    def test_idempotent(self):
        """对自己的产物再跑一次，结果不变。CI 每天重跑，这条必须成立。"""
        once = overlay.render(UPSTREAM)
        self.assertEqual(overlay.render(once), once)

    def test_thrice(self):
        text = UPSTREAM
        for _ in range(3):
            text = overlay.render(text)
        self.assertEqual(text, EXPECTED)


class TestCriticalContent(unittest.TestCase):
    def setUp(self):
        self.out = overlay.render(UPSTREAM)

    def test_update_url_points_at_fork(self):
        self.assertIn(f"update-url = {overlay.FORK_CONF_URL}", self.out)
        self.assertNotIn(
            f"update-url = {overlay.UPSTREAM_RAW}Shadowrocket.conf", self.out
        )

    def test_taiwan_regex_filter_keeps_original_flag(self):
        """组名换成 🇨🇳，但 policy-regex-filter 里的 🇹🇼 必须留着 ——
        它匹配机场给出的真实节点名，改了就一个台湾节点都选不中。"""
        line = next(
            l for l in self.out.splitlines() if l.startswith("🇨🇳 台湾节点 =")
        )
        self.assertIn("policy-regex-filter=🇹🇼|TW", line)
        self.assertNotIn("🇹🇼 台湾节点", self.out)

    def test_final_and_geoip_survive(self):
        self.assertIn("FINAL,🐟 漏网之鱼", self.out)
        self.assertIn("GEOIP,CN,🔒 国内服务", self.out)

    def test_all_synced_lists_present(self):
        base = overlay.FORK_RAW if overlay.POINT_SYNCED_LISTS_AT_FORK else overlay.UPSTREAM_RAW
        for name in overlay.SYNCED_LISTS:
            self.assertIn(base + name, self.out)

    def test_third_party_rules_untouched(self):
        """blackmatrix7 的规则不同步，URL 保持原样。"""
        self.assertIn("blackmatrix7/ios_rule_script", self.out)
        self.assertEqual(
            UPSTREAM.count("blackmatrix7"), self.out.count("blackmatrix7") - 1
        )  # -1 是我们加的 Spotify

    def test_direct_ruleset_is_first_rule(self):
        rules = [l for l in self.out.splitlines() if l.startswith(("RULE-SET,", "DOMAIN", "IP-CIDR", "GEOIP", "FINAL"))]
        self.assertEqual(rules[0], overlay.DIRECT_RULESET)

    def test_auto_group_is_fallback_over_all_regions(self):
        line = next(l for l in self.out.splitlines() if l.startswith(overlay.AUTO_GROUP + " ="))
        self.assertTrue(line.startswith(overlay.AUTO_GROUP + " = fallback,"))
        for region in ("🇭🇰 香港节点", "🇨🇳 台湾节点", "🇯🇵 日本节点", "🇺🇸 美国节点", "🌐 其他节点"):
            self.assertIn(region, line)

    def test_url_test_tuning_applied_everywhere(self):
        for line in self.out.splitlines():
            if "= url-test," in line:
                for key, val in overlay.URL_TEST_TUNING.items():
                    self.assertIn(f"{key}={val}", line)


class TestCaGuard(unittest.TestCase):
    """CA 私钥永不进入这个公开仓库。故意测各种写法。"""

    VARIANTS = (
        "ca-p12 = MIIKfQIBAzCC",
        "ca-p12=MIIKfQIBAzCC",
        "  ca-p12 = MIIKfQIBAzCC",
        "\tca-passphrase = hunter2",
        "CA-P12 = MIIKfQIBAzCC",
        "ca-passphrase=hunter2",
    )

    def test_strip_removes_every_variant(self):
        for variant in self.VARIANTS:
            with self.subTest(variant=variant):
                text = f"[MITM]\n{variant}\nhostname = *.google.cn\n"
                out = overlay.strip_ca(text)
                self.assertNotIn("MIIKfQIBAzCC", out)
                self.assertNotIn("hunter2", out)
                self.assertIn("hostname = *.google.cn", out)

    def test_verify_rejects_ca(self):
        for variant in self.VARIANTS:
            with self.subTest(variant=variant):
                bad = EXPECTED.replace("[MITM]\n", f"[MITM]\n{variant}\n")
                with self.assertRaises(AnchorMissing):
                    overlay.verify(bad)

    def test_upstream_ca_gets_stripped_end_to_end(self):
        """上游哪天带了 CA 进来，整条流水线也不该把它带出去。"""
        poisoned = UPSTREAM.replace(
            "[MITM]\n", "[MITM]\nca-p12 = MIIKfQIBAzCC\nca-passphrase = hunter2\n"
        )
        out = overlay.render(poisoned)
        self.assertNotIn("MIIKfQIBAzCC", out)
        self.assertNotIn("hunter2", out)


class TestAnchors(unittest.TestCase):
    """锚点消失必须炸，而不是静默生成一份少了东西的配置。"""

    CASES = {
        "update-url": "update-url = https://raw.githubusercontent.com/LingJingMaster/Shadowrocket-Rules/refs/heads/main/Shadowrocket.conf\n",
        "ipv6": "ipv6 = false\n",
        "select": "🚀 节点选择 = select,PROXY,DIRECT,REJECT,🇭🇰 香港节点,🇹🇼 台湾节点,🇯🇵 日本节点,🇺🇸 美国节点,🌐 其他节点\n",
        "dns-leak": "🧱 DNS 防泄露 = select,REJECT,🚀 节点选择,DIRECT\n",
        "advertising": "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Advertising/Advertising.list,🛑 广告拦截\n",
    }

    def test_missing_anchor_raises(self):
        for label, anchor in self.CASES.items():
            with self.subTest(anchor=label):
                self.assertIn(anchor, UPSTREAM, f"测试自身失效：{label} 已不在上游快照里")
                with self.assertRaises(AnchorMissing):
                    overlay.render(UPSTREAM.replace(anchor, ""))

    def test_missing_section_raises(self):
        for section in ("General", "Proxy Group", "Rule", "MITM"):
            with self.subTest(section=section):
                with self.assertRaises(AnchorMissing):
                    overlay.render(UPSTREAM.replace(f"[{section}]", "[gone]"))

    def test_renamed_url_test_param_raises(self):
        """上游把 interval= 换成别的写法时，要炸而不是生成一份没调过参数的配置。"""
        with self.assertRaises(AnchorMissing):
            overlay.render(UPSTREAM.replace("interval=600", "check-interval=600"))

    def test_dropped_synced_list_raises(self):
        broken = UPSTREAM.replace(overlay.UPSTREAM_RAW + "HK_Broker.list", "")
        with self.assertRaises(AnchorMissing):
            overlay.render(broken)


class TestUpstreamEvolution(unittest.TestCase):
    def test_new_region_group_picked_up(self):
        """上游以后加了地区组，应自动套上测速参数并进 自动/节点选择 两个组。"""
        added = "🇸🇬 新加坡节点 = url-test,url=http://www.gstatic.com/generate_204,interval=600,tolerance=0,timeout=5,policy-regex-filter=SG\n"
        upstream = UPSTREAM.replace(
            "🌐 其他节点 = url-test", added + "🌐 其他节点 = url-test"
        )
        out = overlay.render(upstream)
        line = next(l for l in out.splitlines() if l.startswith("🇸🇬 新加坡节点 ="))
        self.assertIn("interval=450", line)
        self.assertIn("tolerance=50", line)
        self.assertIn("timeout=2", line)
        for group in ("🚀 节点选择 =", overlay.AUTO_GROUP + " ="):
            self.assertIn("🇸🇬 新加坡节点", next(l for l in out.splitlines() if l.startswith(group)))

    def test_params_parsed_exactly_not_by_substring(self):
        """'interval=600' 是 'check-interval=600' 的子串 —— 必须按参数名精确比。"""
        params = overlay.url_test_params("X = url-test,check-interval=600,timeout=5")
        self.assertEqual(params.get("check-interval"), "600")
        self.assertIsNone(params.get("interval"))

    def test_unknown_params_preserved(self):
        """只动我们要调的参数，上游其它 token 原样保留。"""
        upstream = UPSTREAM.replace(
            "interval=600,tolerance=0,timeout=5,policy-regex-filter=🇭🇰",
            "interval=600,tolerance=0,timeout=5,evaluate-before-use=true,policy-regex-filter=🇭🇰",
            1,
        )
        out = overlay.render(upstream)
        line = next(l for l in out.splitlines() if l.startswith("🇭🇰 香港节点 ="))
        self.assertIn("evaluate-before-use=true", line)
        self.assertIn("interval=450", line)

    def test_ca_equals_no_space_not_bypassed(self):
        """CA_FIELD_RE 故意写宽松：只匹配 'ca-p12 = ' 的话这条就漏了。"""
        self.assertTrue(overlay.CA_FIELD_RE.search("ca-p12=x"))


class TestWriteOutput(unittest.TestCase):
    def test_placeholder_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "Shadowrocket.conf"
            overlay.write_output(overlay.render(UPSTREAM), out)
            text = out.read_text(encoding="utf-8")
            self.assertNotIn(overlay.TS_PLACEHOLDER, text)
            self.assertRegex(text, r"(?m)^# 生成时间: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d \(UTC\+8\)$")

    def test_timestamp_refreshed_even_when_content_identical(self):
        """每次同步都要刷时间戳。它记录的是对齐到上游的时刻，不是内容变化的时刻。

        固定 _now_ts 而不是靠两次真实调用 —— 同一秒内跑两次会拿到一样的时间戳，
        那样这条测试会随机通过。
        """
        rendered = overlay.render(UPSTREAM)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "Shadowrocket.conf"
            with unittest.mock.patch.object(overlay, "_now_ts", return_value="T1"):
                overlay.write_output(rendered, out)
            first = out.read_text(encoding="utf-8")
            with unittest.mock.patch.object(overlay, "_now_ts", return_value="T2"):
                overlay.write_output(rendered, out)
            second = out.read_text(encoding="utf-8")

            self.assertIn("# 生成时间: T1", first)
            self.assertIn("# 生成时间: T2", second)
            # 除了时间戳那行，其余部分逐字节一致
            self.assertEqual(_strip_ts(first), _strip_ts(second))

    def test_writes_when_content_differs(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "Shadowrocket.conf"
            overlay.write_output(overlay.render(UPSTREAM), out)
            changed = overlay.render(
                UPSTREAM.replace("block-quic = all-proxy", "block-quic = off")
            )
            overlay.write_output(changed, out)
            self.assertIn("block-quic = off", out.read_text(encoding="utf-8"))


class TestSyncedSha(unittest.TestCase):
    """定时任务靠 .upstream-sha 判断要不要干活。"""

    def test_missing_file_reads_empty(self):
        """文件不存在时返回空串 —— 定时任务据此照常同步一次，自愈。"""
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(overlay.read_synced_sha(Path(td) / "nope"), "")

    def test_roundtrip(self):
        sha = "833fbda69c6170ddbea3f299deeb38ae350d6f32"
        with tempfile.TemporaryDirectory() as td:
            out, shaf = Path(td) / "Shadowrocket.conf", Path(td) / ".upstream-sha"
            overlay.main([
                "--upstream", str(HERE / "testdata" / "upstream-2026-06-12.conf"),
                "--out", str(out), "--sha-file", str(shaf), "--sha", sha,
            ])
            self.assertEqual(overlay.read_synced_sha(shaf), sha)

    def test_sha_recorded_even_when_conf_unchanged(self):
        """配置内容没变也要记账，否则每天都会被判成"还没同步过"而重复干活。"""
        sha1, sha2 = "a" * 40, "b" * 40
        with tempfile.TemporaryDirectory() as td:
            out, shaf = Path(td) / "Shadowrocket.conf", Path(td) / ".upstream-sha"
            argv = [
                "--upstream", str(HERE / "testdata" / "upstream-2026-06-12.conf"),
                "--out", str(out), "--sha-file", str(shaf), "--sha",
            ]
            overlay.main(argv + [sha1])
            before = out.read_text(encoding="utf-8")
            overlay.main(argv + [sha2])
            # 时间戳会刷新，其余内容不动
            self.assertEqual(_strip_ts(out.read_text(encoding="utf-8")), _strip_ts(before))
            self.assertEqual(overlay.read_synced_sha(shaf), sha2)


class TestShippedArtifact(unittest.TestCase):
    def test_repo_conf_passes_verify(self):
        """仓库里现有的 Shadowrocket.conf 自检要过。"""
        conf = HERE.parent / "Shadowrocket.conf"
        overlay.verify(conf.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
