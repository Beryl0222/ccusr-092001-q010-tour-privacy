"""控制平台核心行为测试：授权、风险、离线包、审计。"""

import hashlib
import hmac
import json
import unittest

from core import (
    ControlPlatform,
    KEY_GRACE_SECONDS,
    PlatformError,
    ROLE_AUDITOR,
    ROLE_OPS,
    mask_identifier,
)


def sign(secret, tracks):
    payload = json.dumps(tracks, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"))
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


TRACKS = [
    {"t": 1000, "lat": 31.2304, "lon": 121.4737},
    {"t": 1060, "lat": 31.2310, "lon": 121.4740},
    {"t": 1120, "lat": 31.2315, "lon": 121.4744},
]


class Base(unittest.TestCase):
    def setUp(self):
        self.now = [10_000.0]
        self.p = ControlPlatform(now=lambda: self.now[0])
        self.device = self.p.register_device("dev-1")

    def grant_all(self, tourist="游客甲", ttl=None):
        for scope in ("定位", "语音", "影像", "日志"):
            self.p.apply_consent(tourist, scope, "授予", ttl)

    def issue(self, tourist="游客甲", trip="行程1", family=None,
              caps=("定位", "语音交互", "影像记录", "日志生成", "路线建议")):
        return self.p.issue_session(self.device["设备"], trip, tourist,
                                    list(caps), family)

    def upload(self, package="pkg-1", trip="行程1", tracks=None, key=None):
        key = key or self.device
        tracks = TRACKS if tracks is None else tracks
        return self.p.submit_offline_package(
            self.device["设备"], key["密钥编号"], trip, package,
            tracks, sign(key["密钥"], tracks))


class ConsentTest(Base):
    def test_least_privilege_session(self):
        # 只授予定位与日志，语音/影像未授权不应下发
        self.p.apply_consent("游客甲", "定位", "授予")
        self.p.apply_consent("游客甲", "日志", "授予")
        session = self.issue()
        self.assertEqual(session["状态"], "有效")
        self.assertEqual(sorted(session["允许能力"]),
                         ["定位", "日志生成", "路线建议"])
        denied = {r["能力"] for r in session["受限"]}
        self.assertEqual(denied, {"语音交互", "影像记录"})

    def test_revoke_invalidates_cache_and_issues_receipt(self):
        self.grant_all()
        session = self.issue()
        result = self.p.revoke_consent("游客甲", "定位")
        receipt = result["回执"]
        self.assertEqual(receipt["动作"], "撤回")
        self.assertEqual(receipt["确认动作"], "删除确认")
        self.assertIn(session["会话"], receipt["失效会话"])
        # 会话已失效，导航策略拒绝
        with self.assertRaises(PlatformError) as ctx:
            self.p.navigation_strategy(session["会话"])
        self.assertEqual(ctx.exception.status, 409)

    def test_expiry_sweep_invalidates_and_deletes_offline_tracks(self):
        self.grant_all(ttl=60)
        session = self.issue()
        self.upload()
        self.now[0] += 120  # 超过有效期
        receipts = self.p.sweep_expired()["回执"]
        actions = {(r["范围"], r["动作"]) for r in receipts}
        self.assertIn(("定位", "到期"), actions)
        location_receipt = next(r for r in receipts if r["范围"] == "定位")
        self.assertIn(session["会话"], location_receipt["失效会话"])
        self.assertIn({"类型": "离线轨迹", "编号": "pkg-1"},
                      location_receipt["删除项"])
        # 轨迹载荷已被删除
        self.assertTrue(self.p.package_view("pkg-1")["轨迹已删除"])
        # 日志授权到期后，游览日志被删除
        self.assertEqual(self.p.trip_logs("行程1", "op", ROLE_AUDITOR)["日志"], [])

    def test_version_bumps_on_change(self):
        self.p.apply_consent("游客甲", "定位", "授予")
        v1 = self.p.consent_view("游客甲")["授权版本"]
        self.p.apply_consent("游客甲", "定位", "限制")
        v2 = self.p.consent_view("游客甲")["授权版本"]
        self.assertGreater(v2, v1)


class FamilyTest(Base):
    def test_member_dissent_blocks_shared_capability(self):
        self.grant_all("游客甲")
        self.p.create_family("家1", ["游客甲", "游客乙"])
        self.p.dissent("家1", "游客乙", "影像")
        session = self.issue(family="家1")
        self.assertNotIn("影像记录", session["允许能力"])
        reasons = {r["能力"]: r["原因"] for r in session["受限"]}
        self.assertIn("不同意", reasons["影像记录"])
        # 定位等个人授权能力不受影响
        self.assertIn("定位", session["允许能力"])

    def test_dissent_invalidates_existing_session(self):
        self.grant_all("游客甲")
        self.p.create_family("家1", ["游客甲", "游客乙"])
        session = self.issue(family="家1")
        result = self.p.dissent("家1", "游客乙", "语音")
        self.assertIn(session["会话"], result["失效会话"])


class KeyRotationTest(Base):
    def test_old_key_works_within_grace_then_quarantined(self):
        old = self.device
        self.grant_all()
        self.issue()
        self.p.rotate_key("dev-1")
        # 宽限期内旧密钥签名仍被接受
        ok = self.upload(package="pkg-old", key=old)
        self.assertEqual(ok["状态"], "已合并")
        # 宽限期过后旧密钥提交的包被隔离
        self.now[0] += KEY_GRACE_SECONDS + 1
        stale = self.upload(package="pkg-stale", key=old)
        self.assertEqual(stale["状态"], "已隔离")
        self.assertIn("宽限", stale["原因"])

    def test_new_key_required_after_rotation(self):
        self.grant_all()
        self.issue()
        new_key = self.p.rotate_key("dev-1")
        result = self.upload(package="pkg-new", key=new_key)
        self.assertEqual(result["状态"], "已合并")

    def test_bad_signature_quarantined(self):
        self.grant_all()
        self.issue()
        result = self.p.submit_offline_package(
            "dev-1", self.device["密钥编号"], "行程1", "pkg-bad",
            TRACKS, "deadbeef")
        self.assertEqual(result["状态"], "已隔离")
        self.assertIn("签名", result["原因"])


class OfflinePackageTest(Base):
    def test_duplicate_upload_merges_once(self):
        self.grant_all()
        self.issue()
        first = self.upload()
        second = self.upload()
        self.assertEqual(first["状态"], "已合并")
        self.assertFalse(first["重复"])
        self.assertTrue(second["重复"])
        self.assertEqual(first["日志"], second["日志"])
        logs = self.p.trip_logs("行程1", "op", ROLE_AUDITOR)["日志"]
        self.assertEqual(len(logs), 1)

    def test_abnormal_track_quarantined(self):
        self.grant_all()
        self.issue()
        crazy = [
            {"t": 1000, "lat": 31.23, "lon": 121.47},
            {"t": 1001, "lat": 39.90, "lon": 116.40},  # 1秒跳到北京的异常
        ]
        result = self.upload(package="pkg-crazy", tracks=crazy)
        self.assertEqual(result["状态"], "已隔离")
        self.assertIn("速度异常", result["原因"])
        self.assertEqual(self.p.trip_logs("行程1", "op", ROLE_AUDITOR)["日志"], [])

    def test_time_reversal_quarantined(self):
        self.grant_all()
        self.issue()
        backwards = [
            {"t": 1000, "lat": 31.23, "lon": 121.47},
            {"t": 900, "lat": 31.24, "lon": 121.48},
        ]
        result = self.upload(package="pkg-back", tracks=backwards)
        self.assertEqual(result["状态"], "已隔离")

    def test_upload_after_log_consent_revoked_quarantined(self):
        self.grant_all()
        self.issue()
        self.p.revoke_consent("游客甲", "日志")
        result = self.upload(package="pkg-late")
        self.assertEqual(result["状态"], "已隔离")
        self.assertIn("日志授权", result["原因"])


class NavigationTest(Base):
    def test_priority_picks_highest_risk(self):
        self.grant_all()
        session = self.issue()
        self.p.report_risk("拥堵")            # 信息提示
        lost = self.p.report_risk("走失")      # 紧急求助
        self.p.report_risk("施工")            # 路线调整
        rec = self.p.navigation_strategy(session["会话"])
        self.assertEqual(rec["策略"], "触发紧急求助并持续上报位置")
        self.assertEqual(rec["依据"]["风险"]["编号"], lost["编号"])
        self.assertEqual(len(rec["依据"]["生效风险"]), 3)

    def test_recommendation_exposes_risk_and_consent_version(self):
        self.grant_all()
        session = self.issue()
        self.p.report_risk("极端环境")
        rec = self.p.navigation_strategy(session["会话"])
        fetched = self.p.recommendation(rec["编号"])
        self.assertEqual(fetched["依据"]["风险"]["级别"], "停止前进")
        expected = {"游客甲": self.p.consent_view("游客甲")["授权版本"]}
        self.assertEqual(fetched["依据"]["授权版本"], expected)

    def test_resolved_risk_no_longer_drives_strategy(self):
        self.grant_all()
        session = self.issue()
        risk = self.p.report_risk("走失")
        self.p.resolve_risk(risk["编号"])
        rec = self.p.navigation_strategy(session["会话"])
        self.assertEqual(rec["策略"], "按当前路线游览")
        self.assertIsNone(rec["依据"]["风险"])


class AuditTest(Base):
    def test_ops_sees_masked_view_and_access_is_logged(self):
        self.grant_all()
        self.issue()
        entries = self.p.view_audit("运营小王", ROLE_OPS)
        self.assertTrue(entries)
        for entry in entries:
            self.assertNotIn("游客甲", entry["对象"])
            self.assertNotIn("详情", entry)
        # 运营的查看行为本身进入审计流水（审计员此次查看记在其后）
        full = self.p.view_audit("审计员", ROLE_AUDITOR)
        self.assertEqual(full[-2]["动作"], "查看审计日志")
        self.assertEqual(full[-2]["操作人"], "运营小王")

    def test_auditor_sees_full_entries(self):
        self.grant_all()
        full = self.p.view_audit("审计员", ROLE_AUDITOR)
        self.assertTrue(any("游客甲" in e["对象"] for e in full))

    def test_trip_logs_masked_for_ops(self):
        self.grant_all()
        self.issue()
        self.upload()
        logs = self.p.trip_logs("行程1", "运营小王", ROLE_OPS)["日志"]
        self.assertEqual(logs[0]["游客"], mask_identifier("游客甲"))
        self.assertRaises(PlatformError, self.p.trip_logs, "行程1", "路人", "游客")


if __name__ == "__main__":
    unittest.main()
