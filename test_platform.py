"""控制平台核心业务测试：授权、票据、密钥、风险导航、离线轨迹、审计。"""

import unittest
from datetime import datetime, timedelta, timezone

from control_platform import (
    CONSENT_SCOPES,
    RISK_LEVELS,
    SCOPE_IMAGE,
    SCOPE_LOCATION,
    SCOPE_LOG,
    SCOPE_VOICE,
    ControlPlatform,
    PlatformError,
)

BASE = datetime(2026, 9, 27, 8, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


class Clock:
    def __init__(self, start=BASE):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, **kw):
        self.now += timedelta(**kw)
        return self.now


class PlatformTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.pf = ControlPlatform(clock=self.clock)
        self.device = self.pf.register_device("dev-1")
        self.pf.create_trip(
            "trip-1",
            members=[
                {"member_id": "tourist", "relation": "游客本人"},
                {"member_id": "spouse", "relation": "配偶"},
                {"member_id": "child", "relation": "儿童"},
            ],
        )

    def grant_all(self, member="tourist", ttl=None):
        return self.pf.grant_consent(
            "trip-1", member, list(CONSENT_SCOPES), ttl=ttl
        )

    def grant_everyone(self, ttl=None):
        """家庭共同口径：全体同行成员逐一独立授权后能力才对行程开放。"""
        return [
            self.pf.grant_consent("trip-1", m, list(CONSENT_SCOPES), ttl=ttl)
            for m in ("tourist", "spouse", "child")
        ]

    def ticket(self, scopes=None, device="dev-1", trip="trip-1"):
        return self.pf.issue_ticket(device, trip, scopes or list(CONSENT_SCOPES))


class ConsentAndTicketTest(PlatformTestBase):
    def test_independent_scopes_and_minimum_privilege(self):
        # 仅游客本人授权：家庭共同口径下能力不开放，票据不含任何范围
        self.grant_all()
        denied_ticket = self.ticket([SCOPE_LOCATION, SCOPE_IMAGE])
        self.assertEqual(denied_ticket["scopes"], [])
        view = self.pf.trip_consent_view("trip-1")
        self.assertEqual(view["trip_effective_scopes"], [])
        self.assertTrue(view["scopes"][SCOPE_LOCATION]["blocked_by"])

        # 全体成员授权后，设备也只能领到本次申请的最小范围
        self.grant_everyone()
        ticket = self.ticket([SCOPE_LOCATION, SCOPE_IMAGE])
        self.assertEqual(ticket["scopes"], [SCOPE_LOCATION, SCOPE_IMAGE])
        self.assertNotIn(SCOPE_VOICE, ticket["scopes"])
        self.assertNotIn(SCOPE_LOG, ticket["scopes"])

    def test_family_disagreement_blocks_scope(self):
        self.grant_all("tourist")
        self.grant_all("spouse")
        # 儿童随行，监护人代其明确不同意影像记录
        self.pf.revoke_consent(
            "trip-1", "child", [SCOPE_IMAGE], family_disagreement=True
        )
        ticket = self.pf.issue_ticket(
            "dev-1", "trip-1", [SCOPE_LOCATION, SCOPE_IMAGE]
        )
        self.assertEqual(ticket["scopes"], [])
        denied = ticket["denied_scopes"][SCOPE_IMAGE]
        self.assertEqual(
            [b["reason"] for b in denied if b["member_id"] == "child"],
            ["同行成员不同意"],
        )

    def test_family_disagreement_persists_until_regrant(self):
        self.grant_all("tourist")
        self.grant_all("spouse")
        # 儿童明确不同意影像，同时授予定位等其他能力
        self.pf.revoke_consent(
            "trip-1", "child", [SCOPE_IMAGE], family_disagreement=True
        )
        self.pf.grant_consent("trip-1", "child", [SCOPE_LOCATION, SCOPE_LOG])
        view = self.pf.trip_consent_view("trip-1")
        self.assertFalse(view["scopes"][SCOPE_IMAGE]["allowed"])
        self.assertTrue(view["scopes"][SCOPE_LOCATION]["allowed"])
        child = next(m for m in view["members"] if m["member_id"] == "child")
        self.assertEqual(child["disagreed_scopes"], [SCOPE_IMAGE])

        # 儿童随后明确授予影像，不同意消除（需全员一致后才开放）
        self.pf.grant_consent("trip-1", "child", [SCOPE_IMAGE])
        view = self.pf.trip_consent_view("trip-1")
        self.assertTrue(view["scopes"][SCOPE_IMAGE]["allowed"])
        child = next(m for m in view["members"] if m["member_id"] == "child")
        self.assertEqual(child["disagreed_scopes"], [])

    def test_consent_versions_increment(self):
        v1 = self.grant_all()
        self.assertEqual(v1["version"], 1)
        v2 = self.pf.revoke_consent("trip-1", "tourist", [SCOPE_VOICE])
        self.assertEqual(v2["version"], 2)
        self.assertNotIn(SCOPE_VOICE, v2["granted_scopes"])

    def test_ticket_expires_no_later_than_consent(self):
        self.grant_everyone(ttl=timedelta(hours=1))
        ticket = self.ticket([SCOPE_LOCATION])
        self.assertEqual(ticket["scopes"], [SCOPE_LOCATION])
        self.assertIsNotNone(ticket["expires_at"])
        self.clock.advance(hours=2)
        sync = self.pf.sync_device("dev-1")
        self.assertEqual(
            sync["invalidated_tickets"][0]["reason"], "票据到期"
        )

    def test_unknown_scope_rejected(self):
        with self.assertRaises(PlatformError):
            self.pf.grant_consent("trip-1", "tourist", ["遥控无人机"])


class RevocationAndReceiptTest(PlatformTestBase):
    def test_revoke_invalidates_cache_and_receipt_is_idempotent(self):
        self.grant_everyone()
        ticket = self.ticket([SCOPE_IMAGE, SCOPE_VOICE])

        self.pf.revoke_consent("trip-1", "tourist", [SCOPE_IMAGE])
        sync = self.pf.sync_device("dev-1")
        invalidation = sync["invalidated_tickets"][0]
        self.assertEqual(invalidation["ticket_id"], ticket["ticket_id"])
        self.assertIn(SCOPE_IMAGE, invalidation["scopes"])
        self.assertFalse(invalidation["cache_deleted"])

        # 票据已不可继续使用
        self.assertEqual(self.pf.tickets[ticket["ticket_id"]]["status"], "失效")

        receipt = self.pf.confirm_cache_deleted("dev-1", ticket["ticket_id"])
        self.assertEqual(receipt["action"], "删除确认")
        again = self.pf.confirm_cache_deleted("dev-1", ticket["ticket_id"])
        self.assertEqual(again["receipt_id"], receipt["receipt_id"])

        sync = self.pf.sync_device("dev-1")
        self.assertTrue(sync["invalidated_tickets"][0]["cache_deleted"])

    def test_expiry_then_regrant_does_not_restore_old_ticket(self):
        self.grant_everyone(ttl=timedelta(minutes=30))
        ticket = self.ticket([SCOPE_VOICE])
        self.clock.advance(minutes=31)
        self.pf.sync_device("dev-1")
        self.assertEqual(self.pf.tickets[ticket["ticket_id"]]["status"], "失效")
        # 重新授权只能领新票，旧票不复活
        self.grant_everyone(ttl=timedelta(hours=2))
        self.assertEqual(self.pf.tickets[ticket["ticket_id"]]["status"], "失效")
        new_ticket = self.ticket([SCOPE_VOICE])
        self.assertEqual(new_ticket["status"], "有效")
        self.assertNotEqual(new_ticket["ticket_id"], ticket["ticket_id"])


class KeyRotationTest(PlatformTestBase):
    def _packet(self, points, **kw):
        return self.pf.make_signed_packet(
            "dev-1",
            "trip-1",
            points,
            formed_at=kw.get("formed_at", self.clock()),
            kid=kw.get("kid"),
            packet_id=kw.get("packet_id"),
        )

    def test_rotation_invalidates_tickets_and_switches_key(self):
        self.grant_everyone()
        ticket = self.ticket([SCOPE_LOCATION])
        rotated = self.pf.rotate_key("dev-1", grace=timedelta(hours=1))
        self.assertNotEqual(rotated["kid"], self.device["kid"])
        self.assertEqual(self.pf.tickets[ticket["ticket_id"]]["status"], "失效")
        # 新密钥立即可签
        packet = self._packet(
            [
                {"ts": iso(self.clock() + timedelta(seconds=1)), "lat": 30.1, "lon": 120.1},
                {"ts": iso(self.clock() + timedelta(seconds=61)), "lat": 30.101, "lon": 120.1},
            ]
        )
        self.assertEqual(packet["kid"], rotated["kid"])
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已合并")

    def test_old_key_accepted_only_within_grace(self):
        self.grant_everyone()
        old_kid = self.device["kid"]
        t0 = self.clock()
        packet = self._packet(
            [
                {"ts": iso(t0 + timedelta(seconds=1)), "lat": 30.1, "lon": 120.1},
                {"ts": iso(t0 + timedelta(seconds=61)), "lat": 30.101, "lon": 120.1},
            ],
            formed_at=t0,
            kid=old_kid,
        )
        # 轮换：离线包形成于轮换前，宽限期 1 小时
        self.pf.rotate_key("dev-1", grace=timedelta(hours=1))
        self.clock.advance(minutes=30)
        ok, why = self.pf.verify_signature(
            "dev-1",
            self.pf._packet_payload(packet),
            old_kid,
            packet["sig"],
            formed_at=t0,
        )
        self.assertTrue(ok, why)

        self.clock.advance(hours=2)
        ok, why = self.pf.verify_signature(
            "dev-1",
            self.pf._packet_payload(packet),
            old_kid,
            packet["sig"],
            formed_at=t0,
        )
        self.assertFalse(ok)
        self.assertIn("宽限期", why)


class RiskNavigationTest(PlatformTestBase):
    def test_priority_overrides_lower_risks(self):
        self.grant_everyone()
        self.pf.add_risk("施工", "路线调整", ["A区"], "栈道维修")
        self.pf.add_risk("走失", "紧急求助", ["A区"], "儿童走失协查")
        rec = self.pf.recommend("dev-1", "trip-1", ["A区"])
        self.assertEqual(rec["risk_level"], "紧急求助")
        self.assertEqual(len(rec["risks"]), 1)
        self.assertEqual(rec["risks"][0]["risk_type"], "走失")
        self.assertEqual(rec["strategy"], "立即中止行程并发起紧急求助，调度力量介入")

    def test_new_risk_makes_old_route_stale(self):
        self.grant_everyone()
        rec1 = self.pf.recommend("dev-1", "trip-1", ["B区"])
        self.assertEqual(rec1["status"], "现行")
        self.pf.add_risk("极端环境", "停止前进", ["B区"], "雷暴大风")
        fetched = self.pf.get_recommendation(rec1["recommendation_id"])
        self.assertIn("失效", fetched["status"])
        # 设备同步时能收到旧路线失效指令
        stale = self.pf.sync_device("dev-1")["stale_recommendations"]
        self.assertEqual(stale[0]["recommendation_id"], rec1["recommendation_id"])
        # 重新获取的建议按高优先级策略执行
        rec2 = self.pf.recommend("dev-1", "trip-1", ["B区"])
        self.assertEqual(rec2["risk_level"], "停止前进")

    def test_recommendation_records_risk_and_consent_versions(self):
        granted = self.grant_all()
        risk = self.pf.add_risk("拥堵", "信息提示", ["C区"], "缆车排队")
        rec = self.pf.recommend("dev-1", "trip-1", ["C区"])
        self.assertEqual(rec["risk_version"], risk_version := rec["risk_version"])
        self.assertGreaterEqual(risk_version, 1)
        self.assertEqual(rec["risks"][0]["risk_id"], risk["risk_id"])
        self.assertEqual(
            rec["consent_versions"][SCOPE_LOCATION]["tourist"]["version"],
            granted["version"],
        )
        self.assertTrue(rec["consent_versions"][SCOPE_LOCATION]["tourist"]["allowed"])
        # 接口可复查整次建议使用的风险信息与授权版本
        again = self.pf.get_recommendation(rec["recommendation_id"])
        self.assertEqual(again["consent_versions"], rec["consent_versions"])
        self.assertEqual(again["risk_level"], "信息提示")


class OfflineTrackTest(PlatformTestBase):
    def _points(self, t0=None, step_seconds=60):
        t0 = t0 or (self.clock() + timedelta(seconds=1))
        return [
            {"ts": iso(t0 + timedelta(seconds=i * step_seconds)),
             "lat": 30.1 + i * 0.001, "lon": 120.1}
            for i in range(4)
        ]

    def test_merge_validates_then_dedupicates(self):
        self.grant_everyone()
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", self._points(), packet_id="pkt-1"
        )
        first = self.pf.upload_offline_packet(packet)
        self.assertEqual(first["status"], "已合并")
        log_id = first["log_id"]

        # 同一离线包原样重传
        second = self.pf.upload_offline_packet(packet)
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["log_id"], log_id)

        # 同内容换包编号重传：设备以新编号重新签名，内容指纹仍判定为同一包
        repackaged = self.pf.make_signed_packet(
            "dev-1",
            "trip-1",
            packet["points"],
            packet_id="pkt-1-retry",
            formed_at=packet["formed_at"],
        )
        third = self.pf.upload_offline_packet(repackaged)
        self.assertTrue(third["duplicate"])
        self.assertEqual(third["log_id"], log_id)

        journal = self.pf.trip_journal("trip-1")
        self.assertEqual(len(journal["logs"]), 1)
        self.assertEqual(journal["logs"][0]["log_id"], log_id)

    def test_bad_signature_is_quarantined(self):
        self.grant_everyone()
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", self._points(), packet_id="pkt-bad"
        )
        packet["sig"] = "0" * 64
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已隔离")
        self.assertTrue(any("签名" in r for r in result["reasons"]))
        self.assertEqual(self.pf.trip_journal("trip-1")["logs"], [])

    def test_out_of_fence_is_quarantined(self):
        self.grant_everyone()
        points = self._points()
        points[2] = {"ts": points[2]["ts"], "lat": 0.0, "lon": 0.0}
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", points, packet_id="pkt-fence"
        )
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已隔离")
        self.assertTrue(any("围栏" in r for r in result["reasons"]))

    def test_impossible_speed_is_quarantined(self):
        self.grant_everyone()
        t0 = self.clock() + timedelta(seconds=1)
        points = [
            {"ts": iso(t0), "lat": 30.1, "lon": 120.1},
            {"ts": iso(t0 + timedelta(seconds=60)), "lat": 30.3, "lon": 120.3},
        ]
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", points, packet_id="pkt-speed"
        )
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已隔离")
        self.assertTrue(any("速度异常" in r for r in result["reasons"]))

    def test_track_after_revocation_is_quarantined(self):
        self.grant_everyone()
        t0 = self.clock()
        self.pf.revoke_consent("trip-1", "tourist", [SCOPE_LOCATION])
        points = [
            {"ts": iso(t0 + timedelta(seconds=10)), "lat": 30.1, "lon": 120.1},
            {"ts": iso(t0 + timedelta(seconds=70)), "lat": 30.101, "lon": 120.1},
        ]
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", points, packet_id="pkt-noconsent"
        )
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已隔离")
        self.assertTrue(any("定位授权无效" in r for r in result["reasons"]))

    def test_historical_track_collected_with_consent_merges(self):
        # 行程结束后才到期，不影响采集时段内授权有效的离线轨迹
        self.grant_everyone(ttl=timedelta(hours=1))
        t0 = self.clock()
        points = [
            {"ts": iso(t0 + timedelta(seconds=10)), "lat": 30.1, "lon": 120.1},
            {"ts": iso(t0 + timedelta(seconds=70)), "lat": 30.101, "lon": 120.1},
        ]
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", points, packet_id="pkt-hist", formed_at=t0
        )
        self.clock.advance(hours=2)
        result = self.pf.upload_offline_packet(packet)
        self.assertEqual(result["status"], "已合并")


class AuditTest(PlatformTestBase):
    def test_operator_read_only_redacted_access(self):
        op = self.pf.register_operator("小李")
        listing = self.pf.list_audit(op["token"])
        self.assertTrue(listing["redacted"])
        self.assertEqual(listing["role"], "审计员")
        self.assertTrue(any(e["action"] == "设备注册" for e in listing["events"]))

        with self.assertRaises(PlatformError) as ctx:
            self.pf.list_audit("not-a-token")
        self.assertEqual(ctx.exception.status, 403)

    def test_audit_never_contains_coordinates_or_secrets(self):
        op = self.pf.register_operator("小王")
        self.grant_everyone()
        ticket = self.ticket([SCOPE_LOCATION])
        self.pf.revoke_consent("trip-1", "tourist", [SCOPE_LOCATION])
        self.pf.sync_device("dev-1")
        self.pf.confirm_cache_deleted("dev-1", ticket["ticket_id"])
        points = [
            {"ts": iso(self.clock() + timedelta(seconds=1)), "lat": 30.123456, "lon": 120.123456},
            {"ts": iso(self.clock() + timedelta(seconds=61)), "lat": 30.124, "lon": 120.123},
        ]
        packet = self.pf.make_signed_packet(
            "dev-1", "trip-1", points, packet_id="pkt-audit"
        )
        self.pf.upload_offline_packet(packet)
        bad = dict(packet, packet_id="pkt-audit-bad", sig="0" * 64)
        self.pf.upload_offline_packet(bad)

        import json
        blob = json.dumps(self.pf.list_audit(op["token"])["events"], ensure_ascii=False)
        self.assertNotIn("30.123456", blob)
        self.assertNotIn(self.device["key"], blob)


if __name__ == "__main__":
    unittest.main()
