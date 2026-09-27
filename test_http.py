"""控制平台 HTTP 接口端到端测试。"""

import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import service
from service import Handler

BASE = datetime(2026, 9, 27, 8, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


class HttpTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, method, path, body=None, token=None, expect_status=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(req) as resp:
                payload = json.loads(resp.read().decode())
                status = resp.status
        except HTTPError as exc:
            payload = json.loads(exc.read().decode())
            status = exc.code
        if expect_status is not None:
            self.assertEqual(status, expect_status, payload)
        return status, payload


class EndToEndTest(HttpTestBase):
    def test_full_journey(self):
        suffix = datetime.now().strftime("%f")
        trip_id = f"trip-{suffix}"
        device_id = f"dev-{suffix}"

        # 健康检查与协议口径
        _, body = self.call("GET", "/health")
        self.assertEqual(body["service"], service.SERVICE_ID)
        _, body = self.call("GET", "/domain")
        self.assertIn("删除确认", body["授权动作"])

        # 行程：游客 + 两名同行成员
        _, trip = self.call(
            "POST", "/trips",
            {
                "trip_id": trip_id,
                "members": [
                    {"member_id": "tourist", "relation": "游客本人"},
                    {"member_id": "spouse", "relation": "配偶"},
                    {"member_id": "child", "relation": "儿童"},
                ],
            },
            expect_status=201,
        )
        self.assertEqual(len(trip["members"]), 3)

        # 设备注册
        _, device = self.call(
            "POST", "/devices", {"device_id": device_id}, expect_status=201
        )

        # 游客与配偶授权四项，儿童不同意影像
        for member, scopes in (
            ("tourist", ["定位", "语音交互", "影像记录", "日志生成"]),
            ("spouse", ["定位", "语音交互", "影像记录", "日志生成"]),
        ):
            self.call(
                "POST",
                f"/trips/{trip_id}/members/{member}/consent",
                {"action": "授予", "scopes": scopes, "ttl_seconds": 7200},
            )
        self.call(
            "POST",
            f"/trips/{trip_id}/members/child/consent",
            {
                "action": "撤回",
                "scopes": ["影像记录"],
                "family_disagreement": True,
            },
        )
        # 儿童仅不同意影像，定位/语音/日志正常授权
        self.call(
            "POST",
            f"/trips/{trip_id}/members/child/consent",
            {"action": "授予", "scopes": ["定位", "语音交互", "日志生成"]},
        )

        # 最小权限票据：影像被家庭否决，定位可领
        _, ticket = self.call(
            "POST",
            f"/devices/{device_id}/tickets",
            {"trip_id": trip_id, "scopes": ["定位", "影像记录"]},
            expect_status=201,
        )
        self.assertEqual(ticket["scopes"], ["定位"])
        self.assertIn("影像记录", ticket["denied_scopes"])

        # 施工风险发布并获取建议：建议含风险版本与授权版本
        _, risk = self.call(
            "POST", "/risks",
            {
                "risk_type": "施工",
                "level": "路线调整",
                "areas": ["A区栈道"],
                "message": "栈道封闭施工",
            },
            expect_status=201,
        )
        _, rec = self.call(
            "POST",
            f"/devices/{device_id}/trips/{trip_id}/recommend",
            {"areas": ["A区栈道"]},
            expect_status=201,
        )
        self.assertEqual(rec["risk_level"], "路线调整")
        self.assertEqual(rec["risks"][0]["risk_id"], risk["risk_id"])
        self.assertGreaterEqual(rec["risk_version"], 1)
        self.assertEqual(
            rec["consent_versions"]["定位"]["tourist"]["version"], 1
        )
        rec_id = rec["recommendation_id"]

        # 接口复查某次建议使用的风险信息与授权版本
        _, fetched = self.call("GET", f"/recommendations/{rec_id}")
        self.assertEqual(fetched["risk_version"], rec["risk_version"])
        self.assertEqual(fetched["consent_versions"], rec["consent_versions"])

        # 更高优先级的走失事件覆盖施工策略，并使旧建议失效
        self.call(
            "POST", "/risks",
            {
                "risk_type": "走失",
                "level": "紧急求助",
                "areas": ["A区栈道"],
                "message": "儿童走失协查",
            },
            expect_status=201,
        )
        _, fetched = self.call("GET", f"/recommendations/{rec_id}")
        self.assertIn("失效", fetched["status"])

        # 撤回定位授权 -> 设备同步到缓存失效指令 -> 删除回执
        self.call(
            "POST",
            f"/trips/{trip_id}/members/tourist/consent",
            {"action": "撤回", "scopes": ["定位"]},
        )
        _, sync = self.call("POST", f"/devices/{device_id}/sync", {})
        invalidation = next(
            i for i in sync["invalidated_tickets"]
            if i["ticket_id"] == ticket["ticket_id"]
        )
        self.assertIn("定位", invalidation["scopes"])
        _, receipt = self.call(
            "POST",
            f"/devices/{device_id}/tickets/{ticket['ticket_id']}/confirm-deletion",
            {},
        )
        self.assertEqual(receipt["action"], "删除确认")

        # 离线轨迹：恢复定位授权后形成的有效包合并，重复上传不产生第二份日志
        self.call(
            "POST",
            f"/trips/{trip_id}/members/tourist/consent",
            {"action": "授予", "scopes": ["定位"]},
        )
        t0 = datetime.now(timezone.utc)
        points = [
            {"ts": iso(t0 + timedelta(seconds=i * 60)),
             "lat": 30.1 + i * 0.001, "lon": 120.1}
            for i in range(3)
        ]
        packet = service.PLATFORM.make_signed_packet(
            device_id, trip_id, points, packet_id=f"pkt-{suffix}"
        )
        _, first = self.call(
            "POST", f"/devices/{device_id}/offline-packets", packet,
            expect_status=201,
        )
        self.assertEqual(first["status"], "已合并")
        _, second = self.call(
            "POST", f"/devices/{device_id}/offline-packets", packet,
            expect_status=201,
        )
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["log_id"], first["log_id"])

        _, journal = self.call("GET", f"/trips/{trip_id}/journal")
        self.assertEqual(len(journal["logs"]), 1)

        # 伪造签名的包被隔离
        tampered = dict(packet, packet_id=f"pkt-{suffix}-bad", sig="0" * 64)
        _, quarantined = self.call(
            "POST", f"/devices/{device_id}/offline-packets", tampered,
            expect_status=201,
        )
        self.assertEqual(quarantined["status"], "已隔离")

        # 运营审计员：只读、脱敏、无凭据拒绝访问
        _, operator = self.call(
            "POST", "/operators", {"name": "审计小张"}, expect_status=201
        )
        status, _ = self.call("GET", "/audit")
        self.assertEqual(status, 403)
        _, audit = self.call("GET", "/audit", token=operator["token"])
        self.assertTrue(audit["redacted"])
        actions = {e["action"] for e in audit["events"]}
        self.assertIn("删除确认", actions)
        self.assertIn("轨迹隔离", actions)

        _, qlist = self.call("GET", "/quarantine", token=operator["token"])
        self.assertTrue(qlist["isolated"])

    def test_check_config_passes(self):
        self.assertEqual(service.check_config(), [])


if __name__ == "__main__":
    unittest.main()
