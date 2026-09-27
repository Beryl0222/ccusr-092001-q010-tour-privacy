"""智能伴游隐私与安全控制平台 HTTP 入口。

在设备与景区业务服务之间提供授权、票据、密钥、风险导航、离线轨迹与审计接口。
状态保存在内存中的单例 ControlPlatform；仅依赖标准库。
"""

import argparse
import json
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from control_platform import (
    CONSENT_ACTIONS,
    DEVICE_CAPABILITIES,
    DOMAIN,
    RISK_LEVELS,
    ControlPlatform,
    PlatformError,
)

SERVICE_ID = "tour-companion-privacy"


def health():
    """返回稳定的服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


def check_config() -> list[str]:
    """校验协议口径完整性。"""
    problems = []
    for key in ("设备能力", "风险级别", "授权动作"):
        if key not in DOMAIN:
            problems.append(f"domain.json 缺少 {key}")
    if "删除确认" not in DOMAIN.get("授权动作", []):
        problems.append("授权动作必须包含 删除确认")
    for level in ("信息提示", "路线调整", "停止前进", "紧急求助"):
        if level not in DOMAIN.get("风险级别", []):
            problems.append(f"风险级别缺少 {level}")
    return problems


PLATFORM = ControlPlatform()
CONSENT_ACTION_MAP = {
    "grant": "授予",
    "授予": "授予",
    "restrict": "限制",
    "限制": "限制",
    "revoke": "撤回",
    "撤回": "撤回",
}


class Handler(BaseHTTPRequestHandler):
    """控制平台 JSON 接口。"""

    server_version = "TourCompanion/1.0"

    # -- 基础工具 -------------------------------------------------------

    def _send_json(self, obj, status: int = 200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise PlatformError(f"请求体不是合法 JSON：{exc}", "bad_json")
        if not isinstance(data, dict):
            raise PlatformError("请求体必须是 JSON 对象")
        return data

    def _operator_token(self, query: dict) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer ") :].strip()
        return (query.get("token") or [""])[0]

    # -- 路由 -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if path == "/health":
                self._send_json(health())
            elif path == "/domain":
                self._send_json(
                    {
                        "设备能力": DEVICE_CAPABILITIES,
                        "风险级别": RISK_LEVELS,
                        "授权动作": CONSENT_ACTIONS,
                    }
                )
            elif path == "/audit":
                token = self._operator_token(query)
                limit = int(query["limit"][0]) if query.get("limit") else None
                self._send_json(PLATFORM.list_audit(token, limit=limit))
            elif path == "/quarantine":
                token = self._operator_token(query)
                self._send_json(PLATFORM.list_quarantine(token))
            elif path.startswith("/recommendations/"):
                self._send_json(PLATFORM.get_recommendation(path.rsplit("/", 1)[1]))
            elif path.startswith("/trips/") and path.endswith("/consent"):
                self._send_json(PLATFORM.trip_consent_view(path.split("/")[2]))
            elif path.startswith("/trips/") and path.endswith("/journal"):
                self._send_json(PLATFORM.trip_journal(path.split("/")[2]))
            else:
                self.send_error(404)
        except PlatformError as exc:
            self._send_json(
                {"error": exc.message, "code": exc.code}, status=exc.status
            )

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        try:
            data = self._read_json()
            self._route_post(parts, data)
        except PlatformError as exc:
            self._send_json(
                {"error": exc.message, "code": exc.code}, status=exc.status
            )
        except (KeyError, TypeError) as exc:
            self._send_json(
                {"error": f"请求参数缺失或非法：{exc}", "code": "bad_request"},
                status=400,
            )

    def _route_post(self, parts: list[str], data: dict):
        # /trips
        if parts == ["trips"]:
            self._send_json(
                PLATFORM.create_trip(
                    trip_id=data.get("trip_id"),
                    name=data.get("name", ""),
                    members=data.get("members"),
                ),
                status=201,
            )
            return

        # /devices
        if parts == ["devices"]:
            self._send_json(PLATFORM.register_device(data.get("device_id")), 201)
            return

        # /operators
        if parts == ["operators"]:
            self._send_json(
                PLATFORM.register_operator(data.get("name", "审计员")), 201
            )
            return

        # /risks
        if parts == ["risks"]:
            self._send_json(
                PLATFORM.add_risk(
                    risk_type=data["risk_type"],
                    level=data["level"],
                    areas=data["areas"],
                    message=data.get("message", ""),
                ),
                status=201,
            )
            return

        if len(parts) == 3 and parts[0] == "risks" and parts[2] == "resolve":
            self._send_json(PLATFORM.resolve_risk(parts[1]))
            return

        if len(parts) >= 2 and parts[0] == "devices":
            self._route_device(parts[1:], data)
            return

        if (
            len(parts) == 5
            and parts[0] == "trips"
            and parts[2] == "members"
            and parts[4] == "consent"
        ):
            # POST /trips/{trip_id}/members/{member_id}/consent
            self._route_consent(parts[1], parts[3], data)
            return

        self.send_error(404)

    def _route_consent(self, trip_id: str, member_id: str, data: dict):
        action = CONSENT_ACTION_MAP.get(data.get("action", ""))
        if not action:
            raise PlatformError(
                f"action 必须是 {sorted(CONSENT_ACTION_MAP)}"
            )
        member_id = data.get("member_id", member_id)
        scopes = data.get("scopes")
        ttl = (
            timedelta(seconds=int(data["ttl_seconds"]))
            if data.get("ttl_seconds") is not None
            else None
        )
        actor = data.get("actor", "游客")
        if action == "授予":
            result = PLATFORM.grant_consent(trip_id, member_id, scopes, ttl, actor)
        elif action == "限制":
            result = PLATFORM.restrict_consent(trip_id, member_id, scopes, actor)
        else:
            result = PLATFORM.revoke_consent(
                trip_id,
                member_id,
                scopes,
                actor,
                family_disagreement=bool(data.get("family_disagreement")),
            )
        self._send_json(result)

    def _route_device(self, parts: list[str], data: dict):
        device_id = parts[0]
        rest = parts[1:]

        if rest == ["rotate-key"]:
            grace = (
                timedelta(seconds=int(data["grace_seconds"]))
                if data.get("grace_seconds") is not None
                else None
            )
            self._send_json(PLATFORM.rotate_key(device_id, grace))
            return

        if rest == ["sync"]:
            self._send_json(PLATFORM.sync_device(device_id))
            return

        if rest == ["tickets"]:
            ttl = (
                timedelta(seconds=int(data["ttl_seconds"]))
                if data.get("ttl_seconds") is not None
                else None
            )
            self._send_json(
                PLATFORM.issue_ticket(
                    device_id, data["trip_id"], data["scopes"], ttl
                ),
                status=201,
            )
            return

        if len(rest) == 3 and rest[0] == "tickets" and rest[2] == "confirm-deletion":
            self._send_json(PLATFORM.confirm_cache_deleted(device_id, rest[1]))
            return

        if len(rest) == 3 and rest[0] == "trips" and rest[2] == "recommend":
            self._send_json(
                PLATFORM.recommend(device_id, rest[1], data["areas"]), status=201
            )
            return

        if rest == ["offline-packets"]:
            self._send_json(PLATFORM.upload_offline_packet(data), status=201)
            return

        self.send_error(404)

    def log_message(self, *_args):
        return


def main():
    parser = argparse.ArgumentParser(description="智能伴游隐私安全控制平台")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        problems = check_config()
        if problems:
            for problem in problems:
                print(f"配置问题：{problem}")
            raise SystemExit(1)
        print("基础检查通过")
        return
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
