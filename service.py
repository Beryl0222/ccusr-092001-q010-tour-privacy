"""智能伴游隐私与安全服务：设备控制平台的 HTTP 入口。

接口（POST JSON 除非注明 GET）:
  POST /consents/grant          {游客, 范围, 有效期秒?}
  POST /consents/restrict       {游客, 范围}
  POST /consents/revoke         {游客, 范围}
  POST /consents/expire-sweep   到期扫描，返回删除回执
  GET  /consents?游客=...       授权视图（含授权版本）
  GET  /receipts?游客=...       删除回执列表
  POST /families                {家庭, 成员:[...]}
  POST /families/dissent        {家庭, 游客, 范围}
  POST /devices                 {设备}
  POST /devices/rotate-key      {设备}
  POST /sessions                {设备, 行程, 游客, 所需能力:[...], 家庭?}
  POST /risks                   {类型(施工/拥堵/极端环境/走失), 级别?, 说明?}
  POST /risks/resolve           {风险}
  POST /navigation              {会话}  -> 建议（含风险信息与授权版本）
  GET  /recommendations?建议=...
  POST /offline-packages        {设备, 密钥编号, 行程, 离线包, 轨迹, 签名}
  GET  /offline-packages?离线包=...
  GET  /trips/日志?行程=...&操作人=...&角色=运营|审计员
  GET  /audit?操作人=...&角色=运营|审计员
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from core import ControlPlatform, PlatformError

SERVICE_ID = "tour-companion-privacy"

PLATFORM = ControlPlatform()


def health():
    """返回稳定的服务身份。"""
    return {"status": "ok", "service": SERVICE_ID}


def _field(data, name, default=None):
    value = data.get(name, default)
    if isinstance(value, str):
        value = value.strip()
    return value


# (路径, 处理函数)：处理函数入参为请求体字典，返回可序列化对象
POST_ROUTES = {
    "/consents/grant": lambda d: PLATFORM.apply_consent(
        _field(d, "游客"), _field(d, "范围"), "授予", d.get("有效期秒")),
    "/consents/restrict": lambda d: PLATFORM.apply_consent(
        _field(d, "游客"), _field(d, "范围"), "限制", d.get("有效期秒")),
    "/consents/revoke": lambda d: PLATFORM.revoke_consent(
        _field(d, "游客"), _field(d, "范围")),
    "/consents/expire-sweep": lambda d: PLATFORM.sweep_expired(),
    "/families": lambda d: PLATFORM.create_family(
        _field(d, "家庭"), d.get("成员", [])),
    "/families/dissent": lambda d: PLATFORM.dissent(
        _field(d, "家庭"), _field(d, "游客"), _field(d, "范围")),
    "/devices": lambda d: PLATFORM.register_device(_field(d, "设备")),
    "/devices/rotate-key": lambda d: PLATFORM.rotate_key(_field(d, "设备")),
    "/sessions": lambda d: PLATFORM.issue_session(
        _field(d, "设备"), _field(d, "行程"), _field(d, "游客"),
        d.get("所需能力", []), d.get("家庭")),
    "/risks": lambda d: PLATFORM.report_risk(
        _field(d, "类型"), d.get("级别"), d.get("说明", "")),
    "/risks/resolve": lambda d: PLATFORM.resolve_risk(_field(d, "风险")),
    "/navigation": lambda d: PLATFORM.navigation_strategy(_field(d, "会话")),
    "/offline-packages": lambda d: PLATFORM.submit_offline_package(
        _field(d, "设备"), _field(d, "密钥编号"), _field(d, "行程"),
        _field(d, "离线包"), d.get("轨迹", []), _field(d, "签名")),
}

GET_ROUTES = {
    "/consents": lambda q: PLATFORM.consent_view(q["游客"][0]),
    "/receipts": lambda q: {"回执": PLATFORM.receipts(q["游客"][0])},
    "/recommendations": lambda q: PLATFORM.recommendation(q["建议"][0]),
    "/offline-packages": lambda q: PLATFORM.package_view(q["离线包"][0]),
    "/trips/日志": lambda q: PLATFORM.trip_logs(
        q["行程"][0], q["操作人"][0], q["角色"][0]),
    "/audit": lambda q: {"审计": PLATFORM.view_audit(q["操作人"][0], q["角色"][0])},
}


class Handler(BaseHTTPRequestHandler):
    """提供健康检查与控制平台接口。"""

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # 请求行按 ISO-8859-1 解码，中文参数需还原为 UTF-8
        path = self.path.encode("iso-8859-1").decode("utf-8", "replace")
        parts = urlsplit(path)
        if parts.path == "/health":
            self._send(200, health())
            return
        route = GET_ROUTES.get(parts.path)
        if route is None:
            self.send_error(404)
            return
        query = parse_qs(parts.query)
        try:
            self._send(200, route(query))
        except KeyError as exc:
            self._send(400, {"错误": f"缺少查询参数:{exc.args[0]}"})
        except PlatformError as exc:
            self._send(exc.status, {"错误": str(exc)})

    def do_POST(self):
        route = POST_ROUTES.get(self.path)
        if route is None:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
            self._send(200, route(data))
        except json.JSONDecodeError:
            self._send(400, {"错误": "请求体不是合法 JSON"})
        except PlatformError as exc:
            self._send(exc.status, {"错误": str(exc)})

    def log_message(self, *_args):
        return


def reset_platform():
    """重置全局平台（测试使用）。"""
    global PLATFORM
    PLATFORM = ControlPlatform()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="智能伴游隐私安全")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        print("基础检查通过")
    else:
        ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()
