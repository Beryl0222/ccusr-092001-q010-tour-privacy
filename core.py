"""伴游设备控制平台的核心域逻辑。

平台位于伴游设备与业务服务之间，负责：
- 游客按范围（定位/语音/影像/日志）独立授权，设备按行程领取最小权限；
- 施工/拥堵/极端环境/走失等风险事件按优先级改变导航策略；
- 离线轨迹包联网后先校验再合并，重复上传不产生重复日志；
- 授权撤回或到期后的缓存失效、删除回执、异常轨迹隔离与受限审计。

协议口径以 domain.json 为准：设备能力、风险级别、授权动作。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import time

# 授权范围 -> 设备能力（domain.json「设备能力」的子集）
SCOPE_TO_CAPABILITY = {
    "定位": "定位",
    "语音": "语音交互",
    "影像": "影像记录",
    "日志": "日志生成",
}
CAPABILITY_TO_SCOPE = {v: k for k, v in SCOPE_TO_CAPABILITY.items()}

# 不涉及隐私、无需游客授权即可下发的设备能力
PUBLIC_CAPABILITIES = {"路线建议"}

# 风险级别 -> 优先级（数值越大越优先，与 domain.json「风险级别」一致）
RISK_PRIORITY = {"信息提示": 1, "路线调整": 2, "停止前进": 3, "紧急求助": 4}
RISK_STRATEGY = {
    "信息提示": "提示游客并继续当前路线",
    "路线调整": "重新规划路线以避开风险区域",
    "停止前进": "停止前进并等待人工确认",
    "紧急求助": "触发紧急求助并持续上报位置",
}
DEFAULT_STRATEGY = "按当前路线游览"

# 风险类型 -> 默认风险级别
RISK_TYPE_LEVEL = {
    "施工": "路线调整",
    "拥堵": "信息提示",
    "极端环境": "停止前进",
    "走失": "紧急求助",
}

KEY_GRACE_SECONDS = 3600   # 设备密钥轮换后旧密钥的宽限期
MAX_TRACK_SPEED_MPS = 60.0  # 超过该速度的轨迹判定为异常

ROLE_OPS = "运营"
ROLE_AUDITOR = "审计员"


def _canonical(obj) -> str:
    """用于校验与签名的规范化 JSON 串。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def mask_identifier(value) -> str:
    """运营视图中的标识脱敏：保留首字符并附加稳定散列后缀。"""
    text = str(value)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:6]
    return f"{text[:1]}***{digest}"


def _distance_m(a, b) -> float:
    """两个轨迹点之间的近似球面距离（米）。"""
    lat = math.radians((a["lat"] + b["lat"]) / 2)
    dx = math.radians(b["lon"] - a["lon"]) * 6371000 * math.cos(lat)
    dy = math.radians(b["lat"] - a["lat"]) * 6371000
    return math.hypot(dx, dy)


class PlatformError(Exception):
    """业务错误，status 为对应的 HTTP 状态码。"""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class _Quarantine(Exception):
    """离线包校验未通过，转入隔离。"""


class ControlPlatform:
    """设备与业务服务之间的控制平台。"""

    def __init__(self, now=None):
        self._now = now or time.time
        self._consents = {}         # 游客 -> {范围: 授权记录}
        self._versions = {}         # 游客 -> 授权版本号
        self._families = {}         # 家庭 -> {"成员": [...], "不同意": {游客: {范围}}}
        self._devices = {}          # 设备 -> {"密钥": [密钥记录]}
        self._sessions = {}         # 会话编号 -> 会话
        self._trips = {}            # 行程 -> {"游客":..., "家庭":...}
        self._risks = {}            # 风险编号 -> 风险事件
        self._recommendations = {}  # 建议编号 -> 导航建议（含依据）
        self._packages = {}         # 离线包编号 -> 处理记录（幂等键）
        self._logs = {}             # 日志编号 -> 游览日志
        self._receipts = {}         # 游客 -> [删除回执]
        self._audit = []            # 审计流水
        self._seq = 0

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _new_id(self, prefix) -> str:
        self._seq += 1
        return f"{prefix}-{self._seq:06d}"

    def _version(self, tourist) -> int:
        return self._versions.get(tourist, 0)

    def _bump_version(self, tourist):
        self._versions[tourist] = self._version(tourist) + 1

    @staticmethod
    def _require(value, name):
        if value is None or value == "":
            raise PlatformError(f"缺少必填字段:{name}")
        return value

    def _require_scope(self, scope):
        self._require(scope, "范围")
        if scope not in SCOPE_TO_CAPABILITY:
            raise PlatformError(f"未知授权范围:{scope}")

    def _audit_append(self, actor, role, action, target, allowed, detail=None):
        self._audit.append({
            "序号": len(self._audit) + 1,
            "时间": self._now(),
            "操作人": actor,
            "角色": role,
            "动作": action,
            "对象": target,
            "允许": allowed,
            "详情": detail,
        })

    # ------------------------------------------------------------------
    # 授权：授予 / 限制 / 撤回 / 到期
    # ------------------------------------------------------------------
    def apply_consent(self, tourist, scope, action, ttl_seconds=None):
        """游客对某一范围授予或限制授权，授权版本随之递增。"""
        self._require(tourist, "游客")
        self._require_scope(scope)
        if action not in ("授予", "限制"):
            raise PlatformError("仅支持授予或限制；撤回请使用撤回接口")
        self._consents.setdefault(tourist, {})[scope] = {
            "状态": action,
            "更新时间": self._now(),
            "到期时间": (self._now() + ttl_seconds) if ttl_seconds else None,
        }
        self._bump_version(tourist)
        self._audit_append("系统", "系统", f"授权{action}", tourist, True, {"范围": scope})
        return self.consent_view(tourist)

    def revoke_consent(self, tourist, scope):
        """撤回授权：相关会话缓存立即失效，并开具删除回执。"""
        self._require(tourist, "游客")
        self._require_scope(scope)
        if scope not in self._consents.get(tourist, {}):
            raise PlatformError("该范围不存在授权记录", 404)
        receipt = self._close_consent(tourist, scope, "撤回")
        return {"回执": receipt}

    def sweep_expired(self):
        """到期处理：把已过期授权置为「到期」，触发缓存失效与删除回执。"""
        receipts = []
        for tourist in list(self._consents):
            receipts.extend(self._refresh(tourist))
        return {"回执": receipts}

    def _refresh(self, tourist):
        """惰性到期检查，返回新开具的回执。"""
        receipts = []
        now = self._now()
        for scope, rec in list(self._consents.get(tourist, {}).items()):
            if rec["状态"] in ("授予", "限制") and rec["到期时间"] is not None \
                    and rec["到期时间"] <= now:
                receipts.append(self._close_consent(tourist, scope, "到期"))
        return receipts

    def _close_consent(self, tourist, scope, action):
        """授权关闭（撤回/到期）：失效会话缓存、删除派生数据、开具回执。"""
        rec = self._consents[tourist][scope]
        rec["状态"] = action
        rec["更新时间"] = self._now()
        capability = SCOPE_TO_CAPABILITY[scope]
        invalidated = self._invalidate_sessions(tourist, capability, f"授权{action}")
        deleted = self._delete_artifacts(tourist, scope)
        self._bump_version(tourist)
        receipt = {
            "回执编号": self._new_id("D"),
            "游客": tourist,
            "范围": scope,
            "动作": action,
            "确认动作": "删除确认",
            "失效会话": invalidated,
            "删除项": deleted,
            "开具时间": self._now(),
        }
        self._receipts.setdefault(tourist, []).append(receipt)
        self._audit_append("系统", "系统", f"授权{action}", tourist, True,
                           {"范围": scope, "回执": receipt["回执编号"]})
        return receipt

    def _invalidate_sessions(self, tourist, capability, reason):
        """使涉及该游客且持有对应能力的会话缓存失效。"""
        invalidated = []
        for session in self._sessions.values():
            if session["状态"] != "有效" or capability not in session["允许能力"]:
                continue
            if not self._involves(session, tourist):
                continue
            session["状态"] = "已失效"
            session["失效原因"] = reason
            invalidated.append(session["编号"])
        return invalidated

    def _involves(self, session, tourist):
        if session["游客"] == tourist:
            return True
        family = self._families.get(session.get("家庭") or "", None)
        return bool(family) and tourist in family["成员"]

    def _delete_artifacts(self, tourist, scope):
        """删除被关闭授权所派生的数据，返回删除项清单。"""
        deleted = []
        trip_ids = {tid for tid, t in self._trips.items() if t["游客"] == tourist}
        if scope == "日志":
            for log in list(self._logs.values()):
                if log["行程"] in trip_ids:
                    del self._logs[log["编号"]]
                    deleted.append({"类型": "游览日志", "编号": log["编号"]})
        if scope == "定位":
            for pkg in self._packages.values():
                if pkg["行程"] in trip_ids and pkg.get("轨迹"):
                    pkg["轨迹"] = None
                    pkg["轨迹已删除"] = True
                    deleted.append({"类型": "离线轨迹", "编号": pkg["离线包"]})
        return deleted

    def consent_view(self, tourist):
        self._require(tourist, "游客")
        self._refresh(tourist)
        scopes = {scope: {"状态": rec["状态"], "到期时间": rec["到期时间"]}
                  for scope, rec in self._consents.get(tourist, {}).items()}
        return {"游客": tourist, "授权版本": self._version(tourist), "授权": scopes}

    def receipts(self, tourist):
        self._require(tourist, "游客")
        self._refresh(tourist)
        return list(self._receipts.get(tourist, []))

    # ------------------------------------------------------------------
    # 家庭同行：成员不同意处理
    # ------------------------------------------------------------------
    def create_family(self, family_id, members):
        self._require(family_id, "家庭")
        if not members:
            raise PlatformError("家庭成员不能为空")
        if family_id in self._families:
            raise PlatformError("家庭组已存在", 409)
        self._families[family_id] = {"成员": list(members), "不同意": {}}
        return {"家庭": family_id, "成员": list(members)}

    def dissent(self, family_id, tourist, scope):
        """家庭同行成员对某一范围表示不同意。

        共享设备上任何成员不同意，该范围对应能力即不下发；
        已发放的会话缓存同步失效。
        """
        family = self._families.get(family_id)
        if family is None:
            raise PlatformError("家庭组不存在", 404)
        if tourist not in family["成员"]:
            raise PlatformError("该游客不是本家庭成员")
        self._require_scope(scope)
        family["不同意"].setdefault(tourist, set()).add(scope)
        self._bump_version(tourist)
        capability = SCOPE_TO_CAPABILITY[scope]
        invalidated = self._invalidate_sessions(tourist, capability, "同行成员不同意")
        self._audit_append("系统", "系统", "同行成员不同意", tourist, True,
                           {"家庭": family_id, "范围": scope})
        return {"家庭": family_id, "游客": tourist,
                "不同意范围": sorted(family["不同意"][tourist]),
                "失效会话": invalidated}

    # ------------------------------------------------------------------
    # 设备与密钥轮换
    # ------------------------------------------------------------------
    def _new_key(self):
        return {"编号": self._new_id("K"), "值": secrets.token_hex(16),
                "状态": "生效中", "创建时间": self._now(), "宽限至": None}

    def register_device(self, device_id):
        self._require(device_id, "设备")
        if device_id in self._devices:
            raise PlatformError("设备已注册", 409)
        key = self._new_key()
        self._devices[device_id] = {"密钥": [key]}
        self._audit_append("系统", "系统", "设备注册", device_id, True)
        return {"设备": device_id, "密钥编号": key["编号"], "密钥": key["值"]}

    def rotate_key(self, device_id):
        """轮换设备密钥：旧密钥进入宽限期，新密钥立即生效。"""
        device = self._devices.get(device_id)
        if device is None:
            raise PlatformError("设备未注册", 404)
        now = self._now()
        for key in device["密钥"]:
            if key["状态"] == "生效中":
                key["状态"] = "已轮换"
                key["宽限至"] = now + KEY_GRACE_SECONDS
        key = self._new_key()
        device["密钥"].append(key)
        self._audit_append("系统", "系统", "密钥轮换", device_id, True,
                           {"新密钥": key["编号"]})
        return {"设备": device_id, "密钥编号": key["编号"], "密钥": key["值"],
                "旧密钥宽限至": now + KEY_GRACE_SECONDS}

    def _check_device_key(self, device_id, key_id, signature, tracks):
        device = self._devices.get(device_id)
        if device is None:
            raise PlatformError("设备未注册", 404)
        key = next((k for k in device["密钥"] if k["编号"] == key_id), None)
        if key is None:
            raise _Quarantine("密钥未知")
        if key["状态"] == "已轮换" and self._now() > (key["宽限至"] or 0):
            raise _Quarantine("密钥已过轮换宽限期")
        if not signature:
            raise _Quarantine("缺少签名")
        expected = hmac.new(key["值"].encode("utf-8"), _canonical(tracks).encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(signature)):
            raise _Quarantine("签名校验失败")

    # ------------------------------------------------------------------
    # 行程会话：最小权限下发
    # ------------------------------------------------------------------
    def issue_session(self, device_id, trip_id, tourist, required_capabilities,
                      family_id=None):
        """按当前行程发放会话，仅下放行程所需且已获授权的最小能力集。"""
        self._require(trip_id, "行程")
        self._require(tourist, "游客")
        if device_id not in self._devices:
            raise PlatformError("设备未注册", 404)
        if not required_capabilities:
            raise PlatformError("所需能力不能为空")
        self._refresh(tourist)
        if family_id is not None:
            family = self._families.get(family_id)
            if family is None:
                raise PlatformError("家庭组不存在", 404)
            if tourist not in family["成员"]:
                raise PlatformError("该游客不是本家庭成员")

        allowed, restricted = [], []
        for cap in required_capabilities:
            if cap in PUBLIC_CAPABILITIES:
                allowed.append(cap)
                continue
            scope = CAPABILITY_TO_SCOPE.get(cap)
            if scope is None:
                restricted.append({"能力": cap, "原因": "未知能力"})
                continue
            rec = self._consents.get(tourist, {}).get(scope)
            if rec is None:
                restricted.append({"能力": cap, "原因": "未授权"})
            elif rec["状态"] != "授予":
                restricted.append({"能力": cap, "原因": f"授权已{rec['状态']}"})
            else:
                allowed.append(cap)

        # 家庭同行成员不同意的范围，共享设备一律不下发
        if family_id is not None:
            for member, scopes in self._families[family_id]["不同意"].items():
                for scope in scopes:
                    cap = SCOPE_TO_CAPABILITY[scope]
                    if cap in allowed:
                        allowed.remove(cap)
                        restricted.append({
                            "能力": cap,
                            "原因": f"同行成员{mask_identifier(member)}不同意",
                        })

        versions = {tourist: self._version(tourist)}
        if family_id is not None:
            for member in self._families[family_id]["成员"]:
                versions[member] = self._version(member)

        session = {
            "编号": self._new_id("S"),
            "设备": device_id,
            "行程": trip_id,
            "游客": tourist,
            "家庭": family_id,
            "允许能力": allowed,
            "受限": restricted,
            "授权版本": versions,
            "状态": "有效",
            "失效原因": None,
            "发放时间": self._now(),
        }
        self._sessions[session["编号"]] = session
        self._trips.setdefault(trip_id, {"游客": tourist, "家庭": family_id})
        self._audit_append("系统", "系统", "发放会话", trip_id, True,
                           {"会话": session["编号"], "允许能力": allowed})
        return self._session_view(session)

    @staticmethod
    def _session_view(session):
        return {"会话": session["编号"], "设备": session["设备"],
                "行程": session["行程"], "允许能力": list(session["允许能力"]),
                "受限": list(session["受限"]), "授权版本": dict(session["授权版本"]),
                "状态": session["状态"], "失效原因": session["失效原因"]}

    # ------------------------------------------------------------------
    # 风险事件与导航策略
    # ------------------------------------------------------------------
    def report_risk(self, risk_type, level=None, note=""):
        self._require(risk_type, "类型")
        if risk_type not in RISK_TYPE_LEVEL:
            raise PlatformError(f"未知风险类型:{risk_type}")
        level = level or RISK_TYPE_LEVEL[risk_type]
        if level not in RISK_PRIORITY:
            raise PlatformError(f"未知风险级别:{level}")
        risk = {"编号": self._new_id("E"), "类型": risk_type, "级别": level,
                "说明": note, "状态": "生效中", "上报时间": self._now()}
        self._risks[risk["编号"]] = risk
        self._audit_append("系统", "系统", "上报风险", risk["编号"], True,
                           {"类型": risk_type, "级别": level})
        return dict(risk)

    def resolve_risk(self, risk_id):
        risk = self._risks.get(risk_id)
        if risk is None:
            raise PlatformError("风险事件不存在", 404)
        risk["状态"] = "已解除"
        risk["解除时间"] = self._now()
        return dict(risk)

    def navigation_strategy(self, session_id):
        """按生效中风险的最高优先级给出导航策略，并留存建议依据。"""
        session = self._sessions.get(session_id)
        if session is None:
            raise PlatformError("会话不存在", 404)
        if session["状态"] != "有效":
            raise PlatformError(f"会话已失效:{session['失效原因']}", 409)
        active = [r for r in self._risks.values() if r["状态"] == "生效中"]
        active.sort(key=lambda r: (RISK_PRIORITY[r["级别"]], r["上报时间"]), reverse=True)
        top = active[0] if active else None
        strategy = RISK_STRATEGY[top["级别"]] if top else DEFAULT_STRATEGY
        recommendation = {
            "编号": self._new_id("R"),
            "会话": session_id,
            "行程": session["行程"],
            "策略": strategy,
            "依据": {
                "风险": ({"编号": top["编号"], "类型": top["类型"], "级别": top["级别"]}
                        if top else None),
                "生效风险": [{"编号": r["编号"], "类型": r["类型"], "级别": r["级别"]}
                            for r in active],
                "授权版本": dict(session["授权版本"]),
            },
            "生成时间": self._now(),
        }
        self._recommendations[recommendation["编号"]] = recommendation
        self._audit_append("系统", "系统", "导航建议", recommendation["编号"], True,
                           {"策略": strategy})
        return recommendation

    def recommendation(self, recommendation_id):
        rec = self._recommendations.get(recommendation_id)
        if rec is None:
            raise PlatformError("建议不存在", 404)
        return rec

    # ------------------------------------------------------------------
    # 离线轨迹包：校验、合并、幂等、隔离
    # ------------------------------------------------------------------
    def submit_offline_package(self, device_id, key_id, trip_id, package_id,
                               tracks, signature):
        """离线包联网后上传：先校验再合并；同一离线包重复上传不产生新日志。"""
        self._require(package_id, "离线包")
        if package_id in self._packages:
            return {**self._package_view(self._packages[package_id]), "重复": True}

        record = {"离线包": package_id, "设备": device_id, "行程": trip_id,
                  "轨迹": tracks, "提交时间": self._now(), "状态": None,
                  "原因": None, "日志": None, "轨迹已删除": False}
        self._packages[package_id] = record  # 先占位，重复提交直接命中幂等
        try:
            self._check_device_key(device_id, key_id, signature, tracks)
            reason = self._validate_tracks(tracks)
            if reason:
                raise _Quarantine(reason)
            trip = self._trips.get(trip_id)
            if trip is None:
                raise _Quarantine("行程不存在")
            tourist = trip["游客"]
            self._refresh(tourist)
            consent = self._consents.get(tourist, {}).get("日志")
            if consent is None or consent["状态"] != "授予":
                raise _Quarantine("日志授权未授予或已失效")
            log = {"编号": self._new_id("L"), "行程": trip_id, "离线包": package_id,
                   "轨迹点数": len(tracks), "合并时间": self._now(),
                   "授权版本": self._version(tourist)}
            self._logs[log["编号"]] = log
            record["状态"] = "已合并"
            record["日志"] = log["编号"]
            self._audit_append("系统", "系统", "离线包合并", package_id, True,
                               {"日志": log["编号"]})
        except _Quarantine as exc:
            record["状态"] = "已隔离"
            record["原因"] = str(exc)
            self._audit_append("系统", "系统", "离线包隔离", package_id, True,
                               {"原因": str(exc)})
        return {**self._package_view(record), "重复": False}

    @staticmethod
    def _validate_tracks(tracks):
        if not isinstance(tracks, list) or not tracks:
            return "轨迹为空"
        prev = None
        for point in tracks:
            try:
                lat, lon, t = point["lat"], point["lon"], point["t"]
            except (KeyError, TypeError):
                return "轨迹点缺少字段"
            if not (-90 <= lat <= 90) or not (-180 <= lon <= 180):
                return "坐标越界"
            if prev is not None:
                dt = t - prev["t"]
                dist = _distance_m(prev, point)
                if dt < 0:
                    return "时间戳回退"
                if dt == 0 and dist > 0:
                    return "时间静止但位置跳变"
                if dt > 0 and dist / dt > MAX_TRACK_SPEED_MPS:
                    return f"速度异常({dist / dt:.0f}米/秒)"
            prev = point
        return None

    @staticmethod
    def _package_view(record):
        return {"离线包": record["离线包"], "设备": record["设备"],
                "行程": record["行程"], "状态": record["状态"],
                "原因": record["原因"], "日志": record["日志"],
                "轨迹已删除": record["轨迹已删除"]}

    def package_view(self, package_id):
        record = self._packages.get(package_id)
        if record is None:
            raise PlatformError("离线包不存在", 404)
        return self._package_view(record)

    # ------------------------------------------------------------------
    # 日志查看与受限审计
    # ------------------------------------------------------------------
    def trip_logs(self, trip_id, actor, role):
        """查看行程日志：运营人员仅见脱敏视图，访问本身记入审计。"""
        if trip_id not in self._trips:
            raise PlatformError("行程不存在", 404)
        allowed = role in (ROLE_OPS, ROLE_AUDITOR)
        self._audit_append(actor, role, "查看行程日志", trip_id, allowed)
        if not allowed:
            raise PlatformError("无权查看行程日志", 403)
        tourist = self._trips[trip_id]["游客"]
        logs = []
        for log in self._logs.values():
            if log["行程"] != trip_id:
                continue
            item = dict(log)
            item["游客"] = tourist if role == ROLE_AUDITOR else mask_identifier(tourist)
            logs.append(item)
        return {"行程": trip_id, "日志": logs}

    def view_audit(self, actor, role):
        """受限审计：审计员见全量，运营仅见脱敏视图且其访问被记录。"""
        allowed = role in (ROLE_OPS, ROLE_AUDITOR)
        self._audit_append(actor, role, "查看审计日志", "审计日志", allowed)
        if not allowed:
            raise PlatformError("无权查看审计日志", 403)
        if role == ROLE_AUDITOR:
            return list(self._audit)
        return [{"序号": e["序号"], "时间": e["时间"], "操作人": e["操作人"],
                 "角色": e["角色"], "动作": e["动作"], "允许": e["允许"],
                 "对象": mask_identifier(e["对象"])} for e in self._audit]
