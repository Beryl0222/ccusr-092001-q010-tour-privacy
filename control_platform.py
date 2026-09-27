"""伴游设备与景区业务服务之间的控制平台核心逻辑。

职责：
- 游客对定位/语音/影像/日志的独立授权、版本化与最小权限票据；
- 授权撤回/到期后的设备缓存失效指令与“删除确认”回执；
- 家庭同行成员任一不同意即否决该能力；
- 设备密钥轮换（旧密钥仅在宽限期内用于离线包验签）；
- 施工/拥堵/极端环境/走失按风险优先级改变导航策略，建议留痕风险与授权版本；
- 离线轨迹校验、异常隔离、同一离线包幂等合并；
- 运营审计员的只读、脱敏、受限审计。

仅依赖标准库，所有状态保存在内存中并加锁。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# 协议口径（来自 domain.json）
# ---------------------------------------------------------------------------

_DOMAIN_PATH = Path(__file__).with_name("domain.json")
DOMAIN = json.loads(_DOMAIN_PATH.read_text(encoding="utf-8"))

DEVICE_CAPABILITIES: list[str] = DOMAIN["设备能力"]
RISK_LEVELS: list[str] = DOMAIN["风险级别"]
CONSENT_ACTIONS: list[str] = DOMAIN["授权动作"]

# 游客可独立授权的范围：设备能力中除平台自身提供的“路线建议”外的四项
SCOPE_LOCATION = "定位"
SCOPE_VOICE = "语音交互"
SCOPE_IMAGE = "影像记录"
SCOPE_LOG = "日志生成"
CONSENT_SCOPES = [
    SCOPE_LOCATION,
    SCOPE_VOICE,
    SCOPE_IMAGE,
    SCOPE_LOG,
]
assert set(CONSENT_SCOPES) <= set(DEVICE_CAPABILITIES)

# 授权动作
ACTION_GRANT = "授予"
ACTION_RESTRICT = "限制"
ACTION_REVOKE = "撤回"
ACTION_EXPIRE = "到期"
ACTION_DELETE_ACK = "删除确认"

# 风险级别下标即优先级（越大越紧急）
RISK_RANK = {level: i for i, level in enumerate(RISK_LEVELS)}

# 各级别对应的导航策略
NAVIGATION_POLICY = {
    "信息提示": "继续当前路线，向游客语音提示风险信息",
    "路线调整": "放弃原定路线，绕行受影响区域",
    "停止前进": "停止前进并原地等待，不得靠近风险区域",
    "紧急求助": "立即中止行程并发起紧急求助，调度力量介入",
}
# 达到该级别即意味着旧路线不应再被设备继续采用
STALE_THRESHOLD = "路线调整"

# 风险类型
RISK_CONSTRUCTION = "施工"
RISK_CONGESTION = "拥堵"
RISK_WEATHER = "极端环境"
RISK_MISSING = "走失"

DEFAULT_PARK_BOUNDS = {
    "min_lat": 30.0,
    "max_lat": 30.5,
    "min_lon": 120.0,
    "max_lon": 120.5,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def canonical_payload(payload: dict) -> bytes:
    """签名/去重共用的规范化报文。"""
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    from math import asin, cos, radians, sin, sqrt

    r = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    )
    return 2 * r * asin(sqrt(a))


class PlatformError(Exception):
    """业务校验失败，message 可直接返回给调用方。"""

    def __init__(self, message: str, code: str = "invalid_request", status: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


@dataclass
class _Member:
    member_id: str
    relation: str = "游客本人"


@dataclass
class _Trip:
    trip_id: str
    name: str
    members: dict[str, _Member] = field(default_factory=dict)
    track: list[dict] = field(default_factory=list)
    journal: list[dict] = field(default_factory=list)
    created_at: datetime = field(default_factory=utcnow)


@dataclass
class _ConsentVersion:
    version: int
    action: str
    scopes: frozenset[str]
    created_at: datetime
    expires_at: datetime | None
    actor: str
    note: str | None = None


@dataclass
class _Risk:
    risk_id: str
    risk_type: str
    level: str
    areas: tuple[str, ...]
    message: str
    created_at: datetime
    active: bool = True
    resolved_at: datetime | None = None


@dataclass
class _KeyVersion:
    kid: str
    secret: str
    created_at: datetime
    rotated_at: datetime | None = None


class ControlPlatform:
    """控制平台的内存实现，方法均为线程安全的业务入口。"""

    def __init__(
        self,
        admin_token: str | None = None,
        park_bounds: dict | None = None,
        max_speed_kmh: float = 150.0,
        key_grace: timedelta = timedelta(hours=24),
        clock=utcnow,
    ):
        self._lock = threading.RLock()
        self._clock = clock
        self.admin_token = admin_token or "admin-dev-token"
        self.bounds = dict(park_bounds or DEFAULT_PARK_BOUNDS)
        self.max_speed_kmh = max_speed_kmh
        self.key_grace = key_grace

        self.trips: dict[str, _Trip] = {}
        # (trip_id, member_id) -> 有序授权版本
        self.consents: dict[tuple[str, str], list[_ConsentVersion]] = {}
        # (trip_id, member_id) -> {能力: 明确不同意的时间}（重新明确授予前持续有效）
        self.disagreements: dict[tuple[str, str], dict[str, datetime]] = {}
        self.devices: dict[str, dict] = {}
        self.tickets: dict[str, dict] = {}
        self.invalidations: dict[str, dict] = {}  # ticket_id -> 待确认的失效指令
        self.receipts: dict[str, dict] = {}
        self.risks: dict[str, _Risk] = {}
        self.risk_board_version = 0
        self.recommendations: dict[str, dict] = {}
        self.accepted_packet_ids: set[str] = set()
        self.accepted_payload_hashes: set[str] = set()
        self.quarantine: dict[str, dict] = {}
        self.quarantine_packet_ids: set[str] = set()
        self.operators: dict[str, dict] = {}
        self.audit_events: list[dict] = []

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------

    def _audit(self, action: str, actor: str, target: str, **detail) -> dict:
        event = {
            "event_id": f"evt_{len(self.audit_events) + 1:06d}",
            "time": to_iso(self._clock()),
            "action": action,
            "actor": actor,
            "target": target,
            # 审计事件只记录元数据：坐标、音视频内容、密钥等一律不进入 detail
            "detail": detail,
        }
        self.audit_events.append(event)
        return event

    def register_operator(self, name: str) -> dict:
        with self._lock:
            operator_id = f"op_{secrets.token_hex(4)}"
            token = f"optk_{secrets.token_hex(16)}"
            self.operators[token] = {
                "operator_id": operator_id,
                "name": name,
                "role": "审计员",
                "scopes": ("audit:read",),
            }
            self._audit("运营人员登记", f"审计员:{name}", operator_id)
            return {
                "operator_id": operator_id,
                "name": name,
                "role": "审计员",
                "token": token,
            }

    def _require_operator(self, token: str) -> dict:
        operator = self.operators.get(token)
        if not operator:
            raise PlatformError("运营人员凭据无效", "forbidden", 403)
        return operator

    def list_audit(self, operator_token: str, limit: int | None = None) -> dict:
        """审计员只读访问：仅返回脱敏后的审计元数据。"""
        with self._lock:
            operator = self._require_operator(operator_token)
            if "audit:read" not in operator["scopes"]:
                raise PlatformError("无审计权限", "forbidden", 403)
            events = list(reversed(self.audit_events))
            if limit is not None:
                events = events[:limit]
            return {
                "operator": operator["name"],
                "role": operator["role"],
                "redacted": True,
                "events": events,
            }

    # ------------------------------------------------------------------
    # 行程与同行成员
    # ------------------------------------------------------------------

    def create_trip(
        self,
        trip_id: str | None = None,
        name: str = "",
        members: list[dict] | None = None,
    ) -> dict:
        with self._lock:
            trip_id = trip_id or f"trip_{secrets.token_hex(6)}"
            if trip_id in self.trips:
                raise PlatformError(f"行程 {trip_id} 已存在", "conflict", 409)
            trip = _Trip(trip_id=trip_id, name=name)
            members = members or [{"member_id": "tourist", "relation": "游客本人"}]
            for m in members:
                mid = m["member_id"]
                if mid in trip.members:
                    raise PlatformError(f"成员 {mid} 重复")
                trip.members[mid] = _Member(mid, m.get("relation", "同行成员"))
            self.trips[trip_id] = trip
            self._audit("行程创建", "运营平台", trip_id, members=len(trip.members))
            return self._trip_view(trip)

    def _get_trip(self, trip_id: str) -> _Trip:
        trip = self.trips.get(trip_id)
        if not trip:
            raise PlatformError(f"行程 {trip_id} 不存在", "not_found", 404)
        return trip

    def _require_member(self, trip: _Trip, member_id: str) -> _Member:
        member = trip.members.get(member_id)
        if not member:
            raise PlatformError(
                f"成员 {member_id} 不在行程 {trip.trip_id} 的同行名单中",
                "not_member",
                403,
            )
        return member

    def _trip_view(self, trip: _Trip) -> dict:
        return {
            "trip_id": trip.trip_id,
            "name": trip.name,
            "members": [
                {"member_id": m.member_id, "relation": m.relation}
                for m in trip.members.values()
            ],
            "created_at": to_iso(trip.created_at),
        }

    # ------------------------------------------------------------------
    # 授权
    # ------------------------------------------------------------------

    def _require_scopes(self, scopes: list[str]) -> list[str]:
        invalid = [s for s in scopes if s not in CONSENT_SCOPES]
        if invalid:
            raise PlatformError(f"未知授权范围：{invalid}")
        if not scopes:
            raise PlatformError("授权范围不能为空")
        return scopes

    def _apply_consent(
        self,
        trip_id: str,
        member_id: str,
        action: str,
        scopes: list[str] | None,
        actor: str,
        ttl: timedelta | None,
        note: str | None = None,
    ) -> dict:
        trip = self._get_trip(trip_id)
        self._require_member(trip, member_id)
        key = (trip_id, member_id)
        history = self.consents.setdefault(key, [])
        previous = history[-1] if history else None
        current = set(previous.scopes) if previous else set()
        now = self._clock()

        if action == ACTION_GRANT:
            asked = self._require_scopes(list(scopes or []))
            new_scopes = current | set(asked)
            # 重新明确授予即视为消除此前的不同意
            marks = self.disagreements.setdefault(key, {})
            for scope in asked:
                marks.pop(scope, None)
        elif action == ACTION_RESTRICT:
            asked = self._require_scopes(list(scopes or []))
            # 限制：仅保留列出的范围（最小授权口径）
            new_scopes = current & set(asked)
        elif action == ACTION_REVOKE:
            asked = self._require_scopes(list(scopes or CONSENT_SCOPES))
            new_scopes = current - set(asked)
        else:
            raise PlatformError(f"不支持的授权动作：{action}")

        if note == "同行成员不同意":
            marks = self.disagreements.setdefault(key, {})
            for scope in asked:
                marks.setdefault(scope, now)

        if action != ACTION_GRANT or ttl is not None:
            # 限制/撤回即时生效且不会自动恢复；未指定 TTL 的新授予视为长期有效
            expires_at = now + ttl if action == ACTION_GRANT else None
        else:
            expires_at = None

        version = _ConsentVersion(
            version=len(history) + 1,
            action=action,
            scopes=frozenset(new_scopes),
            created_at=now,
            expires_at=expires_at,
            actor=actor,
            note=note,
        )
        history.append(version)
        self._audit(
            action,
            actor,
            f"{trip_id}/{member_id}",
            version=version.version,
            scopes=sorted(new_scopes),
            ttl_seconds=int(ttl.total_seconds()) if ttl else None,
            disagreement=bool(note == "同行成员不同意"),
        )
        # 授权变化立即影响已发放票据
        self._sweep_ticket_expiry(now)
        return self._member_consent_view(trip_id, member_id)

    def grant_consent(
        self,
        trip_id: str,
        member_id: str,
        scopes: list[str],
        ttl: timedelta | None = None,
        actor: str = "游客",
    ) -> dict:
        with self._lock:
            return self._apply_consent(
                trip_id, member_id, ACTION_GRANT, scopes, actor, ttl
            )

    def restrict_consent(
        self, trip_id: str, member_id: str, scopes: list[str], actor: str = "游客"
    ) -> dict:
        with self._lock:
            return self._apply_consent(
                trip_id, member_id, ACTION_RESTRICT, scopes, actor, None
            )

    def revoke_consent(
        self,
        trip_id: str,
        member_id: str,
        scopes: list[str] | None = None,
        actor: str = "游客",
        family_disagreement: bool = False,
    ) -> dict:
        """撤回授权；family_disagreement 表示同行成员明确不同意（此前未必授予过）。"""
        with self._lock:
            return self._apply_consent(
                trip_id,
                member_id,
                ACTION_REVOKE,
                scopes,
                actor,
                None,
                note="同行成员不同意" if family_disagreement else None,
            )

    def _version_at(
        self, trip_id: str, member_id: str, at: datetime
    ) -> _ConsentVersion | None:
        history = self.consents.get((trip_id, member_id), [])
        found = None
        for v in history:
            if v.created_at <= at:
                found = v
            else:
                break
        return found

    def _member_scope_granted_at(
        self, trip_id: str, member_id: str, scope: str, at: datetime
    ) -> tuple[bool, int | None, str | None]:
        """返回(是否授权, 版本号, 未授权原因)。"""
        version = self._version_at(trip_id, member_id, at)
        marks = self.disagreements.get((trip_id, member_id), {})
        if scope in marks and marks[scope] <= at:
            return False, version.version if version else None, "同行成员不同意"
        if version is None:
            return False, None, "未授权"
        if scope not in version.scopes:
            reason = (
                "授权撤回" if version.action == ACTION_REVOKE else "未授权"
            )
            return False, version.version, reason
        if version.expires_at is not None and at >= version.expires_at:
            return False, version.version, "授权到期"
        return True, version.version, None

    def _member_consent_view(self, trip_id: str, member_id: str) -> dict:
        now = self._clock()
        key = (trip_id, member_id)
        history = self.consents.get(key, [])
        latest = history[-1] if history else None
        granted: list[str] = []
        expired: list[str] = []
        if latest is not None:
            for scope in CONSENT_SCOPES:
                if scope not in latest.scopes:
                    continue
                if latest.expires_at is not None and now >= latest.expires_at:
                    expired.append(scope)
                else:
                    granted.append(scope)
        return {
            "trip_id": trip_id,
            "member_id": member_id,
            "version": latest.version if latest else 0,
            "action": latest.action if latest else None,
            "granted_scopes": granted,
            "expired_scopes": expired,
            "disagreed_scopes": sorted(
                s
                for s, marked_at in self.disagreements.get(key, {}).items()
                if marked_at <= now
            ),
            "expires_at": to_iso(latest.expires_at)
            if latest and latest.expires_at
            else None,
            "note": latest.note if latest else None,
        }

    def trip_consent_view(self, trip_id: str) -> dict:
        """家庭共同口径：任一成员不同意/未授权，该能力对整段行程不开放。"""
        with self._lock:
            trip = self._get_trip(trip_id)
            now = self._clock()
            members = [
                self._member_consent_view(trip_id, m.member_id)
                for m in trip.members.values()
            ]
            effective: dict[str, dict] = {}
            for scope in CONSENT_SCOPES:
                blockers = []
                versions = {}
                for view in members:
                    ok, ver, reason = self._member_scope_granted_at(
                        trip_id, view["member_id"], scope, now
                    )
                    versions[view["member_id"]] = ver
                    if not ok:
                        blockers.append(
                            {"member_id": view["member_id"], "reason": reason}
                        )
                effective[scope] = {
                    "allowed": not blockers,
                    "consent_versions": versions,
                    "blocked_by": blockers,
                }
            return {
                "trip_id": trip_id,
                "members": members,
                "trip_effective_scopes": [
                    s for s, info in effective.items() if info["allowed"]
                ],
                "scopes": effective,
            }

    # ------------------------------------------------------------------
    # 设备注册与密钥轮换
    # ------------------------------------------------------------------

    def register_device(self, device_id: str | None = None) -> dict:
        with self._lock:
            device_id = device_id or f"dev_{secrets.token_hex(6)}"
            if device_id in self.devices:
                raise PlatformError(f"设备 {device_id} 已注册", "conflict", 409)
            kid = f"kid_{secrets.token_hex(4)}"
            secret = secrets.token_hex(32)
            self.devices[device_id] = {
                "device_id": device_id,
                "keys": [_KeyVersion(kid=kid, secret=secret, created_at=self._clock())],
                "grace_deadline": None,
                "trips": set(),
            }
            self._audit("设备注册", "运营平台", device_id, key_id=kid)
            # 明文密钥仅此一次返回
            return {
                "device_id": device_id,
                "kid": kid,
                "key": secret,
                "rotated_at": None,
                "grace_deadline": None,
            }

    def _get_device(self, device_id: str) -> dict:
        device = self.devices.get(device_id)
        if not device:
            raise PlatformError(f"设备 {device_id} 未注册", "device_unknown", 404)
        return device

    def rotate_key(
        self, device_id: str, grace: timedelta | None = None, actor: str = "运营平台"
    ) -> dict:
        """轮换设备密钥：新密钥立即生效，旧密钥进入宽限期（仅供离线包验签）。

        已发放给该设备的票据立即失效，必须重新申领。
        """
        with self._lock:
            device = self._get_device(device_id)
            now = self._clock()
            grace = grace if grace is not None else self.key_grace

            old = device["keys"][-1]
            old.rotated_at = now
            new_kid = f"kid_{secrets.token_hex(4)}"
            new_secret = secrets.token_hex(32)
            device["keys"].append(
                _KeyVersion(kid=new_kid, secret=new_secret, created_at=now)
            )
            device["grace_deadline"] = now + grace

            for ticket in self.tickets.values():
                if (
                    ticket["device_id"] == device_id
                    and ticket["status"] == "有效"
                ):
                    self._invalidate_ticket(
                        ticket, "设备密钥轮换", list(ticket["scopes"]), now
                    )

            self._audit(
                "密钥轮换",
                actor,
                device_id,
                new_key_id=new_kid,
                retired_key_id=old.kid,
                grace_seconds=int(grace.total_seconds()),
            )
            return {
                "device_id": device_id,
                "kid": new_kid,
                "key": new_secret,
                "rotated_at": to_iso(now),
                "retired_kid": old.kid,
                "grace_deadline": to_iso(device["grace_deadline"]),
            }

    def _find_key(self, device: dict, kid: str) -> _KeyVersion | None:
        for key in reversed(device["keys"]):
            if key.kid == kid:
                return key
        return None

    def sign(self, device_id: str, payload: dict, kid: str | None = None) -> str:
        with self._lock:
            device = self._get_device(device_id)
            key = device["keys"][-1] if kid is None else self._find_key(device, kid)
            if key is None:
                raise PlatformError("密钥编号未知", "bad_key", 403)
            return hmac.new(
                key.secret.encode("utf-8"), canonical_payload(payload), hashlib.sha256
            ).hexdigest()

    def verify_signature(
        self,
        device_id: str,
        payload: dict,
        kid: str,
        signature: str,
        formed_at: datetime | None = None,
    ) -> tuple[bool, str | None]:
        """验签。旧密钥仅允许在宽限期内验签轮换前形成的离线包。"""
        with self._lock:
            device = self._get_device(device_id)
            key = self._find_key(device, kid)
            if key is None:
                return False, "密钥编号未知"
            expected = hmac.new(
                key.secret.encode("utf-8"),
                canonical_payload(payload),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return False, "签名不匹配"

            current = device["keys"][-1]
            if key.kid == current.kid:
                return True, None
            # 旧密钥：宽限期 + 报文形成于轮换前后的容忍窗口内
            now = self._clock()
            grace_deadline = device["grace_deadline"]
            if grace_deadline is None or now > grace_deadline:
                return False, "旧密钥宽限期已过"
            if formed_at is not None and key.rotated_at is not None:
                skew = timedelta(minutes=5)
                if formed_at > key.rotated_at + skew:
                    return False, "离线包形成于密钥轮换之后"
            return True, "旧密钥宽限期验签"

    # ------------------------------------------------------------------
    # 最小权限票据与缓存失效/删除回执
    # ------------------------------------------------------------------

    def issue_ticket(
        self,
        device_id: str,
        trip_id: str,
        needed_scopes: list[str],
        ttl: timedelta | None = None,
    ) -> dict:
        with self._lock:
            now = self._clock()
            self._sweep_ticket_expiry(now)
            device = self._get_device(device_id)
            trip = self._get_trip(trip_id)
            asked = self._require_scopes(needed_scopes)

            granted: list[str] = []
            denied: dict[str, list[dict]] = {}
            consent_versions: dict[str, dict[str, int | None]] = {}
            earliest_expiry: datetime | None = None

            for scope in asked:
                blockers = []
                versions: dict[str, int | None] = {}
                for member in trip.members.values():
                    ok, ver, reason = self._member_scope_granted_at(
                        trip_id, member.member_id, scope, now
                    )
                    versions[member.member_id] = ver
                    if not ok:
                        blockers.append(
                            {"member_id": member.member_id, "reason": reason}
                        )
                consent_versions[scope] = versions
                if blockers:
                    denied[scope] = blockers
                else:
                    granted.append(scope)
                    for member in trip.members.values():
                        history = self.consents.get((trip_id, member.member_id), [])
                        latest = history[-1] if history else None
                        if latest and latest.expires_at is not None:
                            if (
                                earliest_expiry is None
                                or latest.expires_at < earliest_expiry
                            ):
                                earliest_expiry = latest.expires_at

            expires_at = None
            if ttl is not None:
                expires_at = now + ttl
            if earliest_expiry is not None:
                expires_at = (
                    earliest_expiry
                    if expires_at is None
                    else min(expires_at, earliest_expiry)
                )

            ticket_id = f"tk_{secrets.token_hex(8)}"
            kid = device["keys"][-1].kid
            ticket = {
                "ticket_id": ticket_id,
                "device_id": device_id,
                "trip_id": trip_id,
                "kid": kid,
                "needed_scopes": asked,
                "scopes": granted,
                "denied_scopes": denied,
                "consent_versions": consent_versions,
                "issued_at": to_iso(now),
                "expires_at": to_iso(expires_at) if expires_at else None,
                "status": "有效",
            }
            self.tickets[ticket_id] = ticket
            device["trips"].add(trip_id)
            self._audit(
                "票据发放",
                f"设备:{device_id}",
                ticket_id,
                trip_id=trip_id,
                requested=asked,
                granted=granted,
                denied=list(denied),
                consent_versions=consent_versions,
            )
            return dict(ticket)

    def _invalidate_ticket(
        self, ticket: dict, reason: str, lost_scopes: list[str], now: datetime
    ) -> None:
        ticket["status"] = "失效"
        ticket["invalidated_at"] = to_iso(now)
        ticket["invalidate_reason"] = reason
        self.invalidations.setdefault(
            ticket["ticket_id"],
            {
                "ticket_id": ticket["ticket_id"],
                "device_id": ticket["device_id"],
                "scopes": sorted(set(lost_scopes)),
                "reason": reason,
                "issued_at": to_iso(now),
                "cache_deleted": False,
            },
        )
        self._audit(
            "缓存失效" if reason != "设备密钥轮换" else "票据随密钥失效",
            "控制平台",
            ticket["ticket_id"],
            reason=reason,
            lost_scopes=sorted(set(lost_scopes)),
        )

    def _sweep_ticket_expiry(self, now: datetime) -> None:
        """根据授权到期/撤回/家庭不同意及票据自身有效期回收票据。"""
        for ticket in self.tickets.values():
            if ticket["status"] != "有效":
                continue
            if ticket["expires_at"] and now >= parse_iso(ticket["expires_at"]):
                self._invalidate_ticket(ticket, "票据到期", list(ticket["scopes"]), now)
                continue
            lost: list[str] = []
            reason = None
            trip = self.trips[ticket["trip_id"]]
            for scope in ticket["scopes"]:
                for member_id in trip.members:
                    ok, _ver, why = self._member_scope_granted_at(
                        ticket["trip_id"], member_id, scope, now
                    )
                    if not ok:
                        lost.append(scope)
                        reason = why
                        break
            if lost:
                self._invalidate_ticket(ticket, reason or "授权变更", lost, now)

    def sync_device(self, device_id: str) -> dict:
        """设备联网同步：领取缓存失效指令与已失效的旧路线建议。"""
        with self._lock:
            now = self._clock()
            device = self._get_device(device_id)
            self._sweep_ticket_expiry(now)
            self._mark_stale_recommendations(now)
            invalidations = [
                dict(item)
                for item in self.invalidations.values()
                if item["device_id"] == device_id
            ]
            stale = [
                {
                    "recommendation_id": rid,
                    "trip_id": rec["trip_id"],
                    "areas": rec["areas"],
                    "risk_version": rec["risk_version"],
                    "status": rec["status"],
                }
                for rid, rec in self.recommendations.items()
                if rec["device_id"] == device_id and rec["status"] != "现行"
            ]
            return {
                "device_id": device_id,
                "current_kid": device["keys"][-1].kid,
                "invalidated_tickets": invalidations,
                "stale_recommendations": stale,
            }

    def confirm_cache_deleted(
        self, device_id: str, ticket_id: str
    ) -> dict:
        """设备确认本地缓存已删除 → 出具幂等的“删除确认”回执。"""
        with self._lock:
            ticket = self.tickets.get(ticket_id)
            if not ticket or ticket["device_id"] != device_id:
                raise PlatformError("票据不属于该设备", "not_found", 404)
            existing = self.receipts.get(ticket_id)
            if existing:
                return dict(existing)
            invalidation = self.invalidations.get(ticket_id)
            if not invalidation:
                raise PlatformError("该票据没有待确认的失效指令", "no_pending", 409)
            receipt = {
                "receipt_id": f"rcp_{secrets.token_hex(8)}",
                "action": ACTION_DELETE_ACK,
                "ticket_id": ticket_id,
                "device_id": device_id,
                "scopes": invalidation["scopes"],
                "invalidate_reason": invalidation["reason"],
                "confirmed_at": to_iso(self._clock()),
            }
            invalidation["cache_deleted"] = True
            invalidation["receipt_id"] = receipt["receipt_id"]
            self.receipts[ticket_id] = receipt
            self._audit(
                ACTION_DELETE_ACK,
                f"设备:{device_id}",
                ticket_id,
                receipt_id=receipt["receipt_id"],
                scopes=invalidation["scopes"],
            )
            return dict(receipt)

    # ------------------------------------------------------------------
    # 风险与导航策略
    # ------------------------------------------------------------------

    def add_risk(
        self,
        risk_type: str,
        level: str,
        areas: list[str],
        message: str,
        actor: str = "运营平台",
    ) -> dict:
        with self._lock:
            if level not in RISK_LEVELS:
                raise PlatformError(f"未知风险级别：{level}")
            if not areas:
                raise PlatformError("风险影响区域不能为空")
            risk = _Risk(
                risk_id=f"risk_{secrets.token_hex(6)}",
                risk_type=risk_type,
                level=level,
                areas=tuple(areas),
                message=message,
                created_at=self._clock(),
            )
            self.risks[risk.risk_id] = risk
            self.risk_board_version += 1
            self._audit(
                "风险发布",
                actor,
                risk.risk_id,
                risk_type=risk_type,
                level=level,
                areas=list(areas),
                risk_version=self.risk_board_version,
            )
            self._mark_stale_recommendations(self._clock())
            return self._risk_view(risk)

    def resolve_risk(self, risk_id: str, actor: str = "运营平台") -> dict:
        with self._lock:
            risk = self.risks.get(risk_id)
            if not risk:
                raise PlatformError("风险事件不存在", "not_found", 404)
            if not risk.active:
                return self._risk_view(risk)
            risk.active = False
            risk.resolved_at = self._clock()
            self.risk_board_version += 1
            self._audit(
                "风险解除",
                actor,
                risk_id,
                risk_type=risk.risk_type,
                risk_version=self.risk_board_version,
            )
            return self._risk_view(risk)

    def _risk_view(self, risk: _Risk) -> dict:
        return {
            "risk_id": risk.risk_id,
            "risk_type": risk.risk_type,
            "level": risk.level,
            "areas": list(risk.areas),
            "message": risk.message,
            "active": risk.active,
            "created_at": to_iso(risk.created_at),
            "resolved_at": to_iso(risk.resolved_at) if risk.resolved_at else None,
        }

    def _active_risks_for(self, areas: list[str]) -> list[_Risk]:
        wanted = set(areas)
        return [
            r
            for r in self.risks.values()
            if r.active and wanted.intersection(r.areas)
        ]

    def _mark_stale_recommendations(self, now: datetime) -> None:
        """风险板本变化且存在达到“路线调整”级别的新风险时，旧建议标记失效。"""
        threshold = RISK_RANK[STALE_THRESHOLD]
        for rec in self.recommendations.values():
            if rec["status"] != "现行":
                continue
            if rec["risk_version"] >= self.risk_board_version:
                continue
            for risk in self._active_risks_for(rec["areas"]):
                if RISK_RANK[risk.level] >= threshold:
                    rec["status"] = "旧路线已失效，请重新获取建议"
                    rec["superseded_at"] = to_iso(now)
                    rec["superseded_by_risk"] = risk.risk_id
                    self._audit(
                        "旧路线失效",
                        "控制平台",
                        rec["recommendation_id"],
                        risk_id=risk.risk_id,
                        level=risk.level,
                    )
                    break

    def recommend(
        self, device_id: str, trip_id: str, areas: list[str]
    ) -> dict:
        with self._lock:
            now = self._clock()
            device = self._get_device(device_id)
            trip = self._get_trip(trip_id)
            if not areas:
                raise PlatformError("路线区域不能为空")
            self._sweep_ticket_expiry(now)
            self._mark_stale_recommendations(now)

            active = self._active_risks_for(areas)
            if active:
                top = max(RISK_RANK[r.level] for r in active)
                governing = [r for r in active if RISK_RANK[r.level] == top]
                level = RISK_LEVELS[top]
                strategy = NAVIGATION_POLICY[level]
            else:
                governing = []
                level = None
                strategy = "按计划路线通行"

            # 建议留档当时的授权版本（四个独立维度逐成员记录）
            consent_versions: dict[str, dict[str, dict]] = {}
            for scope in CONSENT_SCOPES:
                consent_versions[scope] = {}
                for member in trip.members.values():
                    ok, ver, reason = self._member_scope_granted_at(
                        trip_id, member.member_id, scope, now
                    )
                    consent_versions[scope][member.member_id] = {
                        "version": ver,
                        "allowed": ok,
                        "reason": reason,
                    }

            active_ticket = next(
                (
                    t
                    for t in self.tickets.values()
                    if t["device_id"] == device_id
                    and t["trip_id"] == trip_id
                    and t["status"] == "有效"
                ),
                None,
            )
            rec = {
                "recommendation_id": f"rec_{secrets.token_hex(8)}",
                "device_id": device_id,
                "trip_id": trip_id,
                "areas": list(areas),
                "strategy": strategy,
                "risk_level": level,
                "risks": [self._risk_view(r) for r in governing],
                "risk_version": self.risk_board_version,
                "consent_versions": consent_versions,
                "ticket_id": active_ticket["ticket_id"] if active_ticket else None,
                "created_at": to_iso(now),
                "status": "现行",
            }
            self.recommendations[rec["recommendation_id"]] = rec
            self._audit(
                "路线建议",
                f"设备:{device_id}",
                rec["recommendation_id"],
                trip_id=trip_id,
                risk_level=level,
                risk_version=self.risk_board_version,
                risk_ids=[r.risk_id for r in governing],
                consent_versions=consent_versions,
            )
            return dict(rec)

    def get_recommendation(self, recommendation_id: str) -> dict:
        with self._lock:
            rec = self.recommendations.get(recommendation_id)
            if not rec:
                raise PlatformError("建议不存在", "not_found", 404)
            return dict(rec)

    # ------------------------------------------------------------------
    # 离线轨迹上传：校验 / 隔离 / 幂等合并
    # ------------------------------------------------------------------

    def _packet_payload(self, packet: dict) -> dict:
        return {
            "packet_id": packet["packet_id"],
            "device_id": packet["device_id"],
            "trip_id": packet["trip_id"],
            "formed_at": packet["formed_at"],
            "points": packet["points"],
        }

    def _packet_fingerprint(self, packet: dict) -> str:
        """内容指纹：不含包编号，同内容即使换编号也视为同一离线包。"""
        content = {
            "device_id": packet.get("device_id"),
            "trip_id": packet.get("trip_id"),
            "formed_at": packet.get("formed_at"),
            "points": packet.get("points"),
        }
        return sha256_hex(canonical_payload(content))

    def make_signed_packet(
        self,
        device_id: str,
        trip_id: str,
        points: list[dict],
        packet_id: str | None = None,
        formed_at: datetime | str | None = None,
        kid: str | None = None,
    ) -> dict:
        """模拟设备端组包并签名（测试与设备 SDK 同一路径）。"""
        with self._lock:
            self._get_device(device_id)
            self._get_trip(trip_id)
            formed = formed_at or self._clock()
        if isinstance(formed, datetime):
            formed_iso = to_iso(formed)
        else:
            formed_iso = formed
        packet_id = packet_id or f"pkt_{secrets.token_hex(8)}"
        payload = {
            "packet_id": packet_id,
            "device_id": device_id,
            "trip_id": trip_id,
            "formed_at": formed_iso,
            "points": points,
        }
        sig = self.sign(device_id, payload, kid=kid)
        used_kid = kid or self.devices[device_id]["keys"][-1].kid
        return {**payload, "kid": used_kid, "sig": sig}

    def upload_offline_packet(self, packet: dict) -> dict:
        with self._lock:
            now = self._clock()
            # 同一包重传：直接返回既有结果，绝不产生第二份日志
            packet_id = packet.get("packet_id")
            trip_id = packet.get("trip_id")
            if (
                packet_id
                and trip_id in self.trips
                and packet_id in self.accepted_packet_ids
            ):
                existing = next(
                    j for j in self.trips[packet["trip_id"]].journal
                    if j["packet_id"] == packet_id
                )
                self._audit(
                    "离线包重复上传",
                    f"设备:{packet.get('device_id')}",
                    packet_id,
                    log_id=existing["log_id"],
                )
                return {
                    "status": "重复",
                    "duplicate": True,
                    "log_id": existing["log_id"],
                    "packet_id": packet_id,
                }

            reasons = self._validate_packet(packet, now)

            digest = self._packet_fingerprint(packet)

            if not reasons:
                if digest in self.accepted_payload_hashes:
                    existing_log = next(
                        j
                        for trip in self.trips.values()
                        for j in trip.journal
                        if j["payload_hash"] == digest
                    )
                    self._audit(
                        "离线包重复上传",
                        f"设备:{packet['device_id']}",
                        packet_id,
                        log_id=existing_log["log_id"],
                    )
                    return {
                        "status": "重复",
                        "duplicate": True,
                        "log_id": existing_log["log_id"],
                        "packet_id": packet_id,
                    }
                return self._merge_packet(packet, digest, now)

            return self._quarantine_packet(packet, digest, reasons, now)

    def _validate_packet(self, packet: dict, now: datetime) -> list[str]:
        reasons: list[str] = []
        for field_name in ("packet_id", "device_id", "trip_id", "formed_at", "points"):
            if field_name not in packet:
                reasons.append(f"报文缺少字段:{field_name}")
        if reasons:
            return reasons  # 后续校验依赖字段，直接返回

        device = self.devices.get(packet["device_id"])
        if not device:
            reasons.append("设备未注册")
            return reasons
        trip = self.trips.get(packet["trip_id"])
        if not trip:
            reasons.append("行程不存在")
            return reasons

        try:
            formed_at = parse_iso(packet["formed_at"])
        except (ValueError, TypeError):
            reasons.append("formed_at 时间格式非法")
            return reasons
        if formed_at > now + timedelta(minutes=5):
            reasons.append("离线包形成时间在未来")

        ok, why = self.verify_signature(
            packet["device_id"],
            self._packet_payload(packet),
            packet.get("kid", ""),
            packet.get("sig", ""),
            formed_at=formed_at,
        )
        if not ok:
            reasons.append(f"签名校验失败:{why}")

        points = packet["points"]
        if not isinstance(points, list) or not points:
            reasons.append("轨迹点为空")
            return reasons

        prev_ts = None
        prev_point = None
        for i, p in enumerate(points):
            try:
                lat = float(p["lat"])
                lon = float(p["lon"])
                ts = parse_iso(p["ts"])
            except (KeyError, TypeError, ValueError):
                reasons.append(f"第{i + 1}个轨迹点格式非法")
                return reasons
            if not (
                self.bounds["min_lat"] <= lat <= self.bounds["max_lat"]
                and self.bounds["min_lon"] <= lon <= self.bounds["max_lon"]
            ):
                reasons.append(f"第{i + 1}个轨迹点超出景区围栏")
            if ts > now + timedelta(minutes=5):
                reasons.append(f"第{i + 1}个轨迹点时间在未来")
            if prev_ts is not None:
                if ts < prev_ts:
                    reasons.append("轨迹点时间戳非单调递增")
                else:
                    dt_h = (ts - prev_ts).total_seconds() / 3600.0
                    if dt_h > 0:
                        speed = (
                            _haversine_km(
                                prev_point[0], prev_point[1], lat, lon
                            )
                            / dt_h
                        )
                        if speed > self.max_speed_kmh:
                            reasons.append(
                                f"第{i + 1}个轨迹点移动速度异常:{speed:.1f}km/h"
                            )
            prev_ts, prev_point = ts, (lat, lon)

        # 轨迹采集期间定位授权必须对全体同行成员持续有效
        span_start = parse_iso(points[0]["ts"])
        span_end = parse_iso(points[-1]["ts"])
        for member in trip.members.values():
            for check_at in (span_start, span_end):
                ok, _ver, why = self._member_scope_granted_at(
                    trip.trip_id, member.member_id, SCOPE_LOCATION, check_at
                )
                if not ok:
                    reasons.append(
                        f"成员{member.member_id}定位授权无效({why})"
                    )
                    break
        return reasons

    def _merge_packet(
        self, packet: dict, digest: str, now: datetime
    ) -> dict:
        trip = self.trips[packet["trip_id"]]
        points = [
            {
                "ts": p["ts"],
                "lat": float(p["lat"]),
                "lon": float(p["lon"]),
                "packet_id": packet["packet_id"],
            }
            for p in packet["points"]
        ]
        # 合并后按时间排序并按 (ts,lat,lon) 去重
        existing_keys = {(p["ts"], p["lat"], p["lon"]) for p in trip.track}
        for p in points:
            key = (p["ts"], p["lat"], p["lon"])
            if key not in existing_keys:
                trip.track.append(p)
                existing_keys.add(key)
        trip.track.sort(key=lambda p: p["ts"])

        consent_snapshot = {}
        for member in trip.members.values():
            _ok, ver, _why = self._member_scope_granted_at(
                trip.trip_id,
                member.member_id,
                SCOPE_LOCATION,
                parse_iso(points[-1]["ts"]),
            )
            consent_snapshot[member.member_id] = ver

        log = {
            "log_id": f"log_{secrets.token_hex(8)}",
            "trip_id": trip.trip_id,
            "packet_id": packet["packet_id"],
            "payload_hash": digest,
            "point_count": len(points),
            "start_ts": points[0]["ts"],
            "end_ts": points[-1]["ts"],
            "location_consent_versions": consent_snapshot,
            "risk_version": self.risk_board_version,
            "created_at": to_iso(now),
        }
        trip.journal.append(log)
        self.accepted_packet_ids.add(packet["packet_id"])
        self.accepted_payload_hashes.add(digest)
        self._audit(
            "轨迹合并",
            f"设备:{packet['device_id']}",
            packet["packet_id"],
            trip_id=trip.trip_id,
            log_id=log["log_id"],
            point_count=len(points),
            payload_hash=digest[:16],
            consent_versions=consent_snapshot,
        )
        return {
            "status": "已合并",
            "duplicate": False,
            "log_id": log["log_id"],
            "packet_id": packet["packet_id"],
            "merged_track_points": len(trip.track),
        }

    def _quarantine_packet(
        self, packet: dict, digest: str, reasons: list[str], now: datetime
    ) -> dict:
        duplicate = packet.get("packet_id") in self.quarantine_packet_ids
        quarantine_id = f"qt_{secrets.token_hex(8)}"
        record = {
            "quarantine_id": quarantine_id,
            "packet_id": packet.get("packet_id"),
            "device_id": packet.get("device_id"),
            "trip_id": packet.get("trip_id"),
            "payload_hash": digest[:16],
            "reasons": reasons,
            "isolated": True,
            "received_at": to_iso(now),
            # 原始内容隔离存储区仅保存哈希与计数，坐标不进入常规日志
            "point_count": len(packet.get("points") or []),
        }
        self.quarantine[quarantine_id] = record
        if packet.get("packet_id"):
            self.quarantine_packet_ids.add(packet["packet_id"])
        self._audit(
            "轨迹隔离",
            f"设备:{packet.get('device_id')}",
            packet.get("packet_id", "未知"),
            quarantine_id=quarantine_id,
            reasons=reasons,
            point_count=record["point_count"],
            payload_hash=digest[:16],
        )
        return {
            "status": "已隔离",
            "duplicate": duplicate,
            "quarantine_id": quarantine_id,
            "packet_id": packet.get("packet_id"),
            "reasons": reasons,
        }

    def trip_journal(self, trip_id: str) -> dict:
        with self._lock:
            trip = self._get_trip(trip_id)
            return {
                "trip_id": trip_id,
                "track_point_count": len(trip.track),
                "logs": [dict(j) for j in trip.journal],
            }

    def list_quarantine(self, operator_token: str | None = None) -> dict:
        """隔离区仅对运营开放元数据（不含坐标等原始内容）。"""
        with self._lock:
            if operator_token is not None:
                self._require_operator(operator_token)
            return {
                "isolated": True,
                "items": [dict(item) for item in self.quarantine.values()],
            }
