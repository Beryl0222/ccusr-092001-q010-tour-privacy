# 智能伴游隐私与安全

位于伴游设备与景区业务服务之间的控制平台。`domain.json` 记录设备能力、风险等级和授权动作，`control_platform.py` 实现核心控制逻辑，`service.py` 提供 HTTP JSON 接口。

运行 `python3 service.py --check` 检查协议配置，`python3 -m unittest -v` 验证全部行为，`python3 service.py --port 8000` 启动服务。

## 能力概览

- **独立授权与最小权限**：游客对定位、语音交互、影像记录、日志生成四项分别授权（授予/限制/撤回/到期），设备按行程申请所需范围，平台只签发实际获批的最小权限票据，票据有效期不晚于授权到期时间。
- **家庭同行成员**：任一同行成员未授权或明确不同意，该能力对整段行程不开放；“不同意”按能力持续生效，直至重新明确授予，且不追溯否决采集时点已获授权的历史轨迹。
- **缓存失效与删除回执**：授权撤回/到期或密钥轮换后，已发放票据立即失效；设备联网同步领取失效指令，清除本地缓存后获得幂等的“删除确认”回执。
- **设备密钥轮换**：HMAC-SHA256 签名 + 密钥编号；新密钥立即生效、旧票据全部作废；旧密钥仅在宽限期内可验签轮换前形成的离线包。
- **风险优先导航**：施工/拥堵/极端环境/走失按“信息提示 < 路线调整 < 停止前进 < 紧急求助”取最高优先级改变策略；达到“路线调整”级别的新风险使旧路线建议自动失效。每次建议固化当时的风险信息、风险版本与逐成员授权版本，可随时复查。
- **离线轨迹校验合并**：联网后校验签名、围栏、时间戳、速度与采集时段授权；异常包隔离不合并、不进日志；同一离线包按包编号和内容指纹双重去重，重复上传只生成一份游览日志。
- **受限审计**：运营审计员凭凭据只读访问脱敏后的审计元数据，坐标、音视频、密钥等内容不进入审计日志；无凭据一律拒绝。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` `/domain` | 服务身份、协议口径 |
| POST | `/trips` | 创建行程（含同行成员名单） |
| GET | `/trips/{id}/consent` | 行程授权全景（逐成员版本、家庭共同口径、阻断原因） |
| POST | `/trips/{id}/members/{m}/consent` | 授予/限制/撤回（body：`action`、`scopes`、`ttl_seconds`、`family_disagreement`） |
| POST | `/devices` | 注册设备，返回一次性密钥 |
| POST | `/devices/{id}/rotate-key` | 密钥轮换（可带 `grace_seconds`） |
| POST | `/devices/{id}/sync` | 设备同步：票据失效指令、旧路线失效、当前密钥编号 |
| POST | `/devices/{id}/tickets` | 按行程申请最小权限票据 |
| POST | `/devices/{id}/tickets/{tid}/confirm-deletion` | 缓存删除确认回执（幂等） |
| POST | `/risks` `/risks/{id}/resolve` | 发布/解除风险事件 |
| POST | `/devices/{id}/trips/{tid}/recommend` | 获取导航建议（含风险快照与授权版本） |
| GET | `/recommendations/{id}` | 复查某次建议使用的风险信息与授权版本 |
| POST | `/devices/{id}/offline-packets` | 上传离线轨迹包（已合并/重复/已隔离） |
| GET | `/trips/{id}/journal` | 游览日志（每包仅一份） |
| GET | `/quarantine` | 异常轨迹隔离区元数据（审计员） |
| POST | `/operators` | 登记运营审计员并颁发凭据 |
| GET | `/audit` | 只读、脱敏审计流（Bearer 凭据） |

离线包字段：`packet_id`、`device_id`、`trip_id`、`formed_at`、`points[{ts,lat,lon}]`、`kid`、`sig`，签名内容为不含 `kid/sig` 的规范化 JSON。
