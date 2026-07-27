# A2A v1.0.0 Mock(API-Gateway 前置)— DataQuery Agent

一个零依赖(`python3` 标准库)的 A2A v1.0.0 mock 服务,模拟挂在 **API-Gateway** 后面的 A2A agent。
agent 是 **DataQuery**(campus 数据查询),不调用大模型,按查询关键词 mock 返回数据(安全告警 / 人流统计)。

## 三个 agent / 两种认证

| Agent 路径 | 支持方式 | X-HW-ID | X-HW-APPKEY | 备注 |
|---|---|---|---|---|
| `/idkey` | 仅 AppKey | `hw-id-001` | `hw-key-001` | X-HW-ID + X-HW-APPKEY |
| `/jwt` | 仅 JWT | `hw-id-002` | — | X-HW-ID + `Authorization: Bearer <jwt>` |
| `/both` | AppKey 或 JWT | `hw-id-003` | `hw-key-003` | 二者任一即可 |

三个 agent 共享同一个 DataQuery skill,只是认证方式不同。

两个端点(均需认证):
- `GET /{agent}/.well-known/agent-card.json` — agent 卡片(`securitySchemes` / `supportedInterfaces`)
- `POST /{agent}` — JSON-RPC 端点(`message/send` 同步、`message/stream` SSE 流)

认证失败(缺/错凭据)统一返回 API-Gateway 网关格式:
```json
{"status":401,"source":"API-Gateway","time":"2026-07-27 14:19:03","message":"Authorzation failed"}
```

## DataQuery 返回(按查询关键词 mock)

| 查询含关键词 | 返回 mock 数据 |
|---|---|
| alarm / security / 告警 | 安全告警:`total=12`,按 severity(critical 2 / major 4 / minor 6)、type(入侵 5 / 火警 3 / 设备 4) |
| pedestrian / flow / 出入口 | 人流统计:`total_flow=1283`,各出入口(East 456 / West 321 / South 289 / North 217) |
| 其他 | 空结果(`rows=0`) |

每个 artifact 含两个 Part:text 摘要 + JSON data。

## 启动

```bash
python3 server.py                              # 默认 0.0.0.0:8888,card advertised http://127.0.0.1:8888
python3 server.py --port 9000                  # 换端口
python3 server.py --url http://your-host:8888  # 部署到服务器/域名时,card advertised 这个 URL
```

## 验证示例

**1) 认证失败 → 401**
```bash
curl -i http://127.0.0.1:8888/idkey/.well-known/agent-card.json
```

**2) 取 agent card(AppKey)**
```bash
curl http://127.0.0.1:8888/idkey/.well-known/agent-card.json \
  -H 'X-HW-ID: hw-id-001' -H 'X-HW-APPKEY: hw-key-001'
```

**3) 取测试 JWT(免认证开发端点)**
```bash
curl 'http://127.0.0.1:8888/__dev/jwt?agent=jwt'
```

**4) 数据查询 — 流式(message/stream),查安全告警**
```bash
curl -N http://127.0.0.1:8888/both/ \
  -H 'X-HW-ID: hw-id-003' -H 'X-HW-APPKEY: hw-key-003' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"message/stream","params":{"message":{"role":"user","parts":[{"text":"check the total number of security alarms"}]}}}'
```
SSE 收到:`statusUpdate(TASK_STATE_WORKING)` → `artifactUpdate`(告警 mock 数据,`lastChunk`)→ `statusUpdate(TASK_STATE_COMPLETED)`。

**5) 数据查询 — 同步(message/send),查人流**
```bash
curl http://127.0.0.1:8888/both/ \
  -H 'X-HW-ID: hw-id-003' -H 'X-HW-APPKEY: hw-key-003' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"2","method":"message/send","params":{"message":{"role":"user","parts":[{"text":"check pedestrian flow at each entrance"}]}}}'
```

**6) 浏览器预览三张 card(免认证)**
```
http://127.0.0.1:8888/__dev/cards.html
```

## A2A v1.0 合规要点

- `securitySchemes` 是 proto oneof:`{apiKeySecurityScheme:{location,name,description}}` / `{httpAuthSecurityScheme:{scheme,bearerFormat,description}}`(用 `location`,不是 `in`)。
- `securityRequirements`:`[{schemes:{name:{list:[]}}}]`(`list` = OAuth scopes,apiKey/bearer 恒空)。
- `message/stream` 返回 SSE,每条 `data:` = JSON-RPC 包裹 `StreamResponse`(`statusUpdate`/`artifactUpdate`,`lastChunk`,带 `contextId`)。
- `TaskState` 用 ProtoJSON 完整名:`TASK_STATE_WORKING` / `TASK_STATE_COMPLETED`(见 ADR-001)。
- `--url` 控制 card 里 advertised 的 base URL(默认 localhost);部署到服务器/域名时设成外部可达地址,让 `supportedInterfaces[].url` 与实际访问地址对应。

> JWT 用 HS256,密钥见 `server.py` 的 `JWT_SECRET`,可用 `/__dev/jwt` 端点签发测试 token(生产环境删掉该端点并更换密钥)。
