# A2A v1.0.0 Mock(华为 API-Gateway 前置)

一个零依赖(`python3` 标准库)的 A2A v1.0.0 mock 服务,模拟挂在**华为 API-Gateway**后面的 A2A agent。
agent 不调用大模型,**所有回复固定为「好的」**。

## 三个 agent / 两种认证

| Agent 路径 | 支持方式 | X-HW-ID | X-HW-APPKEY | 备注 |
|---|---|---|---|---|
| `/idkey` | 仅 AppKey | `hw-id-001` | `hw-key-001` | X-HW-ID + X-HW-APPKEY |
| `/jwt` | 仅 JWT | `hw-id-002` | — | X-HW-ID + `Authorization: Bearer <jwt>` |
| `/both` | AppKey 或 JWT | `hw-id-003` | `hw-key-003` | 二者任一即可 |

两个端点(均需认证):
- `GET /{agent}/.well-known/agent-card.json` — agent 卡片(`securitySchemes` / `supportedInterfaces`)
- `POST /{agent}` — JSON-RPC 端点(`message/send` 同步、`message/stream` SSE 流)

认证失败(缺/错凭据)统一返回华为网关格式:
```json
{"status":401,"source":"Huawei API-Gateway","time":"2026-07-27 14:19:03","message":"Authorzation failed"}
```

## 启动

```bash
python3 server.py   # 监听 0.0.0.0:8888
```

## 验证示例

**1) 认证失败 → 401**
```bash
curl -i http://127.0.0.1:8888/idkey/.well-known/agent-card.json
```

**2) 认证成功 → agent card(idkey: AppKey 方式)**
```bash
curl http://127.0.0.1:8888/idkey/.well-known/agent-card.json \
  -H 'X-HW-ID: hw-id-001' -H 'X-HW-APPKEY: hw-key-001'
```

**3) 取一个测试用 JWT(免认证的开发端点)**
```bash
curl 'http://127.0.0.1:8888/__dev/jwt?agent=jwt'
```

**4) JWT 方式调 agent card**
```bash
TOKEN=$(curl -s 'http://127.0.0.1:8888/__dev/jwt?agent=jwt' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl http://127.0.0.1:8888/jwt/.well-known/agent-card.json \
  -H "X-HW-ID: hw-id-002" -H "Authorization: Bearer $TOKEN"
```

**5) SSE 流(`message/stream`)→ 返回「好的」**
```bash
curl -N http://127.0.0.1:8888/both/ \
  -H 'X-HW-ID: hw-id-003' -H 'X-HW-APPKEY: hw-key-003' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"1","method":"message/stream","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}}'
```
流里会依次收到:`status-update(working)` → `artifact-update(text="好的")` → `status-update(completed, final=true)`。

**6) 同步(`message/send`)**
```bash
curl http://127.0.0.1:8888/both/ \
  -H 'X-HW-ID: hw-id-003' -H 'X-HW-APPKEY: hw-key-003' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"2","method":"message/send","params":{"message":{"role":"user","parts":[{"kind":"text","text":"hi"}]}}}'
```

## securitySchemes 设计要点

- `hwId`:`apiKey` / `X-HW-ID` / header —— 两种方式都需要的身份头。
- `hwAppKey`:`apiKey` / `X-HW-APPKEY` / header —— AppKey 凭据(方式 A)。
- `hwBearerJwt`:`http` / `bearer` / `bearerFormat: JWT` —— JWT 凭据(方式 B)。
- `security`(OpenAPI 语义:数组项 OR,项内 key AND):
  - idkey:`[{"hwAppKey":[],"hwId":[]}]`
  - jwt:`[{"hwBearerJwt":[],"hwId":[]}]`
  - both:`[{"hwAppKey":[],"hwId":[]},{"hwBearerJwt":[],"hwId":[]}]`(任一组即可)
- 同时输出 `securityRequirements`(nexent 卡片模型字段名),值与 `security` 一致。

> JWT 用 HS256,密钥见 `server.py` 的 `JWT_SECRET`,可用 `/__dev/jwt` 端点签发测试 token(生产环境删掉该端点)。
