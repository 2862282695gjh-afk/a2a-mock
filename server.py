#!/usr/bin/env python3
"""
A2A v1.0.0 mock server behind an API-Gateway style auth layer — DataQuery Agent.

Three agent endpoints, each advertising different security schemes:
  - idkey : only X-HW-ID + X-HW-APPKEY   (AppID + AppKey)
  - jwt   : only X-HW-ID + Authorization (Bearer JWT)
  - both  : accepts either credential pair

All three expose the same DataQuery skill (campus data: security alarms,
pedestrian flow). Replies are mocked data (no LLM), selected by query keywords.

Endpoints per agent (both auth-gated):
  GET  /{agent}/.well-known/agent-card.json   -> agent card
  POST /{agent}                               -> JSON-RPC (message/send, message/stream)

No-auth dev helpers:
  GET /__dev/jwt?agent=<jwt|both|idkey>       -> mint a test Bearer token
  GET /__dev/cards.html                       -> browser preview of all three cards

Zero third-party dependencies. Run:  python3 server.py
"""
import argparse
import base64
import hashlib
import hmac
import html
import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 8888
BASE_URL = f"http://127.0.0.1:{PORT}"

JWT_SECRET = "hw-mock-jwt-secret"
JWT_TTL = 3600  # seconds

# Known model instances. Requests must carry params.message.metadata.model
# and it must be one of these; otherwise JSON-RPC error -32602 "模型实例找不到。".
KNOWN_MODELS = {
    "MasS-DeepSeek-V4-Flash",
}

# DataQuery agent profile (shared by all three auth variants)
AGENT_DESCRIPTION = (
    "DataQuery Agent is built on campus data services, opens up the subject library "
    "and thematic library, encapsulates data from valuable scenarios such as security "
    "protection and access control, and enables natural language queries."
)
SKILL_DESCRIPTION = (
    "Data Query is built based on campus data services, opens up the subject and thematic "
    "library, encapsulates data from valuable scenarios such as security protection and "
    "access control, and enables natural language queries."
)
SKILL_EXAMPLES = [
    "Check the total number of security alarms.",
    "Check the pedestrian flow statistics at each entrance and exit of the park in the past 5 minutes.",
]

AGENTS = {
    "idkey": {
        "modes": ["appkey"],
        "x_hw_id": "hw-id-001",
        "appkey": "hw-key-001",
        "name": "DataQuery_AppKey_Agent",
    },
    "jwt": {
        "modes": ["jwt"],
        "x_hw_id": "hw-id-002",
        "name": "DataQuery_JWT_Agent",
    },
    "both": {
        "modes": ["appkey", "jwt"],
        "x_hw_id": "hw-id-003",
        "appkey": "hw-key-003",
        "name": "DataQuery_Both_Agent",
    },
}


# --------------------------------------------------------------------------
# JWT helpers (HS256, no external libs)
# --------------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def issue_jwt(sub: str, secret: str = JWT_SECRET, ttl: int = JWT_TTL) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": sub, "iat": now, "exp": now + ttl, "iss": "hw-mock-gateway"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def verify_jwt(token: str, secret: str = JWT_SECRET) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(_b64url_decode(sig_b64), expected):
            return False
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg") not in ("HS256", None):
            return False
        claims = json.loads(_b64url_decode(payload_b64))
        exp = claims.get("exp")
        if isinstance(exp, (int, float)) and exp < time.time():
            return False
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
def authenticate(agent_key: str, headers) -> bool:
    """Way A: X-HW-ID + X-HW-APPKEY.  Way B: X-HW-ID + Authorization: Bearer <jwt>."""
    agent = AGENTS[agent_key]
    x_hw_id = headers.get("X-HW-ID")
    if not x_hw_id:
        return False
    if "appkey" in agent["modes"]:
        appkey = headers.get("X-HW-APPKEY")
        if appkey and x_hw_id == agent["x_hw_id"] and appkey == agent.get("appkey"):
            return True
    if "jwt" in agent["modes"]:
        authz = headers.get("Authorization", "")
        if authz.startswith("Bearer ") and x_hw_id == agent["x_hw_id"]:
            if verify_jwt(authz[len("Bearer "):].strip()):
                return True
    return False


# --------------------------------------------------------------------------
# Security scheme builders (A2A v1.0 proto: discriminated oneof, no "type"/"in")
# --------------------------------------------------------------------------
def _api_key_scheme(name: str, description: str) -> dict:
    return {"apiKeySecurityScheme": {
        "description": description,
        "location": "header",
        "name": name,
    }}


def _http_bearer_scheme(description: str, bearer_format: str = "JWT") -> dict:
    return {"httpAuthSecurityScheme": {
        "description": description,
        "scheme": "bearer",
        "bearerFormat": bearer_format,
    }}


def _security_requirement(*scheme_names: str) -> dict:
    return {"schemes": {n: {"list": []} for n in scheme_names}}


# --------------------------------------------------------------------------
# Agent card (A2A v1.0.0)
# --------------------------------------------------------------------------
def build_agent_card(agent_key: str) -> dict:
    agent = AGENTS[agent_key]
    modes = agent["modes"]
    schemes = {
        "hwId": _api_key_scheme(
            "X-HW-ID", "API-Gateway App ID (identity, required by every mode)."),
    }
    if "appkey" in modes:
        schemes["hwAppKey"] = _api_key_scheme(
            "X-HW-APPKEY", "API-Gateway AppKey credential (paired with X-HW-ID).")
    if "jwt" in modes:
        schemes["hwBearerJwt"] = _http_bearer_scheme(
            "API-Gateway JWT credential (paired with X-HW-ID).")

    requirements = []
    if "appkey" in modes:
        requirements.append(_security_requirement("hwAppKey", "hwId"))
    if "jwt" in modes:
        requirements.append(_security_requirement("hwBearerJwt", "hwId"))

    endpoint = f"{BASE_URL}/{agent_key}"
    return {
        "name": agent["name"],
        "description": AGENT_DESCRIPTION,
        "supportedInterfaces": [
            {"url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "version": "1.0.0",
        "capabilities": {"streaming": True, "pushNotifications": False},
        "securitySchemes": schemes,
        "securityRequirements": requirements,
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "data_query",
                "name": "data query",
                "description": SKILL_DESCRIPTION,
                "tags": ["data", "query", "campus"],
                "examples": SKILL_EXAMPLES,
            }
        ],
    }


# --------------------------------------------------------------------------
# Browser preview of all three agent cards (no auth)
# --------------------------------------------------------------------------
_CARDS_HTML_CSS = """
  :root {--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--orange:#d29922;--green:#3fb950;--purple:#bc8cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;line-height:1.6}
  .wrap{max-width:1080px;margin:0 auto;padding:2rem 1.5rem 4rem}
  h1{font-size:1.5rem;margin:0 0 .25rem;letter-spacing:-.3px}
  .sub{color:var(--dim);font-size:.9rem;margin-bottom:1.2rem}
  .legend{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:.5rem}
  .legend a{color:var(--accent);text-decoration:none;font-size:.82rem;background:var(--card);border:1px solid var(--border);padding:.3rem .75rem;border-radius:6px}
  .legend a:hover{border-color:var(--accent)}
  .card-block{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.1rem 1.4rem;margin:1.1rem 0;scroll-margin-top:1rem}
  .card-block header{display:flex;align-items:center;gap:.8rem;border-bottom:1px solid var(--border);padding-bottom:.7rem;margin-bottom:.8rem;flex-wrap:wrap}
  .card-block h2{margin:0;font-family:'SF Mono',Menlo,Consolas,monospace;color:var(--accent);font-size:1.1rem}
  .badge{font-size:.72rem;padding:2px 9px;border-radius:11px;font-weight:600;color:var(--orange);background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.3)}
  .meta{font-size:.82rem;color:var(--dim);margin-bottom:.9rem}
  .meta div{margin:.15rem 0}
  .meta span{display:inline-block;width:92px;color:var(--dim)}
  .meta code{color:var(--green);font-family:'SF Mono',Menlo,Consolas,monospace}
  pre{background:#0a0e14;border:1px solid var(--border);border-radius:8px;padding:1rem;overflow:auto;margin:0}
  code.json{font-family:'SF Mono',Menlo,Consolas,monospace;font-size:.8rem;color:#c9d1d9;white-space:pre}
  .hint{color:var(--dim);font-size:.84rem;margin-top:1.2rem;border-left:3px solid var(--purple);background:#1a1f2b;padding:.7rem 1rem;border-radius:4px}
  .hint b{color:var(--text)} .hint code{color:var(--green);font-family:'SF Mono',Menlo,Consolas,monospace}
"""


def build_cards_html() -> str:
    agents = ["idkey", "jwt", "both"]
    out = [
        '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>DataQuery Agent · A2A Cards</title>',
        '<style>', _CARDS_HTML_CSS, '</style></head><body><div class="wrap">',
        '<h1>DataQuery Agent · A2A v1.0 Mock</h1>',
        '<div class="sub">API-Gateway 前置 · 三个认证变体 · campus 数据查询(安全告警 / 人流统计)'
        '。本页为免认证开发预览;实际接口需 X-HW 认证。</div>',
    ]
    out.append('<div class="legend">' + ''.join(
        f'<a href="#{k}">/{k}</a>' for k in agents) + '</div>')

    for k in agents:
        card = build_agent_card(k)
        json_str = json.dumps(card, ensure_ascii=False, indent=2)
        ep = card["supportedInterfaces"][0]["url"]
        out.append(
            f'<section class="card-block" id="{k}"><header>'
            f'<h2>/{k}</h2>'
            f'<span class="badge">{" / ".join(AGENTS[k]["modes"]).upper()}</span>'
            f'</header><div class="meta">'
            f'<div><span>Card URL</span><code>GET {ep}/.well-known/agent-card.json</code></div>'
            f'<div><span>JSON-RPC</span><code>POST {ep}</code></div>'
            f'</div>'
            f'<pre><code class="json">{html.escape(json_str)}</code></pre>'
            f'</section>'
        )

    out.append(
        '<div class="hint"><b>说明:</b> 三个变体唯一差异在 <code>securitySchemes</code> / '
        '<code>securityRequirements</code>(idkey 仅 AppKey、jwt 仅 Bearer JWT、both 二者皆可)。'
        '查询关键词含 alarm/security → 返回安全告警 mock;含 pedestrian/flow/出入口 → 返回人流统计 mock;否则返回空结果。'
        '<br>认证失败返回 <code>{"status":401,"source":"API-Gateway",...,"message":"Authorzation failed"}</code>。'
        '测试 JWT:<code>GET /__dev/jwt?agent=jwt</code>。</div>'
    )
    out.append('</div></body></html>')
    return "".join(out)


# --------------------------------------------------------------------------
# Mock query result (no LLM) — keyword-routed campus data
# --------------------------------------------------------------------------
def _mock_query_result(query: str):
    """Return (summary_text, data_dict) based on the user's query keywords."""
    q = (query or "").lower()
    if any(k in q for k in ("alarm", "security", "告警", "安全")):
        return (
            "查询到当前共 12 条安全告警:严重 2、重要 4、次要 6。按类型:入侵 5、火警 3、设备故障 4。",
            {
                "metric": "security_alarms",
                "total": 12,
                "time_window": "current",
                "by_severity": {"critical": 2, "major": 4, "minor": 6},
                "by_type": {"intrusion": 5, "fire": 3, "equipment_failure": 4},
            },
        )
    if any(k in q for k in ("pedestrian", "flow", "人流", "通行", "entrance", "exit", "出入")):
        return (
            "过去 5 分钟各出入口通行人流:东门 456、西门 321、南门 289、北门 217,合计 1283 人次。",
            {
                "metric": "pedestrian_flow",
                "period": "past 5 minutes",
                "total_flow": 1283,
                "by_entrance": [
                    {"gate": "East Gate", "count": 456},
                    {"gate": "West Gate", "count": 321},
                    {"gate": "South Gate", "count": 289},
                    {"gate": "North Gate", "count": 217},
                ],
            },
        )
    return (
        "已执行数据查询,未匹配到结果(0 行)。可尝试:查询安全告警总数 / 各出入口人流统计。",
        {"metric": "data_query", "query": query or "", "rows": 0, "result": "no matching data"},
    )


def _query_artifact(summary_text: str, data: dict) -> dict:
    """A2A v1.0 Artifact: a text summary part + a structured JSON data part."""
    return {
        "artifactId": "query-result-1",
        "name": "query result",
        "parts": [
            {"text": summary_text, "mediaType": "text/plain"},
            {"data": data, "mediaType": "application/json"},
        ],
    }


# --------------------------------------------------------------------------
# A2A payload builders
# --------------------------------------------------------------------------
def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _rpc_ok(rpc_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def build_stream_events(rpc_id, task_id: str, context_id: str, query: str):
    """A2A v1.0 StreamResponse events for message/stream."""
    summary_text, data = _mock_query_result(query)
    yield _rpc_ok(rpc_id, {"statusUpdate": {
        "taskId": task_id,
        "contextId": context_id,
        "status": {"state": "TASK_STATE_WORKING", "timestamp": _ts()},
    }})
    yield _rpc_ok(rpc_id, {"artifactUpdate": {
        "taskId": task_id,
        "contextId": context_id,
        "artifact": _query_artifact(summary_text, data),
        "lastChunk": True,
    }})
    yield _rpc_ok(rpc_id, {"statusUpdate": {
        "taskId": task_id,
        "contextId": context_id,
        "status": {
            "state": "TASK_STATE_COMPLETED",
            "timestamp": _ts(),
            "message": {
                "messageId": f"msg-{task_id}",
                "role": "ROLE_AGENT",
                "parts": [{"text": summary_text, "mediaType": "text/plain"}],
            },
        },
    }})


def build_send_result(rpc_id, task_id: str, context_id: str, query: str) -> dict:
    """A2A v1.0 SendMessageResponse (task payload) for message/send."""
    summary_text, data = _mock_query_result(query)
    return _rpc_ok(rpc_id, {"task": {
        "id": task_id,
        "contextId": context_id,
        "status": {
            "state": "TASK_STATE_COMPLETED",
            "timestamp": _ts(),
            "message": {
                "messageId": f"msg-{task_id}",
                "role": "ROLE_AGENT",
                "parts": [{"text": summary_text, "mediaType": "text/plain"}],
            },
        },
        "artifacts": [_query_artifact(summary_text, data)],
    }})


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
GATEWAY_401_BODY = {
    "status": 401,
    "source": "API-Gateway",
    "message": "Authorzation failed",  # spelling kept as specified
}


class A2AMockHandler(BaseHTTPRequestHandler):
    server_version = "A2A-Mock/1.0"
    protocol_version = "HTTP/1.1"

    def _send_html(self, body: str, status: int = 200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _write_json(self, status: int, obj: dict, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _gateway_401(self):
        body = dict(GATEWAY_401_BODY)
        body["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write_json(401, body)

    def _parse_agent(self, path: str):
        parsed = urlparse(path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 3 and parts[1] == ".well-known" and parts[2] == "agent-card.json":
            return parts[0], "card"
        if len(parts) == 1:
            return parts[0], "rpc"
        if len(parts) == 2 and parts[0] == "__dev" and parts[1] == "jwt":
            return urlparse(path).query, "dev-jwt"
        if len(parts) == 2 and parts[0] == "__dev" and parts[1] == "cards.html":
            return "", "dev-cards"
        return None, None

    @staticmethod
    def _extract_query(rpc: dict) -> str:
        params = rpc.get("params") or {}
        message = params.get("message") or {}
        for p in (message.get("parts") or []):
            if isinstance(p, dict) and p.get("text"):
                return p["text"]
        return ""

    def do_GET(self):
        agent_key, route = self._parse_agent(self.path)
        if route == "dev-jwt":
            return self._handle_dev_jwt(self.path)
        if route == "dev-cards":
            return self._send_html(build_cards_html())
        if route != "card" or agent_key not in AGENTS:
            return self._write_json(404, {"error": "not found"})
        if not authenticate(agent_key, self.headers):
            return self._gateway_401()
        return self._write_json(200, build_agent_card(agent_key))

    def do_POST(self):
        agent_key, route = self._parse_agent(self.path)
        if route != "rpc" or agent_key not in AGENTS:
            return self._write_json(404, {"error": "not found"})
        if not authenticate(agent_key, self.headers):
            return self._gateway_401()

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            rpc = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._write_json(200, _rpc_error(None, -32700, "Parse error"))

        rpc_id = rpc.get("id")
        method = rpc.get("method")
        query = self._extract_query(rpc)

        # Model instance check: params.message.metadata.model is required by
        # every method. Missing/unknown model -> JSON-RPC error -32602.
        params = rpc.get("params") or {}
        model = ((params.get("message") or {}).get("metadata") or {}).get("model")
        if not model or model not in KNOWN_MODELS:
            return self._write_json(200, _rpc_error(rpc_id, -32602, "模型实例找不到。"))

        task_id = str(uuid.uuid4())
        context_id = str(uuid.uuid4())

        # A2A v1.0 JSON-RPC methods (PascalCase proto RPC names).
        if method == "SendStreamingMessage":
            return self._send_stream(rpc_id, task_id, context_id, query)
        if method == "SendMessage":
            return self._write_json(200, build_send_result(rpc_id, task_id, context_id, query))
        # Backwards/alt compatibility: REST-style paths and v0.x names.
        if method in ("message/stream", "tasks/sendSubscribe"):
            return self._send_stream(rpc_id, task_id, context_id, query)
        if method in ("message/send", "tasks/send"):
            return self._write_json(200, build_send_result(rpc_id, task_id, context_id, query))

        return self._write_json(200, _rpc_error(rpc_id, -32601, f"Method not found: {method}"))

    def _send_stream(self, rpc_id, task_id: str, context_id: str, query: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for event in build_stream_events(rpc_id, task_id, context_id, query):
                chunk = f"data: {json.dumps(event, ensure_ascii=False)}\n\n".encode("utf-8")
                self.wfile.write(chunk)
                self.wfile.flush()
                time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _handle_dev_jwt(self, path: str):
        qs = urlparse(path).query
        agent_key = qs.split("=")[-1] if "agent=" in qs else "jwt"
        if agent_key not in AGENTS:
            return self._write_json(400, {"error": "unknown agent", "agent": agent_key})
        token = issue_jwt(sub=AGENTS[agent_key]["x_hw_id"])
        return self._write_json(200, {"token": token, "usage": f"Authorization: Bearer {token}"})

    def log_message(self, fmt, *args):
        try:
            print(f"[{time.strftime('%H:%M:%S')}] {self.address_string()} {fmt % args}")
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="A2A v1.0 DataQuery mock behind API-Gateway auth.")
    parser.add_argument("--host", default=HOST, help="bind address (default 0.0.0.0)")
    parser.add_argument("--port", type=int, default=PORT, help="listen port (default 8888)")
    parser.add_argument(
        "--url", default=None,
        help="externally reachable base URL advertised in agent cards "
             "(default http://127.0.0.1:<port>). Set this when deploying behind a "
             "domain/proxy so cards advertise a reachable URL.")
    args = parser.parse_args()

    global BASE_URL
    if args.url:
        BASE_URL = args.url.rstrip("/")
    else:
        display = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
        BASE_URL = f"http://{display}:{args.port}"

    server = ThreadingHTTPServer((args.host, args.port), A2AMockHandler)
    print(f"A2A v1.0 DataQuery mock (API-Gateway auth) on http://{args.host}:{args.port}")
    print(f"Card advertised base URL: {BASE_URL}")
    print("Agents / demo credentials:")
    for key, a in AGENTS.items():
        ways = " | ".join(a["modes"])
        print(f"  - /{key}  ({ways})  X-HW-ID={a['x_hw_id']}", end="")
        if "appkey" in a["modes"]:
            print(f"  X-HW-APPKEY={a['appkey']}", end="")
        print()
    print(f"Browser preview:  {BASE_URL}/__dev/cards.html")
    print(f"Demo JWT:         curl '{BASE_URL}/__dev/jwt?agent=jwt'")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
