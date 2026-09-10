"""Minimal MCP-over-SSE client for mcp-db-gateway.

Why this exists: the MCP *tool call* path truncates/inflates large result sets, and
these pulls are 64-shard UNIONs returning tens of thousands of rows. This client
speaks the same protocol directly, reads long SQL from a file, and writes the full
JSON result straight to disk.

No third-party deps (urllib + a reader thread).
"""
import json
import os
import queue
import threading
import urllib.request
import urllib.parse

# Internal endpoint is not hardcoded: set MCP_DB_GATEWAY_SSE in the environment.
GATEWAY_SSE = os.environ.get("MCP_DB_GATEWAY_SSE", "http://mcp-db-gateway.internal:8080/sse")


class MCPGateway:
    def __init__(self, sse_url=GATEWAY_SSE, timeout=600):
        self.sse_url = sse_url
        self.timeout = timeout
        self.base = sse_url.rsplit("/sse", 1)[0]
        self._events = queue.Queue()
        self._endpoint = None
        self._next_id = 0
        self._stream = None
        self._thread = None

    # -- SSE reader -------------------------------------------------------
    def _reader(self):
        try:
            self._read_loop()
        except Exception:
            pass  # stream closed by close(); nothing left to deliver

    def _read_loop(self):
        event, data = None, []
        for raw in self._stream:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line == "":
                if data:
                    self._events.put((event or "message", "\n".join(data)))
                event, data = None, []
                continue
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())

    def connect(self):
        req = urllib.request.Request(self.sse_url, headers={"Accept": "text/event-stream"})
        self._stream = urllib.request.urlopen(req, timeout=self.timeout)
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        ev, data = self._events.get(timeout=30)
        if ev != "endpoint":
            raise RuntimeError(f"expected endpoint event, got {ev}: {data[:200]}")
        self._endpoint = urllib.parse.urljoin(self.base + "/", data.lstrip("/"))
        self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "sms-attack-pull", "version": "1.0"},
        })
        self._notify("notifications/initialized", {})
        return self

    # -- JSON-RPC ---------------------------------------------------------
    def _post(self, payload):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self._endpoint, data=body, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=self.timeout).read()

    def _notify(self, method, params):
        self._post({"jsonrpc": "2.0", "method": method, "params": params})

    def _request(self, method, params):
        self._next_id += 1
        rid = self._next_id
        self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        while True:
            _, data = self._events.get(timeout=self.timeout)
            msg = json.loads(data)
            if msg.get("id") == rid:
                if "error" in msg:
                    raise RuntimeError(f"{method} failed: {msg['error']}")
                return msg.get("result")

    # -- public -----------------------------------------------------------
    def mysql_query(self, server, sql):
        res = self._request("tools/call", {
            "name": "mysql_query", "arguments": {"server": server, "sql": sql}
        })
        parts = [c.get("text", "") for c in res.get("content", []) if c.get("type") == "text"]
        text = "".join(parts)
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            raise RuntimeError(f"non-JSON reply: {text[:500]}")
        if isinstance(payload, dict) and payload.get("error"):
            raise RuntimeError(payload["error"])
        return payload

    def close(self):
        try:
            if self._stream:
                self._stream.close()
        except Exception:
            pass


def query(server, sql, sse_url=GATEWAY_SSE):
    """One-shot convenience wrapper."""
    gw = MCPGateway(sse_url).connect()
    try:
        return gw.mysql_query(server, sql)
    finally:
        gw.close()
