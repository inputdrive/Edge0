"""HTTP app layer (Flask optional; stdlib fallback).

Preference order: if ``flask`` is importable it is used (the full
OpenAI-compatible surface with SSE streaming); otherwise a minimal
stdlib ``http.server`` handler serves the same JSON contract and SSE
streaming.  Both share ``build_app_handlers`` so the route
semantics stay identical.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from edge0.server.chat import (QueueServer, RequestLimitError, parse_chat_request,
                               sse_format, decode_tokens)

try:  # pragma: no cover - environment dependent
    from flask import Flask, Response, jsonify, request  # type: ignore

    _HAS_FLASK = True
except ImportError:  # pragma: no cover
    _HAS_FLASK = False

# Local hardening: reject oversized POST bodies (see docs/HARDENING.md)
MAX_BODY_BYTES = 1_048_576  # 1 MiB


def _error(status: int, msg: str) -> tuple:
    """Transport-agnostic error: ``(body, status, headers)`` for Flask and stdlib."""
    body = json.dumps({"error": {"message": msg, "type": "invalid_request"}})
    return body, status, {"Content-Type": "application/json"}


def _split_think(text: str, think: bool):
    """With thinking enabled the model
    streams the reasoning block first and closes it with ``</think>``
    (token 156904); everything before is ``reasoning_content``, after
    is ``content``.  A generation cut off inside the reasoning block
    surfaces what it has so the UI isn't a blank wait."""
    if think:
        if "</think>" in text:
            r, c = text.split("</think>", 1)
            return r.strip(), c.strip()
        return text.strip(), ""
    return "", text


def _chat_once(server: QueueServer, payload: dict):
    req = parse_chat_request(payload)
    tokens, meta = server.chat(req)
    text = decode_tokens(server.engine, tokens)
    think = bool(req.enable_thinking if req.enable_thinking is not None
                 else getattr(server.engine, "think", False))
    reasoning, content = _split_think(text, think)
    return {
        "id": f"chatcmpl-{int(time.time() * 1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": server.model_name,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
                "reasoning_content": reasoning,
            },
            "finish_reason": "stop",
        }],
        "usage": meta["usage"],
    }


def _chat_stream(server: QueueServer, payload: dict):
    req = parse_chat_request(payload)
    events = queue.Queue()
    finished = object()
    request_id = f"chatcmpl-{int(time.time() * 1000)}"
    created = int(time.time())

    def on_token(tid: int):
        text = decode_tokens(server.engine, [tid])
        events.put(sse_format({
            "id": request_id, "object": "chat.completion.chunk",
            "created": created, "model": server.model_name,
            "choices": [{"index": 0,
                         "delta": {"content": text},
                         "finish_reason": None}],
        }).encode("utf-8"))

    def produce():
        try:
            _, meta = server.chat(req, on_token=on_token)
            events.put(sse_format({
                "id": request_id, "object": "chat.completion.chunk",
                "created": created, "model": server.model_name,
                "choices": [{"index": 0, "delta": {},
                             "finish_reason": "stop"}],
                "usage": meta["usage"],
            }).encode("utf-8"))
            events.put(b"data: [DONE]\n\n")
        except Exception as exc:  # pragma: no cover - transport-dependent
            events.put(sse_format({
                "error": {"message": str(exc), "type": "server_error"},
            }).encode("utf-8"))
        finally:
            events.put(finished)

    threading.Thread(target=produce, daemon=True).start()
    while True:
        event = events.get()
        if event is finished:
            return
        yield event


def build_app_handlers(server: QueueServer):
    """Return a handler dispatch dict shared by both transports."""

    def handle_chat(payload: dict):
        # Parse before wrapping a stream so limit errors are 400s, not a
        # 200 SSE response whose generator then raises.
        parse_chat_request(payload)
        if payload.get("stream"):
            if _HAS_FLASK:
                return Response(
                    _chat_stream(server, payload),
                    mimetype="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                    },
                )
            return _chat_stream(server, payload)
        return _chat_once(server, payload)

    handlers = {
        "GET /healthz": lambda: {"status": "ok", "model": server.model_name},
        "GET /v1/models": lambda: {
            "object": "list",
            "data": [{
                "id": server.model_name,
                "object": "model",
                "owned_by": "edge0",
            }],
        },
        "POST /v1/chat/completions": handle_chat,
        "POST /v1/completions": lambda p: _error(
            400, "text completions not supported; use /v1/chat/completions"),
    }
    return handlers


def create_app(server: QueueServer):
    """Flask app (raises ImportError when flask is missing)."""
    if not _HAS_FLASK:
        raise ImportError("flask is required for create_app(); "
                          "use run_stdlib instead")
    app = Flask("edge0")
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    handlers = build_app_handlers(server)

    @app.errorhandler(413)
    def too_large(_e):
        return _error(413, f"request body exceeds {MAX_BODY_BYTES} bytes")

    @app.get("/healthz")
    def healthz():
        return handlers["GET /healthz"]()

    @app.get("/v1/models")
    def models():
        return handlers["GET /v1/models"]()

    def _read_json_body():
        cl = request.content_length
        if cl is not None and cl > MAX_BODY_BYTES:
            return None, _error(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
        raw = request.get_data(cache=True, as_text=False)
        if len(raw) > MAX_BODY_BYTES:
            return None, _error(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, _error(400, "invalid JSON body")
        if not isinstance(payload, dict):
            return None, _error(400, "JSON body must be an object")
        return payload, None

    @app.post("/v1/chat/completions")
    def chat():
        payload, err = _read_json_body()
        if err is not None:
            return err
        try:
            out = handlers["POST /v1/chat/completions"](payload)
        except RequestLimitError as exc:
            return _error(400, str(exc))
        if isinstance(out, Response):
            return out
        if isinstance(out, tuple):
            return out
        return jsonify(out)

    @app.post("/v1/completions")
    def completions():
        _payload, err = _read_json_body()
        if err is not None:
            return err
        out = handlers["POST /v1/completions"]({})
        if isinstance(out, tuple):
            return out
        return jsonify(out)

    return app


class _StdlibHandler(BaseHTTPRequestHandler):
    server_q = None  # type: QueueServer
    protocol_version = "HTTP/1.1"

    def _json(self, status: int, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            for body in events:
                if not body:
                    continue
                size = f"{len(body):X}".encode("ascii")
                self.wfile.write(size + b"\r\n" + body + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        handlers = build_app_handlers(self.server_q)
        if path == "/healthz":
            self._json(200, handlers["GET /healthz"]())
        elif path == "/v1/models":
            self._json(200, handlers["GET /v1/models"]())
        else:
            self._json(404, {"error": {"message": f"no route {path}"}})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        handlers = build_app_handlers(self.server_q)
        if path not in ("/v1/chat/completions", "/v1/completions"):
            self._json(404, {"error": {"message": f"no route {path}"}})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            self._json(400, {"error": {"message": "invalid Content-Length"}})
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._json(413, {"error": {
                "message": f"request body exceeds {MAX_BODY_BYTES} bytes"}})
            return
        raw = self.rfile.read(length) if length else b"{}"
        if len(raw) > MAX_BODY_BYTES:
            self._json(413, {"error": {
                "message": f"request body exceeds {MAX_BODY_BYTES} bytes"}})
            return
        try:
            payload = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._json(400, {"error": {"message": "invalid JSON body"}})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": {"message": "JSON body must be an object"}})
            return
        try:
            if path == "/v1/chat/completions" and payload.get("stream"):
                parse_chat_request(payload)
                self._sse(_chat_stream(self.server_q, payload))
                return
            out = handlers[("POST " + path)](payload)
        except RequestLimitError as exc:
            self._json(400, {"error": {"message": str(exc)}})
            return
        if isinstance(out, tuple):
            body, status, headers = out
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(200, out)

    def log_message(self, fmt, *args):  # quiet by default
        pass


def run_stdlib(server: QueueServer, host: str, port: int):
    handler = type("Edge0Handler", (_StdlibHandler,),
                   {"server_q": server})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.serve_forever()


def run_server(server: QueueServer, host: str = "127.0.0.1",
               port: int = 8000, use_flask: bool | None = None):
    """Run the HTTP server in the foreground (blocking)."""
    if use_flask is None:
        use_flask = _HAS_FLASK
    if use_flask:
        app = create_app(server)
        app.run(host=host, port=port, threaded=True)
    else:
        run_stdlib(server, host, port)
