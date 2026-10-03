"""Bounded classifier queue, acknowledged collection and live verdict lookup."""
import argparse
import hashlib
import json
import threading
import time
import uuid
from http.server import HTTPServer
from pathlib import Path

from .analyzer import classify
from .service import Engine, handler, metadata


class Bridge(Engine):
    # Independent of /ack: the controller must not consume a live scan's verdict.
    VERDICT_TTL = 120
    VERDICT_LIMIT = 10000

    def __init__(self, cfg):
        super().__init__(cfg, None)
        self.results = {}
        self.outstanding = 0
        self.max_results = cfg["max_results"]
        self.verdicts = {}

    def submit(self, raw, meta):
        with self.lock:
            if self.outstanding >= self.max_results:
                self.stats["results_full"] += 1
                return 429, "results_full"
            self.outstanding += 1
        try:
            answer = super().submit(raw, meta)
        except Exception:
            with self.lock:
                self.outstanding -= 1
            raise
        if answer[0] != 202:
            with self.lock:
                self.outstanding -= 1
        return answer

    def _prune_verdicts(self, now):
        # Caller holds self.lock; insertion order also bounds memory at capacity.
        self.verdicts = {k: v for k, v in self.verdicts.items()
                         if now - v[0] < self.VERDICT_TTL}

    def verdict(self, event_id):
        key = hashlib.sha256(event_id.encode()).hexdigest()
        with self.lock:
            now = time.monotonic()
            self._prune_verdicts(now)
            cached = self.verdicts.get(key)
            if cached is not None:
                return dict(cached[1])
            # A deduplicated job may already have aged out of the short cache.
            # Treat it as pending; Lua's deadline prevents an indefinite wait.
            if key in self.recent and now - self.recent[key] < 3600:
                return {"status": "pending"}
            return {"status": "missing"}

    def process(self, raw, meta):
        result = {"id": uuid.uuid4().hex, "meta": meta}
        try:
            verdict = classify(raw, self.cfg["model"], self.cfg["llm_timeout"],
                               self.cfg.get("max_text_chars", 1000))
            result.update({
                "status": "ok", "classification": verdict["classification"],
                "confidence": verdict["confidence"],
                "elapsed_seconds": verdict["elapsed_seconds"],
                "model": verdict["model"],
            })
            for key in ("input_text_chars", "text_truncated", "load_duration_seconds",
                        "prompt_eval_duration_seconds", "eval_duration_seconds",
                        "prompt_eval_count", "eval_count"):
                if key in verdict:
                    result[key] = verdict[key]
            self.count("completed")
        except Exception as exc:
            result.update({"status": "error", "classification": "uncertain",
                           "error_type": type(exc).__name__})
            self.count("inference_error")
        result["completed_at"] = int(time.time())
        public = {k: v for k, v in result.items() if k != "meta"}
        key = hashlib.sha256(meta["event_id"].encode()).hexdigest()
        with self.lock:
            self.results[result["id"]] = result
            now = time.monotonic()
            self._prune_verdicts(now)
            if key not in self.verdicts and len(self.verdicts) >= self.VERDICT_LIMIT:
                del self.verdicts[next(iter(self.verdicts))]
            self.verdicts[key] = (now, public)
        log = dict(public)
        log.update(event="result", event_id=meta["event_id"],
                   queue_id=meta["queue_id"], mode="observe")
        print(json.dumps(log), flush=True)

    def worker(self):
        while True:
            raw, meta = self.jobs.get()
            try:
                self.process(raw, meta)
            finally:
                self.jobs.task_done()

    def pending_results(self):
        with self.lock:
            return list(self.results.values())[:8]

    def acknowledge(self, ids):
        if (not isinstance(ids, list) or len(ids) > 8
                or any(not isinstance(i, str) or len(i) != 32 for i in ids)):
            raise ValueError("Invalid acknowledgement")
        removed = 0
        with self.lock:
            for result_id in ids:
                if self.results.pop(result_id, None) is not None:
                    self.outstanding -= 1
                    removed += 1
            self.stats["acknowledged"] += removed
        return removed

    def confirm(self, meta):
        with self.lock:
            if self.outstanding >= self.max_results:
                self.stats["results_full"] += 1
                return 429, "results_full"
            result_id = uuid.uuid4().hex
            self.results[result_id] = {
                "id": result_id, "meta": meta, "completed_at": int(time.time()),
                "status": "confirmed", "classification": "confirmed",
            }
            self.outstanding += 1
            self.stats["operator_confirmations"] += 1
        return 202, "queued"


def bridge_handler(engine, token):
    base = handler(engine, token)

    class Handler(base):
        def do_GET(self):
            if not self.authorized():
                return self.reply(401, {"status": "unauthorized"})
            if self.path == "/results":
                return self.reply(200, {"results": engine.pending_results()})
            if self.path == "/metrics":
                with engine.lock:
                    value = {"counters": dict(engine.stats),
                             "pending": engine.jobs.qsize(),
                             "results_pending": len(engine.results),
                             "outstanding": engine.outstanding, "mode": "observe"}
                return self.reply(200, value)
            return self.reply(404, {"status": "not_found"})

        def do_POST(self):
            if self.path == "/submit":
                return super().do_POST()
            if not self.authorized():
                return self.reply(401, {"status": "unauthorized"})
            if self.path not in ("/ack", "/confirm", "/verdict"):
                return self.reply(404, {"status": "not_found"})
            try:
                if self.headers.get("Transfer-Encoding"):
                    raise ValueError("Chunked transfer unsupported")
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= 4096:
                    return self.reply(413, {"status": "oversized"})
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Incomplete request")
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError("JSON object required")
                if self.path == "/ack":
                    return self.reply(200, {"removed": engine.acknowledge(value["ids"])})
                meta = metadata(value)
                if self.path == "/verdict":
                    return self.reply(200, engine.verdict(meta["event_id"]))
                if not meta["account"] and not meta["ip"]:
                    raise ValueError("Confirmation needs an identity")
                code, status = engine.confirm(meta)
                return self.reply(code, {"status": status})
            except (ValueError, TypeError, KeyError, UnicodeError):
                return self.reply(400, {"status": "bad_request"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    cfg = json.loads(parser.parse_args().config.read_text())
    for key, upper in [("max_pending", 100), ("max_requests_per_minute", 10000),
                       ("max_results", 10000), ("llm_timeout", 300)]:
        if type(cfg.get(key)) is not int or not 1 <= cfg[key] <= upper:
            raise ValueError("Invalid " + key)
    max_text = cfg.get("max_text_chars", 1000)
    if type(max_text) is not int or not 100 <= max_text <= 4000:
        raise ValueError("Invalid max_text_chars (100..4000)")
    token = Path(cfg["token_file"]).read_text().strip()
    if len(token) < 32:
        raise ValueError("Invalid AISSA API token")
    if not isinstance(cfg.get("model"), str) or not cfg["model"]:
        raise ValueError("Missing model")
    engine = Bridge(cfg)
    threading.Thread(target=engine.worker, daemon=True).start()
    HTTPServer(("127.0.0.1", 8765), bridge_handler(engine, token)).serve_forever()


if __name__ == "__main__":
    main()
