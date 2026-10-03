import json
import math
import re
import time
import urllib.request
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

MAX_MAIL = 2 * 1024 * 1024
MAX_TEXT = 1000
CLASSES = ["ham", "bulk", "spam", "phishing", "uncertain"]
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "classification": {"type": "string", "enum": CLASSES},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reason": {"type": "string", "maxLength": 400},
    }, "required": ["classification", "confidence", "reason"],
}
from .prompt import SYSTEM


class VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.links = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        for key, value in attrs:
            if key == "href" and value and len(self.links) < 20:
                self.links.append(value[:300])

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def extract(raw, max_text=None):
    if max_text is None:
        max_text = MAX_TEXT
    if type(max_text) is not int or not 100 <= max_text <= 4000:
        raise ValueError("Invalid max_text_chars (100..4000)")
    if len(raw) > MAX_MAIL:
        raise ValueError("Mail exceeds 2 MiB limit")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain, html, links = [], [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        data = part.get_content()
        if part.get_content_type() == "text/plain":
            plain.append(data)
        else:
            parser = VisibleHTML()
            parser.feed(data)
            html.append(" ".join(parser.text))
            links.extend(parser.links)
    text = "\n".join(plain or html)
    links.extend(re.findall(r"https?://[^\s<>\"']+", text))
    return {
        "subject": str(msg.get("Subject", ""))[:200],
        "displayed_from": str(msg.get("From", ""))[:200],
        "text": text[:max_text],
        "text_truncated": len(text) > max_text,
        "urls": [url[:300] for url in list(dict.fromkeys(links))[:12]],
        "limitations": "Attachments, images and verified authentication not analyzed; displayed From is untrusted.",
    }


def validate(value):
    if not isinstance(value, dict) or set(value) != set(SCHEMA["required"]):
        raise ValueError("Invalid verdict fields")
    if value["classification"] not in CLASSES:
        raise ValueError("Invalid classification")
    confidence = value["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (float, int)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError("Invalid confidence")
    if not isinstance(value["reason"], str) or len(value["reason"]) > 400:
        raise ValueError("Invalid reason")
    return value


def classify(raw, model="qwen2.5:1.5b", timeout=60, max_text_chars=None):
    sample = extract(raw, max_text_chars)
    payload = {
        "model": model, "stream": False, "format": SCHEMA,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": json.dumps(sample, ensure_ascii=False)}],
        "options": {"temperature": 0, "seed": 42, "num_thread": 2,
                    "num_ctx": 4096, "num_predict": 192},
        "keep_alive": "5m",
    }
    request = urllib.request.Request("http://127.0.0.1:11434/api/chat",
        data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    started = time.monotonic()
    # No proxy, redirects or arbitrary endpoints: email content stays local.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        encoded = response.read(65537)
    if len(encoded) > 65536:
        raise ValueError("Oversized backend response")
    result = json.loads(encoded)
    if result.get("done") is not True or result.get("done_reason") == "length":
        raise ValueError("Incomplete backend response")
    verdict = validate(json.loads(result["message"]["content"]))
    timings = {}
    for key in ("load_duration", "prompt_eval_duration", "eval_duration"):
        value = result.get(key)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0:
            timings[key + "_seconds"] = round(value / 1e9, 3)
    for key in ("prompt_eval_count", "eval_count"):
        value = result.get(key)
        if type(value) is int and value >= 0:
            timings[key] = value
    return {**verdict, **timings, "input_text_chars": len(sample["text"]), "model": model, "elapsed_seconds": round(time.monotonic() - started, 3),
            "text_truncated": sample["text_truncated"], "mode": "observe"}
