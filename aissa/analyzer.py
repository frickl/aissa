import json
import math
import re
import time
import urllib.request
import unicodedata
from urllib.parse import urlsplit
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
        if tag in ("p", "div", "br", "li", "tr", "td", "h1", "h2", "h3"):
            self.text.append(" ")
        # A stylesheet's href is not a clickable message link. Keep complete
        # anchor targets until the shared budget is applied below.
        if tag == "a" and not self.hidden:
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)

    def handle_endtag(self, tag):
        if tag in ("p", "div", "li", "tr", "td", "h1", "h2", "h3"):
            self.text.append(" ")
        if tag in ("script", "style") and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def clean_text(text):
    """Collapse layout padding, preserving join controls within written words.

    ZWNJ/ZWJ can be meaningful in Persian and other scripts. Do not strip all
    Unicode format characters or alter URL targets with this text cleaner.
    """
    out = []
    for index, char in enumerate(text):
        if char == "\u200b":  # zero-width separator: keep a word boundary
            out.append(" ")
        elif char in ("\u200c", "\u200d", "\ufeff", "\u2060"):
            before = text[index - 1] if index else " "
            after = text[index + 1] if index + 1 < len(text) else " "
            in_word = (unicodedata.category(before)[0] in "LMNS"
                       and unicodedata.category(after)[0] in "LMNS")
            if in_word:
                out.append(char)
            else:
                out.append(" ")
        else:
            out.append(char)
    return " ".join("".join(out).split())


def bounded_urls(links, budget):
    """Retain original URL prefixes, never rewrite query parameters.

    Each retained URL includes its full authority (including userinfo/port),
    or is omitted. A shortened prefix is explicitly reported as incomplete.
    Allocate across distinct targets rather than allowing the first long
    tracking URL to exhaust all available evidence.
    """
    unique = list(dict.fromkeys(url.strip() for url in links if url.strip()))
    # Give distinct authorities a chance before repeated tracking links from
    # one host. Do not erase different paths or queries by semantic dedup.
    first, repeated, seen = [], [], set()
    for url in unique:
        try:
            parts = urlsplit(url)
            origin = (parts.scheme, parts.netloc)
        except ValueError:
            origin = ("malformed", url)
        if origin in seen:
            repeated.append(url)
        else:
            first.append(url)
            seen.add(origin)
    candidates, minimum_total = [], 0
    for url in first + repeated:
        if len(candidates) == 12:
            break
        try:
            parts = urlsplit(url)
            authority_end = 0
            if parts.netloc:
                start = url.find("//") + 2
                ends = [url.find(char, start) for char in "/?#"]
                authority_end = min([end for end in ends if end >= 0] or [len(url)])
        except ValueError:
            # Preserve a malformed target if it fits; do not invent a host.
            authority_end = len(url)
        minimum = min(len(url), max(48, authority_end))
        if minimum > 300 or minimum_total + minimum > budget:
            continue
        candidates.append((url, minimum))
        minimum_total += minimum
    lengths = [minimum for _, minimum in candidates]
    remaining = budget - sum(lengths)
    # Fairly distribute remaining characters, up to the prior 300-char limit.
    while remaining:
        changed = False
        for index, (url, _) in enumerate(candidates):
            if lengths[index] < min(len(url), 300) and remaining:
                lengths[index] += 1
                remaining -= 1
                changed = True
        if not changed:
            break
    selected = [url[:length] for (url, _), length in zip(candidates, lengths)]
    omitted = len(unique) - len(selected)
    shortened = any(length < len(url) for (url, _), length in zip(candidates, lengths))
    return selected, bool(omitted or shortened), omitted


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
    original_text = "\n".join(plain or html)
    # Extract URLs before text cleanup so Unicode inside targets is not changed.
    links.extend(re.findall(r"https?://[^\s<>\"']+", original_text))
    text = clean_text(original_text)
    # max_text_chars is now a shared body+URL character budget. Reserve up to
    # two thirds for body, while letting short bodies leave more room for URLs.
    url_budget = max_text - min(len(text), (max_text * 2) // 3)
    urls, urls_truncated, omitted = bounded_urls(links, url_budget)
    body_budget = max_text - sum(map(len, urls))
    return {
        "subject": str(msg.get("Subject", ""))[:200],
        "displayed_from": str(msg.get("From", ""))[:200],
        "text": text[:body_budget],
        "text_truncated": len(text) > body_budget,
        "text_cleaned": text != original_text,
        "urls": urls,
        "urls_truncated": urls_truncated,
        "urls_omitted": omitted,
        "limitations": "Attachments, images and verified authentication not analyzed; displayed From is untrusted. URLs may be incomplete when urls_truncated is true.",
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


def classify(raw, model="qwen2.5:1.5b", timeout=60, max_text_chars=None, keep_alive_seconds=1800):
    if type(keep_alive_seconds) is not int or not 0 <= keep_alive_seconds <= 86400:
        raise ValueError("Invalid keep_alive_seconds (0..86400)")
    sample = extract(raw, max_text_chars)
    input_json = json.dumps(sample, ensure_ascii=False)
    payload = {
        "model": model, "stream": False, "format": SCHEMA,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": input_json}],
        "options": {"temperature": 0, "seed": 42, "num_thread": 2,
                    "num_ctx": 4096, "num_predict": 192},
        "keep_alive": keep_alive_seconds,
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
    for key in ("prompt_eval_count", "prompt_eval_cached_count", "eval_count"):
        value = result.get(key)
        if type(value) is int and value >= 0:
            timings[key] = value
    return {**verdict, **timings, "input_text_chars": len(sample["text"]),
            "input_url_chars": sum(map(len, sample["urls"])),
            "input_json_chars": len(input_json),
            "urls_truncated": sample["urls_truncated"],
            "urls_omitted": sample["urls_omitted"], "model": model, "elapsed_seconds": round(time.monotonic() - started, 3),
            "text_truncated": sample["text_truncated"], "mode": "observe"}
