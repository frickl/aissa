import argparse
import json
import sys
from pathlib import Path
from .analyzer import MAX_MAIL, classify


def main():
    parser = argparse.ArgumentParser(description="AISSA offline sample analyzer; no SMTP enforcement")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--model", default="qwen2.5:1.5b")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--threads", type=int, default=2,
                        help="CPU threads for this offline call (1..64; default 2)")
    parser.add_argument("--no-thinking", action="store_true",
                        help="Request think=false; use with a model that supports it")
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error("timeout must be > 0 and <= 300 seconds")
    if not 1 <= args.threads <= 64:
        parser.error("threads must be 1..64")
    failed = False
    for index, path in enumerate(args.files):
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_MAIL + 1)
            result = {"sample_index": index, **classify(raw, args.model, args.timeout,
                       num_threads=args.threads, think=False if args.no_thinking else None)}
        except Exception as exc:
            failed = True
            # Never label a backend failure as ham. Avoid leaking mail/path content.
            result = {"sample_index": index, "classification": "uncertain",
                      "status": "error", "error_type": type(exc).__name__, "mode": "observe"}
        print(json.dumps(result, ensure_ascii=False))
    return 1 if failed else 0
