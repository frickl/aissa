
"""Explicit operator confirmation through the local AISSA result bridge."""
import argparse
import json
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=["account", "ip"])
    parser.add_argument("identity")
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--token-file", default="/etc/aissa/token", type=Path)
    args = parser.parse_args()
    token = args.token_file.read_text().strip()
    body = {
        "event_id": "operator:" + args.event_id,
        args.kind: args.identity,
    }
    request = urllib.request.Request(
        "http://127.0.0.1:8765/confirm",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        print(response.read().decode())


if __name__ == "__main__":
    main()
