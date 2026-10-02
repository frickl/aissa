"""Explicit operator confirmation; AI never writes this lane."""
import argparse
import json
from .state import State, Redis


def main():
    parser = argparse.ArgumentParser(description='Record one operator-confirmed abuse event')
    parser.add_argument('kind', choices=['account', 'ip'])
    parser.add_argument('identity')
    parser.add_argument('--event-id', required=True)
    parser.add_argument('--redis-db', type=int, default=6)
    args = parser.parse_args()
    result = State(Redis(db=args.redis_db)).confirm(args.kind, args.identity, args.event_id)
    print(json.dumps({'recorded': bool(result)}))


if __name__ == '__main__':
    main()
