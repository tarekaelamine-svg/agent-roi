from __future__ import annotations

import argparse
import json
import os
import time
from typing import Optional

from agent_roi.enterprise.outbox import JsonHttpOutboxHandler, OutboxWorker, PostgresOutboxStore
from agent_roi.runtime.resilience import RetryPolicy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the Agent-ROI enterprise outbox worker")
    parser.add_argument("--dsn", default=os.environ.get("AGENT_ROI_POSTGRES_DSN", ""))
    parser.add_argument("--schema", default=os.environ.get("AGENT_ROI_POSTGRES_SCHEMA", "agent_roi"))
    parser.add_argument("--destinations-json", default=os.environ.get("AGENT_ROI_OUTBOX_DESTINATIONS", "{}"))
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--once", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.dsn:
        raise SystemExit("--dsn or AGENT_ROI_POSTGRES_DSN is required")
    try:
        destinations = json.loads(args.destinations_json)
    except json.JSONDecodeError as exc:
        raise SystemExit("--destinations-json must be a JSON object") from exc
    if not isinstance(destinations, dict) or not destinations:
        raise SystemExit("At least one outbox destination is required")
    handlers = {
        str(name): JsonHttpOutboxHandler(str(endpoint))
        for name, endpoint in destinations.items()
    }
    worker = OutboxWorker(
        PostgresOutboxStore(args.dsn, schema=args.schema),
        handlers,
        retry_policy=RetryPolicy(max_attempts=3, initial_backoff_seconds=0.25),
    )
    while True:
        result = worker.run_once(limit=max(1, args.batch_size))
        print(json.dumps(result), flush=True)
        if args.once:
            return 0
        if result["claimed"] == 0:
            time.sleep(max(0.1, args.poll_seconds))


if __name__ == "__main__":
    raise SystemExit(main())
