from __future__ import annotations

import argparse
import json
import os
from typing import Optional

from agent_roi.db import PostgresConnectionFactory, PostgresMigrationManager, load_postgres_migrations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Agent-ROI PostgreSQL schemas")
    parser.add_argument("command", choices=("status", "migrate", "list"))
    parser.add_argument("--dsn", default=os.environ.get("AGENT_ROI_POSTGRES_DSN", ""))
    parser.add_argument("--schema", default=os.environ.get("AGENT_ROI_POSTGRES_SCHEMA", "agent_roi"))
    parser.add_argument("--target-version", type=int)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        print(json.dumps([{"version": item.version, "name": item.name} for item in load_postgres_migrations()], indent=2))
        return 0
    if not args.dsn:
        raise SystemExit("--dsn or AGENT_ROI_POSTGRES_DSN is required")
    manager = PostgresMigrationManager(PostgresConnectionFactory(args.dsn, schema=args.schema))
    if args.command == "status":
        print(json.dumps({"current_version": manager.current_version(), "schema": args.schema}))
        return 0
    applied = manager.migrate(target_version=args.target_version)
    print(json.dumps({"applied_versions": list(applied), "current_version": manager.current_version()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
