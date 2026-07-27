from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from agent_roi.audit.postgres import PostgresAuditStore
from agent_roi.cli.database import main as database_main
from agent_roi.db import (
    Migration,
    MigrationError,
    PostgresConnectionFactory,
    PostgresMigrationManager,
    load_postgres_migrations,
    split_sql_statements,
)


class MigrationDB:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple]] = []
        self.applied: list[tuple[int, str]] = []
        self.commits = 0
        self.rollbacks = 0

    def connect(self, dsn: str, **kwargs):
        assert dsn == "postgresql://test"
        return MigrationConnection(self)


class MigrationConnection:
    def __init__(self, db: MigrationDB) -> None:
        self.db = db

    def cursor(self):
        return MigrationCursor(self.db)

    def commit(self):
        self.db.commits += 1

    def rollback(self):
        self.db.rollbacks += 1

    def close(self):
        return None


class MigrationCursor:
    description = None

    def __init__(self, db: MigrationDB) -> None:
        self.db = db
        self.results: list[tuple] = []

    def execute(self, sql, params=None):
        normalized = " ".join(str(sql).split())
        params = tuple(params or ())
        self.db.statements.append((normalized, params))
        lowered = normalized.lower()
        if lowered.startswith("select version, name"):
            self.results = list(self.db.applied)
        elif lowered.startswith("select coalesce(max(version)"):
            maximum = max((item[0] for item in self.db.applied), default=0)
            self.results = [(maximum,)]
        elif lowered.startswith("insert into agent_roi_schema_migrations"):
            self.db.applied.append((int(params[0]), str(params[1])))
            self.results = []
        else:
            self.results = []

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        return list(self.results)

    def close(self):
        return None


class AuditInitDB:
    def __init__(self) -> None:
        self.executed: list[str] = []

    def connect(self):
        db = self

        class Connection:
            def cursor(self):
                class Cursor:
                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        return False

                    def execute(self, sql, params=None):
                        db.executed.append(" ".join(str(sql).split()))

                return Cursor()

            def commit(self):
                return None

            def rollback(self):
                return None

            def close(self):
                return None

        return Connection()


def test_split_sql_statements_handles_quotes_comments_and_dollar_blocks() -> None:
    sql = """
    -- semicolon in comment ;
    CREATE TABLE sample(value TEXT);
    INSERT INTO sample VALUES ('a;b');
    /* another ; comment */
    DO $$ BEGIN RAISE NOTICE 'x;y'; END $$;
    CREATE VIEW quoted AS SELECT "semi;colon" FROM sample;
    """
    statements = split_sql_statements(sql)
    assert len(statements) == 4
    assert "'a;b'" in statements[1]
    assert "DO $$" in statements[2]
    assert '"semi;colon"' in statements[3]


def test_split_sql_statements_rejects_unterminated_sql() -> None:
    with pytest.raises(MigrationError, match="unterminated"):
        split_sql_statements("SELECT 'broken;")


def test_packaged_migrations_are_ordered_and_create_all_20_stores() -> None:
    migrations = load_postgres_migrations()
    assert [item.version for item in migrations] == [1, 2, 3, 4, 5]
    combined = "\n".join(item.sql for item in migrations)
    for table in (
        "policy_bundles",
        "agents",
        "scim_users",
        "approval_records",
        "roi_opportunities",
        "enterprise_outbox",
        "idempotency_records",
        "agent_roi_audit_events",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in combined
    assert "attributes_json JSONB" in combined
    assert "decided_at_epoch_ms BIGINT" in combined
    assert "UNIQUE (organization_id, user_name)" in combined
    assert "UNIQUE (organization_id, display_name)" in combined


def test_migration_manager_executes_each_statement_separately() -> None:
    db = MigrationDB()
    factory = PostgresConnectionFactory(
        "postgresql://test", connect_factory=db.connect
    )
    manager = PostgresMigrationManager(
        factory,
        migrations=(
            Migration(1, "first", "CREATE TABLE one(id INT); CREATE INDEX one_idx ON one(id);"),
            Migration(2, "second", "CREATE TABLE two(id INT);"),
        ),
    )
    assert manager.migrate() == (1, 2)
    migration_sql = [sql for sql, _ in db.statements if sql.startswith("CREATE TABLE one") or sql.startswith("CREATE INDEX one_idx") or sql.startswith("CREATE TABLE two")]
    assert migration_sql == [
        "CREATE TABLE one(id INT)",
        "CREATE INDEX one_idx ON one(id)",
        "CREATE TABLE two(id INT)",
    ]
    assert manager.current_version() == 2
    assert manager.migrate() == ()
    assert db.rollbacks == 0


def test_migration_manager_detects_version_name_conflict() -> None:
    db = MigrationDB()
    db.applied.append((1, "old_name"))
    factory = PostgresConnectionFactory("postgresql://test", connect_factory=db.connect)
    manager = PostgresMigrationManager(factory, migrations=(Migration(1, "new_name", "SELECT 1"),))
    with pytest.raises(MigrationError, match="previously applied"):
        manager.migrate()


def test_postgres_audit_initialization_uses_single_statement_calls() -> None:
    db = AuditInitDB()
    PostgresAuditStore(connection_factory=db.connect, schema="agent_roi")
    assert db.executed[0] == 'CREATE SCHEMA IF NOT EXISTS "agent_roi"'
    assert all(";" not in statement.rstrip(";") for statement in db.executed)


def test_database_cli_lists_packaged_migrations(capsys) -> None:
    assert database_main(["list"]) == 0
    output = capsys.readouterr().out
    assert '"version": 5' in output
    assert '"name": "audit"' in output


def test_connection_factory_creates_schema_before_setting_search_path() -> None:
    db = MigrationDB()
    factory = PostgresConnectionFactory("postgresql://test", schema="tenant_a", connect_factory=db.connect)
    with factory.connection():
        pass
    statements = [sql for sql, _ in db.statements]
    assert statements[:2] == [
        'CREATE SCHEMA IF NOT EXISTS "tenant_a"',
        'SET search_path TO "tenant_a", public',
    ]
