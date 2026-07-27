from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
import re
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Protocol, Sequence


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DatabaseConfigurationError(ValueError):
    """Raised when a database configuration is invalid."""


class MigrationError(RuntimeError):
    """Raised when a schema migration cannot be applied safely."""


class ConnectionFactory(Protocol):
    @contextmanager
    def connection(self) -> Iterator[Any]: ...


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or int(self.version) < 1:
            raise ValueError("Migration version must be a positive integer")
        if not str(self.name).strip():
            raise ValueError("Migration name must be non-empty")
        if not str(self.sql).strip():
            raise ValueError("Migration SQL must be non-empty")


class PostgresConnectionFactory:
    """Lazy psycopg connection factory with safe schema selection.

    ``connect_factory`` is injectable for tests and managed database proxies.
    When omitted, the optional ``psycopg`` dependency is imported lazily.
    """

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "agent_roi",
        connect_factory: Optional[Callable[..., Any]] = None,
        connect_kwargs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise DatabaseConfigurationError("PostgreSQL DSN must be a non-empty string")
        if not _IDENTIFIER.fullmatch(schema):
            raise DatabaseConfigurationError("schema must be a valid PostgreSQL identifier")
        self.dsn = dsn.strip()
        self.schema = schema
        self._connect_factory = connect_factory
        self.connect_kwargs = dict(connect_kwargs or {})

    def _connect(self) -> Any:
        if self._connect_factory is not None:
            return self._connect_factory(self.dsn, **self.connect_kwargs)
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "PostgreSQL support requires psycopg. Install agent-roi[postgres]."
            ) from exc
        return psycopg.connect(self.dsn, row_factory=dict_row, **self.connect_kwargs)

    @contextmanager
    def connection(self) -> Iterator[Any]:
        conn = self._connect()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
                cursor.execute(f'SET search_path TO "{self.schema}", public')
            finally:
                cursor.close()
            yield conn
            conn.commit()
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            conn.close()



def split_sql_statements(sql: str) -> tuple[str, ...]:
    """Split a migration script into executable statements.

    The parser recognizes SQL string literals, quoted identifiers, line and block
    comments, and PostgreSQL dollar-quoted bodies. It intentionally avoids
    driver-specific multi-statement execution so migrations work with psycopg's
    extended query protocol and managed database proxies.
    """
    statements: list[str] = []
    buffer: list[str] = []
    index = 0
    quote = ""
    dollar_tag = ""
    block_comment = False
    line_comment = False
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if line_comment:
            buffer.append(char)
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            buffer.append(char)
            if char == "*" and next_char == "/":
                buffer.append(next_char)
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if dollar_tag:
            if sql.startswith(dollar_tag, index):
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = ""
            else:
                buffer.append(char)
                index += 1
            continue
        if quote:
            buffer.append(char)
            if char == quote:
                if next_char == quote:
                    buffer.append(next_char)
                    index += 2
                    continue
                quote = ""
            elif char == "\\" and quote == "'" and next_char:
                buffer.append(next_char)
                index += 2
                continue
            index += 1
            continue
        if char == "-" and next_char == "-":
            buffer.extend((char, next_char))
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            buffer.extend((char, next_char))
            block_comment = True
            index += 2
            continue
        if char in {"'", '"'}:
            quote = char
            buffer.append(char)
            index += 1
            continue
        if char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$", sql[index:])
            if match is not None:
                dollar_tag = match.group(0)
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    if quote or dollar_tag or block_comment:
        raise MigrationError("Migration SQL contains an unterminated quoted value or comment")
    statement = "".join(buffer).strip()
    if statement:
        statements.append(statement)
    return tuple(statements)

def load_postgres_migrations() -> tuple[Migration, ...]:
    root = resources.files("agent_roi.migrations.postgres")
    migrations: list[Migration] = []
    for item in sorted(root.iterdir(), key=lambda value: value.name):
        match = re.fullmatch(r"(\d{4})_([A-Za-z0-9_]+)\.sql", item.name)
        if match is None:
            continue
        migrations.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                sql=item.read_text(encoding="utf-8"),
            )
        )
    versions = [migration.version for migration in migrations]
    if versions != sorted(set(versions)):
        raise MigrationError("PostgreSQL migration versions must be unique and ordered")
    return tuple(migrations)


class PostgresMigrationManager:
    """Applies packaged migrations under a PostgreSQL advisory lock."""

    def __init__(
        self,
        connection_factory: PostgresConnectionFactory,
        *,
        migrations: Optional[Sequence[Migration]] = None,
        advisory_lock_key: int = 873_010_021,
    ) -> None:
        self.connection_factory = connection_factory
        self.migrations = tuple(migrations or load_postgres_migrations())
        self.advisory_lock_key = int(advisory_lock_key)

    def current_version(self) -> int:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS agent_roi_schema_migrations (
                           version INTEGER PRIMARY KEY,
                           name TEXT NOT NULL,
                           applied_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                       )"""
                )
                cursor.execute("SELECT COALESCE(MAX(version), 0) AS version FROM agent_roi_schema_migrations")
                row = cursor.fetchone()
                if row is None:
                    return 0
                if isinstance(row, Mapping):
                    return int(row["version"])
                return int(row[0])
            finally:
                cursor.close()

    def migrate(self, *, target_version: Optional[int] = None) -> tuple[int, ...]:
        selected = [
            migration
            for migration in self.migrations
            if target_version is None or migration.version <= int(target_version)
        ]
        applied: list[int] = []
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", (self.advisory_lock_key,))
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS agent_roi_schema_migrations (
                           version INTEGER PRIMARY KEY,
                           name TEXT NOT NULL,
                           applied_at_utc TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                       )"""
                )
                cursor.execute("SELECT version, name FROM agent_roi_schema_migrations ORDER BY version")
                existing_rows = cursor.fetchall() or []
                existing: dict[int, str] = {}
                for row in existing_rows:
                    if isinstance(row, Mapping):
                        existing[int(row["version"])] = str(row["name"])
                    else:
                        existing[int(row[0])] = str(row[1])
                for migration in selected:
                    prior = existing.get(migration.version)
                    if prior is not None:
                        if prior != migration.name:
                            raise MigrationError(
                                f"Migration {migration.version} was previously applied as {prior!r}, "
                                f"not {migration.name!r}"
                            )
                        continue
                    for statement in split_sql_statements(migration.sql):
                        cursor.execute(statement)
                    cursor.execute(
                        "INSERT INTO agent_roi_schema_migrations(version, name) VALUES (%s, %s)",
                        (migration.version, migration.name),
                    )
                    applied.append(migration.version)
            except Exception as exc:
                if isinstance(exc, MigrationError):
                    raise
                raise MigrationError("PostgreSQL migration failed") from exc
            finally:
                cursor.close()
        return tuple(applied)


def row_to_mapping(cursor: Any, row: Any) -> dict[str, Any]:
    if row is None:
        raise ValueError("row cannot be None")
    if isinstance(row, Mapping):
        return dict(row)
    description = getattr(cursor, "description", None)
    if not description:
        raise TypeError("Database driver did not provide mapping rows or cursor metadata")
    names = [column.name if hasattr(column, "name") else column[0] for column in description]
    return dict(zip(names, row))


def fetchone_mapping(cursor: Any) -> Optional[dict[str, Any]]:
    row = cursor.fetchone()
    return None if row is None else row_to_mapping(cursor, row)


def fetchall_mappings(cursor: Any) -> tuple[dict[str, Any], ...]:
    return tuple(row_to_mapping(cursor, row) for row in (cursor.fetchall() or ()))
