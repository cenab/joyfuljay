"""Database output sink for feature insertion."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Iterable, Literal, Sequence
from urllib.parse import ParseResult, unquote, urlparse

import numpy as np

DatabaseBackend = Literal["sqlite", "postgres"]
IfExistsMode = Literal["append", "replace", "fail"]


@dataclass(frozen=True)
class DatabaseInfo:
    """Resolved database connection info."""

    backend: DatabaseBackend
    dsn: str


def detect_database_backend(dsn: str) -> DatabaseInfo:
    """Detect database backend from a DSN or path.

    Args:
        dsn: Database connection string or SQLite file path.

    Returns:
        DatabaseInfo with backend and normalized DSN/path.
    """
    parsed = urlparse(dsn)

    if parsed.scheme in {"postgresql", "postgres"}:
        return DatabaseInfo(backend="postgres", dsn=dsn)

    if parsed.scheme == "sqlite":
        return DatabaseInfo(backend="sqlite", dsn=_normalize_sqlite_path(parsed))

    if parsed.scheme:
        raise ValueError(f"Unsupported database scheme: {parsed.scheme}")

    return DatabaseInfo(backend="sqlite", dsn=dsn)


def _normalize_sqlite_path(parsed: ParseResult) -> str:
    """Normalize a sqlite:// URL into a filesystem path or :memory:."""
    path = unquote(parsed.path)

    if path in {"", "/"}:
        return ":memory:"

    if path == "/:memory:":
        return ":memory:"

    if path.startswith("//"):
        path = path[1:]

    return path


def _quote_identifier(name: str) -> str:
    """Quote SQL identifiers safely."""
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _split_table_name(table: str) -> tuple[str | None, str]:
    """Split table name into optional schema and table name."""
    if "." in table:
        schema, name = table.split(".", 1)
        return schema, name
    return None, table


class DatabaseWriter:
    """Stream feature dictionaries into SQLite or PostgreSQL."""

    def __init__(
        self,
        dsn: str,
        table: str = "joyfuljay_features",
        if_exists: IfExistsMode = "append",
        batch_size: int = 1000,
        columns: Sequence[str] | None = None,
    ) -> None:
        """Initialize a database writer.

        Args:
            dsn: Database connection string or SQLite path.
            table: Target table name.
            if_exists: Behavior if table exists ("append", "replace", "fail").
            batch_size: Number of rows to buffer before inserting.
            columns: Optional fixed column order for inserts.
        """
        info = detect_database_backend(dsn)
        self.backend = info.backend
        self.dsn = info.dsn
        self.table = table
        self.if_exists = if_exists
        self.batch_size = max(1, batch_size)
        self._columns = list(columns) if columns else None
        self._buffer: list[dict[str, Any]] = []
        self._rows_written = 0
        self._insert_sql: str | None = None
        self._initialized = False

        self._schema, self._table_name = _split_table_name(table)
        self._qualified_table = self._format_table_name()

        self._conn = self._connect()
        self._cursor = self._conn.cursor()
        self._handle_existing_table()

        if self._columns is not None:
            self._initialize_schema_from_columns(self._columns)

    def __enter__(self) -> "DatabaseWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def _connect(self) -> Any:
        if self.backend == "sqlite":
            return sqlite3.connect(self.dsn)

        try:
            import psycopg
        except ImportError as exc:
            raise ImportError(
                "PostgreSQL output requires psycopg. Install with: pip install psycopg"
            ) from exc

        return psycopg.connect(self.dsn)

    def _format_table_name(self) -> str:
        if self.backend == "postgres" and self._schema:
            return f"{_quote_identifier(self._schema)}.{_quote_identifier(self._table_name)}"
        return _quote_identifier(self._table_name)

    def _handle_existing_table(self) -> None:
        table_exists = self._table_exists()

        if self.if_exists == "fail" and table_exists:
            raise ValueError(f"Table already exists: {self.table}")

        if self.if_exists == "replace" and table_exists:
            self._drop_table()

        if self.if_exists == "append" and table_exists and self._columns is None:
            self._columns = self._load_table_columns()
            self._refresh_insert_sql()
            self._initialized = True

    def _table_exists(self) -> bool:
        if self.backend == "sqlite":
            self._cursor.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (self._table_name,),
            )
            return self._cursor.fetchone() is not None

        schema = self._schema or "public"
        self._cursor.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_schema=%s AND table_name=%s",
            (schema, self._table_name),
        )
        return self._cursor.fetchone() is not None

    def _drop_table(self) -> None:
        self._cursor.execute(f"DROP TABLE IF EXISTS {self._qualified_table}")
        self._conn.commit()
        self._initialized = False

    def _load_table_columns(self) -> list[str]:
        if self.backend == "sqlite":
            self._cursor.execute(f"PRAGMA table_info({_quote_identifier(self._table_name)})")
            return [row[1] for row in self._cursor.fetchall()]

        schema = self._schema or "public"
        self._cursor.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position",
            (schema, self._table_name),
        )
        return [row[0] for row in self._cursor.fetchall()]

    def _initialize_schema_from_columns(self, columns: Sequence[str]) -> None:
        if self._initialized:
            return

        if self._table_exists():
            if self.if_exists == "fail":
                raise ValueError(f"Table already exists: {self.table}")
            if self.if_exists == "replace":
                self._drop_table()
            elif self.if_exists == "append":
                existing = self._load_table_columns()
                missing = [col for col in columns if col not in existing]
                if missing:
                    raise ValueError(
                        f"Table {self.table} missing expected columns: {', '.join(missing)}"
                    )
                self._columns = list(columns)
                self._refresh_insert_sql()
                self._initialized = True
                return

        col_defs = ", ".join(f"{_quote_identifier(col)} TEXT" for col in columns)
        self._cursor.execute(f"CREATE TABLE {self._qualified_table} ({col_defs})")
        self._conn.commit()
        self._columns = list(columns)
        self._refresh_insert_sql()
        self._initialized = True

    def _initialize_schema_from_features(self, features: dict[str, Any]) -> None:
        if self._initialized:
            return

        columns = list(features.keys())

        if self._table_exists():
            if self.if_exists == "fail":
                raise ValueError(f"Table already exists: {self.table}")
            if self.if_exists == "replace":
                self._drop_table()
            elif self.if_exists == "append":
                existing = self._load_table_columns()
                new_columns = [col for col in columns if col not in existing]
                if new_columns:
                    self._add_columns(new_columns, features)
                self._columns = existing + [c for c in columns if c not in existing]
                self._refresh_insert_sql()
                self._initialized = True
                return

        col_defs = []
        for col in columns:
            sql_type = self._infer_sql_type(features.get(col))
            col_defs.append(f"{_quote_identifier(col)} {sql_type}")

        self._cursor.execute(
            f"CREATE TABLE {self._qualified_table} ({', '.join(col_defs)})"
        )
        self._conn.commit()
        self._columns = columns
        self._refresh_insert_sql()
        self._initialized = True

    def _add_columns(self, columns: Sequence[str], sample: dict[str, Any]) -> None:
        for column in columns:
            sql_type = self._infer_sql_type(sample.get(column))
            self._cursor.execute(
                f"ALTER TABLE {self._qualified_table} "
                f"ADD COLUMN {_quote_identifier(column)} {sql_type}"
            )
        self._conn.commit()

    def _infer_sql_type(self, value: Any) -> str:
        if isinstance(value, (np.integer, int)) and not isinstance(value, bool):
            return "INTEGER" if self.backend == "sqlite" else "BIGINT"
        if isinstance(value, (np.floating, float)):
            return "REAL" if self.backend == "sqlite" else "DOUBLE PRECISION"
        if isinstance(value, bool):
            return "BOOLEAN"
        return "TEXT"

    def _refresh_insert_sql(self) -> None:
        if not self._columns:
            self._insert_sql = None
            return
        placeholders = ", ".join(
            ["?"] * len(self._columns)
            if self.backend == "sqlite"
            else ["%s"] * len(self._columns)
        )
        columns = ", ".join(_quote_identifier(col) for col in self._columns)
        self._insert_sql = (
            f"INSERT INTO {self._qualified_table} ({columns}) VALUES ({placeholders})"
        )

    def _prepare_row(self, features: dict[str, Any]) -> list[Any]:
        if not self._columns:
            return []
        return [self._normalize_value(features.get(col)) for col in self._columns]

    def _normalize_value(self, value: Any) -> Any:
        if isinstance(value, (np.integer, np.floating)):
            return value.item()
        if isinstance(value, np.ndarray):
            return json.dumps(value.tolist())
        if isinstance(value, (list, dict)):
            return json.dumps(value)
        return value

    def write(self, features: dict[str, Any]) -> None:
        """Write a single feature dictionary."""
        if not self._initialized:
            self._initialize_schema_from_features(features)
        elif self.if_exists == "append" and self._columns is not None:
            new_columns = [col for col in features.keys() if col not in self._columns]
            if new_columns:
                self._add_columns(new_columns, features)
                self._columns.extend(new_columns)
                self._refresh_insert_sql()

        self._buffer.append(features)

        if len(self._buffer) >= self.batch_size:
            self.flush()

    def write_many(self, rows: Iterable[dict[str, Any]]) -> int:
        """Write multiple feature dictionaries."""
        for row in rows:
            self.write(row)
        return self._rows_written

    def flush(self) -> None:
        """Flush buffered rows to the database."""
        if not self._buffer:
            return

        if not self._insert_sql or not self._columns:
            raise RuntimeError("Database writer not initialized with columns.")

        rows = [self._prepare_row(features) for features in self._buffer]
        self._cursor.executemany(self._insert_sql, rows)
        self._conn.commit()
        self._rows_written += len(rows)
        self._buffer = []

    def close(self) -> None:
        """Flush and close the database connection."""
        try:
            self.flush()
        finally:
            try:
                self._cursor.close()
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass

    @property
    def rows_written(self) -> int:
        """Number of rows written so far."""
        return self._rows_written


def to_database(
    features: list[dict[str, Any]],
    dsn: str,
    table: str = "joyfuljay_features",
    if_exists: IfExistsMode = "append",
    batch_size: int = 1000,
) -> int:
    """Write features to a database table.

    Args:
        features: Feature dictionaries to insert.
        dsn: Database connection string or SQLite path.
        table: Table name.
        if_exists: Behavior if table exists ("append", "replace", "fail").
        batch_size: Batch size for inserts.

    Returns:
        Number of rows inserted.
    """
    if not features:
        return 0

    with DatabaseWriter(
        dsn=dsn,
        table=table,
        if_exists=if_exists,
        batch_size=batch_size,
        columns=list(features[0].keys()),
    ) as writer:
        writer.write_many(features)
        writer.flush()
        return writer.rows_written
