"""Tests for database output sinks."""

from __future__ import annotations

import json
import sqlite3

from joyfuljay.output.database import DatabaseWriter


def test_database_writer_sqlite_inserts_and_alters(tmp_path) -> None:
    db_path = tmp_path / "features.db"

    writer = DatabaseWriter(
        dsn=str(db_path),
        table="flows",
        if_exists="replace",
        batch_size=1,
    )
    writer.write(
        {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "duration": 1.25,
            "flags": [1, 2, 3],
        }
    )
    writer.close()

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT src_ip, dst_ip, duration, flags FROM flows").fetchall()
    conn.close()

    assert rows == [("1.1.1.1", "2.2.2.2", 1.25, json.dumps([1, 2, 3]))]

    writer = DatabaseWriter(
        dsn=str(db_path),
        table="flows",
        if_exists="append",
        batch_size=1,
    )
    writer.write(
        {
            "src_ip": "3.3.3.3",
            "dst_ip": "4.4.4.4",
            "duration": 2.5,
            "flags": [],
            "new_field": "added",
        }
    )
    writer.close()

    conn = sqlite3.connect(db_path)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(flows)").fetchall()]
    rows = conn.execute("SELECT new_field FROM flows WHERE src_ip='3.3.3.3'").fetchone()
    conn.close()

    assert "new_field" in columns
    assert rows == ("added",)
