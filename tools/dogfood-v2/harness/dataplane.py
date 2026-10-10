"""Data-plane abstraction: the harness asserts DB invariants through named
lookups so the same probes run against Postgres (live) and the in-memory
fixture (self-test) without raw SQL forks.
"""
from __future__ import annotations

import json
import subprocess
import urllib.parse
import urllib.request


class Unsupported(Exception):
    pass


class DataPlane:
    def ping(self) -> bool: ...

    def count(self, table: str, **eq) -> int: ...

    def row(self, table: str, **eq) -> dict | None: ...

    def tables(self) -> set[str]: ...

    def table_parents(self) -> dict[str, str]: ...

    def columns(self, table: str) -> set[str]: ...

    def scalar(self, sql: str) -> str: ...


def _sql_literal(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).replace("'", "''")
    return f"'{text}'"


def _where(**eq) -> str:
    if not eq:
        return ""
    clauses = []
    for key, value in eq.items():
        if value is None:
            clauses.append(f"{key} IS NULL")
        else:
            clauses.append(f"{key} = {_sql_literal(value)}")
    return " WHERE " + " AND ".join(clauses)


class PsqlDataPlane(DataPlane):
    def __init__(self, cfg):
        self.cfg = cfg
        self._tables: set[str] | None = None

    def _run(self, sql: str, tuples: bool = True):
        cmd = [self.cfg.psql_bin, self.cfg.db_url, "-tAF", "|", "-c", sql]
        import os

        env = dict(os.environ, PGPASSWORD=self.cfg.postgres_password)
        out = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)
        if out.returncode != 0:
            raise RuntimeError(f"psql failed: {out.stderr.strip()[:300]}")
        if tuples:
            rows = []
            for line in out.stdout.splitlines():
                if line == "":
                    continue
                rows.append(line.split("|"))
            return rows
        return out.stdout.strip()

    def ping(self) -> bool:
        try:
            return self.scalar("SELECT 1") == "1"
        except Exception:  # noqa: BLE001
            return False

    def scalar(self, sql: str) -> str:
        rows = self._run(sql)
        return rows[0][0] if rows and rows[0] else ""

    def rows(self, sql: str) -> list[list[str]]:
        return self._run(sql)

    def count(self, table: str, **eq) -> int:
        return int(self.scalar(f"SELECT count(*) FROM {table}{_where(**eq)}") or 0)

    def row(self, table: str, **eq) -> dict | None:
        rows = self._run(f"SELECT row_to_json(t)::text FROM {table} t{_where(**eq)} LIMIT 1")
        if not rows or not rows[0]:
            return None
        try:
            return json.loads(rows[0][0])
        except Exception:  # noqa: BLE001
            return None

    def tables(self) -> set[str]:
        if self._tables is None:
            rows = self._run(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
            )
            self._tables = {r[0] for r in rows if r and r[0]}
        return self._tables

    def table_parents(self) -> dict[str, str]:
        """child table -> partition parent (pg_inherits), for orphan triage:
        a partition child of a migration-declared parent is migration-managed
        even when its own name was created dynamically at runtime."""
        try:
            rows = self._run(
                "SELECT c.relname, p.relname FROM pg_inherits i "
                "JOIN pg_class c ON c.oid = i.inhrelid "
                "JOIN pg_class p ON p.oid = i.inhparent "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'public'"
            )
        except Exception:  # noqa: BLE001
            return {}
        return {row[0]: row[1] for row in rows if len(row) >= 2 and row[0] and row[1]}

    def columns(self, table: str) -> set[str]:
        rows = self._run(
            "SELECT column_name FROM information_schema.columns "
            f"WHERE table_schema='public' AND table_name={_sql_literal(table)}"
        )
        return {r[0] for r in rows if r and r[0]}


class FixtureDataPlane(DataPlane):
    """Named lookups against the self-test fixture's state endpoint."""

    def __init__(self, base: str):
        self.base = base

    def _get(self, path: str, **params) -> dict:
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        url = f"{self.base}{path}" + (f"?{query}" if query else "")
        with urllib.request.urlopen(url, timeout=10) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            body = json.loads(response.read().decode())
        if isinstance(body, dict) and isinstance(body.get("data"), dict):
            return {**body["data"], **{k: v for k, v in body.items() if k not in ("data", "error", "meta")}}
        return body

    def ping(self) -> bool:
        try:
            return self._get("/__fixture/state", op="tables").get("tables") is not None
        except Exception:  # noqa: BLE001
            return False

    def count(self, table: str, **eq) -> int:
        return int(self._get("/__fixture/state", op="count", table=table, **{f"eq_{k}": v for k, v in eq.items()}).get("count", 0))

    def row(self, table: str, **eq) -> dict | None:
        return self._get("/__fixture/state", op="row", table=table, **{f"eq_{k}": v for k, v in eq.items()}).get("row")

    def tables(self) -> set[str]:
        return set(self._get("/__fixture/state", op="tables").get("tables", []))

    def table_parents(self) -> dict[str, str]:
        return {}

    def columns(self, table: str) -> set[str]:
        return set(self._get("/__fixture/state", op="columns", table=table).get("columns", []))

    def scalar(self, sql: str) -> str:
        raise Unsupported("raw SQL is not available against the self-test fixture")
