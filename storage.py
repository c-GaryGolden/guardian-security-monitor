import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path


class EventStorage:

    def __init__(
        self,
        db_path="data/guardian.db",
        max_size_mb=1024,
        maintenance_every=100,
    ):
        self.db_path = Path(db_path)

        self.max_size_bytes = (
            max_size_mb * 1024 * 1024
        )

        self.maintenance_every = (
            maintenance_every
        )

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.insert_count = 0

        self._initialize()
        self._ensure_incident_columns()
    def latest_commands(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    target_host,
                    action,
                    parameters_json,
                    status,
                    result_json,
                    executed_at
                FROM commands
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        result = []

        for row in rows:
            result.append(
                {
                    "id": row[0],
                    "created_at": row[1],
                    "target_host": row[2],
                    "action": row[3],
                    "parameters": json.loads(
                        row[4]
                    ),
                    "status": row[5],
                    "result": (
                        json.loads(row[6])
                        if row[6]
                        else None
                    ),
                    "executed_at": row[7],
                }
            )

        return result
    # =========================
    # DATABASE CONNECTION
    # =========================

    def _connect(self):
        conn = sqlite3.connect(
            self.db_path,
            timeout=10,
        )

        conn.execute(
            "PRAGMA journal_mode=WAL"
        )

        conn.execute(
            "PRAGMA synchronous=NORMAL"
        )

        conn.execute(
            "PRAGMA foreign_keys=ON"
        )

        conn.execute(
            "PRAGMA busy_timeout=10000"
        )

        return conn

    # =========================
    # INITIALIZATION
    # =========================

    def _initialize(self):
        with self._connect() as conn:

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    host TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data_json TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_events_timestamp
                ON events(timestamp)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_events_severity
                ON events(severity)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_events_type
                ON events(type)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_events_host
                ON events(host)
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    event_id INTEGER,
                    rule TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    reaction_status TEXT NOT NULL DEFAULT 'not_run',
                    reaction_result TEXT,
                    reacted_at TEXT
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incidents_created_at
                ON incidents(created_at)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incidents_event_id
                ON incidents(event_id)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incidents_status
                ON incidents(status)
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    action TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    result_json TEXT,
                    executed_at TEXT
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_commands_target_status
                ON commands(target_host, status)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_commands_status
                ON commands(status)
                """
            )

    # =========================
    # INCIDENT MIGRATION
    # =========================

    def _ensure_incident_columns(self):
        required_columns = {
            "status": (
                "TEXT NOT NULL DEFAULT 'open'"
            ),
            "reaction_status": (
                "TEXT NOT NULL DEFAULT 'not_run'"
            ),
            "reaction_result": "TEXT",
            "reacted_at": "TEXT",
        }

        with self._connect() as conn:
            rows = conn.execute(
                "PRAGMA table_info(incidents)"
            ).fetchall()

            existing = {
                row[1]
                for row in rows
            }

            for column, definition in (
                required_columns.items()
            ):
                if column not in existing:
                    conn.execute(
                        f"""
                        ALTER TABLE incidents
                        ADD COLUMN {column} {definition}
                        """
                    )

    # =========================
    # EVENTS
    # =========================

    def insert_event(self, event):
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events (
                    timestamp,
                    host,
                    type,
                    severity,
                    source,
                    data_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp,
                    event.host,
                    event.type,
                    event.severity,
                    event.source,
                    json.dumps(
                        event.data,
                        ensure_ascii=False,
                    ),
                ),
            )

            event_id = cursor.lastrowid

        self.insert_count += 1

        if (
            self.insert_count
            % self.maintenance_every
            == 0
        ):
            self.maintenance()

        return event_id

    # =========================
    # INCIDENTS
    # =========================

    def insert_incident(
        self,
        event_id,
        rule,
        action,
        reason,
        status="open",
    ):
        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO incidents (
                    created_at,
                    event_id,
                    rule,
                    action,
                    reason,
                    status,
                    reaction_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    event_id,
                    rule,
                    action,
                    reason,
                    status,
                    "not_run",
                ),
            )

            return cursor.lastrowid

    def update_reaction(
        self,
        incident_id,
        reaction_status,
        reaction_result=None,
    ):
        reacted_at = datetime.now(
            timezone.utc
        ).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE incidents
                SET
                    reaction_status = ?,
                    reaction_result = ?,
                    reacted_at = ?
                WHERE id = ?
                """,
                (
                    reaction_status,
                    (
                        json.dumps(
                            reaction_result,
                            ensure_ascii=False,
                        )
                        if isinstance(
                            reaction_result,
                            (dict, list),
                        )
                        else reaction_result
                    ),
                    reacted_at,
                    incident_id,
                ),
            )

    # =========================
    # COMMANDS
    # =========================

    def create_command(
        self,
        target_host,
        action,
        parameters,
    ):
        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO commands (
                    created_at,
                    target_host,
                    action,
                    parameters_json,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    target_host,
                    action,
                    json.dumps(
                        parameters,
                        ensure_ascii=False,
                    ),
                    "pending",
                ),
            )

            return cursor.lastrowid

    def get_pending_commands(
        self,
        target_host,
        limit=10,
    ):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    target_host,
                    action,
                    parameters_json,
                    status
                FROM commands
                WHERE
                    target_host = ?
                    AND status = 'pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (
                    target_host,
                    limit,
                ),
            ).fetchall()

        return [
            {
                "id": row[0],
                "created_at": row[1],
                "target_host": row[2],
                "action": row[3],
                "parameters": json.loads(
                    row[4]
                ),
                "status": row[5],
            }
            for row in rows
        ]

    def claim_pending_commands(
        self,
        target_host,
        limit=10,
    ):
        commands = []

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    target_host,
                    action,
                    parameters_json
                FROM commands
                WHERE
                    target_host = ?
                    AND status = 'pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (
                    target_host,
                    limit,
                ),
            ).fetchall()

            for row in rows:
                updated = conn.execute(
                    """
                    UPDATE commands
                    SET status = 'executing'
                    WHERE
                        id = ?
                        AND status = 'pending'
                    """,
                    (row[0],),
                )

                if updated.rowcount != 1:
                    continue

                commands.append(
                    {
                        "id": row[0],
                        "created_at": row[1],
                        "target_host": row[2],
                        "action": row[3],
                        "parameters": json.loads(
                            row[4]
                        ),
                        "status": "executing",
                    }
                )

        return commands

    def update_command(
        self,
        command_id,
        status,
        result=None,
    ):
        valid_statuses = {
            "pending",
            "executing",
            "executed",
            "failed",
            "rejected",
        }

        if status not in valid_statuses:
            raise ValueError(
                f"Invalid command status: {status}"
            )

        executed_at = None

        if status in {
            "executed",
            "failed",
            "rejected",
        }:
            executed_at = datetime.now(
                timezone.utc
            ).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE commands
                SET
                    status = ?,
                    result_json = ?,
                    executed_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    (
                        json.dumps(
                            result,
                            ensure_ascii=False,
                        )
                        if result is not None
                        else None
                    ),
                    executed_at,
                    command_id,
                ),
            )
    # =========================
    # MAINTENANCE
    # =========================

    def maintenance(self):
        self._apply_retention()
        self._enforce_size_limit()

    def _apply_retention(self):
        now = datetime.now(
            timezone.utc
        )

        medium_cutoff = (
            now - timedelta(days=30)
        ).isoformat()

        high_cutoff = (
            now - timedelta(days=90)
        ).isoformat()

        critical_cutoff = (
            now - timedelta(days=180)
        ).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM events
                WHERE
                    severity IN (
                        'info',
                        'low',
                        'medium'
                    )
                    AND timestamp < ?
                """,
                (medium_cutoff,),
            )

            conn.execute(
                """
                DELETE FROM events
                WHERE
                    severity = 'high'
                    AND timestamp < ?
                """,
                (high_cutoff,),
            )

            conn.execute(
                """
                DELETE FROM events
                WHERE
                    severity = 'critical'
                    AND timestamp < ?
                """,
                (critical_cutoff,),
            )

    # =========================
    # SIZE CONTROL
    # =========================

    def _checkpoint(self):
        with self._connect() as conn:
            conn.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            )

    def _database_size(self):
        size = 0

        for path in (
            self.db_path,
            Path(
                f"{self.db_path}-wal"
            ),
            Path(
                f"{self.db_path}-shm"
            ),
        ):
            if path.exists():
                size += path.stat().st_size

        return size

    def _enforce_size_limit(self):
        self._checkpoint()

        while (
            self._database_size()
            > self.max_size_bytes
        ):
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id
                    FROM events
                    ORDER BY timestamp ASC
                    LIMIT 500
                    """
                ).fetchall()

                if not rows:
                    break

                ids = [
                    row[0]
                    for row in rows
                ]

                placeholders = ",".join(
                    "?"
                    for _ in ids
                )

                conn.execute(
                    f"""
                    DELETE FROM events
                    WHERE id IN ({placeholders})
                    """,
                    ids,
                )

            self._checkpoint()

    # =========================
    # QUERIES
    # =========================

    def count(self):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()

        return row[0]

    def latest(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    timestamp,
                    host,
                    type,
                    severity,
                    source,
                    data_json
                FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "host": row[2],
                "type": row[3],
                "severity": row[4],
                "source": row[5],
                "data": json.loads(row[6]),
            }
            for row in rows
        ]

    def latest_incidents(self, limit=50):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    created_at,
                    event_id,
                    rule,
                    action,
                    reason,
                    status,
                    reaction_status,
                    reaction_result,
                    reacted_at
                FROM incidents
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "id": row[0],
                "created_at": row[1],
                "event_id": row[2],
                "rule": row[3],
                "action": row[4],
                "reason": row[5],
                "status": row[6],
                "reaction_status": row[7],
                "reaction_result": row[8],
                "reacted_at": row[9],
            }
            for row in rows
        ]

    def incident_count(self):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()

        return row[0]

    def command_count(self):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM commands"
            ).fetchone()

        return row[0]
