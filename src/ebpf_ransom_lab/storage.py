"""SQLite repository for replay and local-dashboard state."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Sequence

from ebpf_ransom_lab.contracts import FeatureWindow
from ebpf_ransom_lab.detection import Prediction


SCHEMA_VERSION = 1


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    started_ns TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS windows (
                    window_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    boot_id TEXT NOT NULL,
                    tgid TEXT NOT NULL,
                    start_time_ns TEXT NOT NULL,
                    start_ns TEXT NOT NULL,
                    end_ns TEXT NOT NULL,
                    feature_version TEXT NOT NULL,
                    feature_names TEXT NOT NULL,
                    feature_values TEXT NOT NULL,
                    quality TEXT NOT NULL,
                    classifiable INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS windows_process
                    ON windows(run_id, boot_id, tgid, start_time_ns, start_ns);
                CREATE TABLE IF NOT EXISTS predictions (
                    window_id TEXT PRIMARY KEY REFERENCES windows(window_id),
                    model_version TEXT NOT NULL,
                    score REAL,
                    threshold REAL NOT NULL,
                    suspicious INTEGER,
                    quality TEXT NOT NULL,
                    supporting_features TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_id TEXT NOT NULL UNIQUE REFERENCES windows(window_id),
                    run_id TEXT NOT NULL REFERENCES runs(run_id),
                    boot_id TEXT NOT NULL,
                    tgid TEXT NOT NULL,
                    start_time_ns TEXT NOT NULL,
                    score REAL NOT NULL,
                    supporting_features TEXT NOT NULL,
                    valid INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS collector_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    connected INTEGER NOT NULL,
                    event_rate REAL NOT NULL,
                    lost_events INTEGER NOT NULL,
                    recording INTEGER NOT NULL,
                    error TEXT
                );
                INSERT OR IGNORE INTO collector_state
                    (singleton, connected, event_rate, lost_events, recording, error)
                    VALUES (1, 0, 0.0, 0, 0, NULL);
                """
            )
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def upsert_run(self, run_id: str, *, source: str, started_ns: int, status: str) -> None:
        if not run_id or source not in {"replay", "live", "controlled-workload"}:
            raise ValueError("invalid run")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO runs(run_id, source, started_ns, status) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET source=excluded.source, "
                "started_ns=excluded.started_ns, status=excluded.status",
                (run_id, source, str(started_ns), status),
            )

    def upsert_window(self, window: FeatureWindow) -> None:
        quality = ",".join(window.quality)
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO windows(
                    window_id, run_id, boot_id, tgid, start_time_ns, start_ns, end_ns,
                    feature_version, feature_names, feature_values, quality, classifiable
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(window_id) DO UPDATE SET
                    feature_values=excluded.feature_values, quality=excluded.quality,
                    classifiable=excluded.classifiable""",
                (
                    window.window_id, window.run_id, window.process.boot_id,
                    str(window.process.tgid), str(window.process.start_time_ns),
                    str(window.start_ns), str(window.end_ns), str(window.feature_version),
                    _json(window.feature_names), _json(window.values), quality,
                    int(window.classifiable),
                ),
            )
            if not window.classifiable:
                connection.execute(
                    "UPDATE predictions SET score=NULL, suspicious=NULL, quality=? WHERE window_id=?",
                    (quality, window.window_id),
                )
                connection.execute("UPDATE alerts SET valid=0 WHERE window_id=?", (window.window_id,))

    def upsert_prediction(self, prediction: Prediction) -> None:
        with self._connect() as connection:
            _upsert_prediction(connection, prediction)
            if prediction.suspicious is not True:
                connection.execute(
                    "UPDATE alerts SET valid=0 WHERE window_id=?",
                    (prediction.window_id,),
                )

    def create_alert(self, prediction: Prediction, window: FeatureWindow) -> None:
        if prediction.suspicious is not True or prediction.score is None:
            return
        with self._connect() as connection:
            _upsert_alert(connection, prediction, window)

    def replace_run_analysis(
        self,
        run_id: str,
        *,
        source: str,
        started_ns: int,
        windows: Sequence[FeatureWindow],
        predictions: Sequence[Prediction],
    ) -> None:
        """Atomically replace one run and every derived dashboard record."""

        if not run_id or source not in {"replay", "live", "controlled-workload"}:
            raise ValueError("invalid run")
        if len(windows) != len(predictions):
            raise ValueError("every window must have exactly one prediction")
        if any(window.run_id != run_id for window in windows):
            raise ValueError("window run ID does not match transaction run")
        if any(
            prediction.window_id != window.window_id
            for window, prediction in zip(windows, predictions, strict=True)
        ):
            raise ValueError("prediction does not match its window")

        with self._connect() as connection:
            connection.execute("DELETE FROM alerts WHERE run_id=?", (run_id,))
            connection.execute(
                "DELETE FROM predictions WHERE window_id IN "
                "(SELECT window_id FROM windows WHERE run_id=?)",
                (run_id,),
            )
            connection.execute("DELETE FROM windows WHERE run_id=?", (run_id,))
            connection.execute(
                "INSERT INTO runs(run_id, source, started_ns, status) VALUES(?, ?, ?, 'complete') "
                "ON CONFLICT(run_id) DO UPDATE SET source=excluded.source, "
                "started_ns=excluded.started_ns, status=excluded.status",
                (run_id, source, str(started_ns)),
            )
            for window, prediction in zip(windows, predictions, strict=True):
                _upsert_window(connection, window)
                _upsert_prediction(connection, prediction)
                if prediction.suspicious is True:
                    _upsert_alert(connection, prediction, window)

    def update_health(self, *, connected: bool, event_rate: float, lost_events: int,
                      recording: bool, error: str | None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE collector_state SET connected=?, event_rate=?, lost_events=?, "
                "recording=?, error=? WHERE singleton=1",
                (int(connected), float(event_rate), int(lost_events), int(recording), error),
            )

    def health(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM collector_state WHERE singleton=1").fetchone()
        return {
            "collector_connected": bool(row["connected"]),
            "event_rate": row["event_rate"],
            "lost_events": row["lost_events"],
            "recording": bool(row["recording"]),
            "error": row["error"],
        }

    def list_runs(self, *, limit: int, offset: int) -> tuple[dict[str, Any], ...]:
        return self._query(
            "SELECT run_id, source, started_ns, status FROM runs "
            "ORDER BY started_ns DESC, run_id LIMIT ? OFFSET ?", (limit, offset)
        )

    def list_processes(self, *, limit: int, offset: int) -> tuple[dict[str, Any], ...]:
        return self._query(
            """SELECT run_id, boot_id, tgid, start_time_ns,
               COUNT(*) AS window_count, MAX(start_ns) AS latest_window_ns
               FROM windows GROUP BY run_id, boot_id, tgid, start_time_ns
               ORDER BY latest_window_ns DESC, tgid LIMIT ? OFFSET ?""",
            (limit, offset),
        )

    def list_windows(self, *, limit: int, offset: int) -> tuple[dict[str, Any], ...]:
        rows = self._query(
            """SELECT w.window_id, w.run_id, w.tgid, w.start_time_ns,
               w.start_ns, w.end_ns, w.quality, w.classifiable,
               w.feature_names, w.feature_values, p.model_version, p.score,
               p.threshold, p.suspicious
               FROM windows w LEFT JOIN predictions p ON p.window_id=w.window_id
               ORDER BY w.start_ns DESC, w.window_id LIMIT ? OFFSET ?""",
            (limit, offset),
        )
        return tuple({
            **row,
            "classifiable": bool(row["classifiable"]),
            "suspicious": None if row["suspicious"] is None else bool(row["suspicious"]),
            "features": dict(zip(json.loads(row["feature_names"]), json.loads(row["feature_values"]), strict=True)),
        } for row in rows)

    def list_alerts(self, *, limit: int, offset: int) -> tuple[dict[str, Any], ...]:
        rows = self._query(
            """SELECT alert_id, window_id, run_id, tgid, start_time_ns, score,
               supporting_features, valid FROM alerts
               ORDER BY alert_id DESC LIMIT ? OFFSET ?""", (limit, offset)
        )
        return tuple({
            **row, "valid": bool(row["valid"]),
            "supporting_features": json.loads(row["supporting_features"]),
        } for row in rows)

    def metrics(self) -> dict[str, int]:
        with self._connect() as connection:
            windows = connection.execute("SELECT COUNT(*) FROM windows").fetchone()[0]
            suspicious = connection.execute(
                "SELECT COUNT(*) FROM predictions WHERE suspicious=1"
            ).fetchone()[0]
            alerts = connection.execute("SELECT COUNT(*) FROM alerts WHERE valid=1").fetchone()[0]
        return {"windows": windows, "suspicious_windows": suspicious, "active_alerts": alerts}

    def _query(self, sql: str, parameters: tuple[object, ...]) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return tuple(dict(row) for row in rows)


def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _upsert_window(connection: sqlite3.Connection, window: FeatureWindow) -> None:
    quality = ",".join(window.quality)
    connection.execute(
        """INSERT INTO windows(
            window_id, run_id, boot_id, tgid, start_time_ns, start_ns, end_ns,
            feature_version, feature_names, feature_values, quality, classifiable
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(window_id) DO UPDATE SET
            feature_values=excluded.feature_values, quality=excluded.quality,
            classifiable=excluded.classifiable""",
        (
            window.window_id, window.run_id, window.process.boot_id,
            str(window.process.tgid), str(window.process.start_time_ns),
            str(window.start_ns), str(window.end_ns), str(window.feature_version),
            _json(window.feature_names), _json(window.values), quality,
            int(window.classifiable),
        ),
    )


def _upsert_prediction(connection: sqlite3.Connection, prediction: Prediction) -> None:
    connection.execute(
        """INSERT INTO predictions(
            window_id, model_version, score, threshold, suspicious, quality,
            supporting_features
        ) VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(window_id) DO UPDATE SET model_version=excluded.model_version,
            score=excluded.score, threshold=excluded.threshold,
            suspicious=excluded.suspicious, quality=excluded.quality,
            supporting_features=excluded.supporting_features""",
        (
            prediction.window_id, prediction.model_version, prediction.score,
            prediction.threshold,
            None if prediction.suspicious is None else int(prediction.suspicious),
            prediction.quality, _json(prediction.supporting_features),
        ),
    )


def _upsert_alert(
    connection: sqlite3.Connection, prediction: Prediction, window: FeatureWindow
) -> None:
    if prediction.suspicious is not True or prediction.score is None:
        return
    connection.execute(
        """INSERT INTO alerts(
            window_id, run_id, boot_id, tgid, start_time_ns, score,
            supporting_features, valid
        ) VALUES(?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(window_id) DO UPDATE SET
            score=excluded.score,
            supporting_features=excluded.supporting_features,
            valid=1""",
        (
            window.window_id, window.run_id, window.process.boot_id,
            str(window.process.tgid), str(window.process.start_time_ns),
            prediction.score, _json(prediction.supporting_features),
        ),
    )
