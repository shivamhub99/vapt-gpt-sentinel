"""
SQLite Database Storage Layer for VAPT-GPT Sentinel.
Stores findings, scan runs, patches, and verification outcomes in runs/sentinel.db.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from sentinel.core.schemas import (
    DecisionEnum,
    Finding,
    FindingStatus,
    Patch,
    Severity,
    Verification,
)
from sentinel.core.settings import settings


class Database:
    """Manages SQLite persistence for findings, patches, and scan runs."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = settings.runs_dir / "sentinel.db"
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes database tables if they do not exist."""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Runs table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'COMPLETED'
            )
            """
        )

        # Findings table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                cwe TEXT NOT NULL,
                owasp TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss REAL,
                epss REAL,
                file TEXT,
                line INTEGER,
                endpoint TEXT,
                param TEXT,
                evidence TEXT,
                status TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                raw_json TEXT
            )
            """
        )

        # Patches table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS patches (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                diff TEXT NOT NULL,
                branch TEXT NOT NULL,
                rationale TEXT,
                attempt INTEGER DEFAULT 1,
                generated_by TEXT DEFAULT 'template',
                timestamp TEXT NOT NULL
            )
            """
        )

        # Verifications table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS verifications (
                patch_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                unit_passed INTEGER NOT NULL,
                regression_passed INTEGER NOT NULL,
                original_finding_gone INTEGER NOT NULL,
                decision TEXT NOT NULL,
                evidence_json TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )

        conn.commit()
        conn.close()

    def save_run(self, run_id: str, target: str, findings_count: int = 0) -> None:
        """Records a completed scan run."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO runs (run_id, target, timestamp, findings_count)
            VALUES (?, ?, ?, ?)
            """,
            (run_id, target, datetime.now(timezone.utc).isoformat(), findings_count),
        )
        conn.commit()
        conn.close()

    def save_findings(self, findings: List[Finding], run_id: str) -> None:
        """Persists or updates a collection of normalized findings."""
        conn = self.get_connection()
        cursor = conn.cursor()

        for f in findings:
            raw_str = json.dumps(f.raw_tool_data, default=str)
            cursor.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, run_id, tool, cwe, owasp, title, severity, cvss, epss,
                    file, line, endpoint, param, evidence, status, first_seen, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f.id,
                    run_id,
                    f.tool,
                    f.cwe,
                    f.owasp,
                    f.title,
                    f.severity.value,
                    f.cvss,
                    f.epss,
                    f.file,
                    f.line,
                    f.endpoint,
                    f.param,
                    f.evidence,
                    f.status.value,
                    f.first_seen.isoformat(),
                    raw_str,
                ),
            )

        conn.commit()
        conn.close()

    def get_findings_by_run(self, run_id: str) -> List[Finding]:
        """Retrieves all findings discovered in a specific run."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
        rows = cursor.fetchall()
        conn.close()

        findings: List[Finding] = []
        for r in rows:
            raw_data = json.loads(r["raw_json"]) if r["raw_json"] else {}
            findings.append(
                Finding(
                    id=r["id"],
                    tool=r["tool"],
                    cwe=r["cwe"],
                    owasp=r["owasp"],
                    title=r["title"],
                    severity=Severity(r["severity"]),
                    cvss=r["cvss"],
                    epss=r["epss"],
                    file=r["file"],
                    line=r["line"],
                    endpoint=r["endpoint"],
                    param=r["param"],
                    evidence=r["evidence"] or "",
                    status=FindingStatus(r["status"]),
                    first_seen=datetime.fromisoformat(r["first_seen"]),
                    raw_tool_data=raw_data,
                )
            )
        return findings

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Retrieves a single finding by ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        r = cursor.fetchone()
        conn.close()
        if not r:
            return None

        raw_data = json.loads(r["raw_json"]) if r["raw_json"] else {}
        return Finding(
            id=r["id"],
            tool=r["tool"],
            cwe=r["cwe"],
            owasp=r["owasp"],
            title=r["title"],
            severity=Severity(r["severity"]),
            cvss=r["cvss"],
            epss=r["epss"],
            file=r["file"],
            line=r["line"],
            endpoint=r["endpoint"],
            param=r["param"],
            evidence=r["evidence"] or "",
            status=FindingStatus(r["status"]),
            first_seen=datetime.fromisoformat(r["first_seen"]),
            raw_tool_data=raw_data,
        )

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> bool:
        """Updates the lifecycle status of a finding."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status.value, finding_id))
        conn.commit()
        updated = cursor.rowcount > 0
        conn.close()
        return updated

    def get_patch(self, patch_id: str) -> Optional[Patch]:
        """Retrieves a specific patch by ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM patches WHERE id = ?", (patch_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return Patch(
            id=row["id"],
            finding_id=row["finding_id"],
            diff=row["diff"],
            branch=row["branch"],
            rationale=row["rationale"] or "",
            attempt=row["attempt"],
            generated_by=row["generated_by"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )

    def get_patches_by_finding(self, finding_id: str) -> List[Patch]:
        """Retrieves all patches generated for a finding, ordered by attempt."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM patches WHERE finding_id = ? ORDER BY attempt ASC", (finding_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [
            Patch(
                id=r["id"],
                finding_id=r["finding_id"],
                diff=r["diff"],
                branch=r["branch"],
                rationale=r["rationale"] or "",
                attempt=r["attempt"],
                generated_by=r["generated_by"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
            )
            for r in rows
        ]

    def save_verification(self, v: Verification) -> None:
        """Persists a patch verification record."""
        conn = self.get_connection()
        cursor = conn.cursor()
        evidence_payload = {
            "evidence": v.evidence,
            "new_findings": [f.model_dump(mode="json") for f in v.new_findings],
        }
        cursor.execute(
            """
            INSERT OR REPLACE INTO verifications (
                patch_id, finding_id, unit_passed, regression_passed,
                original_finding_gone, decision, evidence_json, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                v.patch_id,
                v.finding_id,
                1 if v.unit_passed else 0,
                1 if v.regression_passed else 0,
                1 if v.original_finding_gone else 0,
                v.decision.value,
                json.dumps(evidence_payload),
                v.timestamp.isoformat(),
            ),
        )
        conn.commit()
        conn.close()

    def get_verification(self, patch_id: str) -> Optional[Verification]:
        """Retrieves a verification record by patch ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM verifications WHERE patch_id = ?", (patch_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None

        evidence_payload = json.loads(row["evidence_json"]) if row["evidence_json"] else {}
        evidence = evidence_payload.get("evidence", {})
        raw_new_findings = evidence_payload.get("new_findings", [])
        new_findings = [Finding.model_validate(f) for f in raw_new_findings]

        return Verification(
            patch_id=row["patch_id"],
            finding_id=row["finding_id"],
            unit_passed=bool(row["unit_passed"]),
            regression_passed=bool(row["regression_passed"]),
            original_finding_gone=bool(row["original_finding_gone"]),
            new_findings=new_findings,
            decision=DecisionEnum(row["decision"]),
            evidence=evidence,
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )


db = Database()
