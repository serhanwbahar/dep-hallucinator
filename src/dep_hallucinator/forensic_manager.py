"""
Forensic capabilities for historical tracking and analysis.

Provides persistent storage of scan results, change tracking, and comparison
capabilities for security investigations and compliance.
"""

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .error_handling import ErrorCategory, get_error_handler
from .scanner import RiskLevel, ScanResult, SecurityFinding


class ChangeType(Enum):
    """Types of changes detected between scans."""

    PACKAGE_ADDED = "package_added"
    PACKAGE_REMOVED = "package_removed"
    RISK_INCREASED = "risk_increased"
    RISK_DECREASED = "risk_decreased"
    VERSION_CHANGED = "version_changed"
    NEW_VULNERABILITY = "new_vulnerability"
    RESOLVED_VULNERABILITY = "resolved_vulnerability"


@dataclass(frozen=True)
class ScanMetadata:
    """Metadata about a scan execution."""

    scan_id: str
    file_path: str
    file_hash: str
    scan_timestamp: str
    scanner_version: str = "1.0.0"
    total_dependencies: int = 0
    scan_duration_ms: int = 0
    scan_options: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class PackageChange:
    """A change detected between two scans."""

    package_name: str
    change_type: ChangeType
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    old_risk_level: Optional[str] = None
    new_risk_level: Optional[str] = None
    description: str = ""


class ForensicManager:
    """Main forensic manager for historical analysis and comparison."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize forensic manager."""
        if db_path is None:
            config_dir = Path.home() / ".config" / "dep-hallucinator"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "forensic_history.db"

        self.db_path = db_path
        self.error_handler = get_error_handler()
        self._init_database()

    def _init_database(self):
        """Initialize database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executescript(
                    """
                CREATE TABLE IF NOT EXISTS scan_metadata (
                    scan_id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    scan_timestamp TEXT NOT NULL,
                    scanner_version TEXT NOT NULL DEFAULT '1.0.0',
                    total_dependencies INTEGER DEFAULT 0,
                    scan_duration_ms INTEGER DEFAULT 0,
                    scan_options TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS scan_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT,
                    risk_level TEXT NOT NULL,
                    suspicion_score REAL,
                    ml_probability REAL,
                    reasons TEXT,
                    recommendations TEXT,
                    registry_exists BOOLEAN,
                    signature_verified BOOLEAN,
                    finding_data TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                );
                
                CREATE TABLE IF NOT EXISTS scan_summary (
                    scan_id TEXT PRIMARY KEY,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    total_packages INTEGER DEFAULT 0,
                    has_vulnerabilities BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_metadata(scan_timestamp);
                CREATE INDEX IF NOT EXISTS idx_file_path ON scan_metadata(file_path);
                CREATE INDEX IF NOT EXISTS idx_package_name ON scan_findings(package_name);
                """
                )
        except sqlite3.Error as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to initialize forensic database: {e}",
                "forensic_manager",
                "_init_database",
                exception=e,
            )
            raise

    def store_scan(
        self,
        scan_result: ScanResult,
        file_path: str,
        scan_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Store a scan result for historical analysis."""
        try:
            scan_id = str(uuid.uuid4())
            file_hash = self._calculate_file_hash(file_path)
            timestamp = datetime.now(timezone.utc).isoformat()

            with sqlite3.connect(self.db_path) as conn:
                # Store metadata
                conn.execute(
                    """
                    INSERT INTO scan_metadata 
                    (scan_id, file_path, file_hash, scan_timestamp, scanner_version,
                     total_dependencies, scan_duration_ms, scan_options)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        scan_id,
                        file_path,
                        file_hash,
                        timestamp,
                        "1.0.0",
                        scan_result.total_dependencies,
                        scan_result.scan_duration_ms,
                        json.dumps(scan_options) if scan_options else None,
                    ),
                )

                # Store findings
                for finding in scan_result.findings:
                    self._store_finding(conn, scan_id, finding)

                # Store summary
                summary = self._calculate_summary(scan_result)
                conn.execute(
                    """
                    INSERT INTO scan_summary
                    (scan_id, critical_count, high_count, medium_count, low_count,
                     error_count, total_packages, has_vulnerabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        scan_id,
                        summary["critical"],
                        summary["high"],
                        summary["medium"],
                        summary["low"],
                        summary["error"],
                        summary["total"],
                        scan_result.has_critical_vulnerabilities,
                    ),
                )

                conn.commit()
                return scan_id

        except (sqlite3.Error, ValueError) as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to store scan result: {e}",
                "forensic_manager",
                "store_scan",
                exception=e,
            )
            raise

    def _store_finding(
        self, conn: sqlite3.Connection, scan_id: str, finding: SecurityFinding
    ):
        """Store a security finding."""
        suspicion_score = (
            finding.heuristic_score.overall_score if finding.heuristic_score else None
        )
        ml_probability = (
            finding.heuristic_score.ml_analysis.overall_ai_probability
            if (finding.heuristic_score and finding.heuristic_score.ml_analysis)
            else None
        )

        registry_exists = None
        if finding.registry_result and finding.registry_result.package_info:
            registry_exists = finding.registry_result.package_info.exists

        conn.execute(
            """
            INSERT INTO scan_findings
            (scan_id, package_name, package_version, risk_level, suspicion_score,
             ml_probability, reasons, recommendations, registry_exists, 
             signature_verified, finding_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan_id,
                finding.dependency.name,
                finding.dependency.version,
                finding.risk_level.value,
                suspicion_score,
                ml_probability,
                json.dumps(finding.reasons) if finding.reasons else None,
                (
                    json.dumps(finding.recommendations)
                    if finding.recommendations
                    else None
                ),
                registry_exists,
                finding.signature_verified,
                json.dumps(self._serialize_finding(finding)),
            ),
        )

    def _serialize_finding(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Serialize a SecurityFinding for storage."""
        return {
            "dependency": {
                "name": finding.dependency.name,
                "version": finding.dependency.version,
                "source_file": finding.dependency.source_file,
            },
            "risk_level": finding.risk_level.value,
            "reasons": finding.reasons,
            "recommendations": finding.recommendations,
            "signature_verified": finding.signature_verified,
        }

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file for change detection."""
        try:
            with open(file_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except OSError:
            return "unknown"

    def _calculate_summary(self, scan_result: ScanResult) -> Dict[str, int]:
        """Calculate summary statistics."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "error": 0}

        for finding in scan_result.findings:
            if finding.risk_level == RiskLevel.CRITICAL:
                summary["critical"] += 1
            elif finding.risk_level == RiskLevel.HIGH:
                summary["high"] += 1
            elif finding.risk_level == RiskLevel.MEDIUM:
                summary["medium"] += 1
            elif finding.risk_level == RiskLevel.LOW:
                summary["low"] += 1
            elif finding.risk_level == RiskLevel.ERROR:
                summary["error"] += 1

        summary["total"] = len(scan_result.findings)
        return summary

    def get_scan_history(
        self, file_path: Optional[str] = None, limit: int = 50
    ) -> List[ScanMetadata]:
        """Get scan history for analysis."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                if file_path:
                    cursor = conn.execute(
                        """
                        SELECT scan_id, file_path, file_hash, scan_timestamp, scanner_version,
                               total_dependencies, scan_duration_ms, scan_options
                        FROM scan_metadata 
                        WHERE file_path = ?
                        ORDER BY scan_timestamp DESC 
                        LIMIT ?
                    """,
                        (file_path, limit),
                    )
                else:
                    cursor = conn.execute(
                        """
                        SELECT scan_id, file_path, file_hash, scan_timestamp, scanner_version,
                               total_dependencies, scan_duration_ms, scan_options
                        FROM scan_metadata 
                        ORDER BY scan_timestamp DESC 
                        LIMIT ?
                    """,
                        (limit,),
                    )

                history = []
                for row in cursor.fetchall():
                    scan_options = json.loads(row[7]) if row[7] else None
                    history.append(
                        ScanMetadata(
                            scan_id=row[0],
                            file_path=row[1],
                            file_hash=row[2],
                            scan_timestamp=row[3],
                            scanner_version=row[4],
                            total_dependencies=row[5],
                            scan_duration_ms=row[6],
                            scan_options=scan_options,
                        )
                    )

                return history

        except (sqlite3.Error, ValueError) as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to get scan history: {e}",
                "forensic_manager",
                "get_scan_history",
                exception=e,
            )
            return []

    def get_package_timeline(
        self, package_name: str, file_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get timeline of a specific package across scans."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = """
                    SELECT sm.scan_timestamp, sf.package_version, sf.risk_level,
                           sf.suspicion_score, sf.ml_probability, sf.registry_exists
                    FROM scan_findings sf
                    JOIN scan_metadata sm ON sf.scan_id = sm.scan_id
                    WHERE sf.package_name = ?
                """
                params = [package_name]

                if file_path:
                    query += " AND sm.file_path = ?"
                    params.append(file_path)

                query += " ORDER BY sm.scan_timestamp ASC"

                cursor = conn.execute(query, params)

                timeline = []
                for row in cursor.fetchall():
                    timeline.append(
                        {
                            "timestamp": row[0],
                            "version": row[1],
                            "risk_level": row[2],
                            "suspicion_score": row[3],
                            "ml_probability": row[4],
                            "registry_exists": row[5],
                        }
                    )

                return timeline

        except sqlite3.Error as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to get package timeline: {e}",
                "forensic_manager",
                "get_package_timeline",
                exception=e,
            )
            return []

    def cleanup_old_data(self, retention_days: int = 90) -> Dict[str, int]:
        """Clean up old forensic data."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
            cutoff_str = cutoff_date.isoformat()

            with sqlite3.connect(self.db_path) as conn:
                # Get scan IDs to delete
                cursor = conn.execute(
                    """
                    SELECT scan_id FROM scan_metadata WHERE scan_timestamp < ?
                """,
                    (cutoff_str,),
                )

                scan_ids = [row[0] for row in cursor.fetchall()]

                if scan_ids:
                    # Delete related records
                    for scan_id in scan_ids:
                        conn.execute(
                            "DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,)
                        )
                        conn.execute(
                            "DELETE FROM scan_summary WHERE scan_id = ?", (scan_id,)
                        )
                        conn.execute(
                            "DELETE FROM scan_metadata WHERE scan_id = ?", (scan_id,)
                        )

                    conn.commit()

                return {"deleted_scans": len(scan_ids)}

        except sqlite3.Error as e:
            self.error_handler.error(
                ErrorCategory.FILESYSTEM,
                f"Failed to cleanup old scans: {e}",
                "forensic_manager",
                "cleanup_old_data",
                exception=e,
            )
            return {"deleted_scans": 0}


# Global instance
_forensic_manager: Optional[ForensicManager] = None


def get_forensic_manager() -> ForensicManager:
    """Get the global forensic manager instance."""
    global _forensic_manager
    if _forensic_manager is None:
        _forensic_manager = ForensicManager()
    return _forensic_manager
