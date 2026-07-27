from __future__ import annotations

import json
import time
from typing import Any, Mapping, Optional

from agent_roi._serialization import canonical_json
from agent_roi.db import (
    PostgresConnectionFactory,
    PostgresMigrationManager,
    fetchall_mappings,
    fetchone_mapping,
)
from agent_roi.runtime.tools import ApprovalGrant

from .base import ApprovalRecord, ApprovalRequest, ApprovalStatus, SqliteApprovalRepository


class PostgresApprovalRepository:
    """Multi-node approval repository with optimistic concurrency and grant consumption."""

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "agent_roi",
        connect_factory: Any = None,
        auto_migrate: bool = True,
    ) -> None:
        self.connection_factory = PostgresConnectionFactory(
            dsn, schema=schema, connect_factory=connect_factory
        )
        if auto_migrate:
            PostgresMigrationManager(self.connection_factory).migrate()

    @staticmethod
    def _request_from_dict(data: Mapping[str, Any]) -> ApprovalRequest:
        return SqliteApprovalRepository._request_from_dict(data)

    def save_record(
        self, record: ApprovalRecord, *, expected_revision: Optional[int] = None
    ) -> int:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO approval_records(
                               checkpoint_id,action_digest,organization_id,environment,agent_id,
                               request_json,status,external_id,decided_by,decision_reason,
                               decided_at_epoch_ms,updated_at_utc,revision
                           ) VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP,1)
                           ON CONFLICT(checkpoint_id) DO UPDATE SET
                             status=EXCLUDED.status,external_id=EXCLUDED.external_id,
                             decided_by=EXCLUDED.decided_by,decision_reason=EXCLUDED.decision_reason,
                             decided_at_epoch_ms=EXCLUDED.decided_at_epoch_ms,
                             updated_at_utc=CURRENT_TIMESTAMP,revision=approval_records.revision+1
                           RETURNING revision""",
                        (
                            record.request.checkpoint_id,
                            record.request.action_digest,
                            record.request.organization_id,
                            record.request.environment,
                            record.request.agent_id,
                            canonical_json(record.request.to_dict()),
                            record.status.value,
                            record.external_id,
                            record.decided_by,
                            record.reason,
                            record.decided_at_epoch_ms,
                        ),
                    )
                else:
                    cursor.execute(
                        """UPDATE approval_records SET status=%s,external_id=%s,decided_by=%s,
                               decision_reason=%s,decided_at_epoch_ms=%s,
                               updated_at_utc=CURRENT_TIMESTAMP,revision=revision+1
                           WHERE checkpoint_id=%s AND revision=%s RETURNING revision""",
                        (
                            record.status.value,
                            record.external_id,
                            record.decided_by,
                            record.reason,
                            record.decided_at_epoch_ms,
                            record.request.checkpoint_id,
                            int(expected_revision),
                        ),
                    )
                row = cursor.fetchone()
                if row is None:
                    raise ValueError("Approval record revision conflict")
                return int(row["revision"] if isinstance(row, Mapping) else row[0])
            finally:
                cursor.close()

    def get_record(self, checkpoint_id: str) -> ApprovalRecord:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT * FROM approval_records WHERE checkpoint_id=%s", (checkpoint_id,)
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(checkpoint_id)
        request_data = row["request_json"]
        if isinstance(request_data, str):
            request_data = json.loads(request_data)
        request = self._request_from_dict(request_data)
        return ApprovalRecord(
            request=request,
            status=ApprovalStatus(str(row["status"])),
            external_id=str(row["external_id"]),
            decided_by=str(row["decided_by"]),
            reason=str(row["decision_reason"]),
            decided_at_epoch_ms=int(row.get("decided_at_epoch_ms", 0) or 0),
        )

    def pending(
        self,
        *,
        organization_id: str = "",
        environment: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[ApprovalRecord, ...]:
        clauses = ["status=%s"]
        params: list[Any] = [ApprovalStatus.PENDING.value]
        if organization_id:
            clauses.append("organization_id=%s")
            params.append(organization_id)
        if environment:
            clauses.append("environment=%s")
            params.append(environment)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT checkpoint_id FROM approval_records WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY updated_at_utc LIMIT %s OFFSET %s",
                    tuple(params),
                )
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
        return tuple(self.get_record(str(row["checkpoint_id"])) for row in rows)

    def save_grant(self, grant: ApprovalGrant, *, expected_revision: Optional[int] = None) -> int:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                if expected_revision is None:
                    cursor.execute(
                        """INSERT INTO approval_grants(
                               action_digest,checkpoint_id,approved_by,expires_at_epoch_ms,reason,revision
                           ) VALUES (%s,%s,%s,%s,%s,1)
                           ON CONFLICT(action_digest) DO UPDATE SET
                             checkpoint_id=EXCLUDED.checkpoint_id,approved_by=EXCLUDED.approved_by,
                             expires_at_epoch_ms=EXCLUDED.expires_at_epoch_ms,reason=EXCLUDED.reason,
                             consumed_at_utc=NULL,revision=approval_grants.revision+1
                           RETURNING revision""",
                        (
                            grant.action_digest,
                            grant.checkpoint_id or "",
                            grant.approved_by,
                            grant.expires_at_epoch_ms,
                            grant.reason,
                        ),
                    )
                else:
                    cursor.execute(
                        """UPDATE approval_grants SET checkpoint_id=%s,approved_by=%s,
                               expires_at_epoch_ms=%s,reason=%s,consumed_at_utc=NULL,revision=revision+1
                           WHERE action_digest=%s AND revision=%s RETURNING revision""",
                        (
                            grant.checkpoint_id or "",
                            grant.approved_by,
                            grant.expires_at_epoch_ms,
                            grant.reason,
                            grant.action_digest,
                            int(expected_revision),
                        ),
                    )
                row = cursor.fetchone()
                if row is None:
                    raise ValueError("Approval grant revision conflict")
                return int(row["revision"] if isinstance(row, Mapping) else row[0])
            finally:
                cursor.close()

    def get_grant(self, action_digest: str) -> ApprovalGrant:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT * FROM approval_grants
                       WHERE action_digest=%s AND consumed_at_utc IS NULL""",
                    (action_digest,),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(action_digest)
        if int(row["expires_at_epoch_ms"]) < int(time.time() * 1000):
            raise KeyError(action_digest)
        return ApprovalGrant(
            action_digest=str(row["action_digest"]),
            approved_by=str(row["approved_by"]),
            expires_at_epoch_ms=int(row["expires_at_epoch_ms"]),
            checkpoint_id=str(row["checkpoint_id"]) or None,
            reason=str(row["reason"]),
        )

    def consume_grant(self, action_digest: str) -> ApprovalGrant:
        """Atomically consume a grant so it cannot authorize a second execution."""
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """UPDATE approval_grants SET consumed_at_utc=CURRENT_TIMESTAMP,revision=revision+1
                       WHERE action_digest=%s AND consumed_at_utc IS NULL
                         AND expires_at_epoch_ms >= %s
                       RETURNING *""",
                    (action_digest, int(time.time() * 1000)),
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
        if row is None:
            raise KeyError(action_digest)
        return ApprovalGrant(
            action_digest=str(row["action_digest"]),
            approved_by=str(row["approved_by"]),
            expires_at_epoch_ms=int(row["expires_at_epoch_ms"]),
            checkpoint_id=str(row["checkpoint_id"]) or None,
            reason=str(row["reason"]),
        )
