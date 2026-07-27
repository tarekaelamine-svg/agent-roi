from __future__ import annotations

from agent_roi.enterprise.outbox import OutboxEvent, OutboxStore

from .base import ApprovalRecord, ApprovalRequest


class OutboxApprovalProvider:
    """Persist approval delivery before returning to the guarded runtime."""

    name = "outbox"

    def __init__(
        self,
        store: OutboxStore,
        *,
        destination: str,
        request_topic: str = "approval.requested",
        update_topic: str = "approval.updated",
    ) -> None:
        self.store = store
        self.destination = destination
        self.request_topic = request_topic
        self.update_topic = update_topic

    def submit(self, request: ApprovalRequest) -> str:
        self.store.enqueue(
            OutboxEvent.create(
                topic=self.request_topic,
                destination=self.destination,
                payload=request.to_dict(),
                idempotency_key=f"approval-request:{request.checkpoint_id}",
            )
        )
        return request.request_id

    def update(self, record: ApprovalRecord) -> None:
        self.store.enqueue(
            OutboxEvent.create(
                topic=self.update_topic,
                destination=self.destination,
                payload={
                    "request": record.request.to_dict(),
                    "status": record.status.value,
                    "external_id": record.external_id,
                    "decided_by": record.decided_by,
                    "reason": record.reason,
                    "decided_at_epoch_ms": record.decided_at_epoch_ms,
                },
                idempotency_key=(
                    f"approval-update:{record.request.checkpoint_id}:"
                    f"{record.status.value}:{record.decided_at_epoch_ms}"
                ),
            )
        )
