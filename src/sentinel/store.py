from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import Lock
from uuid import UUID, uuid4

from sentinel.contracts import ApprovalEvent, ScanBundle


@dataclass
class ScanRecord:
    scan_id: UUID = field(default_factory=uuid4)
    state: str = "queued"
    source: str = ""
    requested_ref: str = "HEAD"
    requested_through: str = "module1"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    bundle: ScanBundle | None = None
    error_code: str | None = None
    error_message: str | None = None


class MemoryStore:
    """Local development store; production adapters persist the same contracts in PostgreSQL."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.scans: dict[UUID, ScanRecord] = {}
        self.idempotency: dict[str, UUID] = {}
        self.approvals: list[ApprovalEvent] = []

    def create_scan(
        self, *, key: str, source: str, ref: str, through: str
    ) -> tuple[ScanRecord, bool]:
        with self._lock:
            if key in self.idempotency:
                return self.scans[self.idempotency[key]], False
            record = ScanRecord(
                source=source,
                requested_ref=ref,
                requested_through=through,
            )
            self.scans[record.scan_id] = record
            self.idempotency[key] = record.scan_id
            return record, True

    def get_scan(self, scan_id: UUID) -> ScanRecord:
        try:
            return self.scans[scan_id]
        except KeyError as exc:
            raise KeyError("scan not found") from exc

    def complete(self, scan_id: UUID, bundle: ScanBundle) -> None:
        with self._lock:
            record = self.scans[scan_id]
            record.bundle = bundle
            record.state = "completed"
            record.updated_at = datetime.now(UTC)

    def fail(self, scan_id: UUID, code: str, message: str) -> None:
        with self._lock:
            record = self.scans[scan_id]
            record.state = "failed"
            record.error_code = code
            record.error_message = message
            record.updated_at = datetime.now(UTC)
