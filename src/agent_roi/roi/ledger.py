from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Mapping, Optional
import uuid

from agent_roi._serialization import canonical_json


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _money_to_cents(value: Any) -> int:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Money values must be numeric") from exc
    if not amount.is_finite() or amount < 0:
        raise ValueError("Money values must be finite and nonnegative")
    try:
        amount = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except InvalidOperation as exc:
        raise ValueError("Money values must be numeric") from exc
    return int(amount * 100)


def _cents_to_money(cents: int) -> float:
    return float(Decimal(int(cents)) / Decimal(100))


class ValueType(str, Enum):
    COST_SAVINGS = "cost_savings"
    COST_AVOIDANCE = "cost_avoidance"
    REVENUE = "revenue"
    PRODUCTIVITY = "productivity"
    RISK_REDUCTION = "risk_reduction"


class ValuePeriod(str, Enum):
    ONE_TIME = "one_time"
    MONTHLY = "monthly"
    ANNUAL = "annual"


class OpportunityStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    REALIZING = "realizing"
    VALIDATED = "validated"
    REJECTED = "rejected"
    CLOSED = "closed"


class ValueStage(str, Enum):
    POTENTIAL = "potential"
    FORECAST = "forecast"
    REALIZED = "realized"
    VALIDATED = "validated"


class CostType(str, Enum):
    MODEL = "model"
    INFRASTRUCTURE = "infrastructure"
    HUMAN_REVIEW = "human_review"
    IMPLEMENTATION = "implementation"
    SUPPORT = "support"
    OTHER = "other"


_ALLOWED_TRANSITIONS: dict[OpportunityStatus, frozenset[OpportunityStatus]] = {
    OpportunityStatus.PROPOSED: frozenset({OpportunityStatus.APPROVED, OpportunityStatus.REJECTED}),
    OpportunityStatus.APPROVED: frozenset({OpportunityStatus.IN_PROGRESS, OpportunityStatus.REJECTED}),
    OpportunityStatus.IN_PROGRESS: frozenset({OpportunityStatus.REALIZING, OpportunityStatus.CLOSED}),
    OpportunityStatus.REALIZING: frozenset({OpportunityStatus.VALIDATED, OpportunityStatus.CLOSED}),
    OpportunityStatus.VALIDATED: frozenset({OpportunityStatus.CLOSED}),
    OpportunityStatus.REJECTED: frozenset({OpportunityStatus.CLOSED}),
    OpportunityStatus.CLOSED: frozenset(),
}


@dataclass(frozen=True)
class ValueOpportunity:
    opportunity_id: str
    organization_id: str
    agent_id: str
    business_unit: str
    business_owner: str
    title: str
    value_type: ValueType
    value_period: ValuePeriod
    status: OpportunityStatus
    currency_code: str
    baseline_usd: float
    forecast_value_usd: float
    confidence: float
    source_key: str
    measurement_start: str
    measurement_end: str
    created_at_utc: str
    created_by: str
    metadata: Mapping[str, Any]
    revision: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "opportunity_id": self.opportunity_id,
            "organization_id": self.organization_id,
            "agent_id": self.agent_id,
            "business_unit": self.business_unit,
            "business_owner": self.business_owner,
            "title": self.title,
            "value_type": self.value_type.value,
            "value_period": self.value_period.value,
            "status": self.status.value,
            "currency_code": self.currency_code,
            "baseline_usd": self.baseline_usd,
            "forecast_value_usd": self.forecast_value_usd,
            "confidence": self.confidence,
            "source_key": self.source_key,
            "measurement_start": self.measurement_start,
            "measurement_end": self.measurement_end,
            "created_at_utc": self.created_at_utc,
            "created_by": self.created_by,
            "metadata": dict(self.metadata),
            "revision": self.revision,
        }


class RealizedROILedger:
    """Persistent, evidence-backed enterprise value and cost ledger.

    Monetary values are stored as integer cents. Unique organization/evidence
    keys prevent the same realized benefit or cost from being counted twice.
    The ledger does not convert currencies; portfolio summaries reject mixed
    currencies unless a specific currency is selected.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _connection(self):
        from contextlib import contextmanager

        @contextmanager
        def managed():
            conn = self._connect()
            try:
                with conn:
                    yield conn
            finally:
                conn.close()

        return managed()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS roi_opportunities (
                    opportunity_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    business_unit TEXT NOT NULL,
                    business_owner TEXT NOT NULL,
                    title TEXT NOT NULL,
                    value_type TEXT NOT NULL,
                    value_period TEXT NOT NULL,
                    status TEXT NOT NULL,
                    currency_code TEXT NOT NULL,
                    baseline_cents INTEGER NOT NULL,
                    forecast_cents INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    source_key TEXT NOT NULL,
                    measurement_start TEXT NOT NULL,
                    measurement_end TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 1,
                    UNIQUE (organization_id, source_key)
                );
                CREATE TABLE IF NOT EXISTS roi_values (
                    measurement_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    opportunity_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    currency_code TEXT NOT NULL,
                    evidence_key TEXT NOT NULL,
                    evidence_uri TEXT NOT NULL,
                    measurement_date TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    UNIQUE (organization_id, evidence_key),
                    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
                );
                CREATE TABLE IF NOT EXISTS roi_costs (
                    cost_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    opportunity_id TEXT,
                    cost_type TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    currency_code TEXT NOT NULL,
                    evidence_key TEXT NOT NULL,
                    incurred_date TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL,
                    recorded_by TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    UNIQUE (organization_id, evidence_key),
                    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
                );
                CREATE TABLE IF NOT EXISTS roi_status_history (
                    history_id TEXT PRIMARY KEY,
                    opportunity_id TEXT NOT NULL,
                    old_status TEXT NOT NULL,
                    new_status TEXT NOT NULL,
                    changed_at_utc TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    FOREIGN KEY (opportunity_id) REFERENCES roi_opportunities(opportunity_id)
                );
                CREATE INDEX IF NOT EXISTS idx_roi_org_agent ON roi_opportunities(organization_id, agent_id);
                CREATE INDEX IF NOT EXISTS idx_roi_values_org_stage ON roi_values(organization_id, stage);
                CREATE INDEX IF NOT EXISTS idx_roi_costs_org_agent ON roi_costs(organization_id, agent_id);
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(roi_opportunities)").fetchall()}
            if "revision" not in columns:
                conn.execute("ALTER TABLE roi_opportunities ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")

    def create_opportunity(
        self,
        *,
        organization_id: str,
        agent_id: str,
        business_unit: str,
        business_owner: str,
        title: str,
        value_type: ValueType | str,
        value_period: ValuePeriod | str,
        baseline_usd: float,
        forecast_value_usd: float,
        confidence: float,
        source_key: str,
        created_by: str,
        currency_code: str = "USD",
        measurement_start: str = "",
        measurement_end: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
        opportunity_id: str = "",
    ) -> ValueOpportunity:
        required = {
            "organization_id": organization_id,
            "agent_id": agent_id,
            "business_unit": business_unit,
            "business_owner": business_owner,
            "title": title,
            "source_key": source_key,
            "created_by": created_by,
        }
        for name, value in required.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        confidence_value = float(confidence)
        if not 0.0 <= confidence_value <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        currency = currency_code.strip().upper()
        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency_code must be a three-letter code")
        opportunity_id = opportunity_id or str(uuid.uuid4())
        created = _utc_now()
        try:
            value_type_enum = ValueType(value_type)
            value_period_enum = ValuePeriod(value_period)
        except ValueError as exc:
            raise ValueError("Invalid value_type or value_period") from exc
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    """INSERT INTO roi_opportunities(
                           opportunity_id,organization_id,agent_id,business_unit,business_owner,title,
                           value_type,value_period,status,currency_code,baseline_cents,forecast_cents,
                           confidence,source_key,measurement_start,measurement_end,created_at_utc,
                           created_by,metadata_json,revision
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        opportunity_id,
                        organization_id.strip(),
                        agent_id.strip(),
                        business_unit.strip(),
                        business_owner.strip(),
                        title.strip(),
                        value_type_enum.value,
                        value_period_enum.value,
                        OpportunityStatus.PROPOSED.value,
                        currency,
                        _money_to_cents(baseline_usd),
                        _money_to_cents(forecast_value_usd),
                        confidence_value,
                        source_key.strip(),
                        measurement_start,
                        measurement_end,
                        created,
                        created_by.strip(),
                        canonical_json(dict(metadata or {})),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(
                    "An ROI opportunity with this source_key already exists for the organization"
                ) from exc
        return self.get_opportunity(opportunity_id)

    def _row_to_opportunity(self, row: sqlite3.Row) -> ValueOpportunity:
        return ValueOpportunity(
            opportunity_id=row["opportunity_id"],
            organization_id=row["organization_id"],
            agent_id=row["agent_id"],
            business_unit=row["business_unit"],
            business_owner=row["business_owner"],
            title=row["title"],
            value_type=ValueType(row["value_type"]),
            value_period=ValuePeriod(row["value_period"]),
            status=OpportunityStatus(row["status"]),
            currency_code=row["currency_code"],
            baseline_usd=_cents_to_money(row["baseline_cents"]),
            forecast_value_usd=_cents_to_money(row["forecast_cents"]),
            confidence=float(row["confidence"]),
            source_key=row["source_key"],
            measurement_start=row["measurement_start"],
            measurement_end=row["measurement_end"],
            created_at_utc=row["created_at_utc"],
            created_by=row["created_by"],
            metadata=json.loads(row["metadata_json"]),
            revision=int(row["revision"]),
        )

    def get_opportunity(self, opportunity_id: str) -> ValueOpportunity:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM roi_opportunities WHERE opportunity_id=?", (opportunity_id,)
            ).fetchone()
        if row is None:
            raise KeyError(opportunity_id)
        return self._row_to_opportunity(row)

    def list_opportunities(
        self,
        *,
        organization_id: str,
        agent_id: str = "",
        status: OpportunityStatus | str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[ValueOpportunity, ...]:
        clauses = ["organization_id=?"]
        params: list[Any] = [organization_id]
        if agent_id:
            clauses.append("agent_id=?")
            params.append(agent_id)
        if status is not None:
            clauses.append("status=?")
            params.append(OpportunityStatus(status).value)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM roi_opportunities WHERE " + " AND ".join(clauses)
                + " ORDER BY created_at_utc LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return tuple(self._row_to_opportunity(row) for row in rows)

    def transition(
        self,
        opportunity_id: str,
        new_status: OpportunityStatus | str,
        *,
        changed_by: str,
        reason: str = "",
        expected_revision: Optional[int] = None,
    ) -> ValueOpportunity:
        new = OpportunityStatus(new_status)
        current = self.get_opportunity(opportunity_id)
        if new not in _ALLOWED_TRANSITIONS[current.status]:
            raise ValueError(f"Invalid ROI status transition: {current.status.value} -> {new.value}")
        with self._lock, self._connection() as conn:
            query = """UPDATE roi_opportunities SET status=?,revision=revision+1
                       WHERE opportunity_id=? AND status=?"""
            params: list[Any] = [new.value, opportunity_id, current.status.value]
            if expected_revision is not None:
                query += " AND revision=?"
                params.append(int(expected_revision))
            cursor = conn.execute(query, params)
            if cursor.rowcount != 1:
                raise ValueError("ROI opportunity revision conflict")
            conn.execute(
                "INSERT INTO roi_status_history VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    opportunity_id,
                    current.status.value,
                    new.value,
                    _utc_now(),
                    changed_by,
                    reason,
                ),
            )
        return self.get_opportunity(opportunity_id)

    def record_value(
        self,
        opportunity_id: str,
        *,
        stage: ValueStage | str,
        amount_usd: float,
        evidence_key: str,
        recorded_by: str,
        evidence_uri: str = "",
        measurement_date: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        opportunity = self.get_opportunity(opportunity_id)
        stage_enum = ValueStage(stage)
        if stage_enum in {ValueStage.REALIZED, ValueStage.VALIDATED} and opportunity.status not in {
            OpportunityStatus.IN_PROGRESS,
            OpportunityStatus.REALIZING,
            OpportunityStatus.VALIDATED,
        }:
            raise ValueError("Realized or validated value requires an in-progress opportunity")
        if not evidence_key.strip() or not recorded_by.strip():
            raise ValueError("evidence_key and recorded_by are required")
        measurement_id = str(uuid.uuid4())
        date_value = measurement_date or date.today().isoformat()
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO roi_values VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        measurement_id,
                        opportunity.organization_id,
                        opportunity_id,
                        stage_enum.value,
                        _money_to_cents(amount_usd),
                        opportunity.currency_code,
                        evidence_key.strip(),
                        evidence_uri,
                        date_value,
                        _utc_now(),
                        recorded_by.strip(),
                        notes,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("This evidence_key has already been counted") from exc
        return {
            "measurement_id": measurement_id,
            "opportunity_id": opportunity_id,
            "stage": stage_enum.value,
            "amount_usd": _cents_to_money(_money_to_cents(amount_usd)),
            "currency_code": opportunity.currency_code,
            "evidence_key": evidence_key,
            "evidence_uri": evidence_uri,
            "measurement_date": date_value,
        }

    def record_cost(
        self,
        *,
        organization_id: str,
        agent_id: str,
        cost_type: CostType | str,
        amount_usd: float,
        currency_code: str,
        evidence_key: str,
        recorded_by: str,
        opportunity_id: str = "",
        incurred_date: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        if opportunity_id:
            opportunity = self.get_opportunity(opportunity_id)
            if opportunity.organization_id != organization_id or opportunity.agent_id != agent_id:
                raise ValueError("Cost opportunity does not match organization and agent")
        if not evidence_key.strip() or not recorded_by.strip():
            raise ValueError("evidence_key and recorded_by are required")
        currency = currency_code.strip().upper()
        cost_id = str(uuid.uuid4())
        date_value = incurred_date or date.today().isoformat()
        with self._lock, self._connection() as conn:
            try:
                conn.execute(
                    "INSERT INTO roi_costs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        cost_id,
                        organization_id,
                        agent_id,
                        opportunity_id or None,
                        CostType(cost_type).value,
                        _money_to_cents(amount_usd),
                        currency,
                        evidence_key.strip(),
                        date_value,
                        _utc_now(),
                        recorded_by.strip(),
                        notes,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("This cost evidence_key has already been counted") from exc
        return {
            "cost_id": cost_id,
            "organization_id": organization_id,
            "agent_id": agent_id,
            "cost_type": CostType(cost_type).value,
            "amount_usd": _cents_to_money(_money_to_cents(amount_usd)),
            "currency_code": currency,
            "evidence_key": evidence_key,
            "incurred_date": date_value,
        }

    def portfolio_summary(
        self,
        *,
        organization_id: str,
        currency_code: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        opportunities = self.list_opportunities(organization_id=organization_id, agent_id=agent_id)
        currencies = {item.currency_code for item in opportunities}
        if currency_code:
            selected = currency_code.upper()
        elif len(currencies) <= 1:
            selected = next(iter(currencies), "USD")
        else:
            raise ValueError("Portfolio contains multiple currencies; select currency_code")
        opportunities = tuple(item for item in opportunities if item.currency_code == selected)
        opportunity_ids = {item.opportunity_id for item in opportunities}
        forecast_cents = sum(_money_to_cents(item.forecast_value_usd) for item in opportunities)
        baseline_cents = sum(_money_to_cents(item.baseline_usd) for item in opportunities)

        with self._connection() as conn:
            values = conn.execute(
                "SELECT opportunity_id, stage, amount_cents FROM roi_values WHERE organization_id=? AND currency_code=?",
                (organization_id, selected),
            ).fetchall()
            costs = conn.execute(
                "SELECT agent_id, opportunity_id, amount_cents FROM roi_costs WHERE organization_id=? AND currency_code=?",
                (organization_id, selected),
            ).fetchall()
        realized_cents = sum(
            row["amount_cents"]
            for row in values
            if row["opportunity_id"] in opportunity_ids and row["stage"] == ValueStage.REALIZED.value
        )
        validated_cents = sum(
            row["amount_cents"]
            for row in values
            if row["opportunity_id"] in opportunity_ids and row["stage"] == ValueStage.VALIDATED.value
        )
        cost_cents = sum(
            row["amount_cents"]
            for row in costs
            if (not agent_id or row["agent_id"] == agent_id)
            and (not row["opportunity_id"] or row["opportunity_id"] in opportunity_ids)
        )
        net_cents = validated_cents - cost_cents
        roi_multiple = None if cost_cents == 0 else round(validated_cents / cost_cents, 4)
        return {
            "organization_id": organization_id,
            "agent_id": agent_id or None,
            "currency_code": selected,
            "opportunity_count": len(opportunities),
            "baseline_usd": _cents_to_money(baseline_cents),
            "forecast_value_usd": _cents_to_money(forecast_cents),
            "realized_value_usd": _cents_to_money(realized_cents),
            "validated_value_usd": _cents_to_money(validated_cents),
            "total_cost_usd": _cents_to_money(cost_cents),
            "net_validated_value_usd": _cents_to_money(net_cents),
            "validated_roi_multiple": roi_multiple,
            "status_counts": {
                status.value: sum(1 for item in opportunities if item.status is status)
                for status in OpportunityStatus
            },
        }
