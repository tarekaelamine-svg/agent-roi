from __future__ import annotations

from datetime import date
import json
from typing import Any, Mapping, Optional
import uuid

from agent_roi._serialization import canonical_json
from agent_roi.db import (
    PostgresConnectionFactory,
    PostgresMigrationManager,
    fetchall_mappings,
    fetchone_mapping,
)

from .ledger import (
    CostType,
    OpportunityStatus,
    ValueOpportunity,
    ValuePeriod,
    ValueStage,
    ValueType,
    _ALLOWED_TRANSITIONS,
    _cents_to_money,
    _money_to_cents,
    _utc_now,
)


def _json_value(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        return dict(json.loads(value))
    return dict(value or {})


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


class PostgresROILedger:
    """Multi-node realized-value ledger backed by PostgreSQL."""

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
        try:
            value_type_enum = ValueType(value_type)
            value_period_enum = ValuePeriod(value_period)
        except ValueError as exc:
            raise ValueError("Invalid value_type or value_period") from exc
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO roi_opportunities(
                           opportunity_id,organization_id,agent_id,business_unit,business_owner,title,
                           value_type,value_period,status,currency_code,baseline_cents,forecast_cents,
                           confidence,source_key,measurement_start,measurement_end,created_at_utc,
                           created_by,metadata_json,revision
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,1)""",
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
                        _utc_now(),
                        created_by.strip(),
                        canonical_json(dict(metadata or {})),
                    ),
                )
            except Exception as exc:
                raise ValueError(
                    "An ROI opportunity with this source_key already exists for the organization"
                ) from exc
            finally:
                cursor.close()
        return self.get_opportunity(opportunity_id)

    @staticmethod
    def _row_to_opportunity(row: Mapping[str, Any]) -> ValueOpportunity:
        return ValueOpportunity(
            opportunity_id=str(row["opportunity_id"]),
            organization_id=str(row["organization_id"]),
            agent_id=str(row["agent_id"]),
            business_unit=str(row["business_unit"]),
            business_owner=str(row["business_owner"]),
            title=str(row["title"]),
            value_type=ValueType(str(row["value_type"])),
            value_period=ValuePeriod(str(row["value_period"])),
            status=OpportunityStatus(str(row["status"])),
            currency_code=str(row["currency_code"]),
            baseline_usd=_cents_to_money(int(row["baseline_cents"])),
            forecast_value_usd=_cents_to_money(int(row["forecast_cents"])),
            confidence=float(row["confidence"]),
            source_key=str(row["source_key"]),
            measurement_start=str(row["measurement_start"]),
            measurement_end=str(row["measurement_end"]),
            created_at_utc=_iso(row["created_at_utc"]),
            created_by=str(row["created_by"]),
            metadata=_json_value(row["metadata_json"]),
            revision=int(row.get("revision", 1)),
        )

    def get_opportunity(self, opportunity_id: str) -> ValueOpportunity:
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT * FROM roi_opportunities WHERE opportunity_id=%s", (opportunity_id,)
                )
                row = fetchone_mapping(cursor)
            finally:
                cursor.close()
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
        clauses = ["organization_id=%s"]
        params: list[Any] = [organization_id]
        if agent_id:
            clauses.append("agent_id=%s")
            params.append(agent_id)
        if status is not None:
            clauses.append("status=%s")
            params.append(OpportunityStatus(status).value)
        params.extend([max(1, min(int(limit), 500)), max(0, int(offset))])
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "SELECT * FROM roi_opportunities WHERE "
                    + " AND ".join(clauses)
                    + " ORDER BY created_at_utc LIMIT %s OFFSET %s",
                    tuple(params),
                )
                rows = fetchall_mappings(cursor)
            finally:
                cursor.close()
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
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                query = """UPDATE roi_opportunities SET status=%s,revision=revision+1
                           WHERE opportunity_id=%s AND status=%s"""
                params: list[Any] = [new.value, opportunity_id, current.status.value]
                if expected_revision is not None:
                    query += " AND revision=%s"
                    params.append(int(expected_revision))
                cursor.execute(query, tuple(params))
                if cursor.rowcount != 1:
                    raise ValueError("ROI opportunity revision conflict")
                cursor.execute(
                    """INSERT INTO roi_status_history(
                           history_id,opportunity_id,old_status,new_status,changed_at_utc,changed_by,reason
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s)""",
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
            finally:
                cursor.close()
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
        cents = _money_to_cents(amount_usd)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO roi_values(
                           measurement_id,organization_id,opportunity_id,stage,amount_cents,
                           currency_code,evidence_key,evidence_uri,measurement_date,recorded_at_utc,
                           recorded_by,notes
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        measurement_id,
                        opportunity.organization_id,
                        opportunity_id,
                        stage_enum.value,
                        cents,
                        opportunity.currency_code,
                        evidence_key.strip(),
                        evidence_uri,
                        date_value,
                        _utc_now(),
                        recorded_by.strip(),
                        notes,
                    ),
                )
            except Exception as exc:
                raise ValueError("This evidence_key has already been counted") from exc
            finally:
                cursor.close()
        return {
            "measurement_id": measurement_id,
            "opportunity_id": opportunity_id,
            "stage": stage_enum.value,
            "amount_usd": _cents_to_money(cents),
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
        cents = _money_to_cents(amount_usd)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """INSERT INTO roi_costs(
                           cost_id,organization_id,agent_id,opportunity_id,cost_type,amount_cents,
                           currency_code,evidence_key,incurred_date,recorded_at_utc,recorded_by,notes
                       ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        cost_id,
                        organization_id,
                        agent_id,
                        opportunity_id or None,
                        CostType(cost_type).value,
                        cents,
                        currency,
                        evidence_key.strip(),
                        date_value,
                        _utc_now(),
                        recorded_by.strip(),
                        notes,
                    ),
                )
            except Exception as exc:
                raise ValueError("This cost evidence_key has already been counted") from exc
            finally:
                cursor.close()
        return {
            "cost_id": cost_id,
            "organization_id": organization_id,
            "agent_id": agent_id,
            "cost_type": CostType(cost_type).value,
            "amount_usd": _cents_to_money(cents),
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
        opportunities = self.list_opportunities(
            organization_id=organization_id, agent_id=agent_id, limit=500
        )
        currencies = {item.currency_code for item in opportunities}
        if currency_code:
            selected = currency_code.upper()
        elif len(currencies) <= 1:
            selected = next(iter(currencies), "USD")
        else:
            raise ValueError("Portfolio contains multiple currencies; select currency_code")
        opportunities = tuple(item for item in opportunities if item.currency_code == selected)
        ids = {item.opportunity_id for item in opportunities}
        forecast_cents = sum(_money_to_cents(item.forecast_value_usd) for item in opportunities)
        baseline_cents = sum(_money_to_cents(item.baseline_usd) for item in opportunities)
        with self.connection_factory.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """SELECT opportunity_id,stage,amount_cents FROM roi_values
                       WHERE organization_id=%s AND currency_code=%s""",
                    (organization_id, selected),
                )
                values = fetchall_mappings(cursor)
                cursor.execute(
                    """SELECT agent_id,opportunity_id,amount_cents FROM roi_costs
                       WHERE organization_id=%s AND currency_code=%s""",
                    (organization_id, selected),
                )
                costs = fetchall_mappings(cursor)
            finally:
                cursor.close()
        realized_cents = sum(
            int(row["amount_cents"])
            for row in values
            if row["opportunity_id"] in ids and row["stage"] == ValueStage.REALIZED.value
        )
        validated_cents = sum(
            int(row["amount_cents"])
            for row in values
            if row["opportunity_id"] in ids and row["stage"] == ValueStage.VALIDATED.value
        )
        cost_cents = sum(
            int(row["amount_cents"])
            for row in costs
            if (not agent_id or row["agent_id"] == agent_id)
            and (not row["opportunity_id"] or row["opportunity_id"] in ids)
        )
        net_cents = validated_cents - cost_cents
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
            "validated_roi_multiple": None if cost_cents == 0 else round(validated_cents / cost_cents, 4),
            "status_counts": {
                status.value: sum(1 for item in opportunities if item.status is status)
                for status in OpportunityStatus
            },
        }
