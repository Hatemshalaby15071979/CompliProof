#!/usr/bin/env python3
"""Prototype confidence gate for CompliProof.

The asserted lineage from Live Support Assistant's tooling/gate/verify-gate.mjs
is unverified. The gate is present but is not imported by the reconciliation
server or CLI. It requires an absolute floor and a measured margin between the
best and second-best match; when the margin is not met, it escalates.

Usage:
    from compliproof.gate import ConfidenceGate, GateDecision
    gate = ConfidenceGate(min_margin=0.18)
    result = gate.evaluate(best_score=0.72, second_score=0.55)
    # result.decision == "escalate" when the margin is below the floor
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

DEFAULT_MIN_MARGIN = 0.18
DEFAULT_ABSOLUTE_FLOOR = 0.60


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class GateDecision:
    """The result of evaluating a confidence gate."""

    decision: str  # "answer" | "escalate"
    margin: float
    best_score: float
    second_score: float
    floor: float
    min_margin: float
    reason: str
    timestamp: str = field(default_factory=_now)
    procedure_title: str | None = None
    suggested_reply: str | None = None
    evidence_passages: list[str] = field(default_factory=list)
    escalation_record: dict | None = None

    def to_dict(self) -> dict:
        return {
            "decision": self.decision,
            "margin": self.margin,
            "best_score": self.best_score,
            "second_score": self.second_score,
            "floor": self.floor,
            "min_margin": self.min_margin,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "procedure_title": self.procedure_title,
            "suggested_reply": self.suggested_reply,
            "evidence_passages": self.evidence_passages,
            "escalation_record": self.escalation_record,
        }


@dataclass
class GateConfig:
    """Gate configuration. Audited so any change can be traced."""

    min_margin: float = DEFAULT_MIN_MARGIN
    absolute_floor: float = DEFAULT_ABSOLUTE_FLOOR
    top_k: int = 5
    require_evidence: bool = True


class ConfidenceGate:
    """Deterministic confidence gate with human escalation fallback.

    The gate answers only when the best procedure clears both:
      1. the absolute floor (best_score >= floor)
      2. the margin between best and second-best (best - second >= min_margin)

    If either condition fails, the query is escalated — no procedure content,
    no title, no suggested reply is exposed. This is safety-first by design:
    a wrong procedure in an audit reply is a compliance breach, not a drafting
    aid.
    """

    def __init__(self, config: GateConfig | None = None):
        self.config = config or GateConfig()

    def evaluate(
        self,
        best_score: float,
        second_score: float,
        best_procedure: dict | None = None,
        all_scores: list[dict] | None = None,
    ) -> GateDecision:
        """Evaluate a query against the confidence gate.

        Args:
            best_score: top-1 match score (0-1)
            second_score: top-2 match score (0-1)
            best_procedure: the matched procedure dict (title, content, etc.)
            all_scores: all candidate scores for the escalation record

        Returns:
            GateDecision with decision "answer" or "escalate".
        """
        margin = round(best_score - second_score, 4)
        floor = self.config.absolute_floor
        min_margin = self.config.min_margin

        # Escalation record — carries candidates for the ops manager, but
        # the agent view carries none of them (leak test).
        escalation_record = {
            "best_score": best_score,
            "second_score": second_score,
            "margin": margin,
            "floor": floor,
            "min_margin": min_margin,
            "all_scores": all_scores or [],
            "reason": "",
        }

        # Floor check: best match must clear the absolute floor.
        if best_score < floor:
            escalation_record["reason"] = (
                f"best_score {best_score} below absolute floor {floor}"
            )
            return GateDecision(
                decision="escalate",
                margin=margin,
                best_score=best_score,
                second_score=second_score,
                floor=floor,
                min_margin=min_margin,
                reason=escalation_record["reason"],
                procedure_title=None,
                suggested_reply=None,
                evidence_passages=[],
                escalation_record=escalation_record,
            )

        # Margin check: best must beat second by at least min_margin.
        if margin < min_margin:
            escalation_record["reason"] = (
                f"margin {margin} below min_margin {min_margin}"
            )
            return GateDecision(
                decision="escalate",
                margin=margin,
                best_score=best_score,
                second_score=second_score,
                floor=floor,
                min_margin=min_margin,
                reason=escalation_record["reason"],
                procedure_title=None,
                suggested_reply=None,
                evidence_passages=[],
                escalation_record=escalation_record,
            )

        # Pass — return answer with evidence passages.
        procedure_title = None
        suggested_reply = None
        evidence_passages = []
        if best_procedure:
            procedure_title = best_procedure.get("title")
            suggested_reply = best_procedure.get("suggested_reply")
            evidence_passages = best_procedure.get("passages", [])

        return GateDecision(
            decision="answer",
            margin=margin,
            best_score=best_score,
            second_score=second_score,
            floor=floor,
            min_margin=min_margin,
            reason="best clears floor and margin",
            procedure_title=procedure_title,
            suggested_reply=suggested_reply,
            evidence_passages=evidence_passages,
            escalation_record=None,
        )

    def verify_gate(self, decision: GateDecision) -> bool:
        """Check a gate decision for internal consistency (leak test).

        Returns True if the decision is consistent with its recorded inputs.
        It does not detect a deliberate rewrite of both the decision and its
        inputs; there is no keyed signature or external anchor.
        """
        expected_margin = round(
            decision.best_score - decision.second_score, 4
        )
        if expected_margin != decision.margin:
            return False
        if decision.decision == "answer":
            if decision.best_score < self.config.absolute_floor:
                return False
            if decision.margin < self.config.min_margin:
                return False
            if decision.procedure_title is None:
                return False
        elif decision.decision == "escalate":
            if decision.procedure_title is not None:
                return False
            if decision.suggested_reply is not None:
                return False
        else:
            return False
        return True


def build_agent_view(decision: GateDecision) -> dict:
    """Build the agent view from a gate decision.

    For escalations, the agent view carries NO procedure content —
    only the decision and margin. This is the leak test: a blocked
    query shows the agent nothing they could misuse.
    """
    if decision.decision == "escalate":
        return {
            "decision": "escalate",
            "margin": decision.margin,
            "reason": decision.reason,
            "procedure_title": None,
            "suggested_reply": None,
            "evidence_passages": [],
        }
    return {
        "decision": "answer",
        "margin": decision.margin,
        "procedure_title": decision.procedure_title,
        "suggested_reply": decision.suggested_reply,
        "evidence_passages": decision.evidence_passages,
    }
