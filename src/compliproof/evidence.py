#!/usr/bin/env python3
"""Prototype scoring and evidence pack for CompliProof.

The asserted lineage from Helix Education's `state_core/event_store.py` and
Helix Prime's evidence packs is unverified. The local EvidencePack hash
includes approval fields but is not a digital signature. Answer-key HMAC
verification detects data changes only while the sibling sealing key remains
trusted; the key is stored locally and has no rotation or revocation workflow.
This is not an independent verifier or an externally anchored seal.

Usage:
    from compliproof.evidence import SealedAnswerKeyStore, EvidencePack
    store = SealedAnswerKeyStore()
    key_hash = store.store("qa-check-001", ["complete", "accurate", "auditable"])
    pack = EvidencePack.build("r-001", {"result": "matched", "key_hash": key_hash})
    print(pack.to_json())  # local prototype pack
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SEALED_KEYS = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "workspace"
    / "sealed_keys.jsonl"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScoringResult:
    """A scoring result with a local SHA-256 hash; not immutable or externally anchored."""

    check_id: str
    criteria: list[str]
    result: str  # "pass" / "fail" / "escalate"
    margin: float
    evidence_refs: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_now)
    sealed_hash: str = ""

    def seal(self) -> str:
        payload = json.dumps(
            {
                "check_id": self.check_id,
                "criteria": self.criteria,
                "result": self.result,
                "margin": self.margin,
                "evidence_refs": self.evidence_refs,
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.sealed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.sealed_hash


@dataclass
class EvidencePack:
    """Exportable task pack with a local SHA-256 integrity check.

    The digest is not a digital signature: a party able to change the pack can
    also recompute it. External trust and independent verification remain
    separate requirements.
    """

    SEAL_MANIFEST = (
        "task_id",
        "correlation_id",
        "actor_id",
        "final_state",
        "steps",
        "approval",
        "evidence_summary",
        "kpi_summary",
        "timestamp",
    )

    task_id: str
    correlation_id: str
    actor_id: str
    final_state: str
    steps: list[dict] = field(default_factory=list)
    approval: dict | None = None
    evidence_summary: dict = field(default_factory=dict)
    kpi_summary: dict = field(default_factory=dict)
    sealed_hash: str = ""
    timestamp: str = field(default_factory=_now)

    def _seal_payload(self) -> dict:
        """Return the canonical field manifest covered by the local digest."""
        return {
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "actor_id": self.actor_id,
            "final_state": self.final_state,
            "steps": self.steps,
            "approval": self.approval,
            "evidence_summary": self.evidence_summary,
            "kpi_summary": self.kpi_summary,
            "timestamp": self.timestamp,
        }

    def seal(self) -> str:
        """Hash all manifest fields, including approval, with local SHA-256."""
        payload = json.dumps(
            self._seal_payload(),
            sort_keys=True,
            separators=(",", ":"),
        )
        self.sealed_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.sealed_hash

    def verify(self) -> bool:
        """Check the persisted digest against every field in the manifest."""
        expected = hashlib.sha256(
            json.dumps(
                self._seal_payload(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return bool(self.sealed_hash and hmac.compare_digest(self.sealed_hash, expected))

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "actor_id": self.actor_id,
            "final_state": self.final_state,
            "steps": self.steps,
            "approval": self.approval,
            "evidence_summary": self.evidence_summary,
            "kpi_summary": self.kpi_summary,
            "sealed_hash": self.sealed_hash,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


@dataclass
class SealedAnswerKey:
    """Answer-key criteria with a keyed SHA-256 HMAC seal; tamper-evident when
    a signing key is provided and stored separately from the data file."""

    check_id: str
    required_keywords: list[str]
    forbidden_keywords: list[str] = field(default_factory=list)
    min_margin: float = 0.0
    sealed_hash: str = ""

    @staticmethod
    def _compute_seal(
        check_id: str,
        required_keywords: list[str],
        forbidden_keywords: list[str],
        min_margin: float,
        signing_key: bytes | None,
    ) -> str:
        """Compute the sealed hash without mutating state. Used by verify()."""
        payload = json.dumps(
            {
                "check_id": check_id,
                "required_keywords": required_keywords,
                "forbidden_keywords": forbidden_keywords,
                "min_margin": min_margin,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if signing_key is not None:
            return hmac.new(
                signing_key, payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def seal(self, signing_key: bytes | None = None) -> str:
        """Seal the answer key.

        If ``signing_key`` is provided, the seal is an HMAC-SHA256: tampering
        with the data without the signing key causes verification to fail.
        Without a signing key, falls back to a plain local SHA-256 (not
        tamper-evident).
        """
        self.sealed_hash = self._compute_seal(
            self.check_id,
            self.required_keywords,
            self.forbidden_keywords,
            self.min_margin,
            signing_key,
        )
        return self.sealed_hash


class SealedAnswerKeyStore:
    """Local storage for answer keys used by the prototype evidence pack.

    Each store holds a signing key (in a sibling ``.sealing_key`` file) that is
    used to compute keyed HMAC seals. Tampering with the stored data without
    the signing key causes :meth:`verify` to return False.
    """

    def __init__(self, path: Path | str | None = None, signing_key: bytes | None = None):
        self._path = Path(path) if path else DEFAULT_SEALED_KEYS
        self._signing_key = signing_key or self._load_or_create_signing_key()
        self._keys: dict[str, SealedAnswerKey] = {}
        self._load()

    def _load_or_create_signing_key(self) -> bytes:
        key_path = self._path.parent / ".sealing_key"
        if key_path.exists():
            return key_path.read_bytes()
        key = os.urandom(32)
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        key_path.write_bytes(key)
        return key

    def _load(self) -> None:
        if not self._path.exists():
            return
        with self._path.open(encoding="utf-8") as f:
            for line_number, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    if not isinstance(rec, dict):
                        raise ValueError("record must be a JSON object")
                    qid = rec.get("check_id")
                    if not isinstance(qid, str) or not qid:
                        raise ValueError("record is missing a check ID")
                    key = SealedAnswerKey(
                        check_id=qid,
                        required_keywords=rec.get("required_keywords", []),
                        forbidden_keywords=rec.get("forbidden_keywords", []),
                        min_margin=rec.get("min_margin", 0.0),
                    )
                    key.sealed_hash = rec.get("sealed_hash", "")
                    self._keys[qid] = key
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Malformed sealed answer key record on line {line_number}"
                    ) from exc

    def store(self, key: SealedAnswerKey) -> str:
        """Store an AnswerKey and return its sealed hash."""
        key.seal(self._signing_key)
        self._keys[key.check_id] = key
        record = {
            "check_id": key.check_id,
            "required_keywords": key.required_keywords,
            "forbidden_keywords": key.forbidden_keywords,
            "min_margin": key.min_margin,
            "sealed_hash": key.sealed_hash,
        }
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        parent = os.path.dirname(self._path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        return key.sealed_hash

    def get(self, check_id: str) -> SealedAnswerKey | None:
        return self._keys.get(check_id)

    def verify(self) -> bool:
        """Recompute each stored key's sealed hash with the store's signing key
        and compare it with the stored value.

        Returns False if any record has been tampered with without the signing
        key. Detects deliberate rewrites, not just accidental drift.
        """
        for key in self._keys.values():
            expected = SealedAnswerKey._compute_seal(
                key.check_id,
                key.required_keywords,
                key.forbidden_keywords,
                key.min_margin,
                self._signing_key,
            )
            if key.sealed_hash != expected:
                return False
        return True

    def count(self) -> int:
        return len(self._keys)


def build_evidence_pack(
    task_id: str,
    correlation_id: str,
    actor_id: str,
    final_state: str,
    steps: list[dict] | None = None,
    evidence_summary: dict | None = None,
    kpi_summary: dict | None = None,
    approval: dict | None = None,
) -> EvidencePack:
    """Factory: build and seal an EvidencePack."""
    pack = EvidencePack(
        task_id=task_id,
        correlation_id=correlation_id,
        actor_id=actor_id,
        final_state=final_state,
        steps=steps or [],
        evidence_summary=evidence_summary or {},
        kpi_summary=kpi_summary or {},
        approval=approval,
    )
    pack.seal()
    return pack
