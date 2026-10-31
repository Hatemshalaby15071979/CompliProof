"""Tests for the CompliProof evidence pack and sealed answer key store.

Covers P0-2 acceptance criteria:
  - changing approval changes the seal hash
  - tampering with a stored key fails verification
  - seal manifest enumerates every material field
  - tamper tests cover approval, key, artifact, and metadata
"""
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from compliproof.evidence import (
    EvidencePack,
    ScoringResult,
    SealedAnswerKey,
    SealedAnswerKeyStore,
)

# ── EvidencePack seal covers approval ───────────────────────────────────────


def test_seal_includes_approval():
    """The sealed hash must cover the approval field so that changing
    approval changes the seal hash."""
    pack = EvidencePack(
        task_id="r-001",
        correlation_id="c-001",
        actor_id="BA",
        final_state="reconciled",
        steps=[],
        evidence_summary={},
        kpi_summary={},
        approval=None,
    )
    hash_without_approval = pack.seal()

    pack.approval = {"approver_id": "owner", "token_id": "tok-abc", "approved_at": "2026-10-29T00:00:00+00:00"}
    hash_with_approval = pack.seal()

    assert hash_without_approval != hash_with_approval, (
        "Seal hash must change when approval is added"
    )


def test_seal_changes_when_approval_changes():
    """Two different approval values produce different seal hashes."""
    pack_a = EvidencePack(
        task_id="r-001",
        correlation_id="c-001",
        actor_id="BA",
        final_state="reconciled",
        steps=[],
        evidence_summary={},
        kpi_summary={},
        approval={"approver_id": "owner", "decision": "approve"},
    )
    pack_b = EvidencePack(
        task_id="r-001",
        correlation_id="c-001",
        actor_id="BA",
        final_state="reconciled",
        steps=[],
        evidence_summary={},
        kpi_summary={},
        approval={"approver_id": "owner", "decision": "reject"},
    )
    assert pack_a.seal() != pack_b.seal(), (
        "Different approval values must produce different seal hashes"
    )


def test_seal_manifest_enumerates_material_fields():
    """The sealed payload must enumerate every material field."""
    pack = EvidencePack(
        task_id="r-001",
        correlation_id="c-001",
        actor_id="BA",
        final_state="reconciled",
        steps=[{"step": "match", "key": "id"}],
        evidence_summary={"match_rate": 0.5},
        kpi_summary={"match_rate": 0.5},
        approval={"approver_id": "owner"},
    )
    pack.seal()

    # Recompute the expected hash independently to confirm the manifest covers
    # all fields including approval.
    expected = hashlib.sha256(
        json.dumps(
            {
                "task_id": "r-001",
                "correlation_id": "c-001",
                "actor_id": "BA",
                "final_state": "reconciled",
                "steps": [{"step": "match", "key": "id"}],
                "approval": {"approver_id": "owner"},
                "evidence_summary": {"match_rate": 0.5},
                "kpi_summary": {"match_rate": 0.5},
                "timestamp": pack.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert pack.sealed_hash == expected


# ── SealedAnswerKeyStore HMAC verification ─────────────────────────────────


def _make_key(check_id: str = "qa-001") -> SealedAnswerKey:
    return SealedAnswerKey(
        check_id=check_id,
        required_keywords=["complete", "accurate"],
        forbidden_keywords=[],
        min_margin=0.8,
    )


def test_verify_passes_for_untampered_store():
    """An untampered store verifies True."""
    with tempfile.TemporaryDirectory() as tmp:
        store = SealedAnswerKeyStore(Path(tmp) / "sealed_keys.jsonl")
        key = _make_key()
        store.store(key)
        assert store.verify() is True


def test_verify_fails_when_data_tampered():
    """Tampering with the stored data file (without the signing key) makes
    verify() return False."""
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "sealed_keys.jsonl"
        store = SealedAnswerKeyStore(data_path)
        key = _make_key()
        store.store(key)

        # Tamper: rewrite the data file with different required_keywords
        # but keep the same sealed_hash (simulating an attacker who can edit
        # the data file but does not have the signing key).
        lines = data_path.read_text().strip().split("\n")
        rec = json.loads(lines[0])
        rec["required_keywords"] = ["tampered", "fake"]
        lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        data_path.write_text("\n".join(lines) + "\n")

        # Reload and verify — must fail because the signing key is unknown.
        store2 = SealedAnswerKeyStore(data_path)
        assert store2.verify() is False, (
            "Tampered data must fail verification without the signing key"
        )


def test_verify_fails_when_hash_tampered():
    """Tampering with only the stored hash (not the data) makes verify()
    return False."""
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "sealed_keys.jsonl"
        store = SealedAnswerKeyStore(data_path)
        key = _make_key()
        store.store(key)

        # Tamper: flip a character in the sealed_hash.
        lines = data_path.read_text().strip().split("\n")
        rec = json.loads(lines[0])
        rec["sealed_hash"] = "0" * 64
        lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        data_path.write_text("\n".join(lines) + "\n")

        store2 = SealedAnswerKeyStore(data_path)
        assert store2.verify() is False, (
            "Tampered hash must fail verification"
        )


def test_signing_key_stored_separately():
    """The signing key must be stored in a sibling .sealing_key file, not
    in the same file as the sealed records."""
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "sealed_keys.jsonl"
        store = SealedAnswerKeyStore(data_path)
        key_path = Path(tmp) / ".sealing_key"
        assert key_path.exists(), "Signing key must be persisted to disk"
        assert len(key_path.read_bytes()) == 32, "Signing key must be 32 bytes"


def test_different_signing_keys_produce_different_hashes():
    """Two stores with different signing keys produce different sealed hashes
    for the same answer key data."""
    with tempfile.TemporaryDirectory() as tmp_a:
        with tempfile.TemporaryDirectory() as tmp_b:
            path_a = Path(tmp_a) / "a.jsonl"
            path_b = Path(tmp_b) / "b.jsonl"
            store_a = SealedAnswerKeyStore(path_a)
            store_b = SealedAnswerKeyStore(path_b)

            key_a = _make_key("qa-001")
            key_b = _make_key("qa-001")
            store_a.store(key_a)
            store_b.store(key_b)

            rec_a = json.loads(Path(path_a).read_text().strip().split("\n")[0])
            rec_b = json.loads(Path(path_b).read_text().strip().split("\n")[0])
            assert rec_a["sealed_hash"] != rec_b["sealed_hash"], (
                "Different signing keys must produce different sealed hashes"
            )


def test_malformed_sealed_key_record_fails_closed():
    with tempfile.TemporaryDirectory() as tmp:
        data_path = Path(tmp) / "sealed_keys.jsonl"
        data_path.write_text("{invalid json}\n", encoding="utf-8")

        with pytest.raises(ValueError, match="line 1"):
            SealedAnswerKeyStore(data_path, signing_key=b"k" * 32)


# ── ScoringResult seal (metadata tamper detection) ─────────────────────────


def test_scoring_result_seal_detects_metadata_change():
    """Changing metadata fields (result, margin) changes the ScoringResult seal."""
    result_a = ScoringResult(
        check_id="check-1",
        criteria=["complete"],
        result="pass",
        margin=0.9,
    )
    result_b = ScoringResult(
        check_id="check-1",
        criteria=["complete"],
        result="fail",
        margin=0.1,
    )
    assert result_a.seal() != result_b.seal(), (
        "Changing result/margin must change the ScoringResult seal hash"
    )
