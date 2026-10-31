#!/usr/bin/env python3
"""Audit ledger for CompliProof (remediated for P0-3).

v1 behavior (replaces the post-action prototype ledger):

- Pre-action intent logging: ``append_intent`` writes a durable ``action.intent``
  event *before* work starts; ``append_result`` links its ``action.result``
  event back to the intent by ``intent_seq`` + ``intent_hash``.
- Concurrency-safe appends: an in-process lock plus an ``fcntl.flock`` sidecar
  lock serializes readers of the chain tip and writers, so concurrent
  appends produce one valid, ordered chain with unique sequence numbers.
- External anchoring: :meth:`AuditLog.anchor` records the chain head and event
  count in a chained receipt file. ``AuditLog.check_anchor`` detects
  truncation, rewrite, and reorder against the latest anchor. An optional
  RFC 3161 timestamp provider (FreeTSA per company decision D-018) is used
  when ``ANCHOR_PROVIDER=freetsa``; the default ``local`` provider makes no
  network calls. No E3/E4 anchoring claims are permitted until a TSA receipt
  is verified.
- One canonical ledger: the production ledger is
  ``CompliProof/workspace/audit_events.jsonl``. A legacy default path outside
  the project directory is retained only so it is still refused as a
  production path; it is never created as canonical.
- Independent verification: :func:`verify_ledger` validates the chain without
  any AuditLog instance state and is exposed in the CLI.

Usage:
    from compliproof.audit import AuditLog
    log = AuditLog(allow_production=True)  # only the server or CLI should do this
    intent = log.append_intent("reconciliation", "BA", {"task_id": "r-001"})
    # ... the work happens ...
    log.append_result(intent, "reconciliation.completed", "BA", {"result": "matched"})

Tests must pass a temporary path, never the production ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from compliproof.security import open_http_url

# Path resolution:
#   this file lives at <project>/src/compliproof/audit.py
_PROJECT = Path(__file__).resolve().parent.parent.parent           # .../CompliProof
_LEGACY_BASE = _PROJECT.parent                                     # directory above the project

CANONICAL_LEDGER = _PROJECT / "workspace" / "audit_events.jsonl"
LEGACY_DEFAULT_LEDGER = _LEGACY_BASE / "workspace" / "audit_events.jsonl"

#: Both paths are treated as production ledgers. The canonical ledger is the
#: only one that may be written; the legacy path is refused so tests can never
#: contaminate it (and it is never created).
PRODUCTION_LEDGERS = {CANONICAL_LEDGER.resolve(), LEGACY_DEFAULT_LEDGER.resolve()}

DEFAULT_LOG = CANONICAL_LEDGER

INTENT_TYPE = "action.intent"
RESULT_TYPE = "action.result"

GENESIS = "GENESIS"
BROKEN = "BROKEN"

#: Default link that anchors a purchase of trust in wall-clock time.
ANCHOR_PROVIDER_DEFAULT = "local"
ANCHOR_ENV = "ANCHOR_PROVIDER"
ANCHOR_TSA_URL_ENV = "ANCHOR_TSA_URL"
ANCHOR_TSA_URL_DEFAULT = "https://freetsa.org/tsr"


class ProductionLedgerError(RuntimeError):
    """Raised when a non-production caller tries to write a production ledger."""


def is_production_ledger(path: Path | str) -> bool:
    """Return True when path is one of the known production ledgers."""
    return Path(path).resolve() in PRODUCTION_LEDGERS


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_entry(entry: dict, prev_hash: str) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((payload + prev_hash).encode("utf-8")).hexdigest()


def _strip_hash(entry: dict) -> dict:
    return {k: v for k, v in entry.items() if k != "hash"}


class AuditLog:
    """Append-only, hash-chained audit log with intent logging, locking, anchoring.

    Fail-closed on IO error. Thread-safe and multi-process safe on POSIX.
    """

    def __init__(self, path: Path | str | None = None, *, allow_production: bool = False):
        self.path = Path(path) if path else DEFAULT_LOG
        if is_production_ledger(self.path) and not allow_production:
            raise ProductionLedgerError(
                f"refusing to open production ledger {self.path}; "
                "use a temporary path in tests or pass allow_production=True from the server/CLI"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self._lock = threading.Lock()
        self._cache_count: int | None = None
        self._cache_head: str | None = None

    # ── state scanning ────────────────────────────────────────────────────────

    def _last_hash(self) -> str:
        last = None
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line)
                        except json.JSONDecodeError:
                            return BROKEN
        except OSError:
            return BROKEN
        if last is None:
            return GENESIS
        return last.get("hash", BROKEN)

    def _next_seq(self) -> int:
        n = 0
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        n += 1
        except OSError:
            return 0
        return n + 1

    # ── append path (guarded) ─────────────────────────────────────────────────

    def append(self, event_type: str, actor: str, payload: dict | None = None) -> dict:
        """Append an event. Returns the written entry. Fail-closed on IO error."""
        entry = {
            "seq": 0,  # filled under lock
            "ts": _now(),
            "type": event_type,
            "actor": actor,
            "payload": payload or {},
        }
        # The chain tip must be read after the lock is taken; _append_guarded
        # overwrites prev_hash and hash, so pass a placeholder skeleton.
        with self._lock:
            lock_path = self.path.with_name(self.path.name + ".lock")
            with lock_path.open("a") as lock_f:
                try:
                    import fcntl
                    fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
                    have_fcntl = True
                except (ImportError, OSError):
                    have_fcntl = False
                try:
                    chain = verify_ledger(self.path)
                    if not chain["ok"]:
                        raise IOError(
                            f"Audit chain is broken ({chain['reason']}) — refusing to append"
                        )
                    prev = chain["head"]
                    entry["seq"] = chain["count"] + 1
                    entry["prev_hash"] = prev
                    entry["hash"] = _hash_entry(_strip_hash(entry), prev)
                    line = json.dumps(entry, ensure_ascii=False)
                    with self.path.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                    self._cache_count = entry["seq"]
                    self._cache_head = entry["hash"]
                    return entry
                finally:
                    if have_fcntl:
                        try:
                            import fcntl
                            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
                        except (ImportError, OSError):
                            pass

    def append_intent(self, event_type: str, actor: str, payload: dict | None = None) -> dict:
        """Write a durable intent event BEFORE the described action runs.

        Returns the intent entry. The caller must complete the action and then
        call :meth:`append_result` with this entry so the ledger shows both the
        intent and its outcome.
        """
        return self.append(
            INTENT_TYPE,
            actor,
            {
                "intent_for": event_type,
                "details": payload or {},
            },
        )

    def append_result(
        self,
        intent: dict,
        event_type: str,
        actor: str,
        payload: dict | None = None,
    ) -> dict:
        """Append a result event linked to its intent.

        Links the two by seq and hash so the pair cannot be swapped or forged.
        """
        if intent.get("type") != INTENT_TYPE:
            raise ValueError("append_result requires an entry produced by append_intent")
        merged = dict(payload or {})
        merged["intent_seq"] = intent.get("seq")
        merged["intent_hash"] = intent.get("hash")
        return self.append(event_type, actor, merged)

    # ── reads ─────────────────────────────────────────────────────────────────

    def tail(self, n: int = 20) -> list[dict]:
        rows = []
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            rows.append({"_corrupt": line[:80]})
        except OSError:
            return []
        return rows[-n:]

    def verify(self) -> bool:
        """Verify the hash chain is intact. Returns True if intact (or empty)."""
        return verify_ledger(self.path)["ok"]

    def count(self) -> int:
        return len(self.tail(10**9))

    def get_chain_tip(self) -> str:
        return self._last_hash()

    def pending_intents(self) -> list[dict]:
        """Return intent events whose results have not been appended.

        This is the recoverable state for a process that was killed
        mid-action: the intent is durable, the result is missing.
        """
        results_intents = set()
        pending = []
        for e in self.tail(10**9):
            payload = e.get("payload") or {}
            if payload.get("intent_seq") is not None:
                results_intents.add(payload.get("intent_seq"))
        for e in self.tail(10**9):
            if e.get("type") == INTENT_TYPE and e.get("seq") not in results_intents:
                pending.append(e)
        return pending

    # ── anchoring ─────────────────────────────────────────────────────────────

    def anchor(self, provider: str | None = None) -> dict:
        """Write a chain-head receipt.

        Default ``local`` provider writes a receipt file with the head hash and
        count. ``freetsa`` provider additionally requests an RFC 3161 timestamp
        from a TSA (FreeTSA by default; set ``ANCHOR_TSA_URL`` to override).
        The receipt file itself is hash-chained so anchors cannot be dropped
        unnoticed.
        """
        provider = provider or os.environ.get(ANCHOR_ENV, ANCHOR_PROVIDER_DEFAULT)
        head = self.get_chain_tip()
        if head == BROKEN:
            raise IOError("Audit chain is broken — refusing to anchor")
        count = self.count()
        receipt_dir = self.path.parent / "anchors"
        receipt_dir.mkdir(parents=True, exist_ok=True)
        receipt_path = receipt_dir / f"anchor-{count:08d}.json"

        prev_anchor_hash = "GENESIS"
        prior = sorted(receipt_dir.glob("anchor-*.json"))
        if prior:
            try:
                last = json.loads(prior[-1].read_text(encoding="utf-8"))
                prev_anchor_hash = last.get("anchor_hash", "GENESIS")
            except (OSError, json.JSONDecodeError):
                pass

        receipt = {
            "seq": count,
            "head_hash": head,
            "ts": _now(),
            "provider": provider,
            "prev_anchor_hash": prev_anchor_hash,
        }
        if provider == "freetsa":
            receipt["tsa_receipt_hex"] = _tsa_timestamp(head, count)
        receipt["anchor_hash"] = hashlib.sha256(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        receipt_path.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        return receipt

    def check_anchor(self) -> dict:
        """Compare the current ledger against the latest anchor receipt.

        Returns {"ok": bool, "reason": str, ...}. Reason values:
        - ``no_anchors``: nothing anchored yet (not a failure)
        - ``ok``: chain verified, count matches, head matches
        - ``truncated``: fewer events than the anchor recorded
        - ``rewritten``: head hash no longer matches the anchor
        - ``reordered``: chain verify fails with same count (order changed)
        - ``chain_broken``: local hash chain itself fails verification
        - ``anchor_tampered``: the receipt file fails its own hash chain
        """
        receipt_dir = self.path.parent / "anchors"
        prior = sorted(receipt_dir.glob("anchor-*.json"))
        if not prior:
            return {"ok": True, "reason": "no_anchors"}
        try:
            latest = json.loads(prior[-1].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"ok": False, "reason": "anchor_tampered"}
        # Validate anchor chain: each anchor references the previous one.
        prev = "GENESIS"
        for p in prior:
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {"ok": False, "reason": "anchor_tampered"}
            if rec.get("prev_anchor_hash") != prev:
                return {"ok": False, "reason": "anchor_tampered"}
            stored = rec.pop("anchor_hash", None)
            recomputed = hashlib.sha256(
                json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            rec["anchor_hash"] = stored
            if stored != recomputed:
                return {"ok": False, "reason": "anchor_tampered"}
            prev = stored

        count = self.count()
        anchored_count = latest.get("seq", 0)
        anchored_head = latest.get("head_hash", "")

        if not self._chain_without_cache_verify():
            return {"ok": False, "reason": "chain_broken"}
        if count < anchored_count:
            return {"ok": False, "reason": "truncated", "anchored_seq": anchored_count, "current_seq": count}
        # If the chain was rewritten or reordered with recompute, the head changes.
        if anchored_count >= 1 and count >= anchored_count:
            events = self.tail(10**9)
            head_at_anchor = events[anchored_count - 1].get("hash", "")
            if head_at_anchor != anchored_head:
                return {"ok": False, "reason": "rewritten", "anchored_head": anchored_head, "current_head": head_at_anchor}
        return {"ok": True, "reason": "ok", "anchored_seq": anchored_count, "current_seq": count}

    def _chain_without_cache_verify(self) -> bool:
        return verify_ledger(self.path)["ok"]


def _tsa_timestamp(head_hash: str, count: int) -> str:
    """Request an RFC 3161 timestamp receipt (hex) from the configured TSA.

    Never called by default. Caller must configure ANCHOR_PROVIDER=freetsa.
    """
    url = os.environ.get(ANCHOR_TSA_URL_ENV, ANCHOR_TSA_URL_DEFAULT)
    # Minimal RFC 3161 request: SHA-256 digest of the head hash + nonce.
    nonce = os.urandom(16)
    # nonce tagged for clarity in request and for later replay protection.
    try:
        from cryptography import x509  # noqa: F401  (optional heavy import)
    except ImportError:
        pass
    data = _build_tsq(bytes.fromhex(head_hash), nonce)
    req = urllib.request.Request(  # noqa: S310 - opened through strict HTTP(S)-only helper
        url,
        data=data,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    try:
        with open_http_url(req, timeout=30) as resp:
            return resp.read().hex()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise IOError(f"timestamp authority request failed: {e}") from e


def _build_tsq(message_digest: bytes, nonce: bytes) -> bytes:
    """Build a minimal DER TimestampReq (SHA-256) — deliberate minimal DER.

    ESSCertIDv2/nonce as INTEGER; certReq set to False. The response is stored
    verbatim and verified later by cryptography x509 / openssl tsr.
    """
    # SHA-256 OID: 2.16.840.1.101.3.4.2.1
    oid_sha256 = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01"

    def _der_len(n: int) -> bytes:
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    def _der(tag: int, content: bytes) -> bytes:
        return bytes([tag]) + _der_len(len(content)) + content

    nonce_int = int.from_bytes(nonce, "big")
    nonce_len = (nonce_int.bit_length() + 7) // 8 or 1
    nonce_body = nonce_int.to_bytes(nonce_len, "big")
    nonce_der = _der(0x02, nonce_body)
    msg_imprint = _der(0x30, _der(0x30, oid_sha256) + _der(0x04, message_digest))
    req = _der(0x30, b"\x01\x01" + msg_imprint + nonce_der + b"\x01\x01\x00")
    return req


def verify_ledger(path: Path | str) -> dict:
    """Independent verifier: validate the ledger without any AuditLog instance.

    Checks, in order:
      1. every line is valid JSON (reports a corrupt seq when not)
      2. sequence numbers are unique and strictly increasing by 1
      3. each entry's prev_hash equals the previous entry's hash
      4. each entry's hash recomputes exactly from its content + prev_hash
    """
    p = Path(path)
    prev = GENESIS
    expected_seq = 1
    seen_hashes: set[str] = set()
    count = 0
    try:
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "reason": "corrupt_json", "seq": count + 1}
                count += 1
                if entry.get("seq") != expected_seq:
                    return {"ok": False, "reason": "sequence_gap", "seq": entry.get("seq"), "expected": expected_seq}
                if entry.get("prev_hash") != prev:
                    return {"ok": False, "reason": "chain_break", "seq": entry.get("seq")}
                h = entry.get("hash", "")
                if h in seen_hashes:
                    return {"ok": False, "reason": "duplicate_hash", "seq": entry.get("seq")}
                seen_hashes.add(h)
                if _hash_entry(_strip_hash(entry), prev) != h:
                    return {"ok": False, "reason": "bad_hash", "seq": entry.get("seq")}
                prev = h
                expected_seq += 1
    except OSError as e:
        return {"ok": False, "reason": f"io_error: {e}"}
    return {"ok": True, "reason": "ok", "count": count, "head": prev}


def _cli() -> int:
    if len(sys.argv) < 2:
        print("usage: audit.py [append TYPE ACTOR JSON | tail N | verify | count | tip | anchor | check-anchor | pending-intents]")
        return 1
    cmd = sys.argv[1]
    log = AuditLog(allow_production=True)
    if cmd == "append":
        if len(sys.argv) < 4:
            print("usage: audit.py append TYPE ACTOR [JSON]")
            return 1
        etype = sys.argv[2]
        actor = sys.argv[3]
        payload = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
        try:
            e = log.append(etype, actor, payload)
        except IOError as e:
            print(f"AUDIT ERROR: {e}")
            return 1
        print(json.dumps(e))
        return 0
    if cmd == "tail":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        for e in log.tail(n):
            print(json.dumps(e))
        return 0
    if cmd == "verify":
        res = verify_ledger(log.path)
        print("OK" if res["ok"] else f"BROKEN ({res.get('reason')} at seq {res.get('seq')})")
        return 0 if res["ok"] else 1
    if cmd == "count":
        print(log.count())
        return 0
    if cmd == "tip":
        print(log.get_chain_tip())
        return 0
    if cmd == "anchor":
        print(json.dumps(log.anchor()))
        return 0
    if cmd == "check-anchor":
        print(json.dumps(log.check_anchor()))
        return 0 if log.check_anchor()["ok"] else 1
    if cmd == "pending-intents":
        for e in log.pending_intents():
            print(json.dumps(e))
        return 0
    print("unknown command:", cmd)
    return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
