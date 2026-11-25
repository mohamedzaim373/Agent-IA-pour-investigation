"""Journal d'audit chaîné : intégrité, ajout seul, détection de falsification (GT-02)."""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy.exc import DBAPIError

from evidence.store import EvidenceIntegrityError, EvidenceStore
from gateway.hashing import GENESIS_HASH, hash_obj


def _fill(audit, n=5):
    for i in range(n):
        audit.append(investigation_id="INV-1", actor="agent", event_type="tool_call", tool="search_logs",
                     params={"i": i}, result_hash=hash_obj({"i": i}), decision="allow", reason="test")


def _raw(db_url):
    return sqlite3.connect(db_url.replace("sqlite:///", ""))


def test_chain_is_valid(audit):
    _fill(audit)
    res = audit.verify()
    assert res.ok and res.checked == 5
    entries = audit.entries("INV-1")
    assert entries[0].prev_hash == GENESIS_HASH
    assert all(entries[i].prev_hash == entries[i - 1].entry_hash for i in range(1, 5))
    assert res.head_hash == entries[-1].entry_hash


def test_update_and_delete_are_refused_by_the_database(audit, db_url):
    _fill(audit, 2)
    with pytest.raises(DBAPIError):
        with audit.engine.begin() as conn:
            conn.exec_driver_sql("UPDATE audit_log SET reason='falsifié' WHERE seq=1")
    with pytest.raises(DBAPIError):
        with audit.engine.begin() as conn:
            conn.exec_driver_sql("DELETE FROM audit_log WHERE seq=1")
    assert audit.verify().ok


def test_modification_is_detected(audit, db_url):
    _fill(audit)
    con = _raw(db_url)
    con.execute("DROP TRIGGER audit_log_no_update")  # un attaquant disposant d'un accès direct à la base
    con.execute("UPDATE audit_log SET decision='deny' WHERE seq=3")
    con.commit()
    res = audit.verify()
    assert not res.ok and any("seq 3" in e and "modifié" in e for e in res.errors)


def test_deletion_is_detected(audit, db_url):
    _fill(audit)
    con = _raw(db_url)
    con.execute("DROP TRIGGER audit_log_no_delete")
    con.execute("DELETE FROM audit_log WHERE seq=2")
    con.commit()
    res = audit.verify()
    assert not res.ok and any("seq 3" in e for e in res.errors)


def test_rehash_attack_is_detected(audit, db_url):
    """Recalculer l'empreinte d'une entrée modifiée casse le lien avec la suivante."""
    from gateway.audit import compute_entry_hash

    _fill(audit)
    con = _raw(db_url)
    con.row_factory = sqlite3.Row
    con.execute("DROP TRIGGER audit_log_no_update")
    row = dict(con.execute("SELECT * FROM audit_log WHERE seq=2").fetchone())
    row["reason"] = "falsifié"
    con.execute("UPDATE audit_log SET reason=?, entry_hash=? WHERE seq=2", (row["reason"], compute_entry_hash(row)))
    con.commit()
    res = audit.verify()
    assert not res.ok and any("seq 3" in e and "lien" in e for e in res.errors)


def test_cli_verify(audit, db_url, capsys):
    from gateway.audit import _main

    _fill(audit, 3)
    assert _main(["--db", db_url, "verify"]) == 0
    assert "INTÈGRE" in capsys.readouterr().out


def test_evidence_must_match_audited_result(db_url):
    store = EvidenceStore(db_url)
    payload = {"items": [{"source": "wazuh", "summary": "événement", "timestamp": "2026-10-12T09:00:00Z"}], "meta": {}}
    entry = store.audit.append(investigation_id="INV-2", actor="agent", event_type="tool_call", tool="search_logs",
                               result_hash=hash_obj(payload))
    evs = store.add_from_result("INV-2", audit_seq=entry.seq, tool="search_logs", query={}, payload=payload)
    assert [e.evidence_id for e in evs] == ["EV-001"] and evs[0].audit_seq == entry.seq
    forged = {"items": [{"source": "wazuh", "summary": "preuve inventée"}], "meta": {}}
    with pytest.raises(EvidenceIntegrityError):
        store.add_from_result("INV-2", audit_seq=entry.seq, tool="search_logs", query={}, payload=forged)
    with pytest.raises(EvidenceIntegrityError):
        store.add_from_result("INV-3", audit_seq=entry.seq, tool="search_logs", query={}, payload=payload)
