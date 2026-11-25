"""Niveaux d'autonomie et politique déclarative (chapitre 8.1, GP-02)."""

from __future__ import annotations

import copy

import pytest

from gateway.policy import Policy


def test_policy_loads_with_hash(policy):
    assert policy.max_level == "N2" and policy.default_level == "N1"
    assert len(policy.sha256) == 64
    assert not policy.level_implemented("N3")


def test_policy_hash_changes_with_content(policy):
    data = copy.deepcopy(policy.data)
    data["budgets"]["max_steps"] = 5
    assert Policy(data).sha256 != Policy(copy.deepcopy(policy.data)).sha256


@pytest.mark.parametrize("analyst,requested,expected", [
    ("jdupont", None, "N1"),     # niveau par défaut
    ("jdupont", "N0", "N0"),     # l'analyste peut abaisser
    ("jdupont", "N2", "N2"),
    ("jdupont", "N3", "N2"),     # jamais au-dessus du maximum SOC (et N3 non implémenté)
    ("jjunior", "N2", "N1"),     # plafond du rôle
    ("aaudit", "N1", "N0"),
])
def test_effective_level(policy, identities, analyst, requested, expected):
    level, notes = policy.effective_level(requested, identities.get(analyst))
    assert level == expected
    if requested and requested != expected:
        assert notes and "relèvement refusé" in notes[0]


def test_soc_max_level_caps_everyone(policy, identities):
    data = copy.deepcopy(policy.data)
    data["autonomy"]["max_level"] = "N0"
    level, _ = Policy(data).effective_level("N2", identities.get("mmanager"))
    assert level == "N0"


def test_invalid_level_in_policy_rejected(policy):
    data = copy.deepcopy(policy.data)
    data["autonomy"]["max_level"] = "N9"
    with pytest.raises(ValueError):
        Policy(data)


def test_unknown_analyst(identities):
    with pytest.raises(KeyError):
        identities.get("inconnu")
