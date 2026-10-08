"""The scenario catalogue must keep telling the truth: the legacy system is
fooled only by the recomputed-checksum forgery, the secure system by nothing."""

from __future__ import annotations

from securecharge.messages import price_for
from securecharge.scenarios import Attack, FORGED_ENERGY, HONEST_ENERGY, run, run_all


def test_secure_system_is_never_fooled():
    assert [r.attack for r in run_all() if r.secure.fooled] == []


def test_legacy_fooled_only_by_recomputed_checksum():
    fooled = {r.attack for r in run_all() if r.legacy.fooled}
    assert fooled == {Attack.TAMPER_RECOMPUTE_MD5}


def test_honest_session_bills_the_same_on_both():
    r = run(Attack.NONE)
    assert r.legacy.billed_paise == r.secure.billed_paise == price_for(HONEST_ENERGY)
    assert r.legacy.accepted and r.secure.accepted


def test_recompute_forgery_underbills_legacy_but_not_secure():
    r = run(Attack.TAMPER_RECOMPUTE_MD5)
    assert r.legacy.billed_paise == price_for(FORGED_ENERGY)  # legacy cheated
    assert not r.secure.accepted  # secure refused


def test_every_non_honest_scenario_is_blocked_by_secure():
    for r in run_all():
        if r.attack is Attack.NONE:
            assert r.secure.accepted
        else:
            assert not r.secure.accepted, r.attack
