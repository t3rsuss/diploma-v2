import numpy as np
from src.detector.rules import apply_rules


def test_no_table_raises_low_elf_any_arch():
    for machine in (62, 40, None):
        lvl, why, raised = apply_rules("low", "ELF", np.zeros(10, int), None, machine)
        assert lvl == "mid" and raised and why


def test_low_agreement_raises_low_x86_elf():
    pred = np.zeros(10, int)
    truth = np.array([0] * 4 + [1] * 6)
    for machine in (62, 3):
        lvl, why, raised = apply_rules("low", "ELF", pred, truth, machine)
        assert lvl == "mid" and raised


def test_low_agreement_ignored_for_other_arch():
    pred = np.zeros(10, int)
    truth = np.array([0] * 4 + [1] * 6)
    for machine in (40, 8, None):
        assert apply_rules("low", "ELF", pred, truth, machine) == ("low", [], False)


def test_high_stays_high_but_reason_kept():
    lvl, why, raised = apply_rules("high", "ELF", np.zeros(10, int), None, 62)
    assert lvl == "high" and not raised and why


def test_normal_elf_unchanged():
    p = np.zeros(10, int)
    assert apply_rules("low", "ELF", p, p.copy(), 62) == ("low", [], False)


def test_pe_never_changed():
    assert apply_rules("low", "PE", np.zeros(10, int), None, None) == ("low", [], False)