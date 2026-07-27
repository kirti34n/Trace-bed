"""Structured incremental-delta consolidation (PLAN.md §7 Phase 2 / §8 improvement 4;
ACE ICLR 2026 brevity-bias / context-collapse). Everything here is offline —
`Consolidator` takes only an injected `Clock`.
"""

from __future__ import annotations

import inspect

import pytest

from tracebed.domain.clock import FakeClock
from tracebed.domain.ids import mint_memory_id
from tracebed.workers.consolidator import Consolidator
from tracebed.workers.deltas import (
    Delta,
    DeltaOp,
    Element,
    ElementSet,
    apply_delta,
    apply_deltas,
    reconstruct,
)

pytestmark = pytest.mark.phase2


def _elements(**names_to_text: str) -> tuple[Element, ...]:
    return tuple(Element(name=name, text=text) for name, text in names_to_text.items())


# --------------------------------------------------------------------------- #
# A delta is emitted and recorded.
# --------------------------------------------------------------------------- #


def test_consolidate_emits_and_records_an_add_delta_for_a_new_element() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()

    outcome = consolidator.consolidate(
        memory_id, ElementSet(), _elements(fact_1="the sky is blue"), sweep=1
    )

    assert len(outcome.deltas) == 1
    assert outcome.deltas[0] == Delta(op=DeltaOp.ADD, name="fact_1", text="the sky is blue")
    assert len(outcome.records) == 1
    assert outcome.records[0].memory_id == memory_id
    assert outcome.records[0].sweep == 1
    assert outcome.records[0].delta == outcome.deltas[0]
    assert outcome.records[0].applied_at == clock.now()


def test_consolidate_emits_an_amend_delta_when_text_changes() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    state = ElementSet(elements=_elements(fact_1="v1"))

    outcome = consolidator.consolidate(mint_memory_id(), state, _elements(fact_1="v2"), sweep=2)

    assert outcome.deltas == (Delta(op=DeltaOp.AMEND, name="fact_1", text="v2"),)
    assert outcome.after.by_name()["fact_1"].text == "v2"


def test_consolidate_emits_nothing_when_nothing_changed() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    state = ElementSet(elements=_elements(fact_1="unchanged"))

    outcome = consolidator.consolidate(mint_memory_id(), state, _elements(fact_1="unchanged"), sweep=3)

    assert outcome.deltas == ()
    assert outcome.records == ()
    assert outcome.after == outcome.before


def test_consolidate_never_synthesizes_a_remove_on_its_own() -> None:
    """The regression this guards: `incoming` omitting a name that WAS in
    `state` (e.g. an upstream fetch only returning a subset this sweep) must
    not be read as "that fact is gone now" -- exactly the brevity-bias
    failure mode this module's docstring names. Only `retract()` removes."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    state = ElementSet(elements=_elements(fact_1="keep me", fact_2="also keep me"))

    outcome = consolidator.consolidate(mint_memory_id(), state, _elements(fact_1="keep me"), sweep=1)

    assert "fact_2" in outcome.after.by_name()
    assert outcome.after.by_name()["fact_2"].text == "also keep me"
    assert not any(d.op is DeltaOp.REMOVE for d in outcome.deltas)


def test_consolidate_rejects_incoming_that_names_one_element_twice() -> None:
    """Unchecked, the same upstream bug splits into two different silent
    behaviours: a repeated name absent from `state` blows up inside
    `apply_deltas` claiming the element "already exists", while a repeated name
    present in `state` emits two AMENDs in one sweep and quietly keeps the last
    -- an unannounced last-writer-wins over a memory's content."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    duplicated = (Element(name="fact_1", text="first"), Element(name="fact_1", text="second"))

    with pytest.raises(ValueError, match="fact_1"):
        consolidator.consolidate(mint_memory_id(), ElementSet(), duplicated, sweep=1)

    state = ElementSet(elements=_elements(fact_1="original"))
    with pytest.raises(ValueError, match="fact_1"):
        consolidator.consolidate(mint_memory_id(), state, duplicated, sweep=1)


def test_a_sweep_that_re_observes_nothing_leaves_every_element_intact() -> None:
    """The realistic brevity-bias trigger: an upstream batch returns nothing at
    all this sweep. "Observed nothing" must mean "learned nothing", never
    "everything is retired"."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    state = ElementSet(elements=_elements(fact_1="a", fact_2="b", fact_3="c"))

    outcome = consolidator.consolidate(mint_memory_id(), state, (), sweep=7)

    assert outcome.after == state
    assert outcome.deltas == ()


def test_re_running_the_same_sweep_is_idempotent() -> None:
    """A worker retry (queue redelivery, crash after apply / before commit)
    must not double-apply. Feeding the same `incoming` against the state the
    first run produced emits nothing at all."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()
    incoming = _elements(fact_1="v1", fact_2="v2")

    first = consolidator.consolidate(memory_id, ElementSet(), incoming, sweep=1)
    second = consolidator.consolidate(memory_id, first.after, incoming, sweep=1)

    assert second.deltas == ()
    assert second.records == ()
    assert second.after == first.after


# --------------------------------------------------------------------------- #
# The deltas module's own preconditions.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("op", "text"),
    [
        (DeltaOp.REMOVE, "text a REMOVE must not carry"),
        (DeltaOp.ADD, None),
        (DeltaOp.AMEND, None),
        (DeltaOp.ADD, "   "),
    ],
)
def test_delta_rejects_mismatched_text(op: DeltaOp, text: str | None) -> None:
    """A REMOVE carrying replacement text is an AMEND under a different name,
    which defeats a closed, inspectable vocabulary; an ADD/AMEND without text
    would construct an empty element."""
    with pytest.raises(ValueError):
        Delta(op=op, name="fact_1", text=text)


def test_delta_and_element_reject_empty_names() -> None:
    with pytest.raises(ValueError):
        Delta(op=DeltaOp.REMOVE, name="   ")
    with pytest.raises(ValueError):
        Element(name="  ", text="something")
    with pytest.raises(ValueError):
        Element(name="fact_1", text="   ")


def test_element_set_rejects_duplicate_names() -> None:
    """`by_name()` silently keeps the last of a duplicated name, so an
    ElementSet that allowed duplicates would make an element unreachable and
    un-amendable while still rendering."""
    with pytest.raises(ValueError):
        ElementSet(elements=(*_elements(fact_1="a"), Element(name="fact_1", text="b")))


def test_apply_delta_enforces_each_op_precondition() -> None:
    """Never silently downgraded to a different op: an AMEND behaving like an
    ADD would make "something vanished and got re-added" indistinguishable from
    "nothing changed"."""
    populated = ElementSet(elements=_elements(fact_1="here"))

    with pytest.raises(ValueError, match="ADD"):
        apply_delta(populated, Delta(op=DeltaOp.ADD, name="fact_1", text="again"))
    with pytest.raises(ValueError, match="AMEND"):
        apply_delta(ElementSet(), Delta(op=DeltaOp.AMEND, name="fact_1", text="v2"))
    with pytest.raises(ValueError, match="REMOVE"):
        apply_delta(ElementSet(), Delta(op=DeltaOp.REMOVE, name="fact_1"))


def test_apply_delta_preserves_element_order_on_amend() -> None:
    """An AMEND must not reorder the set: `render()` joins in stored order, so
    a reordering AMEND silently rewrites the rendered content of a memory
    nobody asked to change."""
    state = ElementSet(elements=_elements(a="1", b="2", c="3"))
    after = apply_delta(state, Delta(op=DeltaOp.AMEND, name="a", text="1-v2"))
    assert [e.name for e in after.elements] == ["a", "b", "c"]
    assert after.render() == "1-v2\n2\n3"


# --------------------------------------------------------------------------- #
# Applying deltas in order reproduces the final state.
# --------------------------------------------------------------------------- #


def test_applying_recorded_deltas_in_order_reproduces_the_final_state() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()
    state = ElementSet()
    all_deltas: list[Delta] = []

    sweeps = [
        {"a": "1"},
        {"a": "1", "b": "2"},
        {"a": "1-updated", "b": "2"},
        {"a": "1-updated", "b": "2", "c": "3"},
    ]
    for sweep, facts in enumerate(sweeps, start=1):
        outcome = consolidator.consolidate(memory_id, state, _elements(**facts), sweep=sweep)
        all_deltas.extend(outcome.deltas)
        state = outcome.after

    replayed = apply_deltas(ElementSet(), all_deltas)
    assert replayed == state
    assert replayed.by_name()["a"].text == "1-updated"
    assert replayed.by_name()["c"].text == "3"


# --------------------------------------------------------------------------- #
# The pre-consolidation state is reconstructible.
# --------------------------------------------------------------------------- #


def test_pre_consolidation_state_is_reconstructible_from_the_delta_log() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()
    state = ElementSet()
    records = []
    before_sweep_2 = None

    for sweep, facts in enumerate([{"a": "1"}, {"a": "1", "b": "2"}, {"a": "1", "b": "2-v2"}], start=1):
        if sweep == 2:
            before_sweep_2 = state
        outcome = consolidator.consolidate(memory_id, state, _elements(**facts), sweep=sweep)
        records.extend(outcome.records)
        state = outcome.after

    reconstructed = reconstruct(records, upto_sweep=2)
    assert before_sweep_2 is not None
    assert reconstructed == before_sweep_2
    assert reconstruct(records) == state  # replaying the whole log reproduces the final state too


def test_reconstruct_upto_sweep_stops_before_that_sweep_not_after_it() -> None:
    """The off-by-one that matters: `upto_sweep=N` is the state a forensics
    walk sees as "before sweep N ran". Including sweep N's own deltas would
    show the auditor the state they are trying to look behind."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()

    first = consolidator.consolidate(memory_id, ElementSet(), _elements(a="1"), sweep=1)
    second = consolidator.consolidate(memory_id, first.after, _elements(a="1", b="2"), sweep=2)
    records = [*first.records, *second.records]

    assert reconstruct(records, upto_sweep=1) == ElementSet()  # before anything ran
    assert reconstruct(records, upto_sweep=2) == first.after  # sweep 2's ADD not applied
    assert reconstruct(records, upto_sweep=3) == second.after  # both sweeps applied


def test_a_whole_content_rewrite_is_representable_but_stays_reversible() -> None:
    """The honest limit of "never rewrite in place" (consolidator docstring):
    an `incoming` that re-states EVERY element with shorter text IS accepted,
    and emits one AMEND per element. What the structure buys is that the sweep
    is inspectable (every AMEND names what it changed) and that the exact
    pre-sweep state comes back out of the log -- not that it was prevented.
    This test pins that limit so nobody reads the structural tests below as a
    stronger claim than they are."""
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()
    before = ElementSet(
        elements=_elements(a="a long, detailed fact", b="another long fact", c="a third")
    )

    outcome = consolidator.consolidate(
        memory_id, before, _elements(a="short", b="short", c="short"), sweep=9
    )

    assert len(outcome.deltas) == len(before.elements)
    assert all(d.op is DeltaOp.AMEND for d in outcome.deltas)
    assert {d.name for d in outcome.deltas} == {"a", "b", "c"}
    # ...and the collapse is fully undone from the recorded log alone.
    assert reconstruct(outcome.records, upto_sweep=9) == ElementSet()
    assert apply_deltas(before, outcome.deltas) == outcome.after


# --------------------------------------------------------------------------- #
# Explicit retraction (REMOVE) is caller-driven, never inferred.
# --------------------------------------------------------------------------- #


def test_retract_emits_an_explicit_remove_delta() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    memory_id = mint_memory_id()
    state = ElementSet(elements=_elements(fact_1="stale"))

    outcome = consolidator.retract(memory_id, state, "fact_1", sweep=1)

    assert outcome.deltas == (Delta(op=DeltaOp.REMOVE, name="fact_1"),)
    assert outcome.after.by_name() == {}
    assert outcome.records[0].delta.op is DeltaOp.REMOVE


def test_retract_raises_for_a_name_that_does_not_exist() -> None:
    clock = FakeClock()
    consolidator = Consolidator(clock)
    with pytest.raises(KeyError):
        consolidator.retract(mint_memory_id(), ElementSet(), "nonexistent", sweep=1)


# --------------------------------------------------------------------------- #
# NO code path replaces content wholesale -- asserted structurally.
# --------------------------------------------------------------------------- #


def test_consolidator_exposes_only_named_element_operations() -> None:
    """`Consolidator`'s only two public entry points are `consolidate`
    (named-element ADD/AMEND) and `retract` (named-element REMOVE); neither
    accepts a parameter that could plausibly mean "replace the whole content
    with this string"."""
    public_methods = [
        name
        for name, _ in inspect.getmembers(Consolidator, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]
    assert set(public_methods) == {"consolidate", "retract"}

    forbidden_param_names = {"content", "new_content", "text", "rewrite"}
    for name in public_methods:
        sig = inspect.signature(getattr(Consolidator, name))
        param_names = set(sig.parameters) - {"self"}
        assert not (param_names & forbidden_param_names), (name, param_names)


def test_element_set_exposes_no_wholesale_rewrite_method() -> None:
    """`ElementSet`'s only way to become a new value is `apply_delta`/
    `apply_deltas` (named-element operations, module-level functions, not
    methods on the class at all); it exposes no `replace`/`set_text`/
    `overwrite`-shaped method that could rewrite `.elements` from an
    arbitrary blob."""
    public_methods = {
        name
        for name, _ in inspect.getmembers(ElementSet, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    assert public_methods == {"by_name", "render"}


def test_apply_delta_is_the_only_function_returning_an_element_set_in_deltas_module() -> None:
    """Structural check over the actual module contents, not a convention:
    every top-level callable in `workers.deltas` that returns an `ElementSet`
    does so by name-scoped delta application, never by accepting a whole new
    content string."""
    import tracebed.workers.deltas as deltas_module

    element_set_producers = []
    for name in dir(deltas_module):
        if name.startswith("_"):
            continue
        obj = getattr(deltas_module, name)
        if not inspect.isfunction(obj):
            continue
        try:
            return_annotation = inspect.signature(obj).return_annotation
        except (TypeError, ValueError):
            continue
        if return_annotation in ("ElementSet", ElementSet):
            element_set_producers.append(name)

    assert set(element_set_producers) == {"apply_delta", "apply_deltas", "reconstruct"}
