"""Offline E1 catalog fences that must survive source-only review.

The exhaustive catalog/ACL proofs use isolated PG18.  These small tests pin
the ordering and staged-profile invariants which are otherwise easy to break
while editing the unreleased migration text.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.phase3


_ROOT = Path(__file__).resolve().parents[2]
_FORWARD = (_ROOT / "migrations" / "0012_erasure_saga.sql").read_text(encoding="utf-8")
_FOUNDATION = (_ROOT / "migrations" / "0010_authority_foundation.sql").read_text(encoding="utf-8")


def test_e1_activity_markers_follow_the_backfill_singleton() -> None:
    """Fence backfill must never invoke a marker before its state exists."""

    singleton = _FORWARD.index("INSERT INTO erasure_cutover_state")
    marker = _FORWARD.index("CREATE TRIGGER subject_key_erasure_activity")
    fence_backfill = _FORWARD.index("INSERT INTO subject_fence")
    assert fence_backfill < singleton < marker


def test_subject_validator_uses_portable_exact_scalar_comparison() -> None:
    """The pinned PG18 image has no ``unicode(text)`` built-in."""

    validator = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.tracebed_subject_tag_is_valid") : _FORWARD.index(
            "CREATE FUNCTION public.tracebed_subject_digest"
        )
    ]
    assert ":= unicode(" not in validator
    assert "FOR code IN 1..31" in validator
    assert "FOR code IN 127..159" in validator
    assert "chr(12288)" in validator
    assert "whitespace_only boolean := true" in validator
    assert "RETURN NOT whitespace_only" in validator


def test_e1_array_and_terminal_contracts_are_explicitly_fail_closed() -> None:
    """Empty canonical arrays and completion cannot depend on PG defaults."""

    versions = _FORWARD[
        _FORWARD.index(
            "CREATE FUNCTION public.tracebed_envelope_versions_are_valid"
        ) : _FORWARD.index("CREATE FUNCTION public.tracebed_erasure_codes_are_valid")
    ]
    codes = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.tracebed_erasure_codes_are_valid") : _FORWARD.index(
            "-- Reject legacy values"
        )
    ]
    transition = _FORWARD[
        _FORWARD.index(
            "CREATE FUNCTION public.erasure_request_enforce_transition"
        ) : _FORWARD.index("CREATE TRIGGER erasure_request_transition_guard")
    ]
    assert "IF cardinality(versions) = 0 THEN" in versions
    assert "IF cardinality(codes) = 0 THEN" in codes
    assert 'COLLATE "C"' in codes
    assert "erasure_request_terminal_pair_ck" in _FORWARD
    assert "erasure request completion is not atomic" in transition
    assert "OLD.phase IS DISTINCT FROM 'verified'" in transition
    assert "NEW.last_code IS DISTINCT FROM 'scope_complete'" in transition
    assert "subject_digest IS NOT NULL" in _FORWARD
    assert "lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL" in _FORWARD
    assert "final_receipt_digest IS NOT NULL" in _FORWARD


def test_c12_partition_acl_matrix_profiles_removed_raw_runtime_writes() -> None:
    """c12 must distinguish its SECDEF-only leaves from c11's raw ACLs."""

    profile_collector = _FOUNDATION[
        _FOUNDATION.index("), partition_acl_mismatch AS (") : _FOUNDATION.index(
            "), partition_acl_metadata_mismatch AS ("
        )
    ]
    assert "WHEN profile::text = 'cutover_0011' THEN" in profile_collector
    assert "WHEN profile::text = 'cutover_0012' THEN" in profile_collector
    # c12 must not bless pre-E2 raw API ownership or worker subject/key DML.
    c12 = profile_collector[profile_collector.index("WHEN profile::text = 'cutover_0012' THEN") :]
    assert "WHEN 'trace_subject' THEN ARRAY['tracebed_worker_group:SELECT']" in c12
    assert "WHEN 'subject_key' THEN ARRAY['tracebed_worker_group:SELECT']" in c12
    assert (
        "WHEN 'run_owner' THEN ARRAY['tracebed_api_group:SELECT','tracebed_worker_group:SELECT']"
        in c12
    )
    for parent in ("subject_fence", "run_fence", "erase_run_set", "erase_mem_set"):
        assert f"WHEN '{parent}' THEN ARRAY[]::text[]" in profile_collector


def test_e1_rollback_authenticates_receipts_fences_and_trace_job_backfill() -> None:
    rollback = (_ROOT / "migrations" / "0012_erasure_saga.rollback.sql").read_text(encoding="utf-8")
    assert "rollback_quarantined_at IS NOT NULL" in rollback
    assert "rollback yoyo history mismatch" in rollback
    assert "rollback binding receipt mismatch" in rollback
    assert "rollback fence membership mismatch" in rollback
    assert "FROM public.trace_learning_job AS job" in rollback


def test_request_acceptance_uses_the_global_run_subject_fence_order() -> None:
    """A request locks a stable full union before any run fence or closure set.

    This guards the exact E2 ordering, including the subtle PL/pgSQL output
    name collision that would otherwise make a no-run request fail after the
    request row had been staged.
    """

    request = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.tracebed_request_erasure") : _FORWARD.index(
            "CREATE FUNCTION public.tracebed_erasure_request_status"
        )
    ]
    union = request.index("INTO closure_digests")
    subject_fences = request.index("INSERT INTO public.subject_fence", union)
    run_fence = request.index("INSERT INTO public.run_fence", subject_fences)
    assert union < subject_fences < run_fence
    assert "ON CONFLICT ON CONSTRAINT erase_run_set_pkey DO NOTHING" in request
    assert "ON CONFLICT ON CONSTRAINT erase_mem_set_pkey DO NOTHING" in request


def test_run_memory_binding_refines_the_project_sentinel_to_real_subjects() -> None:
    """A project-attributed unbound memory cannot retain that sentinel once bound."""

    binding = _FORWARD[
        _FORWARD.index("CREATE FUNCTION public.tracebed_bind_run_memory") : _FORWARD.index(
            "CREATE FUNCTION public.tracebed_lock_run_subject_snapshot"
        )
    ]
    assert "WITH concrete AS" in binding
    assert (
        "WHERE digest <> public.tracebed_subject_digest(expected_project_id, '__project__')"
        in binding
    )
    assert "current_memory_digests" in binding


def test_raw_runtime_dml_has_a_project_locking_fence_backstop() -> None:
    """Legacy runtime grants cannot bypass an active E2 request.

    Application paths acquire the shared project lock before any business row.
    This trigger deliberately uses a nonblocking acquisition because a raw
    UPDATE can already hold a tuple lock; it must fail closed rather than
    invert the request's project→business lock order.
    """

    guard = _FORWARD[
        _FORWARD.index(
            "CREATE FUNCTION public.tracebed_runtime_erasure_write_guard"
        ) : _FORWARD.index("ALTER TABLE principal_grant DROP CONSTRAINT")
    ]
    assert "pg_try_advisory_xact_lock_shared" in guard
    assert "tracebed.erasure.project/v1:" in guard
    assert "request_row.disposition <> 'scope_complete'" in guard
    assert "IF session_user = 'tracebed_owner' THEN" in guard
    assert "session_user NOT IN ('tracebed_api', 'tracebed_worker')" in guard
    assert "ab_trace_subject_erasure_write_guard" in guard
    assert "ab_work_queue_erasure_write_guard" in guard
    assert "ab_run_memory_binding_erasure_write_guard" in guard
    for relation in (
        "run_owner",
        "work_queue",
        "dead_letter",
        "trace_index",
        "trace_subject",
        "subject_key",
        "memory_item",
        "memory_link",
        "derived_state",
        "outcome_event",
        "injection_log",
        "retrieval_event",
        "blackboard_entry",
        "invalidation_event",
        "spend_ledger",
        "review_queue",
        "memory_status_log",
        "memory_q_update",
        "trace_learning_job",
        "killswitch_state",
        "project_config",
        "agent_type_config",
        "run_memory_binding",
    ):
        assert f"ON {relation}" in guard


def test_runtime_rls_uses_an_invoker_wrapper_for_fenced_reads() -> None:
    """Raw SELECT must not inherit a SECDEF current_user bypass."""

    helper = _FORWARD[
        _FORWARD.index(
            "CREATE FUNCTION public.tracebed_erasure_project_is_quiesced"
        ) : _FORWARD.index("-- Keep the established single isolation-policy shape")
    ]
    assert "tracebed_erasure_project_is_quiesced" in helper
    assert "LANGUAGE plpgsql SECURITY DEFINER" in helper
    assert "CREATE FUNCTION public.tracebed_runtime_erasure_read_allowed" in helper
    assert "LANGUAGE plpgsql SECURITY INVOKER" in helper
    assert "session_user NOT IN ('tracebed_owner', 'tracebed_api', 'tracebed_worker')" in helper
    assert "current_user IS DISTINCT FROM session_user" in helper
    assert "RETURN NOT public.tracebed_erasure_project_is_quiesced(expected_project_id)" in helper
    assert "CREATE POLICY work_queue_erasure_isolation" in _FORWARD
    assert "CREATE POLICY dead_letter_erasure_isolation" in _FORWARD
    assert "CREATE POLICY killswitch_state_erasure_isolation" in _FORWARD


def test_c11_profile_does_not_require_unpublished_e1_partition_families() -> None:
    """A live c11 project must remain profile-valid before the E1 cutover."""

    profile_collector = _FOUNDATION[
        _FOUNDATION.index("CREATE FUNCTION public.authority_acl_profile_actual_tuples") :
    ]
    assert "WHERE profile = 'cutover_0012'::public.authority_acl_profile" in profile_collector
    assert "AS erasure_parent(parent_name)" in profile_collector


def test_e3_first_receipt_hashes_the_null_predecessor_with_an_explicit_sentinel() -> None:
    """The generation-zero fence receipt must hash rather than SQL-null out."""

    digest = _FORWARD[
        _FORWARD.index(
            "CREATE OR REPLACE FUNCTION public.tracebed_erasure_receipt_digest("
        ) : _FORWARD.index("CREATE OR REPLACE FUNCTION public.tracebed_erasure_append_receipt(")
    ]
    assert "IMMUTABLE SECURITY INVOKER" in digest
    assert "IMMUTABLE STRICT" not in digest
    assert "CASE WHEN expected_previous_digest IS NULL THEN decode('00','hex')" in digest


def test_e3_project_partition_teardown_keeps_destroyed_key_tombstones() -> None:
    """A deleted project retains its cryptographically destroyed key evidence."""

    teardown = _FORWARD[
        _FORWARD.index(
            "CREATE OR REPLACE FUNCTION public.tracebed_erasure_drop_project_partitions("
        ) : _FORWARD.index("-- Keep the public E3 batch signature")
    ]
    parents = teardown[
        teardown.index("FOREACH parent_name IN ARRAY ARRAY[") : teardown.index(
            "] LOOP", teardown.index("FOREACH parent_name IN ARRAY ARRAY[")
        )
    ]
    assert "subject_key" not in parents
    assert "``subject_key`` is deliberately excluded" in _FORWARD


def test_e3_resume_is_an_atomic_chained_operator_receipt() -> None:
    """A blocked request cannot be silently reactivated outside the receipt chain."""

    resume = _FORWARD[
        _FORWARD.index(
            "CREATE OR REPLACE FUNCTION public.tracebed_erasure_resume_blocked("
        ) : _FORWARD.index(
            "CREATE OR REPLACE FUNCTION public.tracebed_erasure_verify_and_complete("
        )
    ]
    assert "'operator_resumed'" in resume
    assert "'queue', 'succeeded', 'operator_resumed'" in resume
    assert "tracebed_erasure_append_receipt" in resume
    assert "next_step_seq" not in resume  # append_receipt owns cursor allocation.
    assert resume.count("tracebed_erasure_drop_capability") == 2
