"""The embedding model pin registry (PLAN.md §6 `embedding.*`, D-007, PLAN.md §10).

`ModelPin` is the configured embedding identity a deployment has committed to:
`model_id` + `model_version` + `dim`, exactly the triple PLAN.md §5's DDL stamps
on every `memory_item` row (`embedding_model_id`, `embedding_model_version`; the
column is `halfvec(dim)`) and the triple `embedding_model` registers as its
primary key. `assert_pin_matches` is the guard for "swap the embedding model
silently" (PLAN.md §10, D-007): a stamp that disagrees with the currently
configured pin raises instead of silently mixing vector spaces in one ANN
comparison.

HONEST SCOPE, corrected. This docstring used to claim the guard makes a silent
swap "structurally impossible rather than merely forbidden", on the grounds
that "any code path that reads a stored row's stamped identity before using
its vector calls it first". There is no such code path. `assert_pin_matches`
has ZERO production call sites today, no module reads `embedding_model_id` /
`embedding_model_version` off a row, and `stores.pg.search.vector_arm` carries
no pin predicate -- because nothing writes an embedding either
(`Repo.insert_memory_item` has no embedding column in its INSERT), so the ANN
arm has no rows for a pin to protect. The guard is correct, tested, and
waiting; it becomes structural on the day the embedding write path lands, and
that day it must be called from the read path and from the ANN predicate. See
PLAN.md's known-gaps section.

Re-embedding migration path (owned by a later phase's backfill worker, not by
this module — this is the contract that worker must honour):

  1. Choose a new `(model_id, model_version)` pair and register it via
     `Repo.record_embedding_model(...)` as a NEW `embedding_model` row — never
     an `UPDATE` of the old one. Rows already embedded under the old pin must
     stay queryable against their own recorded pin while the migration runs.
  2. Deploy with `EmbeddingConfig` pointing at the new pin. From that moment
     the hot path stamps `embedding_model_id`/`embedding_model_version` with
     the new pin on every newly embedded row.
  3. Run an explicit backfill worker that re-embeds every existing
     `memory_item` row still stamped with the old pin and rewrites its
     `embedding` column and stamped columns in the same write.
  4. Until backfill completes, retrieval must never compare vectors stamped
     with different pins in one ANN scan. `assert_pin_matches` is the runtime
     guard a retriever calls before trusting a fetched row's vector — it is
     the check that catches a not-yet-backfilled row before it reaches a
     distance computation against a query embedded under the new pin.
  5. Retire the old `embedding_model` row only once the backfill sweep
     confirms zero remaining rows stamped with it.

No path exists that changes `model_id`/`model_version` in place; every step
above is an explicit, versioned, observable migration.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from tracebed.domain.errors import TracebedError

__all__ = [
    "EmbeddingDimensionMismatch",
    "EmbeddingPinMismatch",
    "EmbeddingProviderError",
    "ModelPin",
    "assert_pin_matches",
    "validate_batch",
]


@dataclass(frozen=True, slots=True)
class ModelPin:
    """The embedding identity a deployment is configured for right now.

    Mirrors `EffectiveConfig`'s (deployment-level) `embedding.model_id` /
    `model_version` / `dim` fields — constructed once at wiring time and
    handed to every `EmbeddingPort` driver and every consumer that verifies a
    stored row's stamp against it.
    """

    model_id: str
    model_version: str
    dim: int


class EmbeddingPinMismatch(TracebedError):
    """A stored row's stamped `(model_id, model_version)` disagrees with `configured`.

    This is the guard that makes a silently-swapped embedding model (PLAN.md
    §10) a raised error instead of a corrupted vector comparison: any code
    that is about to use a fetched row's `embedding` column for an ANN
    distance calls `assert_pin_matches` first.
    """

    def __init__(self, *, row_model_id: str, row_model_version: str, configured: ModelPin) -> None:
        super().__init__(
            f"row embedded under {row_model_id!r}/{row_model_version!r}; configured pin is "
            f"{configured.model_id!r}/{configured.model_version!r} -- re-embedding is an "
            "explicit versioned migration, never a silent swap"
        )
        self.row_model_id = row_model_id
        self.row_model_version = row_model_version
        self.configured = configured


class EmbeddingDimensionMismatch(TracebedError):
    """A live `EmbeddingPort` driver returned a vector whose length disagrees
    with the configured pin's `dim`.

    Distinct from `EmbeddingPinMismatch`: that one compares two *stamps*
    already on disk; this one catches a driver instance that would write a
    wrong-dimension vector into a `halfvec(dim)` column in the first place —
    the failure this is guarding against is a driver misconfiguration (wrong
    pin wired to a model that does not actually produce `dim`-length output),
    not a stale row.
    """

    def __init__(self, *, actual_dim: int, configured: ModelPin) -> None:
        super().__init__(
            f"embedding driver returned a vector of dim={actual_dim}; configured pin "
            f"{configured.model_id!r}/{configured.model_version!r} requires dim={configured.dim}"
        )
        self.actual_dim = actual_dim
        self.configured = configured


class EmbeddingProviderError(TracebedError):
    """An `EmbeddingPort` driver's transport succeeded but its payload was unusable.

    Deliberately distinct from `EmbeddingTimeout` (`domain.errors`): this is
    "the endpoint answered, but not with something `embed()` can return" —
    wrong vector count for the input batch, a response missing the fields the
    driver needs to reorder vectors into input order, or (for the local
    driver) an inference call that could not be evaluated. Shared by every
    `EmbeddingPort` driver rather than duplicated per-driver so a caller can
    catch one name for "the provider misbehaved" regardless of which driver
    is configured.
    """


def assert_pin_matches(row_model_id: str, row_version: str, configured: ModelPin) -> None:
    """Raises `EmbeddingPinMismatch` unless the row's stamp equals `configured`.

    Pure equality check on the two identity fields — `dim` is not compared
    here because it is not stamped per-row (PLAN.md §5's `memory_item` has no
    separate dim column; the `halfvec(dim)` column type already fixes it for
    the whole partition). A dimension disagreement between a driver and its
    configured pin is `EmbeddingDimensionMismatch`, raised where the vector is
    produced, not where it is compared.
    """
    if row_model_id != configured.model_id or row_version != configured.model_version:
        raise EmbeddingPinMismatch(
            row_model_id=row_model_id, row_model_version=row_version, configured=configured
        )


def validate_batch(
    vectors: Sequence[Sequence[float]], *, expected: int, configured: ModelPin
) -> None:
    """The last gate every `EmbeddingPort` driver passes its output through.

    Shared by both drivers rather than duplicated per-driver so that "what a
    vector must be before it is allowed to reach a `halfvec(dim)` column or an
    ANN distance" is stated exactly once:

      - one vector per input, in input order (a count disagreement means the
        remaining vectors are attributed to the wrong texts);
      - every vector exactly `configured.dim` long (a wrong-length vector is a
        driver wired to a model that does not produce the pinned dimension —
        `EmbeddingDimensionMismatch`, distinct from a stale row's
        `EmbeddingPinMismatch`);
      - every component finite. `json.loads` accepts the bare `NaN` /
        `Infinity` literals and `float("1e999")` is `inf`; either one silently
        poisons every distance the vector ever participates in, and unlike a
        wrong dimension nothing downstream would ever raise on it.
    """
    if len(vectors) != expected:
        raise EmbeddingProviderError(
            f"embedding driver produced {len(vectors)} vectors for {expected} inputs"
        )
    for position, vector in enumerate(vectors):
        if len(vector) != configured.dim:
            raise EmbeddingDimensionMismatch(actual_dim=len(vector), configured=configured)
        if not all(math.isfinite(value) for value in vector):
            raise EmbeddingProviderError(
                f"embedding driver produced a non-finite component in vector {position}"
            )
