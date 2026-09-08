# Tracebed memory-flow model

## Reading this model

The model distinguishes three facts that must not be conflated:

1. A candidate was selected while assembling a Tracebed response.
2. Tracebed recorded that final selected result in its retrieval/injection records.
3. A host actually delivered, used, or benefited from that context.

The first two can be represented by source behavior and transactional records. The third is owned
by the host and is not established by selected-for-response telemetry. HOLDOUT shadow selection is
also deliberate evaluation behavior and is not delivery.

> This is an intended architectural model, not a record of an enabled deployment. For current
> capability states, use [CAPABILITIES.md](CAPABILITIES.md).

Tracebed is designed as an execution-derived learning sidecar. A host may send execution events
and later ask for bounded context. The sidecar should treat derived content as fallible data, not
as instructions or a substitute for the host's policy decisions.

The intended path is:

1. The host sends execution events and outcomes to the ingest boundary.
2. The service stores execution evidence.
3. Background derivation may create a candidate or governed-memory record.
4. A later host query may request bounded retrieval over that candidate set.
5. Retrieval returns a data block or an abstention; the host decides whether and how to use it.

The stages above need separate deployment evidence. In particular, the presence of a worker or a
retrieval path does not show that all events are captured, a learning loop runs, or an agent is
improving. See [DATA-LIFECYCLE.md](DATA-LIFECYCLE.md) for handling expectations and
[THREAT-MODEL.md](THREAT-MODEL.md) for trust boundaries. [ARCHITECTURE.md](ARCHITECTURE.md)
provides accessible retrieval and evidence-flow diagrams with code source maps.

No host-specific adapter is included in this repository. Integrators should implement and test
the ports described in [ADAPTER-GUIDE.md](ADAPTER-GUIDE.md).
