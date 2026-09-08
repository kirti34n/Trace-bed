#!/usr/bin/env python3
"""Reproducible Compose-v1 live acceptance checks.

This is deliberately an operator-free test harness, not a generic Compose
wrapper.  It creates disposable named secret files, brings the fixed profile
up through :mod:`scripts.compose_stack`, probes only the declared container
routes, and removes its containers, networks, volumes, and secrets on exit.
It never accepts a DSN, password, host, service, or Docker argument.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast
from uuid import UUID, uuid4

_ROOT: Final = Path(__file__).resolve().parents[1]
_COMPOSE: Final = _ROOT / "docker" / "compose.yaml"
_PROJECT_LABEL: Final = "com.docker.compose.project"
_PROJECT_PREFIX: Final = "tracebed-acceptance-"
_DEFAULT_PROJECT: Final = "tracebed"
_DOCKER_CONTAINER_ID_RE: Final = re.compile(r"\A[0-9a-f]{12,64}\Z")
_API_HOST_PORT_ENV: Final = "TB_API_HOST_PORT"
_DASHBOARD_HOST_PORT_ENV: Final = "TB_DASHBOARD_HOST_PORT"
_WORKER_SERVING_WAIT_SECONDS: Final = 120.0
_E4_ERASURE_WAIT_SECONDS: Final = 180.0
_E4_RESTART_WAIT_SECONDS: Final = 45.0
_E4_QUIESCE_WAIT_SECONDS: Final = 45.0
_ERASURE_QUIESCE_ACK_PATH: Final = "/tmp/tracebed-erasure-quiesced-v1"  # noqa: S108 - fixed container-local receipt
_ERASURE_QUIESCE_ACK_CONTENT: Final = b"tracebed-erasure-quiesced-v1\n"
_ERASURE_QUIESCE_ACK_MODE: Final = 0o600
_ERASURE_DAEMON_RUNNING_STATES: Final = frozenset({"D", "I", "R", "S"})
_ERASURE_FAULT_PROXY_PORT: Final = 19876
_SECRET_NAMES: Final = (
    "owner_db_password",
    "app_db_password",
    "api_db_password",
    "worker_db_password",
    "erasure_db_password",
    "s3_signing_key",
    "s3_init_access_key",
    "s3_init_secret_key",
    "s3_runtime_access_key",
    "s3_runtime_secret_key",
    "s3_erasure_access_key",
    "s3_erasure_secret_key",
    "holdout_salt",
    "master_key",
    "admin_key",
    "readyz_token",
)
_CURRENT_STEP = ""
_CURRENT_DIAGNOSTIC = ""
_ACTIVE_RESOURCES: _AcceptanceResources | None = None
_LIFECYCLE_DIAGNOSTIC_CODES: Final = frozenset(
    {
        "publish-bootstrap-apply",
        "publish-cutover-0012-closed",
        "publish-cutover-0013",
        "publish-s3-init",
        "publish-runtime-start",
        "publish-closed-probe",
        "publish-one-shot-residue",
        "publish-admission-open",
        "start-rendered-preflight",
        "start-rollback-recovery",
        "start-preflight",
        "start-bootstrap-preflight",
        "start-image-build",
        "start-s3-volume",
        "start-core-start",
        "upgrade-rendered-preflight",
        "upgrade-fence-drain",
        "upgrade-image-build",
        "upgrade-postgres-recreate",
        "rendered-secret-source-preflight",
        "rendered-compose-config",
        "rendered-json",
        "rendered-topology",
        "rendered-project",
        "rendered-network-preflight",
        "rollback-rendered-preflight",
        "rollback-fence-drain",
        "rollback-bootstrap",
        "rollback-refusal-recovery-preflight",
        "rollback-refusal-restore-closed-worker",
        "rollback-restore-closed-worker",
    }
)
_NETWORK_PREFLIGHT_DIAGNOSTIC_REASONS: Final = frozenset(
    {
        "checked-subnet",
        "docker-ipam-overlap",
        "docker-ipam-shape",
        "docker-ipam-subnet",
        "docker-network-inspect",
        "docker-network-json",
        "docker-network-list",
        "docker-network-shape",
        "host-route-destination",
        "host-route-json-shape",
        "host-route-overlap",
        "host-route-read",
        "host-route-shape",
        "ip-command-unavailable",
        "owned-attachment-address",
        "owned-attachment-address-set",
        "owned-attachment-count",
        "owned-attachment-empty",
        "owned-attachment-id",
        "owned-attachment-shape",
        "owned-attachment-stage",
        "owned-bridge-companion-shape",
        "owned-bridge-route-shape",
        "owned-container-address",
        "owned-container-count",
        "owned-container-identity",
        "owned-container-inspect",
        "owned-container-json",
        "owned-container-label",
        "owned-container-networks",
        "owned-container-shape",
        "owned-core-state",
        "owned-network-compose-label",
        "owned-network-containers",
        "owned-network-count",
        "owned-network-identity",
        "owned-network-label",
        "owned-network-logical-set",
        "owned-network-name-set",
        "owned-network-shape",
        "owned-network-subnet",
        "owned-runtime-state",
        "owned-service-set",
        "owned-topology",
        "policy-custom-default",
        "policy-custom-route-overlap",
        "policy-custom-route-shape",
        "policy-reserved-default",
        "policy-rule-action",
        "policy-rule-selector",
        "policy-rule-shape",
        "policy-selector-shape",
        "policy-table-shape",
    }
)

_BOOTSTRAP_HBA_PROBE: Final = r'''
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4
import os
import psycopg

def secret(name):
    return Path('/run/secrets/' + name).read_text().rstrip('\n')

def dsn(user, password, host, database='tracebed'):
    return f'postgresql://{user}:{quote(password, safe="")}@{host}:5432/{database}'

def rejected(label, url):
    try:
        with psycopg.connect(url, connect_timeout=3):
            raise SystemExit(label + ': unexpectedly allowed')
    except psycopg.Error as error:
        print(label + ': rejected sqlstate=' + str(error.sqlstate))

owner = secret('owner_db_password')
api = secret('api_db_password')
worker = secret('worker_db_password')
erasure = secret('erasure_db_password')
with psycopg.connect(dsn('tracebed_owner', owner, 'postgres-admin'), connect_timeout=3) as conn:
    print('owner-admin: allowed')
    nonce = 'tracebed_bootstrap_probe_' + uuid4().hex
    nonce_password = 'nonce' + uuid4().hex
    conn.execute(
        'CREATE ROLE ' + psycopg.sql.Identifier(nonce).as_string(conn)
        + ' LOGIN PASSWORD ' + psycopg.sql.Literal(nonce_password).as_string(conn)
    )
    conn.execute('GRANT CONNECT ON DATABASE tracebed TO ' + psycopg.sql.Identifier(nonce).as_string(conn))
    # The probe opens a second session, so make the disposable login visible
    # before checking the narrowly permitted bootstrap subnet route.
    conn.commit()
    try:
        with psycopg.connect(dsn(nonce, nonce_password, 'postgres-probe'), connect_timeout=3):
            print('nonce-probe: allowed')
        if os.environ.get('B4_ERASURE_LOGIN') == 'active':
            with psycopg.connect(dsn('tracebed_erasure', erasure, 'postgres-erasure'), connect_timeout=3):
                print('erasure-own-subnet: allowed')
        else:
            rejected('erasure-own-subnet', dsn('tracebed_erasure', erasure, 'postgres-erasure'))
        rejected('owner-wrong-subnet', dsn('tracebed_owner', owner, 'postgres-api'))
        rejected('api-wrong-subnet', dsn('tracebed_api', api, 'postgres-worker'))
        rejected('worker-wrong-subnet', dsn('tracebed_worker', worker, 'postgres-api'))
        rejected('erasure-wrong-subnet', dsn('tracebed_erasure', erasure, 'postgres-api'))
        rejected('nonce-wrong-subnet', dsn(nonce, nonce_password, 'postgres-api'))
        rejected('owner-wrong-password', dsn('tracebed_owner', 'wrong-password', 'postgres-admin'))
        rejected('erasure-wrong-password', dsn('tracebed_erasure', 'wrong-password', 'postgres-erasure'))
        rejected('legacy-app', dsn('tracebed_app', secret('app_db_password'), 'postgres-admin'))
        rejected('arbitrary-login', dsn('tracebed_untrusted', 'untrusted', 'postgres-probe'))
        rejected('replication-final-reject', dsn('tracebed_owner', owner, 'postgres-admin', 'replication'))
    finally:
        conn.execute(
            'REVOKE CONNECT ON DATABASE tracebed FROM '
            + psycopg.sql.Identifier(nonce).as_string(conn)
        )
        conn.execute('DROP ROLE ' + psycopg.sql.Identifier(nonce).as_string(conn))
'''

_RUNTIME_HBA_PROBE: Final = r'''
from pathlib import Path
from urllib.parse import quote
import os
import psycopg

role = os.environ['B4_ROLE']
secret_name, host = {
    'tracebed_api': ('api_db_password', 'postgres-api'),
    'tracebed_worker': ('worker_db_password', 'postgres-worker'),
    'tracebed_erasure': ('erasure_db_password', 'postgres-erasure'),
}[role]
password = Path('/run/secrets/' + secret_name).read_text().rstrip('\n')
url = f'postgresql://{role}:{quote(password, safe="")}@{host}:5432/tracebed'
with psycopg.connect(url, connect_timeout=3) as conn:
    row = conn.execute('SELECT session_user::text, current_user::text').fetchone()
    if row != (role, role):
        raise SystemExit('runtime session identity mismatch')
print(role + ': allowed')
'''

_RUNTIME_CAPABILITY_PROBE: Final = r'''
from pathlib import Path
from urllib.parse import quote
import os
import psycopg

role = os.environ['B4_ROLE']
secret_name, host, own_dsn = {
    'tracebed_api': ('api_db_password', 'postgres-api', 'TB_API_DB_DSN'),
    'tracebed_worker': ('worker_db_password', 'postgres-worker', 'TB_WORKER_DB_DSN'),
    'tracebed_erasure': ('erasure_db_password', 'postgres-erasure', 'TB_ERASURE_DB_DSN'),
}[role]
password = Path('/run/secrets/' + secret_name).read_text().rstrip('\n')
url = f'postgresql://{role}:{quote(password, safe="")}@{host}:5432/tracebed'

# Inspect PID 1 names only.  The runtime wrapper deliberately creates its own
# process-local DSN, so this proves it holds exactly that role's credential
# and no owner/app/opposite runtime database variable without serialising any
# value back into the acceptance process.
names = {
    entry.partition(b'=')[0].decode('ascii')
    for entry in Path('/proc/1/environ').read_bytes().split(b'\0')
    if entry
}
forbidden = {
    'TB_STORAGE__PG_DSN',
    'TB_ONBOARDING_PG_DSN',
    'TB_OWNER_DB_DSN',
    'TB_ADMIN_PG_DSN',
    *({'TB_API_DB_DSN', 'TB_WORKER_DB_DSN', 'TB_ERASURE_DB_DSN'} - {own_dsn}),
    'TB_OWNER_DB_PASSWORD',
    'TB_APP_DB_PASSWORD',
    'TB_OWNER_DB_PASSWORD_FILE',
    'TB_APP_DB_PASSWORD_FILE',
}
if own_dsn not in names or names.intersection(forbidden):
    raise SystemExit('runtime environment boundary failed')

statements = (
    (
        ('raw-erasure-request', 'SELECT * FROM public.erasure_request LIMIT 1'),
        ('raw-erasure-ledger', 'SELECT * FROM public.erasure_step_receipt LIMIT 1'),
    )
    if role == 'tracebed_erasure'
    else
    (
        ('queue-insert', 'INSERT INTO public.work_queue DEFAULT VALUES'),
        ('run-owner-insert', 'INSERT INTO public.run_owner DEFAULT VALUES'),
        ('registry-update', 'UPDATE public.principal SET revoked_at = revoked_at WHERE false'),
    )
    if role == 'tracebed_worker'
    else (
        ('queue-update', 'UPDATE public.work_queue SET attempts = attempts WHERE false'),
        ('queue-delete', 'DELETE FROM public.work_queue WHERE false'),
        ('grant-update', 'UPDATE public.principal_grant SET revoked_at = revoked_at WHERE false'),
    )
)
for label, statement in statements:
    with psycopg.connect(url, autocommit=True, connect_timeout=3) as conn:
        try:
            conn.execute(statement)
        except psycopg.errors.InsufficientPrivilege as error:
            if error.sqlstate != '42501':
                raise SystemExit(label + ': unexpected SQLSTATE')
        else:
            raise SystemExit(label + ': unexpectedly allowed')
print(role + ': capability-boundary')
'''

_PROVISION_PROJECTS: Final = r'''
import json
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4
import psycopg
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.partitions import create_project_partitions

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_ids = [uuid4(), uuid4()]
with psycopg.connect(dsn) as conn:
    with conn.transaction():
        for ordinal, project_id in enumerate(project_ids, start=1):
            conn.execute(
                'INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, %s)',
                (project_id, 'compose-acceptance-' + str(ordinal), 'active'),
            )
            create_project_partitions(conn, ProjectId(project_id))
print(json.dumps({'projects': [str(project_id) for project_id in project_ids]}))
'''

_OWNER_ASSERT_QUEUE: Final = r'''
import json
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
run_id = os.environ['B4_RUN_ID']
data_principal = os.environ['B4_DATA_PRINCIPAL']
feedback_principal = os.environ['B4_FEEDBACK_PRINCIPAL']
with psycopg.connect(dsn) as conn:
    rows = conn.execute(
        'SELECT topic, payload, authority_version, run_id, source_principal_id, '
        'source_agent_type_id, source_grant_id, required_role, feedback_source, '
        'run_owner_principal_id, run_owner_agent_type_id, subject_digests '
        'FROM public.work_queue WHERE project_id = %s ORDER BY id',
        (project_id,),
    ).fetchall()
    project_sentinel = conn.execute(
        "SELECT public.tracebed_subject_digest(%s::uuid, '__project__')",
        (project_id,),
    ).fetchone()
if project_sentinel is None or len(project_sentinel) != 1:
    raise SystemExit('project subject sentinel is unavailable')
expected_digests = [project_sentinel[0]]
if len(rows) != 4:
    raise SystemExit('unexpected queue row count')
topics = [row[0] for row in rows]
if sorted(topics) != ['memory_proposal', 'outcome_event', 'trace_event', 'trace_event']:
    raise SystemExit('unexpected queued topics')
for topic, payload, version, item_run, source, source_agent, source_grant, role, feedback, owner, owner_agent, digests in rows:
    if version != 1 or str(item_run) != run_id or source_agent is None or source_grant is None:
        raise SystemExit('incomplete v1 envelope')
    # This fixture supplies no subject tags.  E3 consequently binds every
    # v1 queue row to the canonical project sentinel, rather than leaving an
    # unscoped empty digest array that E4 could not erase conservatively.
    if str(owner) != data_principal or owner_agent is None or digests != expected_digests:
        raise SystemExit('incorrect immutable v1 owner envelope')
    if topic == 'trace_event':
        if set(payload) != {'seq', 'event'} or role != 'data' or feedback is not None or str(source) != data_principal:
            raise SystemExit('trace envelope has a business authority shadow')
    elif topic == 'memory_proposal':
        if set(payload) != {'proposal'} or role != 'data' or feedback is not None or str(source) != data_principal:
            raise SystemExit('proposal envelope has a business authority shadow')
    elif topic == 'outcome_event':
        if set(payload) not in ({'event_id', 'outcome', 'payload'}, {'event_id', 'outcome', 'payload', 'occurred_at'}):
            raise SystemExit('outcome business payload is not exact')
        if role != 'feedback' or feedback != 'downstream' or str(source) != feedback_principal:
            raise SystemExit('outcome provenance is not persisted authority')
print('v1-queue-envelope: exact')
'''

_OWNER_OUTCOME_STATE: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
event_id = os.environ['B4_EVENT_ID']
expect_dead = os.environ['B4_EXPECT_DEAD'] == '1'
with psycopg.connect(dsn) as conn:
    outcome_count = conn.execute(
        'SELECT count(*) FROM public.outcome_event WHERE project_id = %s AND event_id = %s',
        (project_id, event_id),
    ).fetchone()[0]
    queue_count = conn.execute('SELECT count(*) FROM public.work_queue WHERE project_id = %s', (project_id,)).fetchone()[0]
    dead = conn.execute(
        "SELECT authority_version, last_error FROM public.dead_letter WHERE project_id = %s "
        "AND topic = 'outcome_event' ORDER BY failed_at DESC LIMIT 1", (project_id,)
    ).fetchone()
if outcome_count != 1 or queue_count != 0:
    raise SystemExit('worker consumption has not converged')
if expect_dead:
    if dead != (1, 'outcome_replay_conflict'):
        raise SystemExit('divergent v1 replay did not dead-letter exactly')
elif dead is not None:
    raise SystemExit('exact replay unexpectedly dead-lettered')
print('outcome-state: exact')
'''

_OWNER_REVOKE_OR_SUSPEND: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
mode = os.environ['B4_MUTATION']
target = os.environ['B4_TARGET']
with psycopg.connect(dsn) as conn:
    if mode == 'revoke':
        conn.execute('UPDATE public.principal_grant SET revoked_at = now() WHERE principal_id = %s', (target,))
    elif mode == 'suspend':
        conn.execute("UPDATE public.project SET status = 'suspended' WHERE project_id = %s", (target,))
    else:
        raise SystemExit('unsupported owner mutation')
print('owner-mutation: applied')
'''

_OWNER_EVENT_CONSUMED: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
event_id = os.environ['B4_EVENT_ID']
with psycopg.connect(dsn) as conn:
    outcome_count = conn.execute(
        'SELECT count(*) FROM public.outcome_event WHERE project_id = %s AND event_id = %s',
        (project_id, event_id),
    ).fetchone()[0]
    queue_count = conn.execute(
        "SELECT count(*) FROM public.work_queue WHERE project_id = %s "
        "AND topic = 'outcome_event' AND payload ->> 'event_id' = %s",
        (project_id, event_id),
    ).fetchone()[0]
if outcome_count != 1 or queue_count != 0:
    raise SystemExit('queued outcome has not converged')
print('queued-outcome: consumed')
'''

_OWNER_ASSERT_EVENT_PENDING: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    count = conn.execute(
        "SELECT count(*) FROM public.work_queue "
        "WHERE authority_version = 1 AND topic = 'outcome_event' "
        "AND project_id = %s AND payload->>'event_id' = %s",
        (os.environ['B4_PROJECT_ID'], os.environ['B4_EVENT_ID']),
    ).fetchone()
if count != (1,):
    raise SystemExit('expected pending v1 outcome work')
'''


_PROVISION_E4_PROJECTS: Final = r'''
import json
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4
import psycopg
from tracebed.domain.ids import ProjectId
from tracebed.stores.pg.partitions import create_project_partitions

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_ids = [uuid4(), uuid4(), uuid4()]
with psycopg.connect(dsn) as conn:
    with conn.transaction():
        for ordinal, project_id in enumerate(project_ids, start=1):
            conn.execute(
                'INSERT INTO public.project (project_id, name, status) VALUES (%s, %s, %s)',
                (project_id, 'compose-e4-acceptance-' + str(ordinal), 'active'),
            )
            create_project_partitions(conn, ProjectId(project_id))
print(json.dumps({'projects': [str(project_id) for project_id in project_ids]}))
'''


_OWNER_E4_TRACE_READY: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
run_ids = os.environ['B4_RUN_IDS'].split(',')
with psycopg.connect(dsn) as conn:
    rows = conn.execute(
        'SELECT count(*) FROM public.trace_index '
        'WHERE project_id = %s AND run_id = ANY(%s::uuid[]) AND payload_ref IS NOT NULL',
        (project_id, run_ids),
    ).fetchone()
if rows != (len(run_ids),):
    raise SystemExit('E4 trace fixtures are not ready')
print('e4-traces: ready')
'''


_OWNER_E4_LINKED_FIXTURE: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4
import psycopg
from psycopg.types.json import Jsonb

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
target_tag = os.environ['B4_TARGET_TAG']
other_tag = os.environ['B4_OTHER_TAG']
target_run = os.environ['B4_TARGET_RUN']
with psycopg.connect(dsn) as conn:
    target_digest = conn.execute(
        'SELECT public.tracebed_subject_digest(%s::uuid, %s)', (project_id, target_tag)
    ).fetchone()[0]
    other_digest = conn.execute(
        'SELECT public.tracebed_subject_digest(%s::uuid, %s)', (project_id, other_tag)
    ).fetchone()[0]
    target_memory, linked_memory, unrelated_memory = uuid4(), uuid4(), uuid4()
    rows = [
        (target_memory, target_digest, 'target'),
        (linked_memory, target_digest, 'linked'),
        (unrelated_memory, other_digest, 'unrelated'),
    ]
    for memory_id, digest, label in rows:
        conn.execute(
            'INSERT INTO public.memory_item ('
            'id, project_id, scope_type, scope_id, mem_type, kind, lane, trust_tier, status, '
            'content, content_hash, token_count, provenance, scan_verdict_id, subject_digests'
            ") VALUES (%s, %s, 'project_shared', NULL, 'lesson', 'e4_fixture', 'quality', 'B', "
            "'quarantined', %s, %s, 1, %s, %s, %s::bytea[])",
            (memory_id, project_id, 'e4-' + label, (label * 16)[:64], Jsonb({'fixture': label}), uuid4(), [digest]),
        )
    conn.execute(
        "INSERT INTO public.memory_link (project_id, src_id, dst_id, relation, subject_digests) "
        "VALUES (%s, %s, %s, 'related', %s::bytea[])",
        (project_id, target_memory, linked_memory, [target_digest]),
    )
    conn.execute(
        'INSERT INTO public.run_memory_binding (project_id, run_id, memory_id) VALUES (%s, %s, %s)',
        (project_id, target_run, target_memory),
    )
    conn.commit()
print('e4-linked-fixture: ready')
'''


_OWNER_E4_SUBJECT_COMPLETE: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
request_id = os.environ['B4_REQUEST_ID']
target_tag = os.environ['B4_TARGET_TAG']
target_run = os.environ['B4_TARGET_RUN']
shared_run = os.environ['B4_SHARED_RUN']
other_run = os.environ['B4_OTHER_RUN']
with psycopg.connect(dsn) as conn:
    target_digest = conn.execute(
        'SELECT public.tracebed_subject_digest(%s::uuid, %s)', (project_id, target_tag)
    ).fetchone()[0]
    request_row = conn.execute(
        'SELECT phase, disposition, lease_token IS NULL, final_receipt_digest = last_receipt_digest '
        'FROM public.erasure_request WHERE project_id = %s AND request_id = %s',
        (project_id, request_id),
    ).fetchone()
    key_row = conn.execute(
        'SELECT destroyed_at IS NOT NULL, wrapped_kek = %s::bytea FROM public.subject_key '
        'WHERE project_id = %s AND subject_digest = %s',
        (b'', project_id, target_digest),
    ).fetchone()
    target_trace = conn.execute(
        'SELECT count(*) FROM public.trace_index WHERE project_id = %s AND run_id = %s',
        (project_id, target_run),
    ).fetchone()
    retained_traces = conn.execute(
        'SELECT count(*) FROM public.trace_index WHERE project_id = %s AND run_id = ANY(%s::uuid[])',
        (project_id, [shared_run, other_run]),
    ).fetchone()
    target_memory = conn.execute(
        "SELECT count(*) FROM public.memory_item WHERE project_id = %s AND kind = 'e4_fixture' "
        "AND content IN ('e4-target', 'e4-linked')",
        (project_id,),
    ).fetchone()
    unrelated_memory = conn.execute(
        "SELECT count(*) FROM public.memory_item WHERE project_id = %s AND kind = 'e4_fixture' "
        "AND content = 'e4-unrelated'",
        (project_id,),
    ).fetchone()
    capability_count = conn.execute(
        'SELECT count(*) FROM public.erasure_execution_capability WHERE request_id = %s',
        (request_id,),
    ).fetchone()
    receipt_ok = conn.execute(
        'SELECT count(*) >= 2 AND bool_and(receipt_digest = public.tracebed_erasure_receipt_digest('
        'project_id, request_id, step_seq, generation, step_code, result, result_code, attempt, '
        'affected_rows, work_revision, postcondition_digest, previous_receipt_digest, started_at, finished_at)) '
        'FROM public.erasure_step_receipt WHERE request_id = %s',
        (request_id,),
    ).fetchone()
if request_row != ('scope_complete', 'scope_complete', True, True):
    raise SystemExit('subject erasure did not complete coherently')
if key_row != (True, True) or target_trace != (0,) or retained_traces != (2,):
    raise SystemExit('subject erasure did not preserve the conservative closure boundary')
if target_memory != (0,) or unrelated_memory != (1,) or capability_count != (0,) or receipt_ok != (True,):
    raise SystemExit('subject erasure postconditions are incomplete')
print('e4-subject: complete')
'''


_OWNER_E4_BLOCKED: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
request_id = os.environ['B4_REQUEST_ID']
with psycopg.connect(dsn) as conn:
    request_row = conn.execute(
        'SELECT phase, disposition, completed_at IS NULL FROM public.erasure_request WHERE request_id = %s',
        (request_id,),
    ).fetchone()
    trace_checkpoint = conn.execute(
        "SELECT count(*) FROM public.erasure_store_checkpoint WHERE request_id = %s "
        "AND store_code = 'trace_s3_v1' AND verified_revision > 0",
        (request_id,),
    ).fetchone()
if request_row is None or request_row[1:] != ('operator_blocked', True) or request_row[0] == 'scope_complete':
    raise SystemExit('object-lock-shaped refusal did not block')
if trace_checkpoint != (0,):
    raise SystemExit('object-lock-shaped refusal checkpointed prematurely')
print('e4-object-fault: blocked')
'''


# The lease-reclaim proof locks exactly the requested subject-key row that
# the first post-claim crypto mutation needs.  It deliberately does *not*
# take a table lock: E4's successor receipt inspects the profiled authority
# surface during admission, and a table-wide lock could prevent the daemon
# from reaching its durable claim at all.  The daemon is paused while the
# request and exact row lock are established, then resumed to claim it.  The
# holder is a labelled one-off under this harness's entropy-named project and
# is removed by its exact Docker ID in every path below.
_OWNER_E4_LEASE_BLOCKER: Final = r'''
import os
import time
from pathlib import Path
from urllib.parse import quote
from uuid import UUID
import psycopg

request_id = os.environ['B4_REQUEST_ID']
try:
    if str(UUID(request_id)) != request_id:
        raise ValueError
except ValueError:
    raise SystemExit('invalid lease request id') from None
password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    locked = conn.execute(
        "SELECT 1 FROM public.subject_key AS key_row "
        "JOIN public.erasure_request AS request_row "
        "ON request_row.project_id = key_row.project_id "
        "AND request_row.subject_digest = key_row.subject_digest "
        "WHERE request_row.request_id = %s AND request_row.scope = 'subject' "
        "AND request_row.phase = 'fenced' AND request_row.disposition = 'active' "
        "AND request_row.generation = 0 AND key_row.destroyed_at IS NULL "
        "FOR UPDATE OF key_row",
        (request_id,),
    ).fetchone()
    if locked != (1,):
        raise SystemExit('lease target key is not lockable')
    print('e4-lease-blocker: locked', flush=True)
    while True:
        # The fixed PostgreSQL image has a 60-second
        # idle_in_transaction_session_timeout, while an E4 lease lasts 90
        # seconds.  Keep this same uncommitted transaction active so the
        # table lock remains present until the explicit exact-ID cleanup.
        conn.execute('SELECT 1')
        time.sleep(5)
'''


_OWNER_E4_ADMISSION_BLOCKER: Final = r'''
import time
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    locked = conn.execute(
        'SELECT 1 FROM public.authority_admission_state WHERE singleton FOR UPDATE'
    ).fetchone()
    if locked != (1,):
        raise SystemExit('authority admission singleton is not lockable')
    print('e4-admission-blocker: locked', flush=True)
    while True:
        # Keep the exact row lock alive until the authenticated container is
        # removed.  This makes the daemon's admission query demonstrably
        # in-flight when SIGUSR1 requests a safe quiesce boundary.
        conn.execute('SELECT 1')
        time.sleep(5)
'''


_OWNER_E4_ADMISSION_WAIT: Final = r'''
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    waiting = conn.execute(
        "SELECT count(*) FROM pg_catalog.pg_stat_activity "
        "WHERE usename = 'tracebed_erasure' "
        "AND client_addr = inet '10.77.16.3' "
        "AND backend_type = 'client backend' "
        "AND state = 'active' "
        "AND wait_event_type = 'Lock' "
        "AND query = 'SELECT public.tracebed_erasure_admission_is_open()'"
    ).fetchone()
if waiting != (1,):
    raise SystemExit('erasure daemon is not blocked in its admission query')
print('e4-admission-blocker: daemon-waiting')
'''


_OWNER_E4_PAUSED_DAEMON_CLEAN: Final = r'''
from pathlib import Path
from urllib.parse import quote
import psycopg
from tracebed.stores.pg.ddl import PARTITIONED_TABLES

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    idle = conn.execute(
        "SELECT count(*) FROM pg_catalog.pg_stat_activity "
        "WHERE usename = 'tracebed_erasure' "
        "AND client_addr = inet '10.77.16.3' "
        "AND backend_type = 'client backend' "
        "AND state LIKE 'idle in transaction%%'"
    ).fetchone()
    parent_locks = conn.execute(
        "SELECT count(*) "
        "FROM pg_catalog.pg_stat_activity AS activity "
        "JOIN pg_catalog.pg_locks AS lock_row ON lock_row.pid = activity.pid "
        "JOIN pg_catalog.pg_class AS relation ON relation.oid = lock_row.relation "
        "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
        "WHERE activity.usename = 'tracebed_erasure' "
        "AND activity.client_addr = inet '10.77.16.3' "
        "AND activity.backend_type = 'client backend' "
        "AND activity.state LIKE 'idle in transaction%%' "
        "AND lock_row.granted "
        "AND lock_row.locktype = 'relation' "
        "AND lock_row.mode = 'AccessShareLock' "
        "AND namespace.nspname = 'public' "
        "AND relation.relname = ANY(%s::text[])",
        (list(PARTITIONED_TABLES),),
    ).fetchone()
if idle != (0,) or parent_locks != (0,):
    raise SystemExit('paused erasure daemon retained an admission transaction or parent lock')
print('e4-erasure-daemon: quiesced')
'''


_ERASURE_QUIESCE_ACK_ABSENT: Final = r'''
import os

path = '/tmp/tracebed-erasure-quiesced-v1'
try:
    os.lstat(path)
except FileNotFoundError:
    print('e4-erasure-quiesce-ack: absent')
except OSError:
    raise SystemExit('invalid quiesce acknowledgement') from None
else:
    raise SystemExit('quiesce acknowledgement is unexpectedly present')
'''


_ERASURE_QUIESCE_ACK_VALID: Final = r'''
import os
import stat

path = '/tmp/tracebed-erasure-quiesced-v1'
content = b'tracebed-erasure-quiesced-v1\n'
try:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        held = os.fstat(descriptor)
        named = os.lstat(path)
        chunks = bytearray()
        while len(chunks) < len(content) + 1:
            block = os.read(descriptor, len(content) + 1 - len(chunks))
            if not block:
                break
            chunks.extend(block)
    finally:
        os.close(descriptor)
except OSError:
    raise SystemExit('invalid quiesce acknowledgement') from None
if (
    not stat.S_ISREG(held.st_mode)
    or stat.S_IMODE(held.st_mode) != 0o600
    or held.st_uid != os.getuid()
    or held.st_nlink != 1
    or not stat.S_ISREG(named.st_mode)
    or stat.S_IMODE(named.st_mode) != 0o600
    or named.st_uid != os.getuid()
    or named.st_nlink != 1
    or (held.st_dev, held.st_ino, held.st_nlink) != (named.st_dev, named.st_ino, named.st_nlink)
    or bytes(chunks) != content
):
    raise SystemExit('invalid quiesce acknowledgement')
print('e4-erasure-quiesce-ack: valid')
'''


_OWNER_E4_LEASE_GENERATION: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

request_id = os.environ['B4_REQUEST_ID']
expected = os.environ['B4_EXPECTED_GENERATION']
if not expected.isdecimal() or int(expected) < 1:
    raise SystemExit('invalid expected lease generation')
password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    row = conn.execute(
        'SELECT phase, disposition, generation, lease_token IS NOT NULL, '
        'lease_expires_at > statement_timestamp(), first_started_at IS NOT NULL, completed_at IS NULL '
        'FROM public.erasure_request WHERE request_id = %s',
        (request_id,),
    ).fetchone()
expected_row = ('fenced', 'active', int(expected), True, True, True, True)
if row != expected_row:
    raise SystemExit('erasure daemon did not hold the expected live lease')
print('e4-lease: generation-' + expected)
'''


_OWNER_E4_LEASE_OBSERVATION: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

request_id = os.environ['B4_REQUEST_ID']
password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    row = conn.execute(
        "WITH request_row AS ("
        " SELECT phase, disposition, generation, lease_token IS NOT NULL AS leased, "
        " lease_expires_at > statement_timestamp() AS live, "
        " first_started_at IS NOT NULL AS started, completed_at IS NOT NULL AS terminal "
        " FROM public.erasure_request WHERE request_id = %s"
        ") SELECT CASE "
        " WHEN NOT EXISTS (SELECT 1 FROM request_row) THEN 'missing' "
        " WHEN EXISTS (SELECT 1 FROM request_row WHERE phase = 'fenced' AND disposition = 'active' "
        "   AND generation = 0 AND NOT leased AND NOT started AND NOT terminal) THEN 'unclaimed' "
        " WHEN EXISTS (SELECT 1 FROM request_row WHERE generation >= 1 AND leased AND live "
        "   AND started AND NOT terminal) THEN 'live-other' "
        " WHEN EXISTS (SELECT 1 FROM request_row WHERE terminal) THEN 'terminal' "
        " WHEN EXISTS (SELECT 1 FROM request_row) THEN 'nonlive' "
        " ELSE 'unexpected' END",
        (request_id,),
    ).fetchone()
if row is None or row[0] not in {'missing', 'unclaimed', 'live-other', 'terminal', 'nonlive', 'unexpected'}:
    raise SystemExit('invalid bounded lease observation')
print('e4-lease-observation:' + row[0])
'''


_OWNER_E4_RECLAIM_COMPLETE: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

project_id = os.environ['B4_PROJECT_ID']
request_id = os.environ['B4_REQUEST_ID']
password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
with psycopg.connect(dsn) as conn:
    request_row = conn.execute(
        'SELECT phase, disposition, generation, lease_token IS NULL, '
        'final_receipt_digest = last_receipt_digest '
        'FROM public.erasure_request WHERE project_id = %s AND request_id = %s',
        (project_id, request_id),
    ).fetchone()
    recovered_receipts = conn.execute(
        'SELECT count(*) >= 2, '
        'count(*) FILTER (WHERE generation = 2) >= 2, '
        "count(*) FILTER (WHERE generation = 0 AND step_code = 'fence' "
        "AND result = 'succeeded' AND result_code = 'ok') = 1, "
        'count(*) FILTER (WHERE generation = 1) <= 1, '
        'bool_and((generation = 0 AND step_code = \'fence\' '
        "AND result = 'succeeded' AND result_code = 'ok') OR generation = 2 "
        "OR (generation = 1 AND step_code = 'crypto' AND result = 'retryable' "
        "AND result_code = 'dependency_unavailable')), "
        'bool_and(receipt_digest = public.tracebed_erasure_receipt_digest('
        'project_id, request_id, step_seq, generation, step_code, result, result_code, attempt, '
        'affected_rows, work_revision, postcondition_digest, previous_receipt_digest, started_at, finished_at)) '
        'FROM public.erasure_step_receipt WHERE request_id = %s',
        (request_id,),
    ).fetchone()
    last_receipt = conn.execute(
        'SELECT generation = 2 FROM public.erasure_step_receipt '
        'WHERE request_id = %s ORDER BY step_seq DESC LIMIT 1',
        (request_id,),
    ).fetchone()
if request_row != ('scope_complete', 'scope_complete', 2, True, True):
    raise SystemExit('restarted erasure daemon did not complete its reclaimed lease')
if recovered_receipts != (True, True, True, True, True, True) or last_receipt != (True,):
    raise SystemExit('reclaimed erasure receipt chain is incomplete')
print('e4-lease-reclaim: complete')
'''


_OWNER_E4_PROJECT_COMPLETE: Final = r'''
import os
from pathlib import Path
from urllib.parse import quote
import psycopg

password = Path('/run/secrets/owner_db_password').read_text().rstrip('\n')
dsn = 'postgresql://tracebed_owner:' + quote(password, safe='') + '@postgres-admin:5432/tracebed'
project_id = os.environ['B4_PROJECT_ID']
request_id = os.environ['B4_REQUEST_ID']
survivor_project_id = os.environ['B4_SURVIVOR_PROJECT_ID']
survivor_run = os.environ['B4_SURVIVOR_RUN']
with psycopg.connect(dsn) as conn:
    project_row = conn.execute('SELECT status, deleted_at IS NOT NULL FROM public.project WHERE project_id = %s', (project_id,)).fetchone()
    request_row = conn.execute(
        'SELECT phase, disposition, lease_token IS NULL, final_receipt_digest = last_receipt_digest '
        'FROM public.erasure_request WHERE project_id = %s AND request_id = %s',
        (project_id, request_id),
    ).fetchone()
    destroyed_keys = conn.execute(
        'SELECT count(*) > 0 AND bool_and(destroyed_at IS NOT NULL AND wrapped_kek = %s::bytea) '
        'FROM public.subject_key WHERE project_id = %s',
        (b'', project_id),
    ).fetchone()
    survivor_trace = conn.execute(
        'SELECT count(*) FROM public.trace_index WHERE project_id = %s AND run_id = %s',
        (survivor_project_id, survivor_run),
    ).fetchone()
    capability_count = conn.execute(
        'SELECT count(*) FROM public.erasure_execution_capability WHERE request_id = %s',
        (request_id,),
    ).fetchone()
if project_row != ('deleted', True) or request_row != ('scope_complete', 'scope_complete', True, True):
    raise SystemExit('project erasure did not tombstone coherently')
if destroyed_keys != (True,) or survivor_trace != (1,) or capability_count != (0,):
    raise SystemExit('project erasure did not retain only permitted unrelated data')
print('e4-project: complete')
'''


_S3_E4_OVERWRITE: Final = r'''
import os
from uuid import UUID
from tracebed.domain.config import TraceStoreConfig
from tracebed.stores.tracestore.s3 import S3TraceStore

project_id = UUID(os.environ['B4_PROJECT_ID'])
run_id = UUID(os.environ['B4_RUN_ID'])
store = S3TraceStore(TraceStoreConfig(
    driver='s3', endpoint='http://seaweedfs:8333', bucket='tracebed-traces', region='us-east-1',
    access_key_env='TB_S3_INIT_ACCESS_KEY_FILE', secret_key_env='TB_S3_INIT_SECRET_KEY_FILE',
))
try:
    store.put(project_id, run_id, 99, b'e4-overwrite-v1')
    store.put(project_id, run_id, 99, b'e4-overwrite-v2')
finally:
    store.close()
print('e4-s3-overwrite: ready')
'''


_S3_E4_ABSENT: Final = r'''
import os
from uuid import UUID
from tracebed.domain.config import TraceStoreConfig
from tracebed.stores.tracestore.s3 import S3TraceStore
from tracebed.stores.tracestore.s3_erasure import S3TraceEraser

project_id = UUID(os.environ['B4_PROJECT_ID'])
run_id = os.environ.get('B4_RUN_ID')
store = S3TraceStore(TraceStoreConfig(
    driver='s3', endpoint='http://seaweedfs:8333', bucket='tracebed-traces', region='us-east-1',
    access_key_env='TB_S3_INIT_ACCESS_KEY_FILE', secret_key_env='TB_S3_INIT_SECRET_KEY_FILE',
))
try:
    eraser = S3TraceEraser(store)
    if run_id is None:
        eraser.verify_project_absent(project_id, timeout_seconds=10)
        eraser.verify_project_absent(project_id, timeout_seconds=10)
    else:
        parsed = UUID(run_id)
        eraser.verify_run_absent(project_id, parsed, timeout_seconds=10)
        eraser.verify_run_absent(project_id, parsed, timeout_seconds=10)
finally:
    store.close()
print('e4-s3: empty-twice')
'''


_ERASURE_VERSION_DELETE_PROXY: Final = r'''
import http.client
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

project_id = UUID(sys.argv[1])
prefix = '/tracebed-traces/tb/' + str(project_id) + '/'
pid_file = Path('/tmp/tracebed-e4-version-delete-proxy.pid')
log_file = Path('/tmp/tracebed-e4-version-delete-proxy.log')
pid_file.write_text(str(os.getpid()), encoding='ascii')
log_file.unlink(missing_ok=True)

def record(value):
    with log_file.open('a', encoding='ascii') as handle:
        handle.write(value + '\n')

class Proxy(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, format, *args):
        del format, args
    def _serve(self):
        parsed = urlsplit(self.path)
        if parsed.hostname != 'seaweedfs' or parsed.port != 8333:
            record('wrong-route')
            self.send_error(502)
            return
        if self.command == 'DELETE' and parsed.path.startswith(prefix) and 'versionId' in parse_qs(parsed.query, keep_blank_values=True):
            record('version-delete-refused')
            self.send_response(403)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        record('forwarded')
        length = int(self.headers.get('Content-Length', '0'))
        payload = self.rfile.read(length) if length else None
        headers = {key: value for key, value in self.headers.items() if key.lower() not in {'connection', 'proxy-connection'}}
        connection = http.client.HTTPConnection('seaweedfs', 8333, timeout=10)
        try:
            path = parsed.path + (('?' + parsed.query) if parsed.query else '')
            connection.request(self.command, path, body=payload, headers=headers)
            response = connection.getresponse()
            body = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {'connection', 'transfer-encoding'}:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            connection.close()
    do_DELETE = _serve
    do_GET = _serve
    do_HEAD = _serve
    do_PUT = _serve

server = ThreadingHTTPServer(('127.0.0.1', 19876), Proxy)
def stop(signum, frame):
    del signum, frame
    # SIGTERM is handled by the same thread currently blocked in
    # serve_forever(); shutdown() from that thread deadlocks.  Request it
    # from a short-lived helper so the acceptance cleanup cannot strand the
    # erasure container or the fault proxy.
    threading.Thread(target=server.shutdown, daemon=True).start()
signal.signal(signal.SIGTERM, stop)
server.serve_forever()
pid_file.unlink(missing_ok=True)
log_file.unlink(missing_ok=True)
'''


@dataclass(frozen=True, slots=True)
class _AuthorityE2EContext:
    project_id: str
    run_id: str
    feedback_api_key: str


class AcceptanceError(RuntimeError):
    """Opaque failure from the fixed acceptance protocol."""


def _docker_capture(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a closed Docker inspection/removal command without shell expansion."""

    try:
        return subprocess.run(  # noqa: S603 - every caller supplies fixed Docker subcommands
            ("docker", *arguments),  # noqa: S607 - Docker is the explicit acceptance prerequisite
            check=check,
            text=True,
            capture_output=True,
            cwd=_ROOT,
        )
    except (OSError, subprocess.CalledProcessError):
        raise AcceptanceError("Compose-v1 acceptance check failed") from None


@dataclass(slots=True)
class _AcceptanceResources:
    """Track only resources created by one entropy-named acceptance project."""

    project: str
    containers: set[str]
    volumes: set[str]
    networks: set[str]

    def __init__(self, project: str) -> None:
        if not _is_acceptance_project(project):
            raise AcceptanceError("Compose-v1 acceptance check failed")
        self.project = project
        self.containers = set()
        self.volumes = set()
        self.networks = set()

    def _listed(self, kind: str) -> set[str]:
        arguments = {
            "containers": ("ps", "--all", "--quiet"),
            "volumes": ("volume", "ls", "--quiet"),
            "networks": ("network", "ls", "--quiet"),
        }.get(kind)
        if arguments is None:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        result = _docker_capture(*arguments, "--filter", f"label={_PROJECT_LABEL}={self.project}")
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    def preflight(self) -> None:
        """Refuse collisions rather than ever reusing another run's project label."""

        if self._listed("containers") or self._listed("volumes") or self._listed("networks"):
            raise AcceptanceError("Compose-v1 acceptance check failed")

    def capture(self) -> None:
        """Record resources currently bearing this exact project's label."""

        self.containers.update(self._listed("containers"))
        self.volumes.update(self._listed("volumes"))
        self.networks.update(self._listed("networks"))

    def _label_matches(self, kind: str, identifier: str) -> bool:
        command = {
            "containers": (
                "container",
                "inspect",
                "--format",
                "{{ index .Config.Labels \"com.docker.compose.project\" }}",
            ),
            "volumes": (
                "volume",
                "inspect",
                "--format",
                "{{ index .Labels \"com.docker.compose.project\" }}",
            ),
            "networks": (
                "network",
                "inspect",
                "--format",
                "{{ index .Labels \"com.docker.compose.project\" }}",
            ),
        }.get(kind)
        if command is None:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        result = _docker_capture(*command, identifier, check=False)
        return result.returncode == 0 and result.stdout.strip() == self.project

    def cleanup(self) -> None:
        """Remove only recorded exact-label IDs, then prove no label residue.

        A destructive acceptance is not successful until Docker has both
        accepted every authenticated removal and reported an empty exact-label
        inventory.  The final inventory intentionally does *not* remove an
        unrecorded ID: such a resource is evidence of a harness accounting
        fault, not authority to broaden cleanup.
        """

        removals = {
            "containers": ("rm", "--force"),
            "volumes": ("volume", "rm"),
            "networks": ("network", "rm"),
        }
        removal_failed = False
        for kind, identifiers in (
            ("containers", self.containers),
            ("volumes", self.volumes),
            ("networks", self.networks),
        ):
            command = removals[kind]
            for identifier in sorted(identifiers):
                if self._label_matches(kind, identifier):
                    result = _docker_capture(*command, identifier, check=False)
                    if result.returncode != 0:
                        removal_failed = True
        residue = any(self._listed(kind) for kind in ("containers", "volumes", "networks"))
        if removal_failed or residue:
            raise AcceptanceError("Compose-v1 acceptance check failed")


def _is_acceptance_project(project: str) -> bool:
    """Accept only names generated by this harness, never Compose's default."""

    return bool(re.fullmatch(r"tracebed-acceptance-[0-9a-f]{32}", project)) and project != _DEFAULT_PROJECT


def _new_project_name() -> str:
    """Generate one Compose project name that cannot collide with a default stack."""

    return _PROJECT_PREFIX + secrets.token_hex(16)


def _capture_resources(environment: dict[str, str]) -> None:
    """Capture after every Compose mutation, including partial failed mutations."""

    if _ACTIVE_RESOURCES is None:
        return
    if environment.get("COMPOSE_PROJECT_NAME") != _ACTIVE_RESOURCES.project:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    _ACTIVE_RESOURCES.capture()


def _available_loopback_port(excluded: set[int]) -> int:
    """Choose and preflight a non-default loopback port for this one run."""

    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
        if port not in excluded:
            return port
    raise AcceptanceError("Compose-v1 acceptance check failed")


def _validate_loopback_port(port: str) -> None:
    """Validate the fixed acceptance host-port representation."""

    if not port.isdecimal() or not 1024 <= int(port) <= 65535:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _preflight_loopback_port(port: str) -> None:
    """Reject a malformed or occupied host route before Compose can bind it."""

    _validate_loopback_port(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", int(port)))
    except OSError:
        raise AcceptanceError("Compose-v1 acceptance check failed") from None


def _acceptance_environment() -> tuple[dict[str, str], str]:
    """Build the only environment accepted by the destructive live harness."""

    if "COMPOSE_PROJECT_NAME" in os.environ:
        # An operator-provided project could be the normal ``tracebed`` stack
        # or another acceptance process.  Reject it rather than inheriting it.
        raise AcceptanceError("Compose-v1 acceptance check failed")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("TB_") and key != "COMPOSE_PROJECT_NAME"
    }
    project = _new_project_name()
    if not _is_acceptance_project(project):  # defensive against a future generator edit
        raise AcceptanceError("Compose-v1 acceptance check failed")
    api_port = _available_loopback_port(set())
    dashboard_port = _available_loopback_port({api_port})
    environment["COMPOSE_PROJECT_NAME"] = project
    environment[_API_HOST_PORT_ENV] = str(api_port)
    environment[_DASHBOARD_HOST_PORT_ENV] = str(dashboard_port)
    _preflight_loopback_port(environment[_API_HOST_PORT_ENV])
    _preflight_loopback_port(environment[_DASHBOARD_HOST_PORT_ENV])
    return environment, project


def _compose_command(environment: dict[str, str], *arguments: str) -> tuple[str, ...]:
    """Return an explicitly project-scoped Compose command for this run only."""

    project = environment.get("COMPOSE_PROJECT_NAME")
    if not isinstance(project, str) or not _is_acceptance_project(project):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return (
        "docker",
        "compose",
        "--project-name",
        project,
        "--project-directory",
        str(_ROOT),
        "--file",
        str(_COMPOSE),
        *arguments,
    )


def _opaque_compose_failure(arguments: tuple[str, ...], result: subprocess.CompletedProcess[str]) -> str:
    """Return bounded evidence for a failed fixed Compose subprocess.

    The digest makes repeated opaque failures comparable without retaining
    command output, which can contain implementation paths or credentials.
    The command family is selected from fixed harness literals only.
    """

    family = "compose"
    if arguments and arguments[0] == "run":
        family = "onboard" if "tracebed-compose-onboard" in arguments else "compose-run"
    elif arguments and arguments[0] in {"up", "stop", "restart", "rm", "ps"}:
        family = "compose-" + arguments[0]
    status = result.returncode if 1 <= result.returncode <= 255 else 255
    payload = (result.stdout + "\n" + result.stderr).encode("utf-8", errors="replace")
    fingerprint = hashlib.sha256(payload).hexdigest()[:12]
    return f"{family}-exit-{status}-{fingerprint}"


def _compose(*arguments: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    global _CURRENT_DIAGNOSTIC
    try:
        try:
            result = subprocess.run(  # noqa: S603 - all call fragments are local fixed protocol literals
                _compose_command(environment, *arguments),
                check=False,
                text=True,
                capture_output=True,
                cwd=_ROOT,
                env=environment,
            )
        except OSError:
            raise AcceptanceError("Compose-v1 acceptance check failed") from None
        if result.returncode != 0:
            _CURRENT_DIAGNOSTIC = _opaque_compose_failure(arguments, result)
            raise AcceptanceError("Compose-v1 acceptance check failed")
        return result
    finally:
        _capture_resources(environment)


def _compose_must_fail(*arguments: str, environment: dict[str, str]) -> None:
    """Run one fixed negative Compose action without exposing its output."""

    try:
        result = subprocess.run(  # noqa: S603 - all call fragments are fixed acceptance literals
            _compose_command(environment, *arguments),
            check=False,
            text=True,
            capture_output=True,
            cwd=_ROOT,
            env=environment,
        )
    except OSError:
        _capture_resources(environment)
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    finally:
        _capture_resources(environment)
    if result.returncode == 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _compose_with_hba_override(
    override: Path, *arguments: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    """Run the one disposable extra-rule HBA drift fixture."""

    try:
        return subprocess.run(  # noqa: S603 - fixed Compose command and test-owned override
            (
                *_compose_command(environment),
                "--file",
                str(override),
                *arguments,
            ),
            check=True,
            text=True,
            capture_output=True,
            cwd=_ROOT,
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError):
        _capture_resources(environment)
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    finally:
        _capture_resources(environment)


def _compose_with_hba_override_must_fail(
    override: Path, *arguments: str, environment: dict[str, str]
) -> None:
    """Require the controlled extra-HBA bootstrap attempt to refuse safely."""

    try:
        result = subprocess.run(  # noqa: S603 - fixed Compose command and test-owned override
            (
                *_compose_command(environment),
                "--file",
                str(override),
                *arguments,
            ),
            check=False,
            text=True,
            capture_output=True,
            cwd=_ROOT,
            env=environment,
        )
    except OSError:
        _capture_resources(environment)
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    finally:
        _capture_resources(environment)
    if result.returncode == 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _controller(action: str, environment: dict[str, str], *, succeeds: bool) -> None:
    """Invoke only a fixed lifecycle action and retain opaque failures."""

    if action not in {"start", "upgrade", "rollback"}:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    # The controller emits only fixed reason codes and aggregate counts when
    # this acceptance-only flag is present.  It is intentionally set on the
    # subprocess boundary (rather than inherited globally) so the captured
    # diagnostic describes the exact topology/route observation that refused
    # this lifecycle operation, without permitting arbitrary operator input.
    controller_environment = {**environment, "TRACEBED_COMPOSE_NETWORK_DIAGNOSTIC": "1"}
    try:
        result = subprocess.run(  # noqa: S603 - fixed repository controller and literal action
            (sys.executable, str(_ROOT / "scripts" / "compose_stack.py"), action),
            check=False,
            text=True,
            capture_output=True,
            cwd=_ROOT,
            env=controller_environment,
        )
    except OSError:
        _capture_resources(environment)
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    finally:
        _capture_resources(environment)
    if (result.returncode == 0) is not succeeds:
        global _CURRENT_DIAGNOSTIC
        for line in result.stderr.splitlines():
            if not line.startswith("Compose-v1 diagnostic "):
                continue
            try:
                record = json.loads(line.removeprefix("Compose-v1 diagnostic "))
            except json.JSONDecodeError:
                continue
            if (
                isinstance(record, dict)
                and record.get("kind") == "compose-v1-lifecycle"
                and record.get("code") in _LIFECYCLE_DIAGNOSTIC_CODES
            ):
                _CURRENT_DIAGNOSTIC = f"controller-{action}-{record['code']}"
                break
            if (
                isinstance(record, dict)
                and record.get("kind") == "compose-v1-network-preflight"
                and record.get("reason") in _NETWORK_PREFLIGHT_DIAGNOSTIC_REASONS
            ):
                _CURRENT_DIAGNOSTIC = f"controller-{action}-network-{record['reason']}"
                break
        if not _CURRENT_DIAGNOSTIC:
            _CURRENT_DIAGNOSTIC = _opaque_compose_failure((action,), result)
        print(f"controller-{action}: {_CURRENT_DIAGNOSTIC}", file=sys.stderr)
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _write_secrets(directory: Path, environment: dict[str, str]) -> None:
    """Create only this run's named secret files in its private directory."""

    for name in _SECRET_NAMES:
        target = directory / name
        value = (
            base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            if name == "master_key"
            else secrets.token_hex(24)
        )
        target.write_text(value + "\n", encoding="utf-8")
        # Compose local-file secrets are bind mounts, so their source mode is
        # visible in the non-root Seaweed container.  The private temporary
        # directory is 0700; the individual file must still be readable by
        # that container's fixed uid.
        target.chmod(0o444)
        environment["TB_" + name.upper() + "_FILE"] = str(target)


def _run_bootstrap_hba_matrix(
    environment: dict[str, str], *, erasure_login: bool = True
) -> None:
    """Exercise owner/probe routes for the current authenticated epoch."""

    command_environment = {
        **environment,
        "B4_ERASURE_LOGIN": "active" if erasure_login else "absent",
    }
    result = _compose(
        "run",
        "--rm",
        "--no-deps",
        "-e",
        "B4_ERASURE_LOGIN",
        "--entrypoint",
        "python",
        "db-bootstrap",
        "-c",
        _BOOTSTRAP_HBA_PROBE,
        environment=command_environment,
    )
    required = {
        "owner-admin: allowed",
        "nonce-probe: allowed",
        (
            "erasure-own-subnet: allowed"
            if erasure_login
            else "erasure-own-subnet: rejected sqlstate=None"
        ),
        "owner-wrong-subnet: rejected sqlstate=None",
        "api-wrong-subnet: rejected sqlstate=None",
        "worker-wrong-subnet: rejected sqlstate=None",
        "erasure-wrong-subnet: rejected sqlstate=None",
        "nonce-wrong-subnet: rejected sqlstate=None",
        "owner-wrong-password: rejected sqlstate=None",
        "erasure-wrong-password: rejected sqlstate=None",
        "legacy-app: rejected sqlstate=None",
        "arbitrary-login: rejected sqlstate=None",
        "replication-final-reject: rejected sqlstate=None",
    }
    if set(result.stdout.splitlines()) != required:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _run_hba_matrix(environment: dict[str, str]) -> None:
    """Exercise every IPv4 HBA route from its fixed Compose source network."""

    for service, role in (
        ("api", "tracebed_api"),
        ("worker", "tracebed_worker"),
        ("erasure", "tracebed_erasure"),
    ):
        container = _compose("ps", "-q", service, environment=environment).stdout.strip()
        if not container:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        result = subprocess.run(  # noqa: S603 - role/container originate in fixed controller queries
            (  # noqa: S607 - Docker CLI is a required local acceptance prerequisite
                "docker",
                "exec",
                "-e",
                f"B4_ROLE={role}",
                container,
                "python",
                "-c",
                _RUNTIME_HBA_PROBE,
            ),
            check=False,
            text=True,
            capture_output=True,
            cwd=_ROOT,
            env=environment,
        )
        if result.returncode != 0 or result.stdout.strip() != role + ": allowed":
            raise AcceptanceError("Compose-v1 acceptance check failed")
    _run_bootstrap_hba_matrix(environment)


def _run_runtime_capability_matrix(environment: dict[str, str]) -> None:
    """Prove split runtime processes hold no write/identity escape hatch."""

    for service, role in (
        ("api", "tracebed_api"),
        ("worker", "tracebed_worker"),
        ("erasure", "tracebed_erasure"),
    ):
        # The authority exercise deliberately restarts the sole worker just
        # before this matrix.  Docker can expose its container ID a fraction
        # before exec is ready, so use the same bounded reconnect discipline
        # as serving readiness rather than mistaking that transient for a
        # capability result.
        deadline = time.monotonic() + 45.0
        while True:
            container = _compose("ps", "-q", service, environment=environment).stdout.strip()
            result: subprocess.CompletedProcess[str] | None = None
            if container:
                try:
                    result = subprocess.run(  # noqa: S603 - closed service/role pair from this matrix
                        (  # noqa: S607 - Docker CLI is a required local acceptance prerequisite
                            "docker",
                            "exec",
                            "-e",
                            f"B4_ROLE={role}",
                            container,
                            "python",
                            "-c",
                            _RUNTIME_CAPABILITY_PROBE,
                        ),
                        check=False,
                        text=True,
                        capture_output=True,
                        cwd=_ROOT,
                        env=environment,
                    )
                except OSError:
                    result = None
            if result is not None and result.returncode == 0 and result.stdout.strip() == role + ": capability-boundary":
                break
            if time.monotonic() >= deadline:
                raise AcceptanceError("Compose-v1 acceptance check failed")
            time.sleep(0.5)


def _assert_runtime_cannot_start_before_activation(environment: dict[str, str]) -> None:
    """A pre-activity rollback leaves both split identities unready."""

    for service, entrypoint in (
        ("api", "tracebed-compose-api-ready"),
        ("worker", "tracebed-compose-worker-ready"),
        ("erasure", "tracebed-compose-erasure-ready"),
    ):
        _compose_must_fail(
            "run",
            "--rm",
            "--no-deps",
            "--entrypoint",
            entrypoint,
            service,
            environment=environment,
        )


def _wait_for_api_ready(environment: dict[str, str]) -> None:
    """Await authenticated dependency readiness without exposing its token."""

    try:
        token = Path(environment["TB_READYZ_TOKEN_FILE"]).read_text(encoding="utf-8").rstrip("\n")
        port = environment[_API_HOST_PORT_ENV]
    except (KeyError, OSError):
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    _validate_loopback_port(port)
    deadline = time.monotonic() + 45.0
    while True:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/readyz",
            headers={"X-Tracebed-Readiness": token},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - loopback Compose ingress
                if response.status == 200:
                    return
        except (OSError, urllib.error.HTTPError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.5)


def _wait_for_edge_ready(environment: dict[str, str]) -> None:
    """Await the same-origin edge health endpoint inside its fixed container."""

    deadline = time.monotonic() + 45.0
    while True:
        edge_id = _compose("ps", "-q", "edge", environment=environment).stdout.strip()
        if _DOCKER_CONTAINER_ID_RE.fullmatch(edge_id) is not None:
            try:
                result = subprocess.run(  # noqa: S603 - exact project-scoped container ID
                    (  # noqa: S607 - required fixed Docker executable
                        "docker",
                        "exec",
                        edge_id,
                        "python",
                        "-c",
                        "import urllib.request; "
                        "response = urllib.request.urlopen('http://127.0.0.1:8120/healthz', timeout=2); "
                        "assert response.status == 200",
                    ),
                    check=False,
                    text=True,
                    capture_output=True,
                    cwd=_ROOT,
                    env=environment,
                )
            except OSError:
                result = None
            if result is not None and result.returncode == 0:
                return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.5)


def _run_dependency_recovery(environment: dict[str, str]) -> None:
    """Require every published runtime to re-establish its DB route after restart."""

    _compose("restart", "postgres", environment=environment)
    _compose("up", "--detach", "--wait", "postgres", environment=environment)
    # E4 adds a third independently credentialed database client.  Do not
    # race its reconnect against the HBA matrix: each serving probe creates a
    # fresh role-scoped connection after PostgreSQL reports healthy.
    _wait_for_published_runtime(environment)
    _run_hba_matrix(environment)
    print("dependency-recovery: PostgreSQL restart recovered API and worker readiness")


def _owner_python(
    environment: dict[str, str], code: str, *, values: dict[str, str] | None = None
) -> str:
    """Run a fixed owner-side assertion from the only permitted admin route."""

    command_environment = dict(environment)
    names: list[str] = []
    if values is not None:
        command_environment.update(values)
        names = list(values)
    result = _compose(
        "run",
        "--rm",
        "--no-deps",
        *(part for name in names for part in ("-e", name)),
        "--entrypoint",
        "python",
        "db-bootstrap",
        "-c",
        code,
        environment=command_environment,
    )
    return result.stdout.strip()


def _json_output(raw: str) -> dict[str, object]:
    try:
        decoded = json.loads(raw.splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    if type(decoded) is not dict:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return cast("dict[str, object]", decoded)


def _provision_projects(environment: dict[str, str]) -> tuple[str, str]:
    decoded = _json_output(_owner_python(environment, _PROVISION_PROJECTS))
    projects = decoded.get("projects")
    if (
        type(projects) is not list
        or len(projects) != 2
        or any(type(project) is not str for project in projects)
    ):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return cast("tuple[str, str]", tuple(projects))


def _provision_e4_projects(environment: dict[str, str]) -> tuple[str, str, str]:
    """Create isolated subject, project, and unrelated E4 fixture projects."""

    decoded = _json_output(_owner_python(environment, _PROVISION_E4_PROJECTS))
    projects = decoded.get("projects")
    if (
        type(projects) is not list
        or len(projects) != 3
        or any(type(project) is not str for project in projects)
    ):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return cast("tuple[str, str, str]", tuple(projects))


def _onboard_api_agent(
    environment: dict[str, str], *, project_id: str, grants: list[dict[str, str]], label: str
) -> dict[str, str]:
    """Use the installed owner-only CLI, never an HTTP registry path.

    The transient API secret is inherited under its environment *name* rather
    than included in the Docker command line.  It exists only in this test's
    private process environment and is used to exercise the actual API-key
    verifier; no service compose environment receives it.
    """

    key_id = uuid4().hex
    secret = secrets.token_urlsafe(32)
    updates = {
        "TB_ONBOARDING_PROJECT_ID": project_id,
        "TB_ONBOARDING_AGENT_TYPE": "compose-" + label,
        "TB_ONBOARDING_PRINCIPAL_KIND": "api_key",
        "TB_ONBOARDING_API_KEY_ID": key_id,
        "TB_ONBOARDING_API_KEY_SECRET": secret,
        "TB_ONBOARDING_GRANTS": json.dumps(grants, separators=(",", ":")),
    }
    command_environment = dict(environment)
    command_environment.update(updates)
    result = _compose(
        "run",
        "--rm",
        "--no-deps",
        *(part for name in updates for part in ("-e", name)),
        "--entrypoint",
        "tracebed-compose-onboard",
        "db-bootstrap",
        environment=command_environment,
    )
    decoded = _json_output(result.stdout)
    principal_id, agent_type_id = decoded.get("principal_id"), decoded.get("agent_type_id")
    if type(principal_id) is not str or type(agent_type_id) is not str:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return {
        "principal_id": principal_id,
        "agent_type_id": agent_type_id,
        "api_key": "tb_sk_" + key_id + "." + secret,
    }


def _api_request(
    path: str,
    body: dict[str, object],
    api_key: str,
    *,
    expected_status: int,
    environment: dict[str, str],
) -> dict[str, object] | None:
    global _CURRENT_DIAGNOSTIC
    port = environment.get(_API_HOST_PORT_ENV)
    if not isinstance(port, str):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    _validate_loopback_port(port)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}" + path,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    status: int
    response_data: bytes
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback Compose ingress
            status = response.status
            response_data = response.read()
    except urllib.error.HTTPError as error:
        status = error.code
        response_data = error.read()
    except (OSError, ValueError):
        _CURRENT_DIAGNOSTIC = "api-transport"
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    if status != expected_status:
        # HTTP status is a bounded protocol value; do not retain the URL,
        # response body, request body, or bearer credential in diagnostics.
        _CURRENT_DIAGNOSTIC = f"api-status-{status}" if 100 <= status <= 599 else "api-status-invalid"
        raise AcceptanceError("Compose-v1 acceptance check failed")
    if not response_data:
        return None
    try:
        decoded = json.loads(response_data)
    except json.JSONDecodeError:
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    if type(decoded) is not dict:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return cast("dict[str, object]", decoded)


def _api_get(
    path: str,
    api_key: str,
    *,
    expected_status: int,
    environment: dict[str, str],
) -> dict[str, object] | None:
    """Read an actor-scoped API projection without retaining response details."""

    global _CURRENT_DIAGNOSTIC
    port = environment.get(_API_HOST_PORT_ENV)
    if not isinstance(port, str):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    _validate_loopback_port(port)
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}" + path,
        headers={"X-API-Key": api_key},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback Compose ingress
            status, response_data = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, response_data = error.code, error.read()
    except (OSError, ValueError):
        _CURRENT_DIAGNOSTIC = "api-transport"
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    if status != expected_status:
        _CURRENT_DIAGNOSTIC = (
            f"api-status-{status}" if 100 <= status <= 599 else "api-status-invalid"
        )
        raise AcceptanceError("Compose-v1 acceptance check failed")
    if not response_data:
        return None
    try:
        decoded = json.loads(response_data)
    except json.JSONDecodeError:
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    if type(decoded) is not dict:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return cast("dict[str, object]", decoded)


def _e4_terminal_trace(
    environment: dict[str, str], *, api_key: str, label: str, subject_tags: list[str]
) -> str:
    """Publish one terminal actor trace whose tags drive E4's real closure."""

    retrieved = _api_request(
        "/v1/retrieve",
        {"agent_type": "e4-" + label, "run_ctx": {"query_text": "e4 " + label}},
        api_key,
        expected_status=200,
        environment=environment,
    )
    if retrieved is None or type(retrieved.get("run_id")) is not str:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    run_id = cast("str", retrieved["run_id"])
    events: list[dict[str, object]] = [
        {
            "run_id": run_id,
            "seq": 0,
            "event": {
                "type": "run_start",
                "ts": "2026-01-01T00:00:00+00:00",
                "payload": {"query_text": "e4 " + label},
            },
        },
        {
            "run_id": run_id,
            "seq": 1,
            "event": {
                "type": "state_note",
                "ts": "2026-01-01T00:00:01+00:00",
                "payload": {"subject_tags": subject_tags},
            },
        },
        {
            "run_id": run_id,
            "seq": 2,
            "event": {
                "type": "run_end",
                "ts": "2026-01-01T00:00:02+00:00",
                "payload": {"status": "ok"},
            },
        },
    ]
    _api_request(
        "/v1/trace/batch",
        {"events": events},
        api_key,
        expected_status=202,
        environment=environment,
    )
    return run_id


def _s3_e4_probe(
    environment: dict[str, str], code: str, *, values: dict[str, str]
) -> None:
    """Use the isolated S3 initializer identity for fixture/proof work only."""

    command_environment = dict(environment)
    command_environment.update(values)
    _compose(
        "run",
        "--rm",
        "--no-deps",
        *(part for name in values for part in ("-e", name)),
        "--entrypoint",
        "python",
        "s3-init",
        "-c",
        code,
        environment=command_environment,
    )


def _valkey_project_fixture(environment: dict[str, str], project_id: str) -> None:
    """Place an exact project-key fixture which the destructive adapter must remove."""

    parsed = str(UUID(project_id))
    _compose(
        "exec",
        "-T",
        "valkey",
        "valkey-cli",
        "SET",
        f"tb:{parsed}:e4-acceptance",
        "1",
        environment=environment,
    )


def _valkey_unrelated_readiness_fixture(environment: dict[str, str]) -> None:
    """Populate unrelated cache slots before a real E4 readiness/upgrade proof."""

    _compose(
        "exec",
        "-T",
        "valkey",
        "valkey-cli",
        "EVAL",
        "for i = 1, 100 do redis.call('SET', '__tracebed_e4_unrelated:' .. i, '1') end return 1",
        "0",
        environment=environment,
    )


def _assert_valkey_project_empty_twice(environment: dict[str, str], project_id: str) -> None:
    parsed = str(UUID(project_id))
    for _ in range(2):
        result = _compose(
            "exec",
            "-T",
            "valkey",
            "valkey-cli",
            "--scan",
            "--pattern",
            f"tb:{parsed}:*",
            environment=environment,
        )
        if result.stdout.strip():
            raise AcceptanceError("Compose-v1 acceptance check failed")


def _request_e4_erasure(
    environment: dict[str, str], *, api_key: str, scope: str, subject_tag: str | None = None
) -> str:
    if scope == "subject":
        if not isinstance(subject_tag, str):
            raise AcceptanceError("Compose-v1 acceptance check failed")
        body: dict[str, object] = {"scope": "subject", "subject_tag": subject_tag}
    elif scope == "project" and subject_tag is None:
        body = {"scope": "project"}
    else:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    response = _api_request(
        "/v1/erasure-requests",
        body,
        api_key,
        expected_status=202,
        environment=environment,
    )
    if response is None or type(response.get("request_id")) is not str:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    try:
        return str(UUID(cast("str", response["request_id"])))
    except ValueError:
        raise AcceptanceError("Compose-v1 acceptance check failed") from None


def _wait_for_e4_status(
    environment: dict[str, str], *, api_key: str, request_id: str, phase: str, disposition: str
) -> None:
    """Poll only the actor's bounded status view, including after tombstone."""

    try:
        canonical_request_id = str(UUID(request_id))
    except ValueError:
        raise AcceptanceError("Compose-v1 acceptance check failed") from None
    deadline = time.monotonic() + _E4_ERASURE_WAIT_SECONDS
    while True:
        try:
            response = _api_get(
                "/v1/erasure-requests/" + canonical_request_id,
                api_key,
                expected_status=200,
                environment=environment,
            )
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
            continue
        if response is not None and response.get("phase") == phase and response.get("disposition") == disposition:
            return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.5)


def _require_owned_e4_lease_blocker(environment: dict[str, str], container_id: str) -> None:
    """Authenticate the detached lock holder before addressing it directly."""

    if _DOCKER_CONTAINER_ID_RE.fullmatch(container_id) is None:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    resources = _ACTIVE_RESOURCES
    project = environment.get("COMPOSE_PROJECT_NAME")
    if (
        resources is None
        or project != resources.project
        or container_id not in resources.containers
    ):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    result = _docker_capture(
        "container",
        "inspect",
        "--format",
        '{{ index .Config.Labels "com.docker.compose.project" }}\n'
        '{{ index .Config.Labels "com.docker.compose.service" }}',
        container_id,
        check=False,
    )
    if result.returncode != 0 or result.stdout.splitlines() != [project, "db-bootstrap"]:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _labelled_service_containers(environment: dict[str, str], service: str) -> set[str]:
    """Return only exact-label containers for one fixed Compose service."""

    if service != "db-bootstrap":
        raise AcceptanceError("Compose-v1 acceptance check failed")
    resources = _ACTIVE_RESOURCES
    project = environment.get("COMPOSE_PROJECT_NAME")
    if resources is None or project != resources.project:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    result = _docker_capture(
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"label={_PROJECT_LABEL}={project}",
        "--filter",
        "label=com.docker.compose.service=db-bootstrap",
    )
    containers = {identifier.strip() for identifier in result.stdout.splitlines() if identifier.strip()}
    if any(_DOCKER_CONTAINER_ID_RE.fullmatch(identifier) is None for identifier in containers):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return containers


def _start_e4_lease_blocker(environment: dict[str, str], request_id: str) -> str:
    """Lock one already-fenced subject key before releasing the daemon to claim it."""

    canonical_request_id = str(UUID(request_id))
    before = _labelled_service_containers(environment, "db-bootstrap")
    command_environment = {**environment, "B4_REQUEST_ID": canonical_request_id}
    _compose(
        "run",
        "--detach",
        "--no-deps",
        "-e",
        "B4_REQUEST_ID",
        "--entrypoint",
        "python",
        "db-bootstrap",
        "-c",
        _OWNER_E4_LEASE_BLOCKER,
        environment=command_environment,
    )
    created = _labelled_service_containers(environment, "db-bootstrap") - before
    if len(created) != 1:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    container_id = created.pop()
    _require_owned_e4_lease_blocker(environment, container_id)
    deadline = time.monotonic() + _E4_RESTART_WAIT_SECONDS
    while True:
        logs = _docker_capture("logs", container_id, check=False)
        if logs.returncode == 0 and logs.stdout.strip() == "e4-lease-blocker: locked":
            return container_id
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.2)


def _stop_e4_lease_blocker(environment: dict[str, str], container_id: str) -> None:
    """Release exactly the authenticated owner lock-holder container."""

    _require_owned_e4_lease_blocker(environment, container_id)
    _docker_capture("rm", "--force", container_id)


def _start_e4_admission_blocker(environment: dict[str, str]) -> str:
    """Hold admission while the daemon receives its cooperative quiesce signal."""

    before = _labelled_service_containers(environment, "db-bootstrap")
    _compose(
        "run",
        "--detach",
        "--no-deps",
        "--entrypoint",
        "python",
        "db-bootstrap",
        "-c",
        _OWNER_E4_ADMISSION_BLOCKER,
        environment=environment,
    )
    created = _labelled_service_containers(environment, "db-bootstrap") - before
    if len(created) != 1:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    container_id = created.pop()
    _require_owned_e4_lease_blocker(environment, container_id)
    deadline = time.monotonic() + _E4_QUIESCE_WAIT_SECONDS
    while True:
        logs = _docker_capture("logs", container_id, check=False)
        if logs.returncode == 0 and logs.stdout.strip() == "e4-admission-blocker: locked":
            return container_id
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.2)


def _stop_e4_admission_blocker(environment: dict[str, str], container_id: str) -> None:
    """Release exactly the authenticated owner admission lock holder."""

    _require_owned_e4_lease_blocker(environment, container_id)
    _docker_capture("rm", "--force", container_id)


def _owner_python_in_e4_lease_blocker(
    environment: dict[str, str], container_id: str, code: str, *, values: dict[str, str]
) -> str:
    """Run a fixed owner observation beside a static-IP E4 lock holder.

    Compose assigns ``db-bootstrap`` fixed admin/probe addresses.  While the
    detached holder occupies them, another Compose ``run`` would correctly
    refuse an address collision.  An exact-ID exec stays within the already
    authenticated holder and opens a separate owner database session, so it
    can observe the request without weakening the lock or the topology.
    """

    allowed_values = {
        _OWNER_E4_LEASE_GENERATION: {"B4_REQUEST_ID", "B4_EXPECTED_GENERATION"},
        _OWNER_E4_LEASE_OBSERVATION: {"B4_REQUEST_ID"},
        _OWNER_E4_ADMISSION_WAIT: set(),
    }
    required_names = allowed_values.get(code)
    if required_names is None or set(values) != required_names:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    _require_owned_e4_lease_blocker(environment, container_id)
    result = _docker_capture(
        "exec",
        *(part for name in sorted(values) for part in ("-e", f"{name}={values[name]}")),
        container_id,
        "python",
        "-c",
        code,
        check=False,
    )
    if result.returncode != 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return result.stdout.strip()


def _wait_for_e4_daemon_admission_wait(environment: dict[str, str], container_id: str) -> None:
    """Observe the live daemon blocked inside admission before requesting quiesce."""

    deadline = time.monotonic() + _E4_QUIESCE_WAIT_SECONDS
    while True:
        try:
            observed = _owner_python_in_e4_lease_blocker(
                environment, container_id, _OWNER_E4_ADMISSION_WAIT, values={}
            )
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
            continue
        if observed == "e4-admission-blocker: daemon-waiting":
            return
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _e4_lease_timeout_diagnostic(environment: dict[str, str], container_id: str, request_id: str) -> str:
    """Return one fixed non-identifying observation after a lease wait expires."""

    try:
        observed = _owner_python_in_e4_lease_blocker(
            environment,
            container_id,
            _OWNER_E4_LEASE_OBSERVATION,
            values={"B4_REQUEST_ID": str(UUID(request_id))},
        )
    except AcceptanceError:
        return "e4-lease-observation-unavailable"
    prefix = "e4-lease-observation:"
    value = observed.removeprefix(prefix)
    if observed == prefix + value and value in {
        "missing",
        "unclaimed",
        "live-other",
        "terminal",
        "nonlive",
        "unexpected",
    }:
        return "e4-lease-" + value
    return "e4-lease-observation-unavailable"


def _wait_for_e4_lease_generation(
    environment: dict[str, str], container_id: str, *, request_id: str, generation: int, timeout_seconds: float
) -> None:
    """Wait for the live daemon lease to reach one exact generation."""

    if generation < 1 or timeout_seconds <= 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    canonical_request_id = str(UUID(request_id))
    values = {"B4_REQUEST_ID": canonical_request_id, "B4_EXPECTED_GENERATION": str(generation)}
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            _owner_python_in_e4_lease_blocker(
                environment, container_id, _OWNER_E4_LEASE_GENERATION, values=values
            )
            return
        except AcceptanceError:
            if time.monotonic() >= deadline:
                global _CURRENT_DIAGNOSTIC
                _CURRENT_DIAGNOSTIC = _e4_lease_timeout_diagnostic(
                    environment, container_id, canonical_request_id
                )
                raise
            time.sleep(0.5)


def _owned_erasure_container(environment: dict[str, str]) -> str:
    """Return the live E4 daemon only after exact project-label authentication."""

    container_id = _compose("ps", "-q", "erasure", environment=environment).stdout.strip()
    if _DOCKER_CONTAINER_ID_RE.fullmatch(container_id) is None:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    resources = _ACTIVE_RESOURCES
    # Compose's project-scoped ``ps -q`` may abbreviate an ID differently
    # from Docker's label-filtered inventory.  Authenticate the queried
    # container by its exact project label instead of comparing display forms.
    if (
        resources is None
        or environment.get("COMPOSE_PROJECT_NAME") != resources.project
        or not resources._label_matches("containers", container_id)
    ):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return container_id


def _erasure_restart_state(environment: dict[str, str]) -> tuple[str, int, str]:
    """Read the exact daemon container's restart counter and start instant."""

    container_id = _owned_erasure_container(environment)
    result = _docker_capture(
        "container",
        "inspect",
        "--format",
        "{{ .RestartCount }}\n{{ .State.StartedAt }}",
        container_id,
        check=False,
    )
    rows = result.stdout.splitlines()
    if result.returncode != 0 or len(rows) != 2 or not rows[0].isdecimal() or not rows[1]:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return container_id, int(rows[0]), rows[1]


def _restart_erasure_and_wait(environment: dict[str, str]) -> None:
    """Replace the daemon and prove its fresh serving identity returns."""

    before_id, before_count, before_started = _erasure_restart_state(environment)
    # This proof needs the *old executor process*, not merely PID 1, to be
    # gone before a fresh daemon can reclaim its durable lease.  A Compose
    # restart can leave a pre-restart database backend alive long enough to
    # hold the generation-one crypto transaction, which makes a serving
    # check look healthy without proving reclaim.  Recreating this one
    # project-scoped service removes the old container/cgroup, keeps every
    # dependency untouched, and gives the replacement an authenticated ID.
    _compose(
        "up",
        "--detach",
        "--no-deps",
        "--force-recreate",
        "erasure",
        environment=environment,
    )
    deadline = time.monotonic() + _E4_RESTART_WAIT_SECONDS
    while True:
        try:
            after_id, after_count, after_started = _erasure_restart_state(environment)
        except AcceptanceError:
            after_id, after_count, after_started = "", -1, ""
        if (
            after_id != before_id
            or after_count > before_count
            or after_started != before_started
        ):
            _wait_for_erasure_serving_readiness(environment)
            return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.2)


def _request_erasure_daemon_quiesce(environment: dict[str, str]) -> None:
    """Ask the authenticated daemon to park at a transaction-safe boundary."""

    _assert_erasure_quiesce_ack_absent(environment)
    container_id = _owned_erasure_container(environment)
    result = _docker_capture("kill", "--signal", "USR1", container_id, check=False)
    if result.returncode != 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _run_erasure_quiesce_probe(environment: dict[str, str], code: str, expected: str) -> None:
    """Run one fixed local receipt probe without exposing its filesystem data."""

    result = _compose(
        "exec",
        "-T",
        "erasure",
        "python",
        "-c",
        code,
        environment=environment,
    )
    if result.stdout.strip() != expected:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _assert_erasure_quiesce_ack_absent(environment: dict[str, str]) -> None:
    """Reject a stale or malformed acknowledgement before a new USR1 request."""

    _run_erasure_quiesce_probe(
        environment,
        _ERASURE_QUIESCE_ACK_ABSENT,
        "e4-erasure-quiesce-ack: absent",
    )


def _assert_erasure_quiesce_ack_valid(environment: dict[str, str]) -> None:
    """Accept only the exact newly published local quiesce acknowledgement."""

    _run_erasure_quiesce_probe(
        environment,
        _ERASURE_QUIESCE_ACK_VALID,
        "e4-erasure-quiesce-ack: valid",
    )


def _wait_for_erasure_quiesce_ack(environment: dict[str, str], deadline: float) -> None:
    """Wait only to the caller's bounded deadline for the safe-boundary receipt."""

    while True:
        try:
            _assert_erasure_quiesce_ack_valid(environment)
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
        else:
            return


def _erasure_daemon_state(environment: dict[str, str]) -> str:
    """Read the exact one-character state of the authenticated daemon's PID 1."""

    state = _compose(
        "exec",
        "-T",
        "erasure",
        "python",
        "-c",
        "from pathlib import Path; "
        "print(next(line for line in Path('/proc/1/status').read_text().splitlines() "
        "if line.startswith('State:')).split()[1])",
        environment=environment,
    ).stdout.strip()
    if state not in _ERASURE_DAEMON_RUNNING_STATES | {"T"}:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    return state


def _assert_erasure_daemon_not_quiesced(environment: dict[str, str]) -> None:
    """Prove a blocked admission cannot publish an ack or stop PID 1 early."""

    _assert_erasure_quiesce_ack_absent(environment)
    if _erasure_daemon_state(environment) not in _ERASURE_DAEMON_RUNNING_STATES:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _stop_erasure_daemon_after_quiesce_ack(environment: dict[str, str]) -> None:
    """Externally stop only a daemon already parked behind a verified receipt."""

    container_id = _owned_erasure_container(environment)
    result = _docker_capture("kill", "--signal", "STOP", container_id, check=False)
    if result.returncode != 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _wait_for_erasure_daemon_stopped(environment: dict[str, str], deadline: float) -> None:
    """Require PID 1 to report exact ``T`` after the acknowledged external stop."""

    while True:
        if _erasure_daemon_state(environment) == "T":
            return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.2)


def _wait_for_erasure_daemon_quiesced(environment: dict[str, str]) -> None:
    """Verify receipt and lock cleanliness, then stop the parked PID 1."""

    deadline = time.monotonic() + _E4_QUIESCE_WAIT_SECONDS
    _wait_for_erasure_quiesce_ack(environment, deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    _wait_for_owner_assertion(
        environment,
        _OWNER_E4_PAUSED_DAEMON_CLEAN,
        values={},
        timeout_seconds=remaining,
    )
    _stop_erasure_daemon_after_quiesce_ack(environment)
    _wait_for_erasure_daemon_stopped(environment, deadline)


def _pause_erasure_daemon(environment: dict[str, str]) -> None:
    """Park, prove, then stop the authenticated daemon for one-shot work."""

    _request_erasure_daemon_quiesce(environment)
    # A timeout is a whole-acceptance failure.  ``main()``'s outer ``finally``
    # then removes this exact-label stack, so a delayed safe-boundary receipt
    # can never be treated as a successful pause or escape as a serving daemon.
    _wait_for_erasure_daemon_quiesced(environment)


def _resume_erasure_daemon(environment: dict[str, str]) -> None:
    """Continue only the parked daemon and require receipt removal before return."""

    container_id = _owned_erasure_container(environment)
    result = _docker_capture("kill", "--signal", "CONT", container_id, check=False)
    if result.returncode != 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    deadline = time.monotonic() + _E4_QUIESCE_WAIT_SECONDS
    while True:
        try:
            _assert_erasure_quiesce_ack_absent(environment)
            state = _erasure_daemon_state(environment)
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
            continue
        if state in _ERASURE_DAEMON_RUNNING_STATES:
            return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.2)


def _start_version_delete_proxy(environment: dict[str, str], project_id: str) -> None:
    """Start an acceptance-only proxy that refuses only version DELETEs for one project."""

    canonical_project_id = str(UUID(project_id))
    _compose(
        "exec",
        "-T",
        "-d",
        "erasure",
        "python",
        "-c",
        _ERASURE_VERSION_DELETE_PROXY,
        canonical_project_id,
        environment=environment,
    )
    deadline = time.monotonic() + 10.0
    probe = (
        "import socket; client = socket.create_connection(('127.0.0.1', 19876), timeout=1); "
        "client.close()"
    )
    while True:
        try:
            _compose("exec", "-T", "erasure", "python", "-c", probe, environment=environment)
            return
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def _stop_version_delete_proxy(environment: dict[str, str]) -> None:
    _compose(
        "exec",
        "-T",
        "erasure",
        "python",
        "-c",
        "import os, signal\n"
        "from pathlib import Path\n"
        "path = Path('/tmp/tracebed-e4-version-delete-proxy.pid')\n"
        "log_path = Path('/tmp/tracebed-e4-version-delete-proxy.log')\n"
        "pid = int(path.read_text()) if path.exists() else None\n"
        "try:\n"
        "    if pid is not None:\n"
        "        os.kill(pid, signal.SIGTERM)\n"
        "except ProcessLookupError:\n"
        "    pass\n"
        "path.unlink(missing_ok=True)\n"
        "log_path.unlink(missing_ok=True)\n",
        environment=environment,
    )


def _assert_version_delete_proxy_refusal(environment: dict[str, str]) -> None:
    """Require the fault path to reach exactly one version-delete refusal."""

    result = _compose(
        "exec",
        "-T",
        "erasure",
        "python",
        "-c",
        "from pathlib import Path\n"
        "events = Path('/tmp/tracebed-e4-version-delete-proxy.log').read_text().splitlines()\n"
        "if (events.count('version-delete-refused') != 1 "
        "or any(event not in {'forwarded', 'version-delete-refused'} for event in events)):\n"
        "    raise SystemExit('version-delete proxy did not observe the fixed refusal')\n"
        "print('e4-object-fault: proxy-refused')\n",
        environment=environment,
    )
    if result.stdout.strip() != "e4-object-fault: proxy-refused":
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _run_e4_once(
    environment: dict[str, str],
    request_id: str, *, through_proxy: bool = False, expects_block: bool = False
) -> None:
    """Exercise the installed request-ID-only command, including one blocked path."""

    canonical_request_id = str(UUID(request_id))
    arguments: tuple[str, ...] = (
        "exec",
        "-T",
        "erasure",
        "tracebed-compose-erasure-once",
        canonical_request_id,
    )
    if through_proxy:
        arguments = (
            "exec",
            "-T",
            "-e",
            f"HTTP_PROXY=http://127.0.0.1:{_ERASURE_FAULT_PROXY_PORT}",
            "-e",
            f"http_proxy=http://127.0.0.1:{_ERASURE_FAULT_PROXY_PORT}",
            "-e",
            "HTTPS_PROXY=",
            "-e",
            "https_proxy=",
            "-e",
            "ALL_PROXY=",
            "-e",
            "all_proxy=",
            "-e",
            "NO_PROXY=",
            "-e",
            "no_proxy=",
            "erasure",
            "tracebed-compose-erasure-once",
            canonical_request_id,
        )
    if expects_block:
        # The executor persists its operator-blocked receipt before surfacing
        # the typed failure through the one-shot CLI.  Requiring this nonzero
        # exit proves the injected version-delete refusal reached the real
        # command rather than silently bypassing the proxy.
        _compose_must_fail(*arguments, environment=environment)
    else:
        _compose(*arguments, environment=environment)


def _resume_e4_request(environment: dict[str, str], request_id: str) -> None:
    _compose(
        "exec",
        "-T",
        "erasure",
        "tracebed-compose-erasure-resume",
        str(UUID(request_id)),
        "operator_resumed",
        environment=environment,
    )


def _wait_for_owner_assertion(
    environment: dict[str, str], code: str, *, values: dict[str, str], timeout_seconds: float = 45.0
) -> None:
    if timeout_seconds <= 0:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            _owner_python(environment, code, values=values)
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
        else:
            return


def _wait_for_worker_serving_readiness(environment: dict[str, str]) -> None:
    """Await the worker's fixed fresh physical serving-readiness command."""

    deadline = time.monotonic() + _WORKER_SERVING_WAIT_SECONDS
    while True:
        worker_id = _compose("ps", "-q", "worker", environment=environment).stdout.strip()
        if _DOCKER_CONTAINER_ID_RE.fullmatch(worker_id) is not None:
            try:
                result = subprocess.run(  # noqa: S603 - exact project-scoped container ID
                    # Worker ID is returned by this run's fixed project-scoped
                    # Compose query; the command and entrypoint are literals.
                    ("docker", "exec", worker_id, "tracebed-compose-worker-ready"),  # noqa: S607
                    check=False,
                    text=True,
                    capture_output=True,
                    cwd=_ROOT,
                    env=environment,
                )
            except OSError:
                result = None
            if result is not None and result.returncode == 0:
                return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.5)


def _wait_for_erasure_serving_readiness(environment: dict[str, str]) -> None:
    """Await a fresh executor-role serving probe after the final admission open."""

    deadline = time.monotonic() + _WORKER_SERVING_WAIT_SECONDS
    while True:
        erasure_id = _compose("ps", "-q", "erasure", environment=environment).stdout.strip()
        if _DOCKER_CONTAINER_ID_RE.fullmatch(erasure_id) is not None:
            try:
                result = subprocess.run(  # noqa: S603 - exact project-scoped container ID
                    ("docker", "exec", erasure_id, "tracebed-compose-erasure-ready"),  # noqa: S607
                    check=False,
                    text=True,
                    capture_output=True,
                    cwd=_ROOT,
                    env=environment,
                )
            except OSError:
                result = None
            if result is not None and result.returncode == 0:
                return
        if time.monotonic() >= deadline:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        time.sleep(0.5)


def _start_worker_and_require_serving_health(environment: dict[str, str]) -> None:
    """Start the sole consumer and wait for its authenticated serving probe.

    Docker Compose applies its ``--wait`` deadline before a selected service
    has necessarily been created after its checked dependencies.  That makes
    its generic health waiter race the first post-start healthcheck.  Poll the
    installed worker command instead: it creates a fresh, worker-identity DB
    connection and invokes the serving (not prepublication) readiness routine.
    A stopped or non-listening worker cannot satisfy ``docker exec``.
    """

    _compose("up", "--detach", "worker", environment=environment)
    _wait_for_worker_serving_readiness(environment)


def _wait_for_published_runtime(environment: dict[str, str]) -> None:
    """Verify API, edge, worker, and separately credentialed erasure serving state."""

    _wait_for_api_ready(environment)
    _wait_for_edge_ready(environment)
    _wait_for_worker_serving_readiness(environment)
    _wait_for_erasure_serving_readiness(environment)


def _run_authority_e2e(environment: dict[str, str]) -> _AuthorityE2EContext:
    """Exercise B1/B2 over the published split identities and real listener."""

    global _CURRENT_STEP
    _CURRENT_STEP = "authority-stop-worker"
    _compose("stop", "--timeout", "30", "worker", environment=environment)
    _CURRENT_STEP = "authority-provision"
    project_a, project_b = _provision_projects(environment)
    _CURRENT_STEP = "authority-onboard-data"
    data = _onboard_api_agent(
        environment,
        project_id=project_a,
        label="data",
        grants=[{"role": "data"}],
    )
    _CURRENT_STEP = "authority-onboard-feedback"
    feedback = _onboard_api_agent(
        environment,
        project_id=project_a,
        label="feedback",
        grants=[{"role": "feedback", "feedback_source": "downstream"}],
    )
    _CURRENT_STEP = "authority-onboard-other-data"
    other_data = _onboard_api_agent(
        environment,
        project_id=project_a,
        label="other-data",
        grants=[{"role": "data"}],
    )
    _CURRENT_STEP = "authority-onboard-project-b"
    project_b_agent = _onboard_api_agent(
        environment,
        project_id=project_b,
        label="project-b",
        grants=[
            {"role": "data"},
            {"role": "feedback", "feedback_source": "downstream"},
        ],
    )

    _CURRENT_STEP = "authority-retrieve"
    retrieved = _api_request(
        "/v1/retrieve",
        {"agent_type": "untrusted-body-name", "run_ctx": {"query_text": "compose acceptance"}},
        data["api_key"],
        expected_status=200,
        environment=environment,
    )
    if retrieved is None or type(retrieved.get("run_id")) is not str:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    run_id = cast("str", retrieved["run_id"])
    trace_start = {
        "run_id": run_id,
        "seq": 0,
        "event": {
            "type": "run_start",
            "ts": "2026-01-01T00:00:00+00:00",
            "payload": {"query_text": "compose acceptance"},
        },
    }
    trace_end = {
        "run_id": run_id,
        "seq": 1,
        "event": {
            "type": "run_end",
            "ts": "2026-01-01T00:00:01+00:00",
            "payload": {"status": "ok"},
        },
    }
    event_id = str(uuid4())
    feedback_body: dict[str, object] = {
        "run_id": run_id,
        "event": {
            "event_id": event_id,
            "adapter": "downstream",
            "outcome": "positive",
            "payload": {"source": "compose-acceptance"},
        },
    }
    _CURRENT_STEP = "authority-authorized-writes"
    _api_request("/v1/trace", trace_start, data["api_key"], expected_status=202, environment=environment)
    _api_request("/v1/trace/batch", {"events": [trace_end]}, data["api_key"], expected_status=202, environment=environment)
    _api_request(
        "/v1/propose_memory",
        {
            "run_id": run_id,
            "proposal": {
                "mem_type": "lesson",
                "content": "Compose acceptance proposal.",
                "claimed_scope": "agent_type",
            },
        },
        data["api_key"],
        expected_status=202,
        environment=environment,
    )
    _api_request("/v1/feedback", feedback_body, feedback["api_key"], expected_status=202, environment=environment)
    _api_request(
        "/v1/invalidation",
        {"kind": "compose_acceptance", "payload": {"bounded": True}},
        data["api_key"],
        expected_status=202,
        environment=environment,
    )

    # Role, immutable-owner, and project-wall denials are all wire-opaque.
    _CURRENT_STEP = "authority-denied-writes"
    _api_request("/v1/trace", trace_start, feedback["api_key"], expected_status=403, environment=environment)
    _api_request("/v1/feedback", feedback_body, data["api_key"], expected_status=403, environment=environment)
    _api_request("/v1/trace", trace_start, other_data["api_key"], expected_status=404, environment=environment)
    _api_request("/v1/feedback", feedback_body, project_b_agent["api_key"], expected_status=404, environment=environment)
    _api_request(
        "/v1/retrieve",
        {"agent_type": "project-b", "run_ctx": {"query_text": "project-b"}},
        project_b_agent["api_key"],
        expected_status=200,
        environment=environment,
    )

    _CURRENT_STEP = "authority-envelope"
    envelope_values = {
        "B4_PROJECT_ID": project_a,
        "B4_RUN_ID": run_id,
        "B4_DATA_PRINCIPAL": data["principal_id"],
        "B4_FEEDBACK_PRINCIPAL": feedback["principal_id"],
    }
    _owner_python(environment, _OWNER_ASSERT_QUEUE, values=envelope_values)
    _CURRENT_STEP = "authority-worker-consume"
    _start_worker_and_require_serving_health(environment)
    outcome_values = {
        "B4_PROJECT_ID": project_a,
        "B4_EVENT_ID": event_id,
        "B4_EXPECT_DEAD": "0",
    }
    _wait_for_owner_assertion(environment, _OWNER_OUTCOME_STATE, values=outcome_values)

    # An exact delivery replay is an ACK-only success; divergent business
    # content for the same natural key becomes an exact v1 dead letter.
    _CURRENT_STEP = "authority-exact-replay"
    _api_request("/v1/feedback", feedback_body, feedback["api_key"], expected_status=202, environment=environment)
    _wait_for_owner_assertion(environment, _OWNER_OUTCOME_STATE, values=outcome_values)
    divergent: dict[str, object] = {
        "run_id": run_id,
        "event": {
            "event_id": event_id,
            "adapter": "downstream",
            "outcome": "negative",
            "payload": {"source": "divergent"},
        },
    }
    _CURRENT_STEP = "authority-divergent-replay"
    _api_request(
        "/v1/feedback", divergent, feedback["api_key"], expected_status=202, environment=environment
    )
    outcome_values["B4_EXPECT_DEAD"] = "1"
    _wait_for_owner_assertion(environment, _OWNER_OUTCOME_STATE, values=outcome_values)

    # Keep an independently active DATA owner for the upgrade/drain fixture.
    # The revocation denial below is intentionally about the original run
    # owner; reusing that run would turn the lifecycle queue check into a
    # false authorization expectation rather than exercising a real drain.
    _CURRENT_STEP = "authority-onboard-lifecycle-data"
    lifecycle_data = _onboard_api_agent(
        environment,
        project_id=project_a,
        label="lifecycle-data",
        grants=[{"role": "data"}],
    )
    _CURRENT_STEP = "authority-lifecycle-retrieve"
    lifecycle_retrieved = _api_request(
        "/v1/retrieve",
        {"agent_type": "lifecycle-data", "run_ctx": {"query_text": "upgrade drain"}},
        lifecycle_data["api_key"],
        expected_status=200,
        environment=environment,
    )
    if lifecycle_retrieved is None or type(lifecycle_retrieved.get("run_id")) is not str:
        raise AcceptanceError("Compose-v1 acceptance check failed")
    lifecycle_run_id = cast("str", lifecycle_retrieved["run_id"])

    _CURRENT_STEP = "authority-revoke"
    _owner_python(
        environment,
        _OWNER_REVOKE_OR_SUSPEND,
        values={"B4_MUTATION": "revoke", "B4_TARGET": data["principal_id"]},
    )
    _api_request(
        "/v1/invalidation",
        {"kind": "revoked", "payload": {}},
        data["api_key"],
        expected_status=403,
        environment=environment,
    )
    _CURRENT_STEP = "authority-suspend"
    _owner_python(
        environment,
        _OWNER_REVOKE_OR_SUSPEND,
        values={"B4_MUTATION": "suspend", "B4_TARGET": project_b},
    )
    _api_request(
        "/v1/retrieve",
        {"agent_type": "project-b", "run_ctx": {"query_text": "suspended"}},
        project_b_agent["api_key"],
        expected_status=403,
        environment=environment,
    )
    _CURRENT_STEP = ""
    print("authority-e2e: accepted, denied, consumed, replayed, and dead-lettered")
    return _AuthorityE2EContext(project_a, lifecycle_run_id, feedback["api_key"])


def _assert_runtime_is_fenced(
    environment: dict[str, str], *, closed_worker_expected: bool = False
) -> None:
    """A refused rollback has no serving runtime, optionally one closed worker."""

    running = {
        service.strip()
        for service in _compose(
            "ps", "--status", "running", "--services", environment=environment
        ).stdout.splitlines()
    }
    if {"api", "edge", "erasure", "dashboard"}.intersection(running):
        raise AcceptanceError("Compose-v1 acceptance check failed")
    if closed_worker_expected:
        if "worker" not in running:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        _compose(
            "exec",
            "-T",
            "worker",
            "tracebed-compose-worker-prepublication-ready",
            environment=environment,
        )
    elif "worker" in running:
        raise AcceptanceError("Compose-v1 acceptance check failed")


def _remove_fenced_runtime_containers(environment: dict[str, str]) -> None:
    """Remove only this harness's stopped runtime containers before a fresh start."""

    _compose("rm", "--force", "api", "edge", "worker", "erasure", "dashboard", environment=environment)


def _run_lifecycle_matrix(environment: dict[str, str], context: _AuthorityE2EContext) -> None:
    """Exercise pre-activity rollback/reapply, queued upgrade, and active refusal."""

    global _CURRENT_STEP
    _CURRENT_STEP = "lifecycle-stop-worker"
    _compose("stop", "--timeout", "30", "worker", environment=environment)
    event_id = str(uuid4())
    _CURRENT_STEP = "lifecycle-queue-feedback"
    _api_request(
        "/v1/feedback",
        {
            "run_id": context.run_id,
            "event": {
                "event_id": event_id,
                "adapter": "downstream",
                "outcome": "positive",
                "payload": {"source": "upgrade-queued"},
            },
        },
        context.feedback_api_key,
        expected_status=202,
        environment=environment,
    )
    _CURRENT_STEP = "lifecycle-queue-assert"
    _owner_python(
        environment,
        _OWNER_ASSERT_EVENT_PENDING,
        values={"B4_PROJECT_ID": context.project_id, "B4_EVENT_ID": event_id},
    )
    # The controller must leave an actual worker identity running through
    # close/drain.  Start it only after proving the queued item exists.
    _CURRENT_STEP = "lifecycle-start-worker"
    _start_worker_and_require_serving_health(environment)
    _CURRENT_STEP = "lifecycle-upgrade"
    _controller("upgrade", environment, succeeds=True)
    _CURRENT_STEP = "lifecycle-upgrade-serving"
    _wait_for_published_runtime(environment)
    _CURRENT_STEP = "lifecycle-drain"
    _wait_for_owner_assertion(
        environment,
        _OWNER_EVENT_CONSUMED,
        values={"B4_PROJECT_ID": context.project_id, "B4_EVENT_ID": event_id},
    )
    _run_hba_matrix(environment)

    # Ordinary API/worker activity must not be mistaken for E4 executor
    # activity.  The first rollback therefore removes the pre-activity E4
    # deployment and returns to closed c12; the second is c12's own
    # post-activity refusal and must fence every runtime.
    _CURRENT_STEP = "lifecycle-e4-preactivity-rollback"
    _controller("rollback", environment, succeeds=True)
    _CURRENT_STEP = "lifecycle-c12-postactivity-rollback"
    _controller("rollback", environment, succeeds=False)
    _CURRENT_STEP = "lifecycle-postactivity-fence"
    _assert_runtime_is_fenced(environment)
    _remove_fenced_runtime_containers(environment)
    _CURRENT_STEP = "lifecycle-hba"
    # Runtime containers are intentionally absent after the refused rollback;
    # repeating their positive probe here would republish a runtime while
    # testing a fence.  The owner/probe matrix still verifies the mounted HBA
    # and all deny rules through the only remaining controlled route.
    _run_bootstrap_hba_matrix(environment, erasure_login=False)
    _CURRENT_STEP = ""
    print("lifecycle: E4 preactivity return, queued upgrade, and c12 postactivity refusal")


def _run_e4_erasure_acceptance(environment: dict[str, str]) -> None:
    """Exercise E4 through API actors, the deployed executor, and real stores.

    This is intentionally after lifecycle/HBA recovery: all mutations here
    occur under the final authenticated E4 deployment epoch.  The test uses
    no target-bearing executor arguments; only actor API requests and the
    installed request-ID-only command choose work.
    """

    global _CURRENT_STEP
    _CURRENT_STEP = "e4-provision"
    subject_project, project_project, survivor_project = _provision_e4_projects(environment)
    _CURRENT_STEP = "e4-onboard-subject"
    subject_actor = _onboard_api_agent(
        environment,
        project_id=subject_project,
        label="e4-subject",
        grants=[{"role": "data"}, {"role": "erasure_request"}],
    )
    _CURRENT_STEP = "e4-onboard-project"
    project_actor = _onboard_api_agent(
        environment,
        project_id=project_project,
        label="e4-project",
        grants=[{"role": "data"}, {"role": "erasure_request"}],
    )
    _CURRENT_STEP = "e4-onboard-survivor"
    survivor_actor = _onboard_api_agent(
        environment,
        project_id=survivor_project,
        label="e4-survivor",
        grants=[{"role": "data"}],
    )

    target_tag, shared_tag, other_tag = "e4-target", "e4-shared", "e4-unrelated"
    reclaim_tag = "e4-lease-reclaim"
    _CURRENT_STEP = "e4-subject-fixtures"
    target_run = _e4_terminal_trace(
        environment,
        api_key=subject_actor["api_key"],
        label="target",
        subject_tags=[target_tag, shared_tag],
    )
    shared_run = _e4_terminal_trace(
        environment,
        api_key=subject_actor["api_key"],
        label="shared",
        subject_tags=[shared_tag],
    )
    other_run = _e4_terminal_trace(
        environment,
        api_key=subject_actor["api_key"],
        label="other",
        subject_tags=[other_tag],
    )
    reclaim_run = _e4_terminal_trace(
        environment,
        api_key=subject_actor["api_key"],
        label="lease-reclaim",
        subject_tags=[reclaim_tag],
    )
    _wait_for_owner_assertion(
        environment,
        _OWNER_E4_TRACE_READY,
        values={
            "B4_PROJECT_ID": subject_project,
            "B4_RUN_IDS": ",".join((target_run, shared_run, other_run, reclaim_run)),
        },
    )

    # Pause before registering the isolated request, then lock its one live
    # subject-key row.  This guarantees the normal poller cannot claim before
    # the first crypto mutation is held, without table-locking the successor
    # receipt/profile that admission checks before every claim.  Killing PID 1
    # then releases only the old DB session; the restart has to wait out that
    # durable generation-1 lease, claim generation 2, and complete after this
    # exact holder is removed.
    lease_blocker: str | None = None
    reclaim_request = ""
    daemon_paused = False
    try:
        _CURRENT_STEP = "e4-lease-reclaim-pause"
        _pause_erasure_daemon(environment)
        daemon_paused = True
        _CURRENT_STEP = "e4-lease-reclaim-request"
        reclaim_request = _request_e4_erasure(
            environment,
            api_key=subject_actor["api_key"],
            scope="subject",
            subject_tag=reclaim_tag,
        )
        _CURRENT_STEP = "e4-lease-reclaim-blocker"
        lease_blocker = _start_e4_lease_blocker(environment, reclaim_request)
        _CURRENT_STEP = "e4-lease-reclaim-resume"
        _resume_erasure_daemon(environment)
        daemon_paused = False
        _CURRENT_STEP = "e4-lease-reclaim-generation-1"
        _wait_for_e4_lease_generation(
            environment,
            lease_blocker,
            request_id=reclaim_request,
            generation=1,
            timeout_seconds=45.0,
        )
        _CURRENT_STEP = "e4-lease-reclaim-restart"
        _restart_erasure_and_wait(environment)
        _CURRENT_STEP = "e4-lease-reclaim-generation-2"
        _wait_for_e4_lease_generation(
            environment,
            lease_blocker,
            request_id=reclaim_request,
            generation=2,
            timeout_seconds=_E4_ERASURE_WAIT_SECONDS,
        )
        _CURRENT_STEP = "e4-lease-reclaim-release"
        if lease_blocker is None:
            raise AcceptanceError("Compose-v1 acceptance check failed")
        _stop_e4_lease_blocker(environment, lease_blocker)
        lease_blocker = None
    finally:
        if daemon_paused:
            with suppress(AcceptanceError):
                _resume_erasure_daemon(environment)
        if lease_blocker is not None:
            with suppress(AcceptanceError):
                _stop_e4_lease_blocker(environment, lease_blocker)
    _CURRENT_STEP = "e4-lease-reclaim-complete-status"
    _wait_for_e4_status(
        environment,
        api_key=subject_actor["api_key"],
        request_id=reclaim_request,
        phase="scope_complete",
        disposition="scope_complete",
    )
    _CURRENT_STEP = "e4-lease-reclaim-postconditions"
    # Exact removal releases the fixed admin address asynchronously.  Retry
    # the fixed assertion rather than letting that Docker endpoint cleanup
    # race masquerade as a failed reclaimed receipt chain.
    _wait_for_owner_assertion(
        environment,
        _OWNER_E4_RECLAIM_COMPLETE,
        values={"B4_PROJECT_ID": subject_project, "B4_REQUEST_ID": reclaim_request},
    )
    _s3_e4_probe(
        environment,
        _S3_E4_ABSENT,
        values={"B4_PROJECT_ID": subject_project, "B4_RUN_ID": reclaim_run},
    )
    print("e4-lease-reclaim: forced restart reclaimed generation two")

    _CURRENT_STEP = "e4-linked-memory"
    _owner_python(
        environment,
        _OWNER_E4_LINKED_FIXTURE,
        values={
            "B4_PROJECT_ID": subject_project,
            "B4_TARGET_TAG": target_tag,
            "B4_OTHER_TAG": other_tag,
            "B4_TARGET_RUN": target_run,
        },
    )
    _CURRENT_STEP = "e4-versioned-s3-fixture"
    _s3_e4_probe(
        environment,
        _S3_E4_OVERWRITE,
        values={"B4_PROJECT_ID": subject_project, "B4_RUN_ID": target_run},
    )
    _valkey_project_fixture(environment, subject_project)

    # Fault one *version-specific* delete through an in-container proxy.  The
    # paused daemon makes the installed one-shot command the sole claimant;
    # it is resumed in all paths so this adversarial check cannot leave a
    # stopped runtime behind.
    subject_request = ""
    paused, proxy_started = False, False
    try:
        _CURRENT_STEP = "e4-object-fault-pause"
        _pause_erasure_daemon(environment)
        paused = True
        _CURRENT_STEP = "e4-object-fault-proxy"
        _start_version_delete_proxy(environment, subject_project)
        proxy_started = True
        # Create the request only after PID 1 is stopped.  Otherwise the
        # normal two-second poller can claim and finish this tiny fixture
        # before the fault proxy is ready, turning an adversarial delete test
        # into a nondeterministic race.
        _CURRENT_STEP = "e4-subject-request"
        subject_request = _request_e4_erasure(
            environment,
            api_key=subject_actor["api_key"],
            scope="subject",
            subject_tag=target_tag,
        )
        _CURRENT_STEP = "e4-object-fault-once"
        _run_e4_once(environment, subject_request, through_proxy=True, expects_block=True)
        _CURRENT_STEP = "e4-object-fault-proxy-proof"
        _assert_version_delete_proxy_refusal(environment)
        _CURRENT_STEP = "e4-object-fault-status"
        _wait_for_e4_status(
            environment,
            api_key=subject_actor["api_key"],
            request_id=subject_request,
            # Graph has closed before the versioned trace delete is faulted.
            # ``external_purged`` is its durable checkpoint phase; the
            # unfinished trace, Valkey, and vector work remains unverified
            # until the explicit operator resume starts a fresh full pass.
            phase="external_purged",
            disposition="operator_blocked",
        )
        _owner_python(
            environment, _OWNER_E4_BLOCKED, values={"B4_REQUEST_ID": subject_request}
        )
        _CURRENT_STEP = "e4-object-fault-remove"
        _stop_version_delete_proxy(environment)
        proxy_started = False
        _CURRENT_STEP = "e4-object-fault-resume"
        _resume_e4_request(environment, subject_request)
        _CURRENT_STEP = "e4-subject-retry-once"
        _run_e4_once(environment, subject_request)
    finally:
        if proxy_started:
            with suppress(AcceptanceError):
                _stop_version_delete_proxy(environment)
        if paused:
            with suppress(AcceptanceError):
                _resume_erasure_daemon(environment)
    _CURRENT_STEP = "e4-subject-complete-status"
    _wait_for_e4_status(
        environment,
        api_key=subject_actor["api_key"],
        request_id=subject_request,
        phase="scope_complete",
        disposition="scope_complete",
    )
    _CURRENT_STEP = "e4-subject-postconditions"
    _owner_python(
        environment,
        _OWNER_E4_SUBJECT_COMPLETE,
        values={
            "B4_PROJECT_ID": subject_project,
            "B4_REQUEST_ID": subject_request,
            "B4_TARGET_TAG": target_tag,
            "B4_TARGET_RUN": target_run,
            "B4_SHARED_RUN": shared_run,
            "B4_OTHER_RUN": other_run,
        },
    )
    _s3_e4_probe(
        environment,
        _S3_E4_ABSENT,
        values={"B4_PROJECT_ID": subject_project, "B4_RUN_ID": target_run},
    )
    _assert_valkey_project_empty_twice(environment, subject_project)

    _CURRENT_STEP = "e4-project-fixtures"
    project_run = _e4_terminal_trace(
        environment,
        api_key=project_actor["api_key"],
        label="project-target",
        subject_tags=["e4-project-subject"],
    )
    survivor_run = _e4_terminal_trace(
        environment,
        api_key=survivor_actor["api_key"],
        label="survivor",
        subject_tags=["e4-survivor-subject"],
    )
    _wait_for_owner_assertion(
        environment,
        _OWNER_E4_TRACE_READY,
        values={"B4_PROJECT_ID": project_project, "B4_RUN_IDS": project_run},
    )
    _wait_for_owner_assertion(
        environment,
        _OWNER_E4_TRACE_READY,
        values={"B4_PROJECT_ID": survivor_project, "B4_RUN_IDS": survivor_run},
    )
    _valkey_project_fixture(environment, project_project)
    # Exercise cooperative quiescence against the real admission transaction
    # before registering the destructive project request.  The owner holder
    # first makes PID 1 wait inside ``admission_open()``; SIGUSR1 must only
    # stop it after that transaction returns.  This is the regression proof
    # for a raw SIGSTOP leaving an idle-in-transaction parent-table reader
    # that made project partition detach wait through its fixed timeout.
    project_request = ""
    admission_blocker: str | None = None
    quiesce_requested = False
    paused = False
    try:
        _CURRENT_STEP = "e4-project-quiesce-blocker"
        admission_blocker = _start_e4_admission_blocker(environment)
        _CURRENT_STEP = "e4-project-quiesce-admission"
        _wait_for_e4_daemon_admission_wait(environment, admission_blocker)
        _CURRENT_STEP = "e4-project-quiesce-request"
        _request_erasure_daemon_quiesce(environment)
        quiesce_requested = True
        _CURRENT_STEP = "e4-project-quiesce-pending"
        _assert_erasure_daemon_not_quiesced(environment)
        _CURRENT_STEP = "e4-project-quiesce-release"
        _stop_e4_admission_blocker(environment, admission_blocker)
        admission_blocker = None
        _CURRENT_STEP = "e4-project-once-pause"
        _wait_for_erasure_daemon_quiesced(environment)
        paused = True
        _CURRENT_STEP = "e4-project-request"
        project_request = _request_e4_erasure(
            environment,
            api_key=project_actor["api_key"],
            scope="project",
        )
        _CURRENT_STEP = "e4-project-once"
        _run_e4_once(environment, project_request)
    finally:
        if admission_blocker is not None:
            with suppress(AcceptanceError):
                _stop_e4_admission_blocker(environment, admission_blocker)
        # If the bounded wait failed after SIGUSR1, this disposable acceptance
        # run is failed and its outer finally removes the whole exact-label
        # stack.  CONT here is only best-effort cleanup; it is never a raw
        # STOP fallback and cannot make a timed-out quiesce pass.
        if quiesce_requested or paused:
            with suppress(AcceptanceError):
                _resume_erasure_daemon(environment)
    _CURRENT_STEP = "e4-project-complete-status"
    _wait_for_e4_status(
        environment,
        api_key=project_actor["api_key"],
        request_id=project_request,
        phase="scope_complete",
        disposition="scope_complete",
    )
    _CURRENT_STEP = "e4-project-postconditions"
    _owner_python(
        environment,
        _OWNER_E4_PROJECT_COMPLETE,
        values={
            "B4_PROJECT_ID": project_project,
            "B4_REQUEST_ID": project_request,
            "B4_SURVIVOR_PROJECT_ID": survivor_project,
            "B4_SURVIVOR_RUN": survivor_run,
        },
    )
    _s3_e4_probe(
        environment,
        _S3_E4_ABSENT,
        values={"B4_PROJECT_ID": project_project},
    )
    _assert_valkey_project_empty_twice(environment, project_project)
    _CURRENT_STEP = "e4-valkey-unrelated-readiness"
    _valkey_unrelated_readiness_fixture(environment)
    _wait_for_erasure_serving_readiness(environment)
    # A real executor claim above records E4 activity.  Its rollback refusal
    # is a defined controller recovery state: only the closed ordinary worker
    # remains, then the next supported upgrade must authenticate/drain it and
    # re-publish.  The upgrade's closed probe also exercises Valkey SCAN with
    # the unrelated fixture above.
    _CURRENT_STEP = "e4-postactivity-rollback-refusal"
    _controller("rollback", environment, succeeds=False)
    _CURRENT_STEP = "e4-postactivity-fence"
    _assert_runtime_is_fenced(environment, closed_worker_expected=True)
    _CURRENT_STEP = "e4-postactivity-upgrade"
    _controller("upgrade", environment, succeeds=True)
    _CURRENT_STEP = "e4-postactivity-upgrade-serving"
    _wait_for_published_runtime(environment)
    _CURRENT_STEP = ""
    print(
        "e4-erasure: subject fault/resume, project tombstone, active rollback recovery, and unrelated-cache upgrade completed"
    )


def _run_active_hba_drift(environment: dict[str, str], directory: Path) -> None:
    """Prove an active retry refuses a valid-but-extra mounted HBA rule."""

    from tracebed.stores.pg.hba import checked_hba_text

    drift_hba = directory / "hba-extra.conf"
    drift_hba.write_text(
        checked_hba_text() + "host    all             all                                         192.0.2.0/24           reject\n",
        encoding="utf-8",
    )
    drift_hba.chmod(0o444)
    override = directory / "hba-extra.compose.yaml"
    override.write_text(
        "services:\n"
        "  postgres:\n"
        "    volumes:\n"
        "      - type: bind\n"
        f"        source: {drift_hba}\n"
        "        target: /etc/postgresql/pg_hba.conf\n"
        "        read_only: true\n",
        encoding="utf-8",
    )
    _compose(
        "stop", "--timeout", "30", "dashboard", "api", "worker", "erasure", environment=environment
    )
    _compose_with_hba_override(
        override, "up", "--detach", "--wait", "--force-recreate", "postgres", environment=environment
    )
    # The closed controller intentionally restores its checked bind mount
    # before every action.  Attest the live drift through the same fixed
    # owner/bootstrap entrypoint while the controlled override is mounted;
    # otherwise controller preflight would erase the fixture before it could
    # prove detection.
    _compose_with_hba_override_must_fail(
        override,
        "run",
        "--rm",
        "--no-deps",
        "-e",
        "TB_DB_BOOTSTRAP_ACTION=apply",
        "db-bootstrap",
        environment=environment,
    )
    _assert_runtime_is_fenced(environment)
    # The retained checked mount is restored only by recreating the disposable
    # container from the supported profile; no repository HBA bytes change.
    _compose(
        "up", "--detach", "--wait", "--force-recreate", "postgres", environment=environment
    )
    _controller("start", environment, succeeds=True)
    _run_hba_matrix(environment)
    print("hba-drift: extra live rule refused and canonical mount restored")


def main(argv: list[str] | None = None) -> int:
    """Run clean Compose-v1 HBA and authority acceptance, then remove its state."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage-receipt",
        type=Path,
        help="test-only path that receives `passed` or the opaque failed stage",
    )
    arguments = parser.parse_args(argv)

    def receipt(value: str) -> None:
        if arguments.stage_receipt is not None:
            arguments.stage_receipt.write_text(value + "\n", encoding="utf-8")

    global _ACTIVE_RESOURCES
    try:
        environment, project = _acceptance_environment()
        resources = _AcceptanceResources(project)
        # This is the first Docker operation.  Refuse a same-label collision
        # before this process can create, stop, or remove any resource.
        resources.preflight()
    except AcceptanceError:
        receipt("failed:preflight")
        print("compose-v1 acceptance failed during preflight", file=sys.stderr)
        return 1

    _ACTIVE_RESOURCES = resources
    with (
        tempfile.TemporaryDirectory(prefix="tracebed-compose-acceptance-") as temporary,
        tempfile.TemporaryDirectory(prefix="tracebed-compose-hba-drift-") as drift_temporary,
    ):
        secret_dir = Path(temporary)
        drift_dir = Path(drift_temporary)
        secret_dir.chmod(0o700)
        drift_dir.chmod(0o700)
        _write_secrets(secret_dir, environment)
        stage = "clean-start"
        primary_receipt = ""
        primary_message = ""
        cleanup_failed = False
        try:
            _controller("start", environment, succeeds=True)
            _wait_for_published_runtime(environment)
            stage = "HBA-matrix"
            _run_hba_matrix(environment)
            stage = "bootstrap-failure-retry"
            _compose_must_fail(
                "run",
                "--rm",
                "--no-deps",
                "-e",
                "TB_0011_INGRESS_QUARANTINED=on",
                "db-bootstrap",
                environment=environment,
            )
            # No queue activity has occurred yet: the owner-side rollback and
            # normal controller reapply must both succeed.
            stage = "preactivity-rollback"
            _controller("rollback", environment, succeeds=True)
            stage = "preactivity-runtime-denial"
            _assert_runtime_cannot_start_before_activation(environment)
            stage = "preactivity-reapply"
            # A successful E4 rollback intentionally restores a single
            # closed-ready worker.  ``start`` recognizes only that exact,
            # bootstrap-authenticated c12 handoff, drains it internally, and
            # republishes E4; no direct Compose repair participates here.
            _controller("start", environment, succeeds=True)
            _wait_for_published_runtime(environment)
            stage = "preactivity-HBA"
            _run_hba_matrix(environment)
            stage = "authority-e2e"
            authority_context = _run_authority_e2e(environment)
            stage = "runtime-capability-matrix"
            _run_runtime_capability_matrix(environment)
            stage = "dependency-recovery"
            _run_dependency_recovery(environment)
            stage = "lifecycle"
            _run_lifecycle_matrix(environment, authority_context)
            stage = "active-HBA-drift"
            # The host-side secret source validator requires an exact leaf
            # allowlist.  Keep the disposable HBA drift file in a different
            # private directory so this negative HBA fixture cannot weaken or
            # accidentally invalidate the independent secret-source proof.
            _run_active_hba_drift(environment, drift_dir)
            stage = "e4-erasure"
            _run_e4_erasure_acceptance(environment)
        except (OSError, subprocess.CalledProcessError, AcceptanceError):
            failed_step = _CURRENT_STEP or stage
            # Both values are assigned solely from this module's fixed stage
            # literals.  Keeping the substage identifies a controller-boundary
            # refusal without forwarding a command, endpoint, or secret.
            suffix = f"; {_CURRENT_DIAGNOSTIC}" if _CURRENT_DIAGNOSTIC else ""
            primary_receipt = "failed:" + failed_step
            primary_message = f"compose-v1 acceptance failed during {stage} [{failed_step}{suffix}]"
        else:
            primary_receipt = "passed"
            primary_message = (
                "compose-v1 E4 acceptance passed; IPv6 live probe unavailable because Compose-v1 does not enable Docker IPv6"
            )

        finally:
            try:
                resources.cleanup()
            except (OSError, subprocess.CalledProcessError, AcceptanceError):
                cleanup_failed = True
            finally:
                _ACTIVE_RESOURCES = None
                shutil.rmtree(secret_dir, ignore_errors=True)

        if cleanup_failed:
            # Preserve the primary failed stage if there was one.  Cleanup
            # evidence is additive in that case; it must never make a failed
            # lifecycle look like a mere teardown issue.  A clean primary run
            # with failed authenticated cleanup is itself an acceptance fail.
            receipt("failed:cleanup" if primary_receipt == "passed" else primary_receipt)
            if primary_receipt == "passed":
                print("compose-v1 acceptance failed during cleanup", file=sys.stderr)
            else:
                print(primary_message, file=sys.stderr)
                print("compose-v1 acceptance cleanup also failed", file=sys.stderr)
            return 1

        receipt(primary_receipt)
        if primary_receipt == "passed":
            print(primary_message)
            return 0
        print(primary_message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
