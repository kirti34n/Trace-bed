<#
.SYNOPSIS
    Bring up the compose stack and run every gate that cannot run without it.

.DESCRIPTION
    The repository was authored on a machine with no Docker, so the Phase 0 leak suite, the
    Phase 1 latency bench, and every @pytest.mark.integration test have never executed. They
    are written in full; they have simply never had a database to run against. This script is
    what converts the gate reports from INCOMPLETE to a real verdict.

    It deliberately does NOT swallow failures. A red gate here is the finding.

.PARAMETER SkipUp
    Assume the stack is already running.

.PARAMETER KeepUp
    Leave the containers running afterwards (default tears them down).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/verify_with_stack.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipUp,
    [switch]$KeepUp
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$python = Join-Path $repo '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { throw "venv not found at $python — run: uv venv --python 3.13 .venv" }

# Ports come from docker/compose.yaml, which deliberately avoids the defaults so the stack
# cannot collide with a Postgres or Redis the developer already has running.
$env:TB_STORAGE__PG_DSN       = 'postgresql://tracebed_owner:tracebed_dev_only@localhost:5442/tracebed'
$env:TB_STORAGE__VALKEY_URL   = 'valkey://localhost:6389/0'
$env:TB_S3_ENDPOINT           = 'http://localhost:8333'
$env:TB_S3_ACCESS_KEY         = 'tracebed'
$env:TB_S3_SECRET_KEY         = 'tracebed_dev_only'
$env:TB_S3_BUCKET             = 'tracebed-test'
$env:TB_EMBEDDING__MODEL_VERSION = 'stack-verify'
$env:TB_HOLDOUT_SALT          = 'stack-verify-salt'

$results = [ordered]@{}
function Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ""
    Write-Host ("=" * 78)
    Write-Host "  $Name"
    Write-Host ("=" * 78)
    try {
        & $Body
        $ok = ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE)
    } catch {
        Write-Host $_.Exception.Message
        $ok = $false
    }
    $script:results[$Name] = if ($ok) { 'PASS' } else { "FAIL (exit $LASTEXITCODE)" }
}

# --------------------------------------------------------------------------------------- #
# 1. Stack
# --------------------------------------------------------------------------------------- #
if (-not $SkipUp) {
    Step 'docker compose up' {
        docker compose -f docker/compose.yaml up -d
    }

    # Healthchecks are declared in compose.yaml; poll them rather than sleeping a fixed
    # interval, because "how long Postgres takes to init" is not a constant.
    Step 'wait for healthy' {
        $deadline = (Get-Date).AddMinutes(4)
        do {
            $states = docker compose -f docker/compose.yaml ps --format json 2>$null |
                ForEach-Object { try { $_ | ConvertFrom-Json } catch {} }
            $unhealthy = @($states | Where-Object { $_.Health -and $_.Health -ne 'healthy' })
            if ($unhealthy.Count -eq 0 -and $states) { Write-Host "  all services healthy"; break }
            Write-Host ("  waiting: " + (($unhealthy | ForEach-Object { "$($_.Service)=$($_.Health)" }) -join ', '))
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $deadline)
        if ((Get-Date) -ge $deadline) { throw "services did not become healthy within 4 minutes" }
        $global:LASTEXITCODE = 0
    }
}

# --------------------------------------------------------------------------------------- #
# 2. Roles + schema
#
# The app role must NOT own the tables: FORCE ROW LEVEL SECURITY does not apply to a table's
# owner, so running the app as the owner silently disables every RLS policy in 0003_rls.sql.
# --------------------------------------------------------------------------------------- #
Step 'bootstrap roles' {
    Get-Content docker/initdb/01-roles.sql -Raw |
        docker exec -i tracebed-pg psql -U tracebed_owner -d tracebed -v ON_ERROR_STOP=0
    $global:LASTEXITCODE = 0   # roles may already exist from initdb; not fatal
}

Step 'apply migrations' {
    & $python -m tracebed.stores.pg.migrate apply
}

Step 'verify extensions' {
    docker exec -i tracebed-pg psql -U tracebed_owner -d tracebed -c "\dx"
}

# --------------------------------------------------------------------------------------- #
# 3. The tests that have never run
# --------------------------------------------------------------------------------------- #
Step 'integration tests (the ones that have never executed)' {
    & $python -m pytest -m integration -v --tb=short -p no:cacheprovider
}

Step 'full test suite against the live stack' {
    & $python -m pytest -q -p no:cacheprovider
}

Step 'cross-project leak suite (Phase 0 security gate)' {
    & $python -m pytest harness/leak_suite -v --tb=short -p no:cacheprovider
}

# --------------------------------------------------------------------------------------- #
# 4. Gates
# --------------------------------------------------------------------------------------- #
foreach ($p in 0, 1, 2, 3, 4) {
    Step "phase$p gate" { & $python "harness/phase${p}_gate.py" }
}

Step 'latency bench (50 projects x 100k items, concurrent)' {
    & $python harness/latency_bench.py
}

Step 'full gate' { & $python harness/full_gate.py }

# --------------------------------------------------------------------------------------- #
# 5. Summary
# --------------------------------------------------------------------------------------- #
Write-Host ""
Write-Host ("=" * 78)
Write-Host "  SUMMARY"
Write-Host ("=" * 78)
$failed = 0
foreach ($k in $results.Keys) {
    $v = $results[$k]
    if ($v -ne 'PASS') { $failed++ }
    "{0,-58} {1}" -f $k, $v
}
Write-Host ""
if ($failed -gt 0) {
    Write-Host "$failed step(s) did not pass. Read the output above — a red gate here is the finding."
} else {
    Write-Host "Every step passed against a real stack."
}

if (-not $KeepUp -and -not $SkipUp) {
    Write-Host ""
    Write-Host "Tearing down (pass -KeepUp to leave it running)."
    docker compose -f docker/compose.yaml down
}

exit $failed
