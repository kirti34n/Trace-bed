<#
.SYNOPSIS
    Retired legacy host-port stack verifier.

.DESCRIPTION
    Compose-v1 deliberately has no host PostgreSQL, Valkey, or S3 port and
    accepts only mounted secret files. The former verifier bypassed both
    boundaries with plaintext owner credentials and is intentionally not a
    compatibility path. Use the closed, secret-file-only controller on a
    supported Compose-v1 host instead.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Write-Error 'verify_with_stack.ps1 is retired. Use python scripts/compose_stack.py start with the required TB_*_FILE environment only.'
exit 1
