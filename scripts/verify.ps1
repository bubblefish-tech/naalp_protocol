# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP verification recipe (CLAUDE.md), PowerShell runner — native-Windows twin of
# scripts/verify.sh. Same four steps, same fail-loudly contract:
#   1. regenerate every vector from its independent oracle,
#   2. Go build + vet + test -race (GOWORK=off),
#   3. Rust build + test,
#   4. assert regenerated vectors match the committed corpus.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = if ($env:PYTHON) { $env:PYTHON } else { 'python' }

function Assert-LastExit([string]$what) {
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" }
}

Write-Host '== [1/5] regenerate vectors from independent oracles =='
$oracles = Get-ChildItem -Path tools -Filter '*_oracle.py' -ErrorAction SilentlyContinue
if (-not $oracles) {
    Write-Host '   (no oracles yet)'
} else {
    foreach ($o in $oracles) {
        Write-Host "   oracle: tools/$($o.Name)"
        & $py $o.FullName
        Assert-LastExit "oracle $($o.Name)"
    }
}

Write-Host '== [2/5] Go: build + vet + test -race (GOWORK=off) =='
$env:GOWORK = 'off'
$env:CGO_ENABLED = '1'
Push-Location impl/go
try {
    go build ./...;               Assert-LastExit 'go build'
    go vet ./...;                 Assert-LastExit 'go vet'
    go test -race -count=1 ./...; Assert-LastExit 'go test -race'
} finally { Pop-Location }

Write-Host '== [3/5] Rust: build + test =='
Push-Location impl/rust
try {
    cargo build --quiet; Assert-LastExit 'cargo build'
    cargo test --quiet;  Assert-LastExit 'cargo test'
} finally { Pop-Location }

Write-Host '== [4/5] Go == Rust deterministic byte-parity: COSE_Sign1 + object envelope (R-16.2) =='
if (Test-Path 'vectors/cose/cases.json') {
    $seed = & $py -c "import json;print(json.load(open('vectors/cose/cases.json'))['mldsa_keygen'][0]['seed_hex'])"
    $env:GOWORK = 'off'
    Push-Location impl/go
    $sigGo = (go run ./cmd/naalp-cose-sig $seed); Assert-LastExit 'go run naalp-cose-sig'
    Pop-Location
    Push-Location impl/rust
    $sigRs = (cargo run --quiet --example naalp_cose_sig -- $seed); Assert-LastExit 'cargo run naalp_cose_sig'
    Pop-Location
    if ($sigGo -ne $sigRs) {
        Write-Host "   go:   $($sigGo.Substring(0,48))..."
        Write-Host "   rust: $($sigRs.Substring(0,48))..."
        throw 'Go and Rust produced different COSE_Sign1 bytes'
    }
    Write-Host "   COSE_Sign1  Go == Rust ($($sigGo.Length) hex chars): $($sigGo.Substring(0,32))..."
    if (Test-Path 'vectors/envelope/cases.json') {
        Push-Location impl/go
        $envGo = (go run ./cmd/naalp-envelope $seed); Assert-LastExit 'go run naalp-envelope'
        Pop-Location
        Push-Location impl/rust
        $envRs = (cargo run --quiet --example naalp_envelope -- $seed); Assert-LastExit 'cargo run naalp_envelope'
        Pop-Location
        if ($envGo -ne $envRs) {
            Write-Host "   go:   $($envGo.Substring(0,48))..."
            Write-Host "   rust: $($envRs.Substring(0,48))..."
            throw 'Go and Rust produced different object envelopes'
        }
        Write-Host "   envelope    Go == Rust ($($envGo.Length) hex chars): $($envGo.Substring(0,32))..."
    }
} else {
    Write-Host '   (no COSE corpus yet - skipped)'
}

Write-Host '== [5/5] vectors current (oracle output == committed corpus, LF-normalized) =='
git diff --quiet -- vectors/
if ($LASTEXITCODE -ne 0) {
    git --no-pager diff --stat -- vectors/
    throw 'regenerated vectors differ from the committed corpus (stale vectors or non-deterministic oracle)'
}

Write-Host 'ALL GREEN'
