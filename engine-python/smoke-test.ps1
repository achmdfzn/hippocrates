<#
.SYNOPSIS
  Docker Compose smoke test for the Hippocrates ML Engine.

.DESCRIPTION
  Builds, starts, and verifies the ML engine + Redis stack:
    1. docker compose build
    2. docker compose up -d
    3. Wait for healthchecks (60s timeout)
    4. Test GET /health endpoint
    5. Test POST /analyze with SQL injection payload
    6. Test POST /analyze with clean payload
    7. docker compose down

.NOTES
  Requires Docker Engine 24+ and Docker Compose v2.
  Run from the repository root (where docker-compose.yml lives).
#>

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Write-Host "=== Hippocrates ML Engine — Docker Smoke Test ===" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Build ─────────────────────────────────────────────────
Write-Host "[1/7] Building Docker images..." -ForegroundColor Yellow
Set-Location -LiteralPath $Root
docker compose build ml-engine 2>&1
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
Write-Host "  ✅ Build succeeded" -ForegroundColor Green

# ── Step 2: Start ─────────────────────────────────────────────────
Write-Host "[2/7] Starting services..." -ForegroundColor Yellow
docker compose up -d 2>&1
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
Write-Host "  ✅ Services started" -ForegroundColor Green

try {
  # ── Step 3: Wait for healthy ───────────────────────────────────
  Write-Host "[3/7] Waiting for healthchecks (60s max)..." -ForegroundColor Yellow
  $Timeout = 60
  $Interval = 3
  $Elapsed = 0

  while ($Elapsed -lt $Timeout) {
    $mlHealth = docker compose ps --status healthy ml-engine 2>&1
    $redisHealth = docker compose ps --status healthy redis 2>&1

    if ($mlHealth -match "ml-engine" -and $redisHealth -match "redis") {
      Write-Host "  ✅ Both services healthy after ${Elapsed}s" -ForegroundColor Green
      break
    }

    Start-Sleep -Seconds $Interval
    $Elapsed += $Interval
  }

  if ($Elapsed -ge $Timeout) {
    Write-Host "  ⚠️  Not all services healthy within ${Timeout}s — checking status..." -ForegroundColor Yellow
    docker compose ps
    # Continue anyway — the service might still work
  }

  # ── Step 4: Test GET /health ───────────────────────────────────
  Write-Host "[4/7] Testing GET /health..." -ForegroundColor Yellow
  $health = curl -s http://localhost:8000/health
  if ($LASTEXITCODE -ne 0) { throw "Health endpoint unreachable" }

  $healthJson = $health | ConvertFrom-Json
  if ($healthJson.status -ne "ok") { throw "Health status is not ok: $health" }
  Write-Host "  ✅ /health returned status=ok" -ForegroundColor Green
  Write-Host "     Analyzers: prompt=$($healthJson.analyzers.prompt_injection) obfuscation=$($healthJson.analyzers.obfuscation_advanced) content=$($healthJson.analyzers.content_risk)"

  # ── Step 5: Test POST /analyze with SQL injection ──────────────
  Write-Host "[5/7] Testing POST /analyze (SQL injection)..." -ForegroundColor Yellow
  $sqlPayload = @{
    request_id = "smoke-test-1"
    ip         = "10.0.0.1"
    method     = "POST"
    path       = "/api/data"
    headers    = @{ "content-type" = "application/json" }
    body       = @{ query = "1' OR '1'='1"; userId = "admin" }
    body_raw   = '{"query":"1'+"' OR '1'='1"+'","userId":"admin"}'
  } | ConvertTo-Json -Compress

  $sqlResult = curl -s -X POST http://localhost:8000/analyze `
    -H "Content-Type: application/json" `
    -d $sqlPayload
  if ($LASTEXITCODE -ne 0) { throw "Analyze endpoint unreachable" }

  $sqlJson = $sqlResult | ConvertFrom-Json
  if ($sqlJson.score -le 0) { throw "Expected score > 0 for SQL injection, got $($sqlJson.score)" }
  Write-Host "  ✅ SQL injection detected — score=$($sqlJson.score) tags=$($sqlJson.tags -join ',')" -ForegroundColor Green

  # ── Step 6: Test POST /analyze with clean payload ──────────────
  Write-Host "[6/7] Testing POST /analyze (clean payload)..." -ForegroundColor Yellow
  $cleanPayload = @{
    request_id = "smoke-test-2"
    ip         = "10.0.0.2"
    method     = "POST"
    path       = "/api/data"
    headers    = @{ "content-type" = "application/json" }
    body       = @{ userId = "550e8400-e29b-41d4-a716-446655440000"; action = "read" }
    body_raw   = '{"userId":"550e8400-e29b-41d4-a716-446655440000","action":"read"}'
  } | ConvertTo-Json -Compress

  $cleanResult = curl -s -X POST http://localhost:8000/analyze `
    -H "Content-Type: application/json" `
    -d $cleanPayload
  if ($LASTEXITCODE -ne 0) { throw "Analyze endpoint unreachable" }

  $cleanJson = $cleanResult | ConvertFrom-Json
  if ($cleanJson.score -ne 0) { throw "Expected score = 0 for clean payload, got $($cleanJson.score)" }
  Write-Host "  ✅ Clean payload OK — score=0" -ForegroundColor Green

  Write-Host ""
  Write-Host "=== Smoke test PASSED ===" -ForegroundColor Green
}
finally {
  # ── Step 7: Cleanup ────────────────────────────────────────────
  Write-Host ""
  Write-Host "[7/7] Cleaning up..." -ForegroundColor Yellow
  docker compose down 2>&1
  Write-Host "  ✅ Services stopped and removed" -ForegroundColor Green
}
