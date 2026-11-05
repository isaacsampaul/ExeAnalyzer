# Runs the whole EXE Inspector test suite (PowerShell 7 on Linux / WSL - see tests/README.md).
# Usage:  pwsh -NoProfile -File tests/run_all.ps1
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$work = Join-Path $here 'work'
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
$pw = (Get-Process -Id $PID).Path
$b = (& $pw -NoProfile -File (Join-Path $here 'build_mock.ps1') 2>&1 | Out-String)
if (-not (Test-Path (Join-Path $work 'media8/Setup.dll'))) { Write-Output 'build_mock.ps1 FAILED:'; Write-Output $b; exit 1 }
Write-Output 'Mock program built.'
$allOk = $true
foreach ($t in 'test_units.ps1', 'harness_session.ps1', 'harness_edge.ps1', 'harness_refs.ps1') {
    $out = (& $pw -NoProfile -File (Join-Path $here $t) 2>&1 | Out-String) -replace "\x1b\[[0-9;]*m", ''
    $pass = ([regex]::Matches($out, '(?m)^\s*PASS ')).Count
    $fails = @([regex]::Matches($out, '(?m)^\s*FAIL .*$') | ForEach-Object { $_.Value.Trim() })
    $ok = ($out -match 'RESULT: ALL PASSED') -and $fails.Count -eq 0
    if (-not $ok) { $allOk = $false }
    Write-Output ('{0,-22} {1,4} passed  {2,3} failed   {3}' -f $t, $pass, $fails.Count, $(if ($ok) { 'OK' } else { 'FAILED' }))
    foreach ($f in $fails) { Write-Output "    $f" }
}
Write-Output $(if ($allOk) { 'ALL TESTS PASSED' } else { 'SOME TESTS FAILED' })
