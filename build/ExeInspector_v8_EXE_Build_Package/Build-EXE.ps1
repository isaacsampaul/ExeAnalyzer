<#
    Build-EXE.ps1 - compiles ExeInspector_v*.ps1 into ExeInspector.exe using the bundled ps2exe module.
    Run from this folder:   powershell.exe -ExecutionPolicy Bypass -File .\Build-EXE.ps1
    Developed by Isaac Sam Paul
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'ps2exe\ps2exe.psd1') -Force

$src = Get-ChildItem -LiteralPath $here -Filter 'ExeInspector_v*.ps1' | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $src) { throw "ExeInspector_v*.ps1 not found in $here" }
$ver = '1.0.0.0'
if ($src.Name -match '_v(\d+)\.ps1$') { $ver = "$($Matches[1]).0.0.0" }
$out = Join-Path $here 'ExeInspector.exe'

Write-Host "Source : $($src.FullName)"
Write-Host "Output : $out  (version $ver)"
Invoke-ps2exe -inputFile $src.FullName -outputFile $out -noConsole -STA `
    -title 'EXE Inspector' -description 'Looks inside Windows EXE/DLL files for troubleshooting' `
    -product 'EXE Inspector' -company 'Developed by Isaac Sam Paul' -copyright 'Isaac Sam Paul' -version $ver

if (Test-Path -LiteralPath $out) { Write-Host "`nBuilt: $out" -ForegroundColor Green } else { Write-Host "`nBuild failed - see messages above." -ForegroundColor Red }
