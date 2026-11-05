# Test harness for ExeInspector_v5.ps1 on Linux pwsh: GUI controls, WinForms, UI Automation,
# event log and CIM are stubbed; everything else (engine, run/watch, find cause, export) is the real code.
param([string]$Target = (Join-Path $PSScriptRoot '../src/ExeInspector_v8.ps1'), [string]$OutRoot = (Join-Path $PSScriptRoot 'work/out_edge'))
if (Test-Path $OutRoot) { Remove-Item $OutRoot -Recurse -Force }   # fresh output folder for every run
$ErrorActionPreference = 'Continue'
$media = Join-Path $PSScriptRoot 'work/media8'

Add-Type -TypeDefinition @'
namespace System.Windows.Forms {
  public static class MessageBox {
    public static string Answer = "Yes";
    public static System.Collections.Generic.List<string> Asked = new System.Collections.Generic.List<string>();
    static string A(string t) { Asked.Add(t); if (t.Contains("Open the folder")) return "No"; return Answer; }
    public static string Show(string t) { return A(t); }
    public static string Show(string t, string c) { return A(t); }
    public static string Show(string t, string c, string b, string i) { return A(t); }
  }
  public static class Application { public static void DoEvents() { } }
  public static class Cursors { public static object WaitCursor = "wait"; public static object Default = "default"; }
  public class FolderBrowserDialog { public static string Path; public string Description; public string SelectedPath; public string ShowDialog() { SelectedPath = Path; return "OK"; } }
}
'@

# ---- load the tool without its GUI start-up ----
$code = Get-Content -LiteralPath $Target -Raw
$code = $code -replace '(?m)^Add-Type -AssemblyName System\.(Windows\.Forms|Drawing)\s*$', '#'
$code = $code -replace '(?m)^\[System\.Windows\.Forms\.Application\]::EnableVisualStyles\(\)\s*$', '#'
$code = $code -replace '(?m)^\$script:(MonoFont|UiFont|BoldFont) = New-Object System\.Drawing\.Font.*$', '$script:$1 = $null'
$code = $code -replace '(?m)^\$null = Show-MainWindow\s*$', '#'
. ([scriptblock]::Create($code))

# ---- control stubs ----
function New-StubText { $o = [pscustomobject]@{ Text = ''; SelectionStart = 0; TextLength = 0; Name = '' }
    $o | Add-Member ScriptMethod AppendText { param($t) $this.Text += $t; $this.TextLength = $this.Text.Length }
    $o | Add-Member ScriptMethod ScrollToCaret { }
    $o | Add-Member ScriptMethod Clear { $this.Text = ''; $this.TextLength = 0 }
    return $o }
function New-StubGrid { [pscustomobject]@{ DataSource = $null; Tag = $null; Columns = @(); CurrentRow = $null } }
$script:txtLog = New-StubText; $script:txtRun = New-StubText; $script:txtOverview = New-StubText; $script:txtDlgText = New-StubText
$script:txtCause = New-StubText; $script:txtErr = New-StubText; $script:txtPath = New-StubText
$script:txtRunExe = New-StubText; $script:txtRunArgs = New-StubText; $script:txtRunDir = New-StubText; $script:txtErrExe = New-StubText
$script:lblStatus = [pscustomobject]@{ Text = '' }; $script:lblRunStatus = [pscustomobject]@{ Text = '' }; $script:lblRel = [pscustomobject]@{ Text = '' }; $script:lblDlg = [pscustomobject]@{ Text = '' }
foreach ($n in 'chkRecursive', 'chkCapture', 'chkAfterEvents', 'chkWatchDlg', 'chkDlgRelated', 'chkDlgOnly', 'chkWer') { Set-Variable -Scope Script -Name $n -Value ([pscustomobject]@{ Checked = $true }) }
$script:chkVerifySig = [pscustomobject]@{ Checked = $false }; $script:chkSysLog = [pscustomobject]@{ Checked = $false }
$script:numDays = [pscustomobject]@{ Value = 7 }
foreach ($n in 'btnRunStart', 'btnRunStop', 'btnBack', 'btnSaveScript') { Set-Variable -Scope Script -Name $n -Value ([pscustomobject]@{ Enabled = $true }) }
foreach ($n in 'gridRel', 'gridCause', 'gridErr', 'gridWin', 'gridDeps', 'gridFuncs') { Set-Variable -Scope Script -Name $n -Value (New-StubGrid) }
$script:form = [pscustomobject]@{ Cursor = $null; Text = '' }
$script:tabs = [pscustomobject]@{ SelectedTab = $null; SelectedIndex = 0 }
$t = [pscustomobject]@{ Running = $false }; $t | Add-Member ScriptMethod Start { $this.Running = $true }; $t | Add-Member ScriptMethod Stop { $this.Running = $false }
$script:Run.Timer = $t
# tabs whose controls are trees/grids not needed for the report
function Update-ScriptTab { } ; function Update-DotNetTab { } ; function Update-ImportsTab { } ; function Update-StringsTab { } ; function Update-ResourcesTab { }

# ---- OS stubs: CIM from /proc, event log, UI Automation ----
function Get-CimInstance { param($ClassName, $Property, $Filter, $ErrorAction)
    foreach ($d in (Get-ChildItem /proc -Directory | Where-Object { $_.Name -match '^\d+$' })) {
        try {
            $st = Get-Content "$($d.FullName)/status" -ErrorAction Stop
            $nm = (($st | Where-Object { $_ -like 'Name:*' }) -split '\s+', 2)[1]
            $pp = [int]((($st | Where-Object { $_ -like 'PPid:*' }) -split '\s+', 2)[1])
            $cl = ((Get-Content "$($d.FullName)/cmdline" -Raw -ErrorAction SilentlyContinue) -replace "`0", ' ').Trim()
            [pscustomobject]@{ ProcessId = [int]$d.Name; ParentProcessId = $pp; Name = $nm; CommandLine = $cl; ExecutablePath = $null }
        } catch { }
    } }
$script:MockEvents = @()
function Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction)
    $q = $FilterHashtable
    @($script:MockEvents | Where-Object { $_.TimeCreated -ge $q.StartTime -and $_.LogName -eq $q.LogName -and (-not $q.ProviderName -or $_.ProviderName -eq $q.ProviderName) -and (-not $q.Level -or $q.Level -contains $_.Level) }) }
function New-MockEvent { param($Provider, $Id, $Level, $LevelName, $Msg, $Time = (Get-Date))
    [pscustomobject]@{ LogName = 'Application'; RecordId = (Get-Random); ProviderName = $Provider; Id = $Id; Level = $Level; LevelDisplayName = $LevelName; TimeCreated = $Time; Message = $Msg; Properties = @() } }
$script:FakeDialogs = @{}
function Initialize-Uia { return $true }
function Get-OpenWindows { param([bool]$DialogsOnly = $true, $OnlyPids = $null)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $script:FakeDialogs.Keys) { $w = $script:FakeDialogs[$k]; if (-not $OnlyPids -or $OnlyPids -contains $w.Pid) { $out.Add($w) } }
    return , $out }
function Get-UiaWindowText { param($Element) return $Element }
function New-FakeDialog { param([int]$ProcId, [string]$Proc, [string]$Title, [string[]]$Lines)
    $cap = [pscustomobject]@{ Title = $Title; Lines = (New-Object System.Collections.Generic.List[string]); Buttons = (New-Object System.Collections.Generic.List[string]) }
    foreach ($l in $Lines) { $cap.Lines.Add($l) }; $cap.Buttons.Add('OK')
    [pscustomobject]@{ Process = $Proc; Pid = $ProcId; Title = $Title; Class = '#32770'; Handle = [int64](Get-Random); IsDialog = $true; Element = $cap } }

function Invoke-WatchUntilDone { param([int]$MaxTicks = 120, [scriptblock]$OnTick = $null)
    $n = 0
    while ($script:Run.Timer.Running -and $n -lt $MaxTicks) { $n++; Invoke-WatchTick; if ($OnTick) { & $OnTick $n }; Start-Sleep -Milliseconds 250 }
    return $n }


$fail = New-Object System.Collections.Generic.List[string]
function Assert { param($Cond, [string]$Msg) if ($Cond) { "  PASS  $Msg" } else { "  FAIL  $Msg"; $script:fail.Add($Msg) } }
New-Item -ItemType Directory -Force $OutRoot | Out-Null
[System.Windows.Forms.FolderBrowserDialog]::Path = $OutRoot
function Get-LastExport { Get-ChildItem $OutRoot -Directory | Sort-Object LastWriteTime | Select-Object -Last 1 }

"== A. empty session (analysis only, nothing run/captured/searched)"
Invoke-Analysis "$media/Setup.ini"
Export-Report
$d = Get-LastExport; $fx = Get-Content (Join-Path $d.FullName '00_Findings.txt') -Raw
Assert ($fx -notmatch 'could not be built') 'non-PE file: all sections built'
Assert ($fx -match 'No program was run') 'run section says nothing was run'
Assert ($fx -match 'Error History was not searched') 'error history not searched'
Assert ($fx -match 'No dialog was captured') 'no dialogs'
Assert ($fx -match 'Not a Windows program file') 'non-PE reported as WARNING'
Assert ((Get-Content (Join-Path $d.FullName '13_RunWatch_Events.csv')).Count -eq 1) 'events CSV header only'

"== B. recovered script outline (PS2EXE result simulated on the analysed .NET file)"
Start-Sleep -Seconds 1
Invoke-Analysis "$media/Setup.dll"
$script:S.PS = [ordered]@{ Found = $true; IsPS2EXE = $true; Name = 'CCS_Tool.ps1'; Method = 'PS2EXE (current format)'; Markers = @(); Script = (Get-Content "$media/Helper.ps1" -Raw) + "`nfunction Broken { if ( }`n" }
$env:ProgramData = (Join-Path $OutRoot 'empty'); $script:MockEvents = @(); $script:txtErrExe.Text = 'Setup.dll'; Invoke-ErrorHistorySearch
Export-Report
$d = Get-LastExport; $fx = Get-Content (Join-Path $d.FullName '00_Findings.txt') -Raw
$so = Get-Content (Join-Path $d.FullName '14_ScriptOutline.txt') -Raw
Assert ($so -match 'FUNCTIONS DEFINED' -and $so -match 'Test-Domain') '14_ScriptOutline lists functions'
Assert ($fx -match 'SCRIPT OUTLINE') 'program analysis shows script outline'
Assert ($fx -match 'Recovered script has a parse error') 'parse error reported as WARNING'
Assert ($fx -match 'No events or crash reports were found') 'empty error history search reported'
Assert (Test-Path (Join-Path $d.FullName '06_Recovered_CCS_Tool.ps1')) 'v4 file 06 still written'
""
if ($fail.Count) { "RESULT: $($fail.Count) FAILED" } else { 'RESULT: ALL PASSED' }
