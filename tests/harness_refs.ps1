# v9 test harness (F21-F25): files / programs named in a native program, present or missing on this PC.
# Same stubs as harness_edge.ps1 (GUI, WinForms, UI Automation, event log, CIM); engine and report code are real.
param([string]$Target = (Join-Path $PSScriptRoot '../src/ExeInspector_v9.ps1'), [string]$OutRoot = (Join-Path $PSScriptRoot 'work/out_refs'))
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

# ---- a fake station: paths like E:\apps\... resolve under this folder (ConvertTo-LocalPath turns \ into / on Linux) ----
$native = Join-Path $PSScriptRoot 'work/native9'
$station = Join-Path $PSScriptRoot 'work/station9'
if (Test-Path $station) { Remove-Item $station -Recurse -Force }
[void][System.IO.Directory]::CreateDirectory("$station/E:/apps/plant/bin/tools")
foreach ($f in 'getval.exe', 'lister.exe') { [System.IO.File]::WriteAllText("$station/E:/apps/plant/bin/tools/$f", 'x') }
Set-Location $station; [Environment]::CurrentDirectory = $station
# tab 11 controls
$script:gridRefs = New-StubGrid; $script:lblRefs = [pscustomobject]@{ Text = '' }; $script:chkRefsMissing = [pscustomobject]@{ Checked = $false }
function Get-Ref { param([string]$Path, [string]$Kind = '') return , @($script:S.Refs | Where-Object { $_.Path -eq $Path -and (-not $Kind -or $_.Kind -eq $Kind) }) }

"== A. station where some helper programs exist and some do not"
Invoke-Analysis "$native/PlantTool.exe"
$R = $script:S.Refs
Assert ($script:S.PE.Valid -and -not $script:S.PE.IsDotNet) 'native (non-.NET) mock program analysed'
Assert ($R -and $R.Count -ge 12) "referenced files found ($($R.Count))"
$x = Get-Ref 'E:\apps\plant\bin\tools\getval.exe'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'Yes') 'F21: present full path marked Present = Yes'
$x = Get-Ref 'E:\apps\plant\api\drv.tsk.exe'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No') 'F21/F24: missing program with two dots in its name listed whole, Present = No'
Assert ($x.Count -eq 1 -and $x[0].Times -eq 2 -and ($x[0].Args -join '') -match '^-d 1 -o 7 >C:\\tmp\\BLK\.TX$') 'F24: command-line arguments kept separately, both uses counted'
Assert ($x.Count -eq 1 -and (Get-RefSeverity $x[0]) -eq 'WARNING') 'F21: missing program is a WARNING'
Assert (@($R | Where-Object { $_.Path -match 'tsk\.exe$' -and $_.Path -notmatch 'drv\.tsk\.exe$' }).Count -eq 0) 'F24: no truncated "tsk.exe" entry'
$x = Get-Ref 'E:/apps/plant/bin/tools/setval.exe'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No' -and ($x[0].Args -join '') -eq '-mDESC:%32d') 'F22: forward-slash path found with its arguments'
$x = Get-Ref 'C:\tmp\BLK.TX'
Assert ($x.Count -eq 1 -and $x[0].Uses.Contains('output of a command (> redirect)') -and (Get-RefSeverity $x[0]) -eq 'INFO') 'F23/F24: redirect output with a 2-letter extension found, INFO (created at run time)'
$x = Get-Ref 'C:\tmp\GET_DATA.SH'
Assert ($x.Count -eq 1 -and (Get-RefSeverity $x[0]) -eq 'INFO') 'F23: .SH file in a temp folder found, INFO'
$x = Get-Ref 'E:\apps\plant\wp\editor.exe'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No') 'path inside a sentence ("The file X is missing, ...") found exactly'
Assert (@($R | Where-Object { $_.Path -like '*data\cfg*' }).Count -eq 0) 'sentence text is not taken as one long path'
Assert ((Get-Ref 'settings.xml' 'File name only').Count -eq 1) 'file name inside a sentence found'
Assert ((Get-Ref 'E:\apps\plant\lib\old.dll.bak').Count -eq 1 -and @($R | Where-Object { $_.Path -match 'old\.dll$' }).Count -eq 0) 'F24: dot inside the name does not cut it short (old.dll.bak)'
Assert ((Get-Ref 'C:\Program Files\Vendor Suite\bin\viewer.exe').Count -eq 1) 'path with spaces found'
$x = Get-Ref '\\srv01\share\tools\sync.bat'
Assert ($x.Count -eq 1 -and ($x[0].Args -join '') -eq '/x') 'UNC path found with its arguments'
$x = Get-Ref 'helperx3.dll' 'File name only'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No' -and (Get-RefSeverity $x[0]) -eq 'INFO') 'DLL named without a folder, not found anywhere: INFO'
$x = Get-Ref 'E:\apps\plant\bin\report.exe'
Assert ($x.Count -eq 1 -and $x[0].Encoding -eq 'UTF-16') 'UTF-16 path found'
Assert (@($R | Where-Object { $_.Path -match 'example\.com|^tool\.exe$|3\.9\.0|System\.Xml|^Use$' }).Count -eq 0) 'no false hits: URL, version number, .NET name, plain sentence'
$x = Get-Ref 'lister' 'Program run by name'
Assert ($x.Count -eq 1 -and ($x[0].Args -join '') -eq '-p plant_server >C:\tmp\LST.TX') 'F25: program started by name without extension found'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No' -and $x[0].Note -match 'also names E:\\apps\\plant\\bin\\tools\\lister\.exe' -and (Get-RefSeverity $x[0]) -eq 'WARNING') 'F25: not in PATH -> WARNING, linked to the full path the program names'
Assert (@($script:S.Related | Where-Object { $_.Name -eq 'getval.exe' }).Count -eq 1) 'F22: present referenced file also listed in Related Files'
Assert (@($script:S.Related | Where-Object { $_.Name -eq 'drv.tsk.exe' }).Count -eq 0) 'Related Files still lists only files that exist (unchanged)'
Assert ($script:gridRefs.DataSource.Rows.Count -eq $R.Count -and $script:lblRefs.Text -match 'NOT on this PC') 'tab 11 filled'
$script:chkRefsMissing.Checked = $true; Update-RefsTab
Assert ($script:gridRefs.DataSource.DefaultView.Count -eq @($R | Where-Object { $_.Present -ne 'Yes' }).Count) 'tab 11 "Only files NOT on this PC" filter'
$script:chkRefsMissing.Checked = $false

Export-Report
$d = Get-LastExport; $fx = Get-Content (Join-Path $d.FullName '00_Findings.txt') -Raw
Assert ($fx -notmatch 'could not be built') 'all report sections built'
Assert ($fx -match '\[WARNING\] Referenced files: File named in the program is missing on this PC: E:\\apps\\plant\\api\\drv\.tsk\.exe') 'F21: missing program in the summary as WARNING'
Assert ($fx -match 'Evidence: offset 0x[0-9A-F]{8} \(ASCII\), 2 time\(s\)') 'F21: evidence shows offset, encoding and count'
Assert ($fx -match '\[WARNING\] Referenced files: Program started by name is not found on this PC: lister') 'F25: run-by-name program in the summary'
Assert ($fx -notmatch 'missing on this PC: E:\\apps\\plant\\bin\\tools\\getval\.exe') 'present file not reported as missing'
Assert ($fx -match '\[FILES AND PROGRAMS NAMED IN THE PROGRAM\]' -and $fx -match '\[MISSING - WARNING\] E:\\apps\\plant\\api\\drv\.tsk\.exe') 'section 3 lists the missing files'
$csv = @(Import-Csv (Join-Path $d.FullName '17_ReferencedFiles.csv'))
Assert ($csv.Count -eq $R.Count -and @($csv | Where-Object { $_.ReferencedAs -eq 'E:\apps\plant\api\drv.tsk.exe' -and $_.Present -eq 'No' }).Count -eq 1) '17_ReferencedFiles.csv written with every reference'
foreach ($f in '01_Overview.txt', '11_RelatedFiles.csv', '13_RunWatch_Events.csv', '14_ScriptOutline.txt') { Assert (Test-Path (Join-Path $d.FullName $f)) "existing export file $f still written" }

"== B. another station: the helper that existed before is missing now"
Start-Sleep -Seconds 1
Remove-Item -LiteralPath "$station/E:/apps/plant/bin/tools/getval.exe" -Force
Invoke-Analysis "$native/PlantTool.exe"
$x = Get-Ref 'E:\apps\plant\bin\tools\getval.exe'
Assert ($x.Count -eq 1 -and $x[0].Present -eq 'No' -and $x[0].FolderExists -eq 'yes') 'F21: same program, file now missing -> Present = No, folder exists'
Export-Report
$d = Get-LastExport; $fx = Get-Content (Join-Path $d.FullName '00_Findings.txt') -Raw
Assert ($fx -match 'missing on this PC: E:\\apps\\plant\\bin\\tools\\getval\.exe') 'F21: newly missing program reported'

"== C. .NET program: reference scan runs without changing earlier results"
Invoke-Analysis "$media/Setup.dll"
Assert ($script:S.MD.Valid -and $null -ne $script:S.Refs) '.NET program: referenced files computed'
Assert (@($script:S.Refs | Where-Object { $_.Path -match '(?i)StampLoc\.dll$' }).Count -eq 1) '.NET program: DllImport full path listed (C:\Users\All Users\...\StampLoc.dll)'
""
if ($fail.Count) { "RESULT: $($fail.Count) FAILED" } else { 'RESULT: ALL PASSED' }
