# Test harness for ExeInspector_v5.ps1 on Linux pwsh: GUI controls, WinForms, UI Automation,
# event log and CIM are stubbed; everything else (engine, run/watch, find cause, export) is the real code.
param([string]$Target = (Join-Path $PSScriptRoot '../src/ExeInspector_v8.ps1'), [string]$OutRoot = (Join-Path $PSScriptRoot 'work/out_session'))
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
function New-FakeDialog { param([int]$ProcId, [string]$Proc, [string]$Title, [string[]]$Lines, [string]$Class = '#32770')
    $cap = [pscustomobject]@{ Title = $Title; Lines = (New-Object System.Collections.Generic.List[string]); Buttons = (New-Object System.Collections.Generic.List[string]) }
    foreach ($l in $Lines) { $cap.Lines.Add($l) }; $cap.Buttons.Add('OK')
    [pscustomobject]@{ Process = $Proc; Pid = $ProcId; Title = $Title; Class = $Class; Handle = [int64](Get-Random); IsDialog = $true; Element = $cap } }

function Invoke-WatchUntilDone { param([int]$MaxTicks = 120, [scriptblock]$OnTick = $null)
    $n = 0
    while ($script:Run.Timer.Running -and $n -lt $MaxTicks) { $n++; Invoke-WatchTick; if ($OnTick) { & $OnTick $n }; Start-Sleep -Milliseconds 250 }
    return $n }

# =================== mock session ===================
$fail = New-Object System.Collections.Generic.List[string]
function Assert { param($Cond, [string]$Msg) if ($Cond) { "  PASS  $Msg" } else { "  FAIL  $Msg"; $script:fail.Add($Msg) } }

# Add-Type gives libraries a random assembly name; copy the helper under that name so it resolves as a real reference would
$an = [System.Reflection.AssemblyName]::GetAssemblyName("$media/IASeries.InstallCommon.dll").Name
Copy-Item "$media/IASeries.InstallCommon.dll" "$media/$an.dll" -Force
"== 1. Analyse $media/Setup.dll"
Invoke-Analysis "$media/Setup.dll"
Assert ($script:S.MD -and $script:S.MD.Valid) '.NET metadata read'
Assert ($script:S.Related.Count -ge 2) "related files found: $(($script:S.Related | ForEach-Object Name) -join ', ')"

"== 2. Run #1: launcher with a child process, console error lines, an automatic dialog, events"
$sh = "$media/mock_setup.sh"
Set-Content $sh -Value (@'
#!/bin/bash
echo "CCS installer starting"
echo "Installed 0 errors so far"
(sleep 2; exit 3) &
sleep 0.6
echo "Error: ERROR_INSTALLER_ACCT_REQUIRED" >&2
echo "Setup failed: ERROR_INSTALLER_ACCT_REQUIRED"
sleep 3
echo "11/1/2026 3:39:47 PM ... ERROR_INSTALLER_ACCT_REQUIRED" >> __MEDIA__/state/SilentSetup.log
echo "ERROR_INSTALLER_ACCT_REQUIRED"
exit 1
'@).Replace('__MEDIA__', $media)
& chmod +x $sh
$script:txtRunExe.Text = $sh; $script:txtRunArgs.Text = '/q:"D:\Media\RPFiles\CCS_Day1.txt"'; $script:txtRunDir.Text = $media
$script:MockEvents = @()
Start-WatchedProcess
$mainPid = $script:Run.MainPid
$ticks = Invoke-WatchUntilDone -OnTick {
    param($n)
    if ($n -eq 1) { $script:FakeDialogs['main'] = New-FakeDialog $script:Run.MainPid 'mock_setup.sh' 'CCS Software Installation' @() 'WindowsForms10.Window.8.app.0.141b42a_r6_ad1'; $script:FakeDialogs['main'].Element.Buttons.Clear() }
    if ($n -eq 2) { $script:MainOnlyTitleAt2 = ($script:RunHistory[0].Dialogs.Count -eq 0) }
    if ($n -eq 4) { $script:FakeDialogs['main'].Element.Lines.Add('Retrieving group policies from the domain controller.  Please wait.'); $script:FakeDialogs['main'].Element.Lines.Add('Error: the account could not be verified - unable to reach the domain controller.') }
    if ($n -eq 3) {
        $script:FakeDialogs['d1'] = New-FakeDialog $script:Run.MainPid 'mock_setup.sh' 'CCS Software Installation' @('Unable to reach the domain controller for authentication. Please check that this station is connected to the domain.')
        $script:MockEvents += New-MockEvent 'Application Error' 1000 2 'Error' "Faulting application name: mock_setup.sh, version: 1.0`r`nFaulting module name: StampLoc.dll, version: 2.1.0.0`r`nException code: 0xc0000005`r`nFault offset: 0x0001a2b3"
        $script:MockEvents += New-MockEvent 'MsiInstaller' 11708 2 'Error' "Product: Foxboro CCS -- Installation failed. (mock_setup.sh)"
    }
    if ($n -eq 12) { $script:FakeDialogs.Clear() } }
$r1 = $script:RunHistory[0]
"  ticks: $ticks  status: $($r1.Status)  main code: $($r1.MainCode)  procs: $($r1.Procs.Count)"
Assert ($r1.Status -eq 'Finished') 'run #1 finished'
Assert ($r1.MainCode -eq 1) 'run #1 main exit code 1 recorded'
Assert ($r1.Procs.Count -ge 2) 'run #1 child process recorded'
Assert ($r1.Console.Count -ge 3) "run #1 console lines recorded ($($r1.Console.Count))"
Assert ($script:MainOnlyTitleAt2) 'F11: main window with only a title is NOT reported as a dialog'
Assert ($r1.Windows.Count -ge 1 -and ($r1.Windows -join ' ') -match 'WindowsForms10') 'F11: main window logged as a window'
Assert ($r1.Dialogs.Count -eq 2) "F11: real message box + main window with error text both recorded ($($r1.Dialogs.Count))"
Assert (@($r1.Dialogs | Where-Object { $_.Text -match 'could not be verified' }).Count -eq 1) 'F11: main window re-read and its later error text captured'
Assert ($r1.WinEvents.Count -ge 2) "run #1 windows events recorded ($($r1.WinEvents.Count))"
Assert ($script:DialogHistory.Count -eq 2 -and $script:DialogHistory[0].Searched) 'auto dialogs in Dialog Finder history and searched'
# Linux cannot report the exit code of a grandchild; inject the code an msiexec child would report on Windows so the report path is exercised
$child = @($r1.Procs | Where-Object { -not $_.IsMain })[0]
if ($child) { $child.Name = 'msiexec.exe'; $child.ExitCode = 1603; $child.Meaning = Get-ExitCodeText 1603 }

"== 3. Run #2: start failure (not executable)"
$bad = "$media/notexec.bin"; Set-Content $bad 'x'
$script:txtRunExe.Text = $bad; $script:txtRunArgs.Text = ''
Start-WatchedProcess
$r2 = $script:RunHistory[1]
Assert ($r2 -and $r2.Status -eq 'Start failed' -and $r2.StartError) "run #2 start failure recorded: $($r2.StartError)"

"== 4. Run #3: force-stopped by the user"
$sh3 = "$media/long.sh"; Set-Content $sh3 "#!/bin/bash`necho waiting`nsleep 30"; & chmod +x $sh3
$script:txtRunExe.Text = $sh3
Start-WatchedProcess
Start-Sleep -Milliseconds 400; Invoke-WatchTick
New-Item -ItemType Directory -Force "$OutRoot/partial" | Out-Null
[System.Windows.Forms.FolderBrowserDialog]::Path = "$OutRoot/partial"
[System.Windows.Forms.MessageBox]::Answer = 'No'
Export-Report
Assert (@(Get-ChildItem "$OutRoot/partial" -Directory).Count -eq 0) 'F12: answering No cancels the export while a run is in progress'
Assert (@([System.Windows.Forms.MessageBox]::Asked | Where-Object { $_ -match 'still being watched' }).Count -ge 1) 'F12: user is warned that a run is in progress'
[System.Windows.Forms.MessageBox]::Answer = 'Yes'
Export-Report
$pd = Get-ChildItem "$OutRoot/partial" -Directory | Select-Object -First 1
$pf = if ($pd) { Get-Content (Join-Path $pd.FullName '00_Findings.txt') -Raw } else { '' }
Assert ($pf -match 'PARTIAL - still running when the report was exported') 'F12: running run marked PARTIAL in section 4'
Assert ($pf -match 'still in progress when the report was exported') 'F12: PARTIAL listed in the summary'
[System.Windows.Forms.MessageBox]::Answer = 'No'   # "No = stop only the main process"
Stop-WatchedProcess
[System.Windows.Forms.MessageBox]::Answer = 'Yes'
$null = Invoke-WatchUntilDone
$r3 = $script:RunHistory[2]
Assert ($r3.StoppedByUser -and $r3.Status -eq 'Stopped by user') "run #3 stopped by user ($($r3.Status))"

"== 5. Dialog Finder: capture + Find cause, pasted text, capture never searched"
$sleeper = Start-Process sleep -ArgumentList 60 -PassThru
$script:DlgWindows = New-Object System.Collections.Generic.List[object]
$script:DlgWindows.Add((New-FakeDialog $sleeper.Id 'Setup' 'CCS Software Installation' @('Unable to reach the domain controller for authentication. Please check that this station is connected to the domain.')))
$script:DlgWindows.Add((New-FakeDialog $sleeper.Id 'Setup' 'Setup' @('Could not load file or assembly ''CSEncryptionSupport, Version=1.0.0.0'' or one of its dependencies. The system cannot find the file specified.')))
$script:gridWin.CurrentRow = [pscustomobject]@{ Cells = @{ '_Idx' = [pscustomobject]@{ Value = 0 } } }
[System.Windows.Forms.MessageBox]::Answer = 'No'   # do not switch analysis to the owner
Invoke-CaptureSelectedWindow
$null = Invoke-FindCause
$script:txtDlgText.Text = 'Error: ERROR_INSTALLER_ACCT_REQUIRED'
$null = Invoke-FindCause
$script:gridWin.CurrentRow = [pscustomobject]@{ Cells = @{ '_Idx' = [pscustomobject]@{ Value = 1 } } }
Invoke-CaptureSelectedWindow
[System.Windows.Forms.MessageBox]::Answer = 'Yes'
Stop-Process -Id $sleeper.Id -Force -ErrorAction SilentlyContinue
Assert ($script:DialogHistory.Count -eq 5) "dialog history has 5 entries ($($script:DialogHistory.Count))"
Assert ($script:DialogHistory[2].Searched -and $script:DialogHistory[2].Origin -like '*captured*') 'capture #2 searched'
Assert ($script:DialogHistory[3].Origin -like '*pasted*') 'pasted text recorded as its own entry'
Assert (-not $script:DialogHistory[4].Searched) 'capture #4 not searched in session'

"== 6. Error History search"
$env:ProgramData = "$OutRoot/ProgramData"
$werDir = "$env:ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_Setup.dll_abc123"
New-Item -ItemType Directory -Force $werDir | Out-Null
Set-Content "$werDir/Report.wer" -Value "EventType=APPCRASH`nAppName=Setup.dll`nSig[0].Name=Application Name`nSig[0].Value=Setup.dll`nSig[3].Name=Fault Module Name`nSig[3].Value=StampLoc.dll`nSig[6].Name=Exception Code`nSig[6].Value=c0000005`nLoadedModule[0]=D:\Media\CCS\Setup.dll`nLoadedModule[1]=C:\Users\All Users\Invensys\IASeries\Installer\SupportFiles\StampLoc.dll"
$script:MockEvents = @(
    (New-MockEvent 'Application Error' 1000 2 'Error' "Faulting application name: Setup.dll, version: 5.0`r`nFaulting module name: StampLoc.dll, version: 2.1.0.0`r`nException code: 0xc0000005" (Get-Date).AddDays(-2)),
    (New-MockEvent '.NET Runtime' 1026 2 'Error' "Application: Setup.dll`r`nFramework Version: v4.0.30319`r`nDescription: The process was terminated due to an unhandled exception.`r`nException Info: System.DllNotFoundException`r`n   at CcsSetup.Program.StampLocation(System.String)" (Get-Date).AddDays(-1)),
    (New-MockEvent 'Application Hang' 1002 2 'Error' "The program Setup.dll version 5.0 stopped interacting with Windows" (Get-Date).AddHours(-3)),
    (New-MockEvent '.NET Runtime' 1026 2 'Error' "Application: Setup.dll`r`nFramework Version: v4.0.30319`r`nDescription: The process was terminated due to an unhandled exception.`r`nException Info: System.InvalidOperationException`r`n   at System.Windows.Forms.MessageBox.ShowCore(System.Windows.Forms.IWin32Window, System.String)`r`n   at IASeries.InstallCommon.Util.AcctError()`r`n   at CcsSetup.Program.Main(System.String[])`r`n" (Get-Date).AddHours(-2)),
    (New-MockEvent '.NET Runtime' 1026 2 'Error' "Application: Setup.dll`r`nException Info: System.InvalidOperationException`r`n   at System.Windows.Forms.MessageBox.ShowCore(System.Windows.Forms.IWin32Window, System.String)`r`n   at IASeries.InstallCommon.Util.AcctError()`r`n   at CcsSetup.Program.Main(System.String[])`r`n" (Get-Date).AddHours(-1)),
    (New-MockEvent '.NET Runtime' 1026 2 'Error' "Application: Setup.dll`r`nFramework Version: v4.0.30319`r`nDescription: The process was terminated due to an unhandled exception.`r`nException Info: System.InvalidOperationException`r`n   at System.Windows.Forms.MessageBox.ShowCore(System.Windows.Forms.IWin32Window, System.String, System.String, System.Windows.Forms.MessageBoxButtons, System.Windows.Forms.MessageBoxIcon, System.Windows.Forms.MessageBoxDefaultButton, System.Windows.Forms.MessageBoxOptions, Boolean)`r`n   at IASeries.InstallCommon.ADAccountHelper.AnonymousIsUserGroupMember(System.String, System.String, System.String, System.String, Boolean)`r`n   at IASeries.InstallCommon.ADAccountHelper.AnonymousIsGroupMember(System.String, System.String, Boolean)`r`n   at CcsSetup.Program.Day1Check(System.String)`r`n" (Get-Date).AddMinutes(-30)),
    (New-MockEvent 'Application Error' 1000 2 'Error' "Faulting application name: Setup.dll, version: 3.48.70.0`r`nFaulting module name: KERNELBASE.dll, version: 10.0.20348.5256`r`nException code: 0xe0434352`r`nFaulting application path: C:\Windows\A\PDQDeployRunner\service-1\exec\Setup.dll`r`nFaulting module path: C:\Windows\System32\KERNELBASE.dll" (Get-Date).AddMinutes(-30))
)
$script:txtErrExe.Text = 'Setup.dll'
Invoke-ErrorHistorySearch
Assert ($script:S.ErrorRows.Count -eq 8) "error history rows: $($script:S.ErrorRows.Count)"

"== 7. Export Report (full v4 export + v5 files)"
New-Item -ItemType Directory -Force $OutRoot | Out-Null
[System.Windows.Forms.FolderBrowserDialog]::Path = $OutRoot
Export-Report
$dir = Get-ChildItem $OutRoot -Directory -Filter 'ExeInspector_Setup_*' | Sort-Object LastWriteTime | Select-Object -Last 1
"  export folder: $($dir.FullName)"
Get-ChildItem $dir.FullName | ForEach-Object { "    {0,-32} {1,8}" -f $_.Name, $_.Length }
foreach ($f in '00_Findings.txt', '01_Overview.txt', '07_DotNet_Members.txt', '08_DotNet_IL_AllMethods.txt', '09_RunWatch_Log.txt', '10_ErrorHistory.csv', '11_RelatedFiles.csv', '12_DialogFinder.txt', '13_RunWatch_Events.csv', '14_ScriptOutline.txt') {
    Assert (Test-Path (Join-Path $dir.FullName $f)) "file $f written" }
$fx = Get-Content (Join-Path $dir.FullName '00_Findings.txt') -Raw
foreach ($sec in '1) SUMMARY OF FINDINGS', '2) PROGRAM ANALYSIS', '3) RELATED FILES', '4) RUN AND WATCH ANALYSIS', '5) ERROR HISTORY ANALYSIS', '6) DIALOG FINDER ANALYSIS') { Assert ($fx.Contains($sec)) "section '$sec'" }
Assert ($fx -match '(?s)--- Run #1:.*--- Run #2:.*--- Run #3:') 'one section per run'
Assert ($fx -match 'same event as listed under run #1') 'overlapping run events not double-counted'
Assert ($fx -match 'same text and source as Dialog #\d') 'identical dialog detail not repeated'
Assert (@([regex]::Matches($fx, 'Windows Installer reported a problem')).Count -eq 1) 'installer warning listed once in summary'
$d3 = $script:DialogHistory[3]; Assert ($d3.Top.Count -gt 0 -and $d3.Top[0].Text -eq 'ERROR_INSTALLER_ACCT_REQUIRED') 'pasted ERROR_INSTALLER_ACCT_REQUIRED traced to the helper DLL literal'
Assert ($fx -notmatch 'could not be built') 'no section failed to build'
Assert ($fx -match 'Dialog #5') 'every dialog in section 6'
$f15 = Join-Path $dir.FullName '15_ErrorHistory_StackCode.txt'
Assert (Test-Path $f15) 'F13: 15_ErrorHistory_StackCode.txt written'
$t15 = if (Test-Path $f15) { Get-Content $f15 -Raw } else { '' }
Assert ($t15 -match '2 time\(s\)') 'F13: identical stacks grouped (2 times)'
Assert ($t15 -match 'Method IASeries\.InstallCommon\.Util::AcctError') 'F13: helper-DLL method from the stack decoded'
Assert ($t15 -match '(?m)^\s*>>.*Util::AcctError\(') 'F13: >> marks the call to the next stack method inside Main'
Assert ($fx -match 'System\.InvalidOperationException in IASeries\.InstallCommon\.Util\.AcctError while calling System\.Windows\.Forms\.MessageBox\.ShowCore') 'F13: stack finding in summary'
Assert ($fx -match 'Code of the methods in the \.NET exception stack') 'F13: stack code in section 5'
Assert ($fx -match 'failed - exit code 1 = ERROR_INSTALLER_ACCT_REQUIRED') 'F15: printed name shown with the exit code in the summary'
Assert ($fx -match '= ERROR_INSTALLER_ACCT_REQUIRED \(name printed by the program') 'F15: printed name shown in section 4'
Assert ((Get-Content (Join-Path $dir.FullName '09_RunWatch_Log.txt') -Raw) -notmatch 'printed .ERROR_INSTALLER') 'F15 log line belongs to run #1 (log 09 is the last run only)'
'== v8 checks'
$relF16 = @($script:S.Related | Where-Object { $_.Name -eq 'IASoftwareInstallInfo.xml' })
Assert ($relF16.Count -eq 1 -and $relF16[0].Why -match ("path built in the program from '" + [regex]::Escape("$media/state") + "' \+ 'IASoftwareInstallInfo.xml'")) "F16: state XML found from folder + file pieces ($($relF16.Why))"
Assert (@($script:S.ProgramLogs | Where-Object { $_ -like '*SilentSetup.log' }).Count -eq 1) 'F17: program log file detected'
$lt1 = Get-RunLogTexts $script:RunHistory[0]
Assert (($lt1.Values -join ' ') -match '3:39:47 PM ... ERROR_INSTALLER_ACCT_REQUIRED' -and ($lt1.Values -join ' ') -notmatch 'ERROR_REBOOT_REQUIRED') 'F17: only the lines written during run #1 captured'
Assert ($fx -match 'Program log files - lines written during this run') 'F17: section 4 shows program log lines'
Assert ($fx -match 'Program log SilentSetup.log: 11/1/2026 3:39:47 PM ... ERROR_INSTALLER_ACCT_REQUIRED') 'F17: error line from the program log in the summary'
Assert (Test-Path (Join-Path $dir.FullName '16_ProgramLogs.txt')) 'F17: 16_ProgramLogs.txt written'
$il08 = Get-Content (Join-Path $dir.FullName '08_DotNet_IL_AllMethods.txt') -Raw
Assert ($il08 -match 'ldc\.i4\.s\s+12\s+// = InstallInfoTag\.DomainName') 'F19: enum name for a constant, enum defined in the helper DLL'
Assert ($il08 -match '// = SetupEXEReturnVal\.ERROR_INSTALLER_ACCT_REQUIRED') 'F19: enum name for -33 (enum in the same file)'
Assert ($il08 -match '// = StationType\.Server') 'F19: enum name for enumValue.ToString() pattern'
Assert ($il08 -match '// ---- try \{' -and $il08 -match '// ---- catch \(System\.IO\.IOException\)') 'F19: try / catch blocks marked in IL listings'
$f15v = Get-Content (Join-Path $dir.FullName '15_ErrorHistory_StackCode.txt') -Raw
Assert ($f15v -match "Box this method can show: 'Unable to reach the domain controller for authentication.  Please check") 'F20: box texts of the failing method listed'
Assert ($f15v -match 'How IL_[0-9A-F]{4} \(call to MessageBox\.Show\) is reached' -and $f15v -match "reached when TRUE : the exception -> Exception.get_Message -> String.ToLower -> `"the server is not operational`" -> String.StartsWith") 'F18/F20: condition before the box call explained in the stack code'
Assert ($fx -match 'started by PDQ Deploy') 'F20: deployment tool recognised from the faulting path'
Assert ($fx -match 'UserInteractive mode') 'F20: no-desktop explanation given'
# F18 in Dialog Finder: the catch-block message
$script:LastCapture = $null
$script:txtDlgText.Text = "CCS Software Installation`r`nUnable to reach the domain controller for authentication.  Please check the domain controller/network connection and retry later.`r`n[Buttons: OK]"
$rowsF18 = Invoke-FindCause
$topF18 = @($rowsF18 | Where-Object { $_.Kind -eq '.NET string literal' -and $_.Text -like 'Unable to reach the domain controller for authentication.  Please*' })[0]
$detF18 = if ($topF18) { Get-CauseDetail $topF18 } else { '' }
Assert ($detF18 -match 'inside a catch handler for System\.Exception') 'F18: message located inside a catch handler'
Assert ($detF18 -match 'the protected code calls: .*DirectoryInfo\.GetFiles') 'F18: what the protected code calls is listed'
Assert ($detF18 -match 'reached when TRUE : the exception -> Exception\.get_Message -> String\.ToLower -> "the server is not operational" -> String\.StartsWith') 'F18: exception-message condition decoded'
Assert ($detF18 -match 'reached when (FALSE: silent \(argument\)|TRUE : NOT silent \(argument\))') 'F18: silent-flag condition decoded'
Assert ((Get-CauseHowSummary $topF18) -match 'ADAccountHelper\.AnonymousIsUserGroupMember: inside a catch handler') 'F18: one-line summary for the report'
"--- F18 detail sample ---"; ($detF18 -split "`r?`n" | Select-Object -First 14) -join "`n"
$ev = Import-Csv (Join-Path $dir.FullName '13_RunWatch_Events.csv')
Assert ((@($ev | Select-Object -ExpandProperty Run -Unique)).Count -eq 3) "events CSV covers 3 runs ($($ev.Count) rows)"
"  log warnings/errors:"
($script:txtLog.Text -split "`n" | Where-Object { $_ -match 'WARN|ERROR' }) | ForEach-Object { "    $_" }
""
if ($fail.Count) { "RESULT: $($fail.Count) FAILED" } else { 'RESULT: ALL PASSED' }
