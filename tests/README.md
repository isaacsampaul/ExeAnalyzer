# EXE Inspector test kit

Runs the REAL tool code (engine, Run and Watch, Dialog Finder, Error History, Export Report) with the Windows-only
parts replaced by stubs: WinForms controls/dialogs, UI Automation (window tree incl. raw view), the event log
(Get-WinEvent), WMI process list (Get-CimInstance, read from /proc). The tool's GUI window itself is never opened.

## Requirements
- PowerShell 7 (`pwsh`) on Linux or WSL. The session test starts bash scripts and reads /proc, so it does NOT run on
  native Windows. (The tool itself targets Windows PowerShell 5.1 - final checks must still be done on a station.)

## Run
    pwsh -NoProfile -File tests/run_all.ps1

Expected at v9:

    test_units.ps1           21 passed    0 failed   OK
    harness_session.ps1      75 passed    0 failed   OK
    harness_edge.ps1         11 passed    0 failed   OK
    harness_refs.ps1         40 passed    0 failed   OK
    ALL TESTS PASSED

## Files
- `build_mock.ps1`      builds the mock target in tests/work/media8: Setup.dll (.NET, enums, catch block, P/Invoke,
                         log path literal), IASeries.InstallCommon.dll (helper: enum InstallInfoTag, path built from
                         "{0}\{1}" pieces, catch handler that shows a MessageBox), Setup.ini, Helper.ps1, state XML + log.
                         Add-Type gives the helper a random assembly name; the session test copies it under that name.
- `test_units.ps1`      F14 (UI Automation raw-tree text reading with a stub automation tree) and F15 (exit-code texts,
                         ERROR_ name printed before exit).
- `harness_session.ps1` full mock session: analysis, 3 Run and Watch runs (child processes, console errors, automatic
                         dialogs, start failure, force-stop, export while running), Dialog Finder captures / pasted text,
                         Error History (crash, hang, .NET stacks, WER report, deployment-tool path), Export Report, and
                         checks for F10-F20 in 00_Findings.txt and files 08-16.
- `harness_edge.ps1`    empty session, non-PE file, recovered-script outline, empty Error History search.
- `harness_refs.ps1`    v9 (F21-F25): native mock PlantTool.exe (minimal PE32, Delphi-style CODE section, built by
                         build_mock.ps1 in tests/work/native9) on a fake station folder (tests/work/station9; E:\... paths
                         resolve under it). Checks every referenced file / program is listed with Present Yes/No, severity,
                         arguments, run-by-name programs, no false hits; tab 11, findings, section 3, 17_ReferencedFiles.csv;
                         a second station where a helper is missing; the .NET mock still works.
- `run_all.ps1`         builds the mocks and runs all four, prints a summary.

## Adding a test
Add `Assert (<condition>) '<Fnn: what is checked>'` lines in harness_session.ps1 (section "== v8 checks" or a new
section). Stubs are at the top of the harness (New-StubText, New-FakeDialog, New-MockEvent, Get-CimInstance, ...).
