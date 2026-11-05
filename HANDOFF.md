# HANDOFF - EXE Inspector (PowerShell WinForms tool) - continue from v9

Status on 2026-11-05: v9 is the latest version (F21-F25), tested in the automated kit (147 checks pass).
No feedback item is open. Next feedback number: F26.

## 1. What the tool is
GUI tool to look inside Windows EXE/DLL files for troubleshooting (Foxboro/CCS stations, but GENERIC for any program).
Reads the target as bytes only; runs it only when the user presses Start on Run and Watch.

Tabs: 1 Overview, 2 Script (PS2EXE recovery), 3 .NET Code (classes/methods/IL), 4 Imports and DLLs (recursive
missing / wrong-bitness check), 5 Strings, 6 Resources, 7 Run and Watch, 8 Error History (event logs + WER),
9 Related Files, 10 Dialog Finder (UI Automation capture + find the code/text that produces a box),
11 Referenced Files (v9: every file/program named in the program, present on this PC or not).

Export Report folder `ExeInspector_<name>_<yyyyMMdd_HHmmss>`:
| File | Since | Content |
|---|---|---|
| 00_Findings.txt | v5 | plain-text analysis: 1) summary PROBLEM/WARNING/INFO with evidence, 2) program analysis, 3) related files + program logs, 4) one section per run, 5) Error History analysis + code of .NET exception stacks, 6) every Dialog Finder capture |
| 01_Overview.txt .. 10_ErrorHistory.csv | v1-v4 | overview, dependencies, imports, strings, resources, recovered script (06), .NET members (07), IL of all methods (08, optional), last Run and Watch log (09), Error History rows (10) |
| 11_RelatedFiles.csv | v5 | related files with kind, version, company |
| 12_DialogFinder.txt | v5 | full detail (code / IL / script lines) of every capture |
| 13_RunWatch_Events.csv | v5 | time, run, type, process, detail for all runs of the session |
| 14_ScriptOutline.txt | v5 | steps, functions, commands of a recovered PS2EXE script |
| 15_ErrorHistory_StackCode.txt | v6 | every .NET exception stack with the IL of each method (>> = call to the next method) |
| 16_ProgramLogs.txt | v8 | log files the program writes, last 200 lines each, + lines written during each run |
| 17_ReferencedFiles.csv | v9 | every file / program named in the program's text: Present (Yes/No/Unknown on the PC that made the report), severity, kind, how used, arguments, offset, encoding, text |

## 2. Feedback log (all implemented)
- F1-F5 (v2): grid MinimumWidth crash, guarded event handlers, absolute-path DLL check, column layout on DataBindingComplete.
- F6-F8 (v3): watch child processes until all exit, MsiInstaller events, installer exit codes; + Related Files and Dialog Finder tabs.
- F9 (v4): Run and Watch buttons were off-screen (no right-edge anchors inside tab strips).
- F10 (v5): Export Report writes 00_Findings.txt + 11-14; Run and Watch keeps a structured record per run
  (`$script:RunHistory`); Dialog Finder keeps a session history (`$script:DialogHistory`); captures never searched
  are searched at export.
- F11 (v6): a window counts as an error box only if it is a real message box (#32770) or its text has error words;
  windows are re-read on later checks until they show text.
- F12 (v6): Export Report warns when a run is still in progress; that run is marked PARTIAL.
- F13 (v6): .NET exception stacks (Error History + run events) traced into the analysed file and related files, IL shown.
- F14 (v7): box text unreadable by the normal UI Automation pass is read from the raw tree (Get-UiaRawText);
  message boxes get 5 checks (~10 s) for text.
- F15 (v7): small negative exit codes are program-defined (not NTSTATUS); an ERROR_... name printed just before
  exit is shown with the code (Get-RunExitName). One existing line in Get-ExitCodeText was changed (range check).
- F16 (v8): Related Files finds files whose path is built from pieces (folder text + file text, "{0}\file"
  templates), also inside the program's .NET helper DLLs (Get-PathPieceCandidates, Get-ProgramTextSets).
- F17 (v8): program log files detected (Get-ProgramLogs); Run and Watch snapshots their size at start and keeps the
  lines written during each run (LogStart / LogTexts on the run record); error lines go into the summary.
- F18 (v8): "how is this text reached": enclosing catch/finally (EH clauses), what the protected code calls, and
  the conditions checked just before it (Get-ILContextAt, Get-TokenContextText, Get-CauseHowSummary).
- F19 (v8): IL listings mark try/catch/finally blocks and show enum names for constants
  (`ldc.i4.s 12  // = InstallInfoTag.DomainName`), also for enums defined in related DLLs (Get-ILEnumAnnotations,
  Get-MdEnumMaps; metadata table 0x0B Constant is now loaded).
- F20 (v8): Error History shows where each crashed copy was started from; copies started by deployment tools /
  services are flagged ($script:DeployPathRules: PDQ, SCCM/MECM, Intune, Ansible, Chocolatey, ConnectWise, Kaseya,
  ManageEngine, Tanium, BigFix, Puppet, Salt, SYSTEM profile, Windows\Temp, Package Cache) with the "no desktop"
  explanation; the message boxes the failing method can show are listed (Get-MessageBoxTexts).
- F21 (v9): reported with TagSelect.exe (native Delphi, Schneider Electric) - on some stations
  D:\opt\fox\ciocfg\api\iccdrvr.tsk.exe was missing, on others present, and the tool never showed it. Cause found in
  the code (not the double dot another chat suspected - v8's full-path regex extracts it whole): Get-RelatedFiles drops
  every path that does not exist on the PC running the tool, so a MISSING helper was never reported anywhere. Fix:
  Get-ReferencedFiles ($S.Refs, region ENGINE4) lists every full path / file name / program-run-by-name in the
  extracted strings (ASCII + UTF-16, whole file) and recovered script, with Present Yes/No/Unknown, FolderExists,
  offset, encoding, usage and arguments. New tab 11, summary findings (Get-RefSeverity: missing program/code file =
  WARNING; output "> file", temp folder, .log, data file, name without folder, unknown = INFO), report section 3
  (Get-ReferencedFilesText), 17_ReferencedFiles.csv. Related Files unchanged, except it also lists present
  referenced files the v3 patterns missed. Generic - nothing in it is specific to TagSelect or Foxboro.
- F22 (v9): forward-slash paths (D:/opt/.../getpars.exe in command lines).
- F23 (v9): a full path (drive, \\server\share, %VAR%) accepts any 1-5 character extension containing a letter (.SH, .TX);
  a name without a folder needs a known extension, written all lower or all upper case ("System.Xml" is a .NET name).
- F24 (v9): an extension followed by ".letter" does not end the path (iccdrvr.tsk.exe, file.dll.bak kept whole);
  sentence-like matches ("C:\x is missing. Check y.txt") fall back to the part without spaces; text after an
  executable path that looks like arguments is kept as Args; a path after ">" is an output (INFO).
- F25 (v9): "name -switch ..." / "cmd /c name ..." with no extension is a program run by name when the name resolves
  in the program folder / System32 / Windows / PATH, or the program also names name.exe with a full path
  (glof -p csa_server + D:\opt\fox\bin\tools\glof.exe). Not found in PATH -> WARNING (Windows only searches the
  working folder and PATH for it). api-ms-win-* / ext-ms-* names count as present (API sets).

## 3. Not yet verified on a real Windows station
Everything since v6 passed the Linux test kit, and v8's engine was also checked against the REAL vendor DLL
(IASeries.InstallCommon.dll), but these GUI/OS paths still need one real run:
1. F14 - message box text actually read on Windows (it was empty in the v6 run).
2. F15 - exit -33 shown as "= ERROR_INSTALLER_ACCT_REQUIRED".
3. F16-F20 in a real export of D:\Media\CCS\Setup.exe (Related Files should list IASoftwareInstallInfo.xml and
   SilentSetup.log; 08 IL should show `// = InstallInfoTag.DomainName` and `// = SetupEXEReturnVal...`).
Ask the user for an export (zip) after analysing Setup.exe, running it once, searching Error History, exporting.
4. F21-F25 on a real station: analyse TagSelect.exe on a station WITHOUT iccdrvr.tsk.exe (tab 11 should show it as
   NOT on this PC and 00_Findings.txt should have a WARNING for it) and on one WITH it (Present = Yes); check that
   `glof` (run by name in "glof -p csa_server") is resolved or flagged depending on PATH. Also check the time the
   new scan adds on a big EXE in Windows PowerShell 5.1 (Linux pwsh 7: ~1.5 s for 124,000 strings).

## 4. Real-world case solved with the tool (keep as regression reference)
Station CRAW01, domain QELNGONLR.DCS.local, account qelngonlr\ccsinstaller (member of IA Installer).
`D:\Media\CCS\Setup.exe /q:"D:\Media\RPFiles\CCS\CCS_Day1_EnterpriseEdition.txt"` (Foxboro DCS Control Core
Services 9.9, .NET 4.8, x86, requireAdministrator) failed with exit -33 = ERROR_INSTALLER_ACCT_REQUIRED and the box
"CCS Software Installation - Unable to reach the domain controller for authentication...".
Chain found from the code:
1. Program.Main reads InstallationInfo property 12 = DomainName from
   C:\Users\All Users (= C:\ProgramData)\Invensys\IASeries\Installer\IASoftwareInstallInfo.xml
   (`<InstallerProperty name="DomainName" value=...>`, written by the Day0 "Connect to host domain" step).
2. ADAccountHelper.AnonymousIsGroupMember -> AnonymousIsUserGroupMember binds LDAP://<DomainName>, searches
   (objectclass=user), checks memberOf for CN=IA Installer,OU=IA Groups,OU=Groups,OU=Accounts,OU=Foxboro
   (overridable by HKLM\SOFTWARE\Invensys\IASeries\Installer\IAInstallUserGroup).
3. The catch handler: exception message starting "the server is not operational" -> that box; otherwise
   "Unknown error authenticating the domain account: ..."; returns false -> Main returns -33.
4. The XML held a wrong domain name; LDAP://QELNGONLR.DCS fails with "The server is not operational",
   LDAP://QELNGONLR.DCS.local works. User corrected the XML -> install ran.
5. Five crashes in Error History came from PDQ Deploy (C:\Windows\A\PDQDeployRunner\...): the same MessageBox in a
   non-interactive session -> InvalidOperationException in MessageBox.ShowCore.
Silent install log: D:\usr\fox\sp\SilentSetup.log. This case is what F11-F20 were built from; the mock in tests/
reproduces it.

## 5. Ideas discussed but not requested
None open. (All suggestions A-E from 2026-11-02 became F16-F20.)
