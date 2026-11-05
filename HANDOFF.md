# HANDOFF - EXE Inspector (PowerShell WinForms tool) - continue from v8

Status on 2026-11-04: v8 is the latest version, delivered and tested in the automated kit (107 checks pass).
No feedback item is open. Next feedback number: F21.

## 1. What the tool is
GUI tool to look inside Windows EXE/DLL files for troubleshooting (Foxboro/CCS stations, but GENERIC for any program).
Reads the target as bytes only; runs it only when the user presses Start on Run and Watch.

Tabs: 1 Overview, 2 Script (PS2EXE recovery), 3 .NET Code (classes/methods/IL), 4 Imports and DLLs (recursive
missing / wrong-bitness check), 5 Strings, 6 Resources, 7 Run and Watch, 8 Error History (event logs + WER),
9 Related Files, 10 Dialog Finder (UI Automation capture + find the code/text that produces a box).

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

## 3. Not yet verified on a real Windows station
Everything since v6 passed the Linux test kit, and v8's engine was also checked against the REAL vendor DLL
(IASeries.InstallCommon.dll), but these GUI/OS paths still need one real run:
1. F14 - message box text actually read on Windows (it was empty in the v6 run).
2. F15 - exit -33 shown as "= ERROR_INSTALLER_ACCT_REQUIRED".
3. F16-F20 in a real export of D:\Media\CCS\Setup.exe (Related Files should list IASoftwareInstallInfo.xml and
   SilentSetup.log; 08 IL should show `// = InstallInfoTag.DomainName` and `// = SetupEXEReturnVal...`).
Ask the user for an export (zip) after analysing Setup.exe, running it once, searching Error History, exporting.

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
