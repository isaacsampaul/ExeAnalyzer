# EXE Inspector - project instructions for Claude Code

Developed by Isaac Sam Paul (DCS Engineer). EXE Inspector is a PowerShell WinForms GUI that looks inside
Windows EXE/DLL files to troubleshoot them (used on Foxboro DCS / CCS stations, but it must stay GENERIC -
it is for troubleshooting ANY exe/dll, never built around one program).

Read HANDOFF.md for the full history (feedback log F1-F20, architecture, the real-world test case).

## Files
- `src/ExeInspector_v8.ps1`            - the tool (current version, ~5,800 lines). Single file.
- `build/ExeInspector_v8_EXE_Build_Package/` - what the user receives: the .ps1, Build-EXE.ps1, README.txt,
  ps2exe 1.0.18 module (MS-LPL, LICENSE.txt). Build-EXE.ps1 compiles the newest ExeInspector_v*.ps1 in that folder.
- `tests/`                             - automated test kit (PowerShell 7 on Linux/WSL, GUI stubbed). See tests/README.md.

## Hard constraints (never break these)
1. Windows PowerShell 5.1 only. Only what ships with Windows: WinForms, built-in cmdlets, UI Automation via
   `Add-Type -AssemblyName`. NO third-party tools, NO `Add-Type` C# compilation in the tool. (Tests may compile C#.)
2. The .ps1 must stay pure ASCII (PS 5.1 reads BOM-less files as ANSI).
   Check: `LC_ALL=C grep -cP '[^\x00-\x7F]' src/ExeInspector_v8.ps1` must print 0.
3. No Write-Host and no stray pipeline output (compiled with ps2exe -noConsole -STA; stray output becomes message boxes).
   Use `[void]`, `$null =`, `| Out-Null`.
4. Additive, conservative changes. Layer new code on; do not refactor verified code. When an existing line
   must change, keep its old behaviour and say so in the summary.
5. No PowerShell 7-only syntax (`??`, `?.`, ternary, `&&`/`||`, `::new(`, 3-argument Join-Path, `-Parallel`).
6. The target file is only READ. It is executed only when the user presses Start on Run and Watch (after a confirm box).

## Conventions
- Version appears in 4 places - bump all: filename `ExeInspector_vN.ps1`, header `.SYNOPSIS` line + `Version : vN`
  + a `vN changes:` note in the header, `$script:AppTitle = 'EXE Inspector vN'`, credit label
  `'Developed by Isaac Sam Paul  |  EXE Inspector vN'`.
- Credit line: "Developed by Isaac Sam Paul".
- EVERY delivery = the GUI .ps1 + the EXE build package zip (Build-EXE.ps1, bundled ps2exe 1.0.18 + LICENSE,
  README.txt updated for the version, copy of the .ps1).
- Feedback workflow: log each point as F-number (next is F21), propose a fix plan, implement ONLY after the user
  says "proceed" (or explicitly "implement").
- Ask before assuming. Verify facts with multiple sources. Actually test / stress-test code - never just describe it.
- User wants concrete, step-by-step commands when troubleshooting; prefers config/software fixes before hardware.
- When asking the user to run commands on a station: write output to a file (`| Out-File C:\Temp\x.txt; notepad ...`) -
  the station console sometimes renders text invisibly (black on black).

## Code layout (regions in the .ps1)
`#region ENGINE` PE/.NET parsers -> `#region ENGINE2` (v3: related-file search, message matching, known messages,
MSI exit codes) -> `#region ENGINE3` (v8: EH clauses, enum names, "how is this text reached", message-box texts,
path pieces, log files, deployment-tool rules) -> `#region GUI` (WinForms; v3+ functions before
`# ---------------- build window ----------------`; v5+ report functions in the "v5 additions (F10)" block there).
Engine/report functions must not touch GUI controls (keeps them testable).

## PowerShell pitfalls already hit (do not repeat)
- Variables are case-insensitive: a loop var `$s` overwrites `$S` (the session state). Never use `$pid`/`$PID`,
  `$input`, `$event`, `$args`, `$matches`, `$error`, `$host`, `$this`, `$sender` as your own variables.
- Functions returning `, $list`: do not wrap the call in `@(...)` (gives a 1-item array, even when empty); do not
  use `@($listObject)` either; and piping a returned List into Where-Object passes the WHOLE list as one object -
  use `foreach ($x in (Func))`.
- Single-item results unroll: build tuples as `[pscustomobject]`, wrap pipelines in `@()` before `foreach`.
- Hex literals >= 0x80000000 are negative Int32 - use decimal. Hashtable Int32 vs Int64 keys do not match - cast
  keys to `[int64]` on both store and lookup.
- `-f` format strings: a literal `{` or `}` must be written `{{` / `}}` (this broke IL listings once, in v8).
- `[System.Windows.Forms.Cursors]::WaitCursor`, not strings. Grid columns only exist after the tab is first shown.
- No `Anchor = Right` inside tab-strip panels (buttons ended up off-screen, F9). Timer tick needs the re-entrancy guard.
- IL patterns differ between Debug and Release builds (Debug: `stloc N; ldloc N` before branches, `x == 0` for `!x`);
  analysis code must handle both.
- Exit codes: only 0xC0000000-0xCFFFFFFF are NTSTATUS; small negatives (-33) are program-defined (F15).

## Checks before delivering
1. Parse: `pwsh -NoProfile -c '$t=$null;$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile("src/ExeInspector_v8.ps1",[ref]$t,[ref]$e);$e.Count'` -> 0
2. ASCII check (above) -> 0
3. `pwsh -NoProfile -File tests/run_all.ps1` -> ALL TESTS PASSED (107 checks at v8). Add tests for every new feature.
4. Review the diff against the previous version: only additive changes, version bumped in all 4 places.
5. Build the package folder + zip, update its README.txt.
