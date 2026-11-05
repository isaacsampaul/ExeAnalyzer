EXE Inspector v9 - EXE build package
Developed by Isaac Sam Paul
=====================================

CONTENTS
  ExeInspector_v9.ps1   The tool (GUI). Can be run directly or compiled to an EXE.
  Build-EXE.ps1         Compiles the tool to ExeInspector.exe with the bundled ps2exe.
  ps2exe\               ps2exe 1.0.18 module (Markus Scholtes, MS-LPL licence - see LICENSE.txt).

RUN WITHOUT BUILDING
  powershell.exe -ExecutionPolicy Bypass -STA -File .\ExeInspector_v9.ps1
  (optional) add a file to analyse straight away:
  powershell.exe -ExecutionPolicy Bypass -STA -File .\ExeInspector_v9.ps1 "D:\path\program.exe"

BUILD THE EXE
  1. Copy this folder to a Windows PC (Windows PowerShell 5.1).
  2. If the zip was downloaded, right-click it > Properties > Unblock before extracting
     (or run:  Get-ChildItem -Recurse | Unblock-File).
  3. powershell.exe -ExecutionPolicy Bypass -File .\Build-EXE.ps1
  4. ExeInspector.exe appears in this folder. It is a GUI EXE (-noConsole, STA).
     You can drag an EXE onto ExeInspector.exe to analyse it immediately.

EXPORT REPORT (top bar > Export Report)
  Creates a folder ExeInspector_<name>_<date_time> with:
  00_Findings.txt          NEW in v5 - plain-text analysis of everything in this session:
                             1) summary of findings (PROBLEM / WARNING / INFO, area, evidence)
                             2) program analysis (overview, script outline or .NET entry point + P/Invoke)
                             3) related files (what each is, why it is related)
                             4) Run and Watch - one section per run: command line, start/end/duration,
                                main + child exit codes with meaning, console lines that look like errors
                                and where that text comes from, dialogs with top 3 causes, non-Windows
                                DLLs loaded, Windows/installer events of that run
                             5) Error History - counts by type, most frequent faulting module /
                                exception code, first/last seen, newest entries in full
                             6) Dialog Finder - every dialog captured/searched in the session, owner,
                                known-message explanation, top 5 sources, code/script/IL of the best match
  01_Overview.txt ... 10_ErrorHistory.csv   same files as v4
  11_RelatedFiles.csv      NEW - related files with kind, version, company
  12_DialogFinder.txt      NEW - full detail (code / IL / script lines) of every capture
  13_RunWatch_Events.csv   NEW - time, run, type, process, detail for every run of the session
  14_ScriptOutline.txt     NEW - steps, functions and commands of a recovered PS2EXE script
  15_ErrorHistory_StackCode.txt  NEW in v6 - each .NET exception stack from Error History / run events,
                           with the IL of every method in it found in the EXE or its related files
                           (>> marks the call to the next method in the stack). Written only when stacks exist.
  16_ProgramLogs.txt       NEW in v8 - log files the program writes (found in its text), last 200 lines of
                           each, and the lines written to them during every Run and Watch run.
  17_ReferencedFiles.csv   NEW in v9 - every file or program named in the program's text, with Present
                           (Yes / No / Unknown on the PC that made the report), kind, how it is used,
                           command-line arguments, offset and encoding in the file, and the text it is in.
  v8 analysis (works for any .NET program, and partly for native ones):
    - Related Files also finds files whose path the program builds from a folder text + a file-name text.
    - Dialog Finder / report explain how a message is reached: inside which catch / finally block, what
      the protected code calls, and the conditions checked just before it.
    - IL listings mark try / catch / finally blocks and show enum names for constants
      (e.g. "ldc.i4.s 12  // = InstallInfoTag.DomainName"), also for enums defined in the program's DLLs.
    - Error History shows where each crashed copy was started from and flags copies started by
      deployment tools / services (PDQ, SCCM, Intune, ...), which have no desktop for message boxes.
  v9 analysis (works for any program - native, .NET or script):
    - New tab "11. Referenced Files": every file or program the program names, ALSO the ones that do not
      exist on this PC (Related Files lists only files that exist - a missing helper program was never
      shown there). Tick "Only files NOT on this PC" to see just the missing ones.
    - Missing programs / code files are WARNINGs in 00_Findings.txt (summary + section 3) with evidence.
      Files that are probably created when the program runs (command output "> file", temp folder, .log)
      and names without a folder are INFO.
    - Found now: paths with forward slashes (D:/folder/tool.exe), any extension on a full path (.sh, .TX),
      names with a dot inside (tool.tsk.exe, file.dll.bak), \\server\share and %VARIABLE% paths, UTF-16 text,
      command lines (arguments are kept separately), and programs started by name without an extension
      ("tool -switch ..."), which Windows only finds in the working folder or PATH.
    - Present / missing is checked on the PC running EXE Inspector: run it ON the station that has the
      problem (or compare the reports of a working and a failing station).
  Run and Watch / Dialog Finder history is kept for the whole session (the Clear button only
  clears the Run and Watch view). A captured dialog that was never searched with "Find cause"
  is searched automatically when the report is exported.
  Exporting while a watched program is still running asks first; that run is marked PARTIAL.

NOTES
  - Uses only what ships with Windows: PowerShell 5.1, WinForms, UI Automation, built-in cmdlets.
    No Add-Type C# compilation, no third-party tools.
  - The analysed file is only READ. It is never loaded or run, except when you press
    Start on the "7. Run and Watch" tab (you are asked to confirm first).
  - Some antivirus products flag ANY ps2exe-built EXE. If that happens, run the .ps1
    directly, or have the EXE whitelisted.
  - On stations locked by application whitelisting (e.g. Solidcore), a newly built EXE
    must be authorised before it can run; running the .ps1 from an engineering PC is
    an alternative.
  - Event logs and WER crash reports of other users/services may need "Run as administrator".
  - Dialog Finder / error-box detection read other programs' windows through Windows UI
    Automation. A program running as administrator can only be read when EXE Inspector
    also runs as administrator. If a box cannot be read, click it, press Ctrl+C (copies a
    standard message box's text) and paste it into the Dialog Finder text area.
  - Programs packed inside an EXE (Costura .compressed resources, embedded EXE/DLL) are
    extracted to %TEMP%\ExeInspector only when you choose "Decode selected".
