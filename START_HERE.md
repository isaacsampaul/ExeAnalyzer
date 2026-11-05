# Moving EXE Inspector to Claude Code

## 1. Put the project on your PC
1. Extract `ExeInspector_ClaudeCode_Project.zip` to a working folder, e.g. `C:\Work\ExeInspector`.
   (If downloaded: right-click the zip > Properties > Unblock before extracting.)
2. Optional but recommended - make it a git repo so every version is tracked:
   `cd C:\Work\ExeInspector` then `git init` and `git add .` and `git commit -m "EXE Inspector v8 baseline"`.

## 2. Open it in Claude Code
Start Claude Code in that folder (terminal: `cd C:\Work\ExeInspector` then `claude`, or open the folder in the
Claude desktop app / IDE extension). `CLAUDE.md` in the folder root is loaded automatically - it holds all the rules
(PS 5.1 only, ASCII, no stray output, additive changes, versioning, delivery = .ps1 + build zip, F-number workflow).

## 3. Running the tests
- The test kit (`tests/`) needs PowerShell 7 on Linux or WSL (it uses bash and /proc). On Windows: install WSL,
  install PowerShell 7 inside it, and run `pwsh -NoProfile -File tests/run_all.ps1` from the project folder.
- Without WSL, Claude Code can still do the parse and ASCII checks with Windows PowerShell 5.1, and you test the GUI on a station.

## 4. First message to paste into Claude Code
> Read CLAUDE.md and HANDOFF.md. We are continuing EXE Inspector from v9 (src/ExeInspector_v9.ps1).
> Run the checks listed in CLAUDE.md (parse, ASCII, tests/run_all.ps1 if pwsh is available) and tell me the result.
> Then wait - I will send new feedback. Log it as F26 onwards, propose a fix plan, and only implement after I say "proceed".

## What is in the folder
| Path | What |
|---|---|
| CLAUDE.md | project rules for Claude Code (auto-loaded) |
| HANDOFF.md | full history: features, F1-F25 log, export files, what still needs a Windows check, the Setup.exe case |
| src/ExeInspector_v9.ps1 | the tool |
| build/ExeInspector_v9_EXE_Build_Package/ | the delivery package (Build-EXE.ps1 + ps2exe 1.0.18 + README) |
| tests/ | automated test kit (147 checks at v9) - see tests/README.md |
