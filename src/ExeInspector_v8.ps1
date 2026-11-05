<#
.SYNOPSIS
    EXE Inspector v8 - look inside a Windows .exe/.dll to troubleshoot it.

.DESCRIPTION
    Pure PowerShell 5.1 + WinForms + UI Automation (built into Windows). No third-party tools,
    no Add-Type C# compilation.
    The target file is only READ as bytes for analysis - it is never loaded or executed,
    except when you explicitly press "Start" on the Run & Watch tab.

    Auto-detects the kind of EXE and shows:
      - PS2EXE-compiled PowerShell: the original script (current and legacy PS2EXE formats),
        with an outline of its steps, functions and commands.
      - .NET (C#/VB.NET): every class and method, decoded IL "steps" for any method,
        external calls grouped by category, string literals, P/Invoke native calls,
        assembly references and embedded resources.
      - Native (C/C++, VB6, Delphi...): imported DLLs/functions with categories,
        missing/wrong-bitness DLL check (recursive), exports, resources
        (manifest, string tables, message tables), strings.
      - Run & Watch: launch it on demand, capture console output, child processes,
        loaded DLLs, windows, exit code meaning, and related crash events.
      - Error History: Windows event-log entries and WER crash reports for this EXE.

.NOTES
    Developed by Isaac Sam Paul
    Version : v8
    Requires: Windows PowerShell 5.1 (Windows 7 SP1 / Server 2008 R2 and later)
    v2 changes: grid column layout re-applied when a tab is first shown (fixes the
              'MinimumWidth' error), every event handler guarded (errors go to Output
              instead of a crash dialog), DLLs referenced by a full path are checked at that path.
    v3 changes: Related Files tab (decode files the EXE uses, incl. programs packed inside it),
              Dialog Finder tab (capture an error box via UI Automation and find the code/text
              that produces it), Run and Watch follows child processes until all exit,
              collects Windows Installer events, explains installer exit codes, and detects
              error boxes automatically.
    v4 changes: Run and Watch buttons (Start/Stop/Clear/Browse) and tab info labels use fixed
              positions - they were pinned to a panel edge measured too early and ended up off-screen.
    v5 changes: Export Report adds 00_Findings.txt - a plain-text analysis of every tab: summary of findings
              (PROBLEM/WARNING/INFO with evidence), program analysis, related files, one section per
              Run and Watch run, Error History analysis and every Dialog Finder capture of the session.
              Also adds 11_RelatedFiles.csv, 12_DialogFinder.txt, 13_RunWatch_Events.csv, 14_ScriptOutline.txt.
              Run and Watch keeps a structured record of every run; Dialog Finder keeps a session
              history of every capture / Find cause. Existing export files are unchanged.
    v6 changes: F11 - Run and Watch re-reads a window on later checks until it shows text; only a real
              message box (#32770) or a window with error text counts as an error box (an installer's
              main window whose title contains "Installation" is no longer reported as a dialog).
              F12 - Export Report warns when a watched run is still in progress; that run is marked
              PARTIAL in the report.
              F13 - .NET exception stacks in Error History / run events are traced into the analysed
              file and its related files: each method in the stack is shown with its IL (>> marks the
              call to the next method in the stack). Section 5 of 00_Findings.txt + 15_ErrorHistory_StackCode.txt.
    v7 changes: F14 - box text that the normal UI Automation pass cannot read (seen on a Setup.exe message box)
              is read with a second pass over the full (raw) UI Automation tree; a message box gets up to
              5 checks (about 10 s) for its text before it is recorded without text.
              F15 - small negative exit codes (e.g. -33) are reported as program-defined, not NTSTATUS; when
              the program printed an ERROR_... name just before it exited, that name is shown with the code.
    v8 changes: F16 - Related Files also finds files whose path the program builds from pieces (a folder text +
              a file-name text, or a "{0}\file" template), in the EXE and in its .NET helper DLLs.
              F17 - log files the program writes are detected; Run and Watch records the lines written to
              them during each run (report section 4, 16_ProgramLogs.txt).
              F18 - for a message found in .NET code the tool explains how it is reached: inside which catch /
              finally handler, what the protected code calls, and the conditions checked just before it.
              F19 - IL listings show enum names for constants passed where an enum is expected
              (e.g. "ldc.i4.s 12  // = InstallInfoTag.DomainName"), also across the program's DLLs;
              IL listings mark try / catch / finally blocks.
              F20 - Error History shows where each crashed copy was started from and flags runs started by
              deployment tools / services (no desktop), and lists the message boxes the failing method shows.
#>

#region ENGINE
# =====================================================================
#  ENGINE - pure PowerShell, read-only analysis. Nothing here executes
#  or loads the target file; it is only read as bytes.
# =====================================================================

$script:Latin1 = [System.Text.Encoding]::GetEncoding(28591)

function Get-U16 { param($b, $o) return [int][BitConverter]::ToUInt16($b, [int]$o) }
function Get-U32 { param($b, $o) return [int64][BitConverter]::ToUInt32($b, [int]$o) }
function Get-U64 { param($b, $o) return [BitConverter]::ToUInt64($b, [int]$o) }

function Read-AsciiZ {
    param($b, [int64]$o, [int]$max = 1024)
    if ($o -lt 0 -or $o -ge $b.Length) { return '' }
    $end = [Array]::IndexOf($b, [byte]0, [int]$o, [int][Math]::Min($max, $b.Length - $o))
    if ($end -lt 0) { $end = [int][Math]::Min($o + $max, $b.Length) }
    return $script:Latin1.GetString($b, [int]$o, [int]($end - $o))
}

function Read-UnicodeCounted {
    # WORD length (in chars) followed by UTF-16 text
    param($b, [int64]$o)
    if ($o + 2 -gt $b.Length) { return '' }
    $len = Get-U16 $b $o
    if ($o + 2 + $len * 2 -gt $b.Length) { return '' }
    return [System.Text.Encoding]::Unicode.GetString($b, [int]($o + 2), [int]($len * 2))
}

function Read-FileBytesShared {
    param([string]$Path)
    try { $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) } catch { }
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try {
        $buf = New-Object byte[] $fs.Length
        $read = 0
        while ($read -lt $buf.Length) {
            $n = $fs.Read($buf, $read, $buf.Length - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        return , $buf
    } finally { $fs.Dispose() }
}

$script:MachineNames = @{
    0x14c = 'x86 (32-bit)'; 0x8664 = 'x64 (64-bit)'; 0xaa64 = 'ARM64'; 0x1c0 = 'ARM'; 0x1c4 = 'ARM Thumb-2'; 0x200 = 'Itanium (IA-64)'; 0 = 'Any / unknown'
}
$script:SubsystemNames = @{
    1 = 'Native (driver)'; 2 = 'Windows GUI'; 3 = 'Windows Console'; 5 = 'OS/2 Console'; 7 = 'POSIX Console'; 9 = 'Windows CE GUI'
    10 = 'EFI Application'; 14 = 'Xbox'; 16 = 'Windows Boot Application'
}

function Get-PEInfo {
    param([byte[]]$Bytes)
    $pe = [ordered]@{ Valid = $false; Error = '' }
    try {
        if ($Bytes.Length -lt 64 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) { $pe.Error = 'Not a Windows executable (no MZ header).'; return $pe }
        $lfanew = Get-U32 $Bytes 0x3C
        if ($lfanew -le 0 -or $lfanew + 24 -gt $Bytes.Length) { $pe.Error = 'MZ header present but no PE header (DOS program or damaged file).'; return $pe }
        if ((Get-U32 $Bytes $lfanew) -ne 0x00004550) { $pe.Error = 'MZ header present but PE signature missing (16-bit/DOS program or damaged file).'; return $pe }
        $coff = $lfanew + 4
        $pe.Machine = Get-U16 $Bytes $coff
        $pe.MachineName = if ($script:MachineNames.ContainsKey($pe.Machine)) { $script:MachineNames[$pe.Machine] } else { ('Unknown (0x{0:X})' -f $pe.Machine) }
        $nSec = Get-U16 $Bytes ($coff + 2)
        $pe.TimeDateStamp = Get-U32 $Bytes ($coff + 4)
        $optSize = Get-U16 $Bytes ($coff + 16)
        $pe.Characteristics = Get-U16 $Bytes ($coff + 18)
        $pe.IsDll = [bool]($pe.Characteristics -band 0x2000)
        $opt = $coff + 20
        $magic = Get-U16 $Bytes $opt
        if ($magic -eq 0x20B) { $pe.Is64 = $true } elseif ($magic -eq 0x10B) { $pe.Is64 = $false } else { $pe.Error = ('Unknown optional header magic 0x{0:X}' -f $magic); return $pe }
        $pe.LinkerVersion = '{0}.{1}' -f $Bytes[$opt + 2], $Bytes[$opt + 3]
        $pe.EntryPointRva = Get-U32 $Bytes ($opt + 16)
        if ($pe.Is64) { $pe.ImageBase = Get-U64 $Bytes ($opt + 24) } else { $pe.ImageBase = [uint64](Get-U32 $Bytes ($opt + 28)) }
        $pe.SizeOfImage = Get-U32 $Bytes ($opt + 56)
        $pe.SizeOfHeaders = Get-U32 $Bytes ($opt + 60)
        $pe.OsVersion = '{0}.{1}' -f (Get-U16 $Bytes ($opt + 40)), (Get-U16 $Bytes ($opt + 42))
        $pe.SubsystemVersion = '{0}.{1}' -f (Get-U16 $Bytes ($opt + 48)), (Get-U16 $Bytes ($opt + 50))
        $pe.Subsystem = Get-U16 $Bytes ($opt + 68)
        $pe.SubsystemName = if ($script:SubsystemNames.ContainsKey($pe.Subsystem)) { $script:SubsystemNames[$pe.Subsystem] } else { "Unknown ($($pe.Subsystem))" }
        $pe.DllCharacteristics = Get-U16 $Bytes ($opt + 70)
        if ($pe.Is64) { $nDirOff = $opt + 108; $dirOff = $opt + 112 } else { $nDirOff = $opt + 92; $dirOff = $opt + 96 }
        $nDirs = [Math]::Min([int](Get-U32 $Bytes $nDirOff), 16)
        $dirs = @()
        for ($i = 0; $i -lt 16; $i++) {
            if ($i -lt $nDirs -and ($dirOff + $i * 8 + 8) -le $Bytes.Length) {
                $dirs += , @((Get-U32 $Bytes ($dirOff + $i * 8)), (Get-U32 $Bytes ($dirOff + $i * 8 + 4)))
            } else { $dirs += , @([int64]0, [int64]0) }
        }
        $pe.Dirs = $dirs
        $secOff = $opt + $optSize
        $sections = New-Object System.Collections.Generic.List[object]
        $maxEnd = [int64]$pe.SizeOfHeaders
        for ($i = 0; $i -lt $nSec; $i++) {
            $s = $secOff + $i * 40
            if ($s + 40 -gt $Bytes.Length) { break }
            $name = (Read-AsciiZ $Bytes $s 8)
            $sec = [pscustomobject]@{
                Name = $name; VirtualSize = (Get-U32 $Bytes ($s + 8)); VirtualAddress = (Get-U32 $Bytes ($s + 12))
                RawSize = (Get-U32 $Bytes ($s + 16)); RawPointer = (Get-U32 $Bytes ($s + 20)); Flags = (Get-U32 $Bytes ($s + 36))
            }
            $sections.Add($sec)
            if ($sec.RawSize -gt 0 -and ($sec.RawPointer + $sec.RawSize) -gt $maxEnd) { $maxEnd = $sec.RawPointer + $sec.RawSize }
        }
        $pe.Sections = $sections
        # Certificate table (dir 4) uses a FILE offset and lives in the overlay area legitimately
        $certOff = $dirs[4][0]; $certSize = $dirs[4][1]
        $pe.OverlayOffset = $maxEnd
        $pe.OverlaySize = [Math]::Max([int64]0, [int64]$Bytes.Length - [int64]$maxEnd)
        if ($certSize -gt 0 -and $certOff -ge $maxEnd -and ($certOff + $certSize) -ge ($Bytes.Length - 8)) {
            $pe.OverlaySize = [Math]::Max([int64]0, [int64]$certOff - [int64]$maxEnd)
        }
        $pe.IsDotNet = ($dirs[14][0] -ne 0)
        $pe.Valid = $true
    } catch { $pe.Error = "PE parse error: $($_.Exception.Message)" }
    return $pe
}

function ConvertTo-FileOffset {
    param($pe, [int64]$Rva)
    if ($Rva -lt $pe.SizeOfHeaders) { return $Rva }
    foreach ($s in $pe.Sections) {
        $size = [Math]::Max($s.VirtualSize, $s.RawSize)
        if ($Rva -ge $s.VirtualAddress -and $Rva -lt ($s.VirtualAddress + $size)) {
            $off = $Rva - $s.VirtualAddress
            if ($off -ge $s.RawSize) { return -1 }   # in uninitialised data, not stored in file
            return $s.RawPointer + $off
        }
    }
    return -1
}

function Get-PEImports {
    param([byte[]]$Bytes, $pe)
    $list = New-Object System.Collections.Generic.List[object]
    $thunkSize = if ($pe.Is64) { 8 } else { 4 }
    # --- normal imports ---
    $rva = $pe.Dirs[1][0]
    if ($rva -ne 0) {
        $off = ConvertTo-FileOffset $pe $rva
        $guard = 0
        while ($off -ge 0 -and $off + 20 -le $Bytes.Length -and $guard -lt 2000) {
            $guard++
            $oft = Get-U32 $Bytes $off; $nameRva = Get-U32 $Bytes ($off + 12); $ft = Get-U32 $Bytes ($off + 16)
            if ($oft -eq 0 -and $nameRva -eq 0 -and $ft -eq 0) { break }
            $dll = Read-AsciiZ $Bytes (ConvertTo-FileOffset $pe $nameRva) 256
            $thunkRva = if ($oft -ne 0) { $oft } else { $ft }
            $t = ConvertTo-FileOffset $pe $thunkRva
            $count = 0
            if ($t -lt 0) { $list.Add([pscustomobject]@{ Dll = $dll; Function = '(unreadable thunk table)'; Kind = 'Import' }) }
            while ($t -ge 0 -and $t + $thunkSize -le $Bytes.Length -and $count -lt 20000) {
                $count++
                $isOrd = ($Bytes[$t + $thunkSize - 1] -band 0x80) -ne 0
                if ($thunkSize -eq 8) { $v = Get-U64 $Bytes $t; $zero = ($v -eq 0) } else { $v = Get-U32 $Bytes $t; $zero = ($v -eq 0) }
                if ($zero) { break }
                if ($isOrd) {
                    $fn = 'Ordinal #' + (Get-U16 $Bytes $t)
                } else {
                    $hn = ConvertTo-FileOffset $pe ([int64](Get-U32 $Bytes $t))
                    $fn = if ($hn -ge 0) { Read-AsciiZ $Bytes ($hn + 2) 512 } else { '(bad name pointer)' }
                }
                $list.Add([pscustomobject]@{ Dll = $dll; Function = $fn; Kind = 'Import' })
                $t += $thunkSize
            }
            if ($count -eq 0 -and $t -ge 0) { $list.Add([pscustomobject]@{ Dll = $dll; Function = '(no functions listed)'; Kind = 'Import' }) }
            $off += 20
        }
    }
    # --- delay-load imports ---
    $rva = $pe.Dirs[13][0]
    if ($rva -ne 0) {
        $off = ConvertTo-FileOffset $pe $rva
        $guard = 0
        while ($off -ge 0 -and $off + 32 -le $Bytes.Length -and $guard -lt 2000) {
            $guard++
            $attr = Get-U32 $Bytes $off; $nameRva = Get-U32 $Bytes ($off + 4); $intRva = Get-U32 $Bytes ($off + 16)
            if ($nameRva -eq 0) { break }
            if (($attr -band 1) -eq 0) {
                # old-style descriptor holds virtual addresses, not RVAs
                $nameRva = [int64]$nameRva - [int64]$pe.ImageBase; $intRva = [int64]$intRva - [int64]$pe.ImageBase
            }
            $dll = Read-AsciiZ $Bytes (ConvertTo-FileOffset $pe $nameRva) 256
            $t = ConvertTo-FileOffset $pe $intRva
            $count = 0
            while ($t -ge 0 -and $t + $thunkSize -le $Bytes.Length -and $count -lt 20000) {
                $count++
                $isOrd = ($Bytes[$t + $thunkSize - 1] -band 0x80) -ne 0
                if ($thunkSize -eq 8) { $v = Get-U64 $Bytes $t; $zero = ($v -eq 0) } else { $v = Get-U32 $Bytes $t; $zero = ($v -eq 0) }
                if ($zero) { break }
                if ($isOrd) { $fn = 'Ordinal #' + (Get-U16 $Bytes $t) }
                else {
                    $nr = [int64](Get-U32 $Bytes $t)
                    if (($attr -band 1) -eq 0) { $nr = $nr - [int64]$pe.ImageBase }
                    $hn = ConvertTo-FileOffset $pe $nr
                    $fn = if ($hn -ge 0) { Read-AsciiZ $Bytes ($hn + 2) 512 } else { '(bad name pointer)' }
                }
                $list.Add([pscustomobject]@{ Dll = $dll; Function = $fn; Kind = 'Delay-load' })
                $t += $thunkSize
            }
            $off += 32
        }
    }
    return , $list
}

function Get-PEExports {
    param([byte[]]$Bytes, $pe)
    $list = New-Object System.Collections.Generic.List[object]
    $rva = $pe.Dirs[0][0]; $size = $pe.Dirs[0][1]
    if ($rva -eq 0) { return , $list }
    $off = ConvertTo-FileOffset $pe $rva
    if ($off -lt 0 -or $off + 40 -gt $Bytes.Length) { return , $list }
    $base = Get-U32 $Bytes ($off + 16)
    $nFunc = Get-U32 $Bytes ($off + 20); $nNames = Get-U32 $Bytes ($off + 24)
    $aFunc = ConvertTo-FileOffset $pe (Get-U32 $Bytes ($off + 28))
    $aNames = ConvertTo-FileOffset $pe (Get-U32 $Bytes ($off + 32))
    $aOrd = ConvertTo-FileOffset $pe (Get-U32 $Bytes ($off + 36))
    $named = @{}
    if ($aNames -ge 0 -and $aOrd -ge 0) {
        for ($i = 0; $i -lt [Math]::Min($nNames, 50000); $i++) {
            if ($aNames + $i * 4 + 4 -gt $Bytes.Length) { break }
            $n = Read-AsciiZ $Bytes (ConvertTo-FileOffset $pe (Get-U32 $Bytes ($aNames + $i * 4))) 512
            $idx = Get-U16 $Bytes ($aOrd + $i * 2)
            $named[[int]$idx] = $n
        }
    }
    if ($aFunc -ge 0) {
        for ($i = 0; $i -lt [Math]::Min($nFunc, 50000); $i++) {
            if ($aFunc + $i * 4 + 4 -gt $Bytes.Length) { break }
            $fr = Get-U32 $Bytes ($aFunc + $i * 4)
            if ($fr -eq 0) { continue }
            $name = if ($named.ContainsKey($i)) { $named[$i] } else { '(no name)' }
            $fwd = ''
            if ($fr -ge $rva -and $fr -lt ($rva + $size)) { $fwd = Read-AsciiZ $Bytes (ConvertTo-FileOffset $pe $fr) 256 }
            $list.Add([pscustomobject]@{ Ordinal = $base + $i; Name = $name; ForwardedTo = $fwd })
        }
    }
    return , $list
}

function Get-PEDebugInfo {
    param([byte[]]$Bytes, $pe)
    $rva = $pe.Dirs[6][0]; $size = $pe.Dirs[6][1]
    $res = [ordered]@{ PdbPath = ''; Reproducible = $false }
    if ($rva -eq 0) { return $res }
    $off = ConvertTo-FileOffset $pe $rva
    for ($i = 0; $i -lt [Math]::Min([int]($size / 28), 32); $i++) {
        $e = $off + $i * 28
        if ($e -lt 0 -or $e + 28 -gt $Bytes.Length) { break }
        $type = Get-U32 $Bytes ($e + 12)
        $ptr = Get-U32 $Bytes ($e + 24)
        if ($type -eq 16) { $res.Reproducible = $true }
        if ($type -eq 2 -and $ptr -gt 0 -and $ptr + 24 -lt $Bytes.Length) {
            if ((Get-U32 $Bytes $ptr) -eq 0x53445352) { $res.PdbPath = Read-AsciiZ $Bytes ($ptr + 24) 520 }      # 'RSDS'
            elseif ((Get-U32 $Bytes $ptr) -eq 0x3031424E) { $res.PdbPath = Read-AsciiZ $Bytes ($ptr + 16) 520 }  # 'NB10'
        }
    }
    return $res
}

$script:ResTypeNames = @{
    1 = 'CURSOR'; 2 = 'BITMAP'; 3 = 'ICON'; 4 = 'MENU'; 5 = 'DIALOG'; 6 = 'STRING TABLE'; 7 = 'FONTDIR'; 8 = 'FONT'; 9 = 'ACCELERATOR'
    10 = 'RCDATA'; 11 = 'MESSAGE TABLE'; 12 = 'GROUP_CURSOR'; 14 = 'GROUP_ICON'; 16 = 'VERSION'; 17 = 'DLGINCLUDE'; 19 = 'PLUGPLAY'
    20 = 'VXD'; 21 = 'ANICURSOR'; 22 = 'ANIICON'; 23 = 'HTML'; 24 = 'MANIFEST'; 240 = 'DLGINIT'; 241 = 'TOOLBAR'
}

function Get-PEResources {
    param([byte[]]$Bytes, $pe)
    $list = New-Object System.Collections.Generic.List[object]
    $rva = $pe.Dirs[2][0]
    if ($rva -eq 0) { return , $list }
    $root = ConvertTo-FileOffset $pe $rva
    if ($root -lt 0) { return , $list }
    $readName = {
        param($v)
        if (($v -band 2147483648) -ne 0) { return (Read-UnicodeCounted $Bytes ($root + ($v -band 0x7FFFFFFF))) }
        return [string]$v
    }
    $readDir = {
        param($dirOff)
        $out = @()
        if ($dirOff -lt 0 -or $dirOff + 16 -gt $Bytes.Length) { return $out }
        $n = (Get-U16 $Bytes ($dirOff + 12)) + (Get-U16 $Bytes ($dirOff + 14))
        for ($i = 0; $i -lt [Math]::Min($n, 4000); $i++) {
            $e = $dirOff + 16 + $i * 8
            if ($e + 8 -gt $Bytes.Length) { break }
            $out += , @((Get-U32 $Bytes $e), (Get-U32 $Bytes ($e + 4)))
        }
        return , $out
    }
    foreach ($t in (& $readDir $root)) {
        $typeId = $t[0]
        $typeName = if (($typeId -band 2147483648) -ne 0) { & $readName $typeId } elseif ($script:ResTypeNames.ContainsKey([int]$typeId)) { $script:ResTypeNames[[int]$typeId] } else { "Type $typeId" }
        if (($t[1] -band 2147483648) -eq 0) { continue }
        foreach ($nEnt in (& $readDir ($root + ($t[1] -band 0x7FFFFFFF)))) {
            $name = & $readName $nEnt[0]
            if (($nEnt[1] -band 2147483648) -eq 0) { continue }
            foreach ($l in (& $readDir ($root + ($nEnt[1] -band 0x7FFFFFFF)))) {
                if (($l[1] -band 2147483648) -ne 0) { continue }
                $de = $root + $l[1]
                if ($de + 16 -gt $Bytes.Length) { continue }
                $dRva = Get-U32 $Bytes $de; $dSize = Get-U32 $Bytes ($de + 4)
                $list.Add([pscustomobject]@{
                        Source = 'Native'; TypeId = $typeId; Type = $typeName; Name = $name; Lang = $l[0]
                        Size = $dSize; Offset = (ConvertTo-FileOffset $pe $dRva)
                    })
            }
        }
    }
    return , $list
}

function Get-ResourceBytes {
    param([byte[]]$Bytes, $res)
    if ($res.Offset -lt 0 -or $res.Size -le 0 -or ($res.Offset + $res.Size) -gt $Bytes.Length) { return , (New-Object byte[] 0) }
    $buf = New-Object byte[] $res.Size
    [Array]::Copy($Bytes, [int64]$res.Offset, $buf, 0, [int64]$res.Size)
    return , $buf
}

function Get-StringTableEntries {
    param([byte[]]$Data, [int]$BlockId)
    $out = New-Object System.Collections.Generic.List[object]
    $o = 0
    for ($i = 0; $i -lt 16; $i++) {
        if ($o + 2 -gt $Data.Length) { break }
        $len = Get-U16 $Data $o
        $text = ''
        if ($len -gt 0 -and $o + 2 + $len * 2 -le $Data.Length) { $text = [System.Text.Encoding]::Unicode.GetString($Data, $o + 2, $len * 2) }
        if ($len -gt 0) { $out.Add([pscustomobject]@{ Id = (($BlockId - 1) * 16 + $i); Text = $text }) }
        $o += 2 + $len * 2
    }
    return , $out
}

function Get-MessageTableEntries {
    param([byte[]]$Data)
    $out = New-Object System.Collections.Generic.List[object]
    if ($Data.Length -lt 4) { return , $out }
    $nBlocks = Get-U32 $Data 0
    for ($b = 0; $b -lt [Math]::Min($nBlocks, 5000); $b++) {
        $bo = 4 + $b * 12
        if ($bo + 12 -gt $Data.Length) { break }
        $low = Get-U32 $Data $bo; $high = Get-U32 $Data ($bo + 4); $eo = Get-U32 $Data ($bo + 8)
        for ($id = $low; $id -le $high -and $out.Count -lt 20000; $id++) {
            if ($eo + 4 -gt $Data.Length) { break }
            $len = Get-U16 $Data $eo; $flags = Get-U16 $Data ($eo + 2)
            if ($len -lt 4 -or $eo + $len -gt $Data.Length) { break }
            if ($flags -band 1) { $txt = [System.Text.Encoding]::Unicode.GetString($Data, $eo + 4, $len - 4) }
            else { $txt = $script:Latin1.GetString($Data, $eo + 4, $len - 4) }
            $out.Add([pscustomobject]@{ Id = ('0x{0:X8}' -f $id); Text = $txt.TrimEnd([char]0, "`r", "`n") })
            $eo += $len
        }
    }
    return , $out
}

function Get-ManifestInfo {
    param([string]$Text)
    $info = [ordered]@{ ExecutionLevel = '(not specified - runs as invoker)'; UiAccess = ''; Dependencies = @(); DpiAware = ''; Error = '' }
    if (-not $Text) { $info.ExecutionLevel = '(no manifest)'; return $info }
    try {
        $clean = $Text.Trim([char]0xFEFF, [char]0, ' ', "`r", "`n", "`t")
        $xml = New-Object System.Xml.XmlDocument
        $xml.XmlResolver = $null
        $xml.LoadXml($clean)
        $el = $xml.SelectNodes("//*[local-name()='requestedExecutionLevel']")
        if ($el.Count -gt 0) { $info.ExecutionLevel = $el[0].GetAttribute('level'); $info.UiAccess = $el[0].GetAttribute('uiAccess') }
        $deps = @()
        foreach ($a in $xml.SelectNodes("//*[local-name()='dependentAssembly']/*[local-name()='assemblyIdentity']")) {
            $deps += [pscustomobject]@{ Name = $a.GetAttribute('name'); Version = $a.GetAttribute('version'); Arch = $a.GetAttribute('processorArchitecture'); Token = $a.GetAttribute('publicKeyToken') }
        }
        $info.Dependencies = $deps
        $d = $xml.SelectNodes("//*[local-name()='dpiAware' or local-name()='dpiAwareness']")
        if ($d.Count -gt 0) { $info.DpiAware = $d[0].InnerText }
    } catch { $info.Error = "Manifest XML could not be parsed: $($_.Exception.Message)" }
    return $info
}

# ---------------------------------------------------------------------
#  Strings
# ---------------------------------------------------------------------
$script:StrCategoryRules = @(
    @('URL', '(?i)\b(https?|ftp|ldap|file)://'),
    @('Registry', '(?i)(HKEY_[A-Z_]+|\bHK(LM|CU|CR|U)\b|SOFTWARE\\|SYSTEM\\CurrentControlSet)'),
    @('Path', '(?i)([a-z]:\\|\\\\[a-z0-9_.$-]+\\|%[a-z_]+%\\|^/(opt|usr|etc|var|home)/)'),
    @('IP address', '\b(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'),
    @('SQL', '(?i)\b(select\s.+\sfrom|insert\s+into|update\s+\S+\s+set|delete\s+from|create\s+table)\b'),
    @('File name', '(?i)\.(exe|dll|ini|cfg|conf|config|xml|txt|log|dat|mdb|accdb|db|csv|bat|cmd|ps1|vbs|sys|ocx|json|env|acl|fdf|tmp|bak)\b'),
    @('Error / message', '(?i)(error|fail|unable|cannot|can''t|could not|invalid|denied|not found|exception|missing|warning|timeout|timed out)')
)

function Get-StringCategory {
    param([string]$s)
    if ($s -match 'This program (cannot|must) be run (in DOS mode|under Win32)') { return 'Other' }
    foreach ($r in $script:StrCategoryRules) { if ($s -match $r[1]) { return $r[0] } }
    return 'Other'
}

function Test-NoiseString {
    param([string]$s)
    $good = ([regex]::Matches($s, '[A-Za-z0-9 \\/:._\-%,()]')).Count
    if ($good / $s.Length -lt 0.85) { return $true }
    if ($s -notmatch '[A-Za-z]{3}') { return $true }
    return $false
}

function Get-ExeStrings {
    param([byte[]]$Bytes, [int]$MinLength = 5, [int]$MaxCount = 200000)
    $out = New-Object System.Collections.Generic.List[object]
    $pattern = '[\x20-\x7E\t]{' + $MinLength + ',}'
    $ascii = $script:Latin1.GetString($Bytes)
    foreach ($m in [regex]::Matches($ascii, $pattern)) {
        if ($out.Count -ge $MaxCount) { break }
        $out.Add([pscustomobject]@{ Offset = $m.Index; Encoding = 'ASCII'; Text = $m.Value })
    }
    foreach ($shift in 0, 1) {
        if ($Bytes.Length -lt 2 + $shift) { continue }
        $len = (($Bytes.Length - $shift) -band (-bnot 1))
        $uni = [System.Text.Encoding]::Unicode.GetString($Bytes, $shift, $len)
        foreach ($m in [regex]::Matches($uni, $pattern)) {
            if ($out.Count -ge $MaxCount) { break }
            $out.Add([pscustomobject]@{ Offset = ($m.Index * 2 + $shift); Encoding = 'UTF-16'; Text = $m.Value })
        }
    }
    return , $out
}

function Test-PrintableText {
    param([byte[]]$Data, [int]$Sample = 4096)
    if ($Data.Length -eq 0) { return $false }
    $n = [Math]::Min($Data.Length, $Sample); $ok = 0
    for ($i = 0; $i -lt $n; $i++) { $c = $Data[$i]; if (($c -ge 0x20 -and $c -lt 0x7F) -or $c -eq 9 -or $c -eq 10 -or $c -eq 13 -or $c -ge 0x80) { $ok++ } }
    return ($ok / $n) -ge 0.95
}

function Convert-BytesToText {
    param([byte[]]$Data)
    if ($Data.Length -ge 2 -and $Data[0] -eq 0xFF -and $Data[1] -eq 0xFE) { return [System.Text.Encoding]::Unicode.GetString($Data, 2, $Data.Length - 2) }
    if ($Data.Length -ge 3 -and $Data[0] -eq 0xEF -and $Data[1] -eq 0xBB -and $Data[2] -eq 0xBF) { return [System.Text.Encoding]::UTF8.GetString($Data, 3, $Data.Length - 3) }
    # UTF-16 without BOM: many zero bytes at odd positions
    if ($Data.Length -ge 8) {
        $z = 0; $n = [Math]::Min($Data.Length, 400)
        for ($i = 1; $i -lt $n; $i += 2) { if ($Data[$i] -eq 0) { $z++ } }
        if ($z -gt ($n / 2) * 0.8) { return [System.Text.Encoding]::Unicode.GetString($Data, 0, $Data.Length - ($Data.Length % 2)) }
    }
    return [System.Text.Encoding]::UTF8.GetString($Data)
}

function Format-HexDump {
    param([byte[]]$Data, [int]$Max = 1024)
    $sb = New-Object System.Text.StringBuilder
    $n = [Math]::Min($Data.Length, $Max)
    for ($i = 0; $i -lt $n; $i += 16) {
        $hex = ''; $asc = ''
        for ($j = 0; $j -lt 16; $j++) {
            if ($i + $j -lt $n) { $c = $Data[$i + $j]; $hex += ('{0:X2} ' -f $c); if ($c -ge 0x20 -and $c -lt 0x7F) { $asc += [char]$c } else { $asc += '.' } }
            else { $hex += '   ' }
        }
        [void]$sb.AppendLine(('{0:X8}  {1} {2}' -f $i, $hex, $asc))
    }
    if ($Data.Length -gt $n) { [void]$sb.AppendLine("... ($($Data.Length - $n) more bytes)") }
    return $sb.ToString()
}

# ---------------------------------------------------------------------
#  API categories (for imports and .NET external calls)
# ---------------------------------------------------------------------
$script:ApiRules = @(
    @('Process / launching', '(?i)^(CreateProcess|ShellExecute|WinExec|OpenProcess|TerminateProcess|CreateRemoteThread|ExitProcess|GetExitCodeProcess|CreateJobObject|AssignProcessToJobObject)'),
    @('DLL loading (dynamic)', '(?i)^(LoadLibrary|GetProcAddress|FreeLibrary|LdrLoadDll|GetModuleHandle|SetDllDirectory|AddDllDirectory)'),
    @('INI / profile files', '(?i)^(GetPrivateProfile|WritePrivateProfile|GetProfile|WriteProfile)'),
    @('Registry', '(?i)^(Reg(Open|Create|Query|Set|Delete|Enum|Close|Get|Load|Save|Notify|Connect|Flush|Copy|Rename|Override|Unload|Restore|Replace|Disable|Enable)|SHGetValue|SHSetValue|SHRegGet|SHDeleteKey|SHDeleteValue)'),
    @('Services', '(?i)^(OpenSCManager|CreateService|OpenService|StartService|ControlService|DeleteService|QueryServiceStatus|ChangeServiceConfig|StartServiceCtrlDispatcher|RegisterServiceCtrlHandler)'),
    @('Network shares / mapped drives', '(?i)^(WNet|Net[A-Z]\w*(Share|Use|Server|Wksta|User|Group))'),
    @('Network', '(?i)^(WSA|socket|connect|bind|listen|accept|send|recv|gethostby|getaddrinfo|inet_|htons|ntohs|closesocket|select|Internet|HttpOpen|HttpSend|WinHttp|URLDownload|FtpGet|FtpPut|IcmpSendEcho|GetAdaptersInfo|GetAdaptersAddresses)'),
    @('Device / serial port I/O', '(?i)^(DeviceIoControl|SetCommState|GetCommState|SetCommTimeouts|PurgeComm|ClearCommError|WaitCommEvent|EscapeCommFunction|SetupDi)'),
    @('Files / folders', '(?i)^(CreateFile|ReadFile|WriteFile|DeleteFile|CopyFile|MoveFile|ReplaceFile|FindFirstFile|FindNextFile|GetFileAttributes|SetFileAttributes|CreateDirectory|RemoveDirectory|GetTempPath|GetTempFileName|SetFilePointer|GetFileSize|FlushFileBuffers|LockFile|GetFullPathName|SHFileOperation|SHGetFolderPath|SHGetSpecialFolder|SHGetKnownFolderPath|PathFileExists|GetCurrentDirectory|SetCurrentDirectory|GetLogicalDrives|GetDriveType|GetDiskFreeSpace|GetVolumeInformation|CreateFileMapping|MapViewOfFile|_open|_wopen|fopen|_wfopen)'),
    @('Security / accounts / privileges', '(?i)^(AdjustTokenPrivileges|OpenProcessToken|OpenThreadToken|LookupPrivilege|LogonUser|ImpersonateLoggedOnUser|RevertToSelf|GetTokenInformation|LookupAccount|CheckTokenMembership|AllocateAndInitializeSid|SetSecurityInfo|GetSecurityInfo|SetNamedSecurityInfo|GetNamedSecurityInfo|SetEntriesInAcl|Cred[A-Z]|CryptProtectData|CryptUnprotectData)'),
    @('Crypto / hashing', '(?i)^(Crypt[A-Z]|BCrypt|NCrypt|CertOpen|CertFind|CertGet)'),
    @('COM / OLE / ActiveX', '(?i)^(CoCreateInstance|CoInitialize|CoUninitialize|CoGetClassObject|OleInitialize|CLSIDFromProgID|CLSIDFromString|SysAllocString|VariantInit|VariantClear|DllGetClassObject|CoCreateGuid|SafeArray)'),
    @('Database (ODBC)', '(?i)^(SQLConnect|SQLDriverConnect|SQLExecDirect|SQLPrepare|SQLExecute|SQLFetch|SQLAllocHandle|SQLDisconnect|SQLGetDiagRec)'),
    @('Error handling / crash', '(?i)^(GetLastError|SetLastError|FormatMessage|SetUnhandledExceptionFilter|UnhandledExceptionFilter|RaiseException|RtlUnwind|IsDebuggerPresent|OutputDebugString|ReportEvent|RegisterEventSource|MiniDumpWriteDump|SetErrorMode)'),
    @('Environment / system info', '(?i)^(GetEnvironmentVariable|SetEnvironmentVariable|ExpandEnvironmentStrings|GetComputerName|GetUserName|GetVersion|GetSystemInfo|GetNativeSystemInfo|GetSystemDirectory|GetWindowsDirectory|GetCommandLine|GetStartupInfo|IsWow64Process|GetSystemMetrics|GetModuleFileName)'),
    @('Threads / timing / sync', '(?i)^(CreateThread|Sleep|WaitForSingleObject|WaitForMultipleObjects|CreateMutex|OpenMutex|ReleaseMutex|CreateEvent|SetEvent|ResetEvent|CreateSemaphore|EnterCriticalSection|LeaveCriticalSection|InitializeCriticalSection|SetTimer|KillTimer|GetTickCount|QueryPerformanceCounter|CreateWaitableTimer|TlsAlloc)'),
    @('Windows UI', '(?i)^(CreateWindow|DialogBox|CreateDialog|MessageBox|ShowWindow|SendMessage|PostMessage|GetMessage|PeekMessage|DispatchMessage|DefWindowProc|RegisterClass|FindWindow|SetWindowText|GetDlgItem|EndDialog|LoadIcon|LoadCursor|LoadString|LoadMenu|TrackPopupMenu|InitCommonControls|GetOpenFileName|GetSaveFileName|SHBrowseForFolder|BeginPaint|EndPaint)'),
    @('Memory', '(?i)^(VirtualAlloc|VirtualFree|VirtualProtect|HeapAlloc|HeapFree|HeapCreate|GlobalAlloc|GlobalFree|LocalAlloc|LocalFree|malloc|free|calloc|realloc)')
)
$script:DllCategoryRules = @(
    @('Network', '(?i)^(ws2_32|wsock32|wininet|winhttp|iphlpapi|dnsapi|urlmon|mswsock)\.dll$'),
    @('Network shares / mapped drives', '(?i)^(mpr|netapi32)\.dll$'),
    @('Database (ODBC)', '(?i)^odbc32\.dll$'),
    @('Windows UI', '(?i)^(user32|gdi32|comctl32|comdlg32|uxtheme|gdiplus|mfc\d+u?|msimg32)\.dll$'),
    @('COM / OLE / ActiveX', '(?i)^(ole32|oleaut32|olepro32|combase)\.dll$'),
    @('Crypto / hashing', '(?i)^(crypt32|bcrypt|ncrypt|wintrust)\.dll$'),
    @('C/C++ runtime', '(?i)^(msvcr\d*|msvcp\d*|vcruntime\d*|ucrtbase|api-ms-win-crt-.*|libgcc.*|libstdc\+\+.*)\.dll$'),
    @('Visual Basic 6 runtime', '(?i)^msvbvm\d+\.dll$'),
    @('.NET runtime', '(?i)^mscoree\.dll$')
)

function Get-ApiCategory {
    param([string]$Dll, [string]$Func)
    foreach ($r in $script:ApiRules) { if ($Func -match $r[1]) { return $r[0] } }
    foreach ($r in $script:DllCategoryRules) { if ($Dll -match $r[1]) { return $r[0] } }
    return 'Other'
}

$script:NetNsRules = @(
    @('Process / launching', '^System\.Diagnostics\.(Process|ProcessStartInfo)\b'),
    @('Files / folders', '^System\.IO\.(File|Directory|Path|FileInfo|DirectoryInfo|FileStream|StreamReader|StreamWriter|DriveInfo|FileSystemWatcher)\b'),
    @('Registry', '^Microsoft\.Win32\.Registry'),
    @('Network', '^System\.Net\b|^System\.Web\b|^System\.ServiceModel\b'),
    @('Database', '^System\.Data\b|^Oracle\.|^MySql\.|^Npgsql'),
    @('WMI / management', '^System\.Management\b'),
    @('PowerShell engine', '^System\.Management\.Automation\b'),
    @('Services', '^System\.ServiceProcess\b'),
    @('Serial port / devices', '^System\.IO\.Ports\b'),
    @('Event log', '^System\.Diagnostics\.EventLog'),
    @('Reflection / dynamic loading', '^System\.Reflection\.(Assembly|MethodInfo|Emit)\b|^System\.Activator\b'),
    @('Security / crypto', '^System\.Security\b'),
    @('Windows UI', '^System\.Windows\.Forms\b|^System\.Windows\b|^System\.Drawing\b'),
    @('XML / config', '^System\.Xml\b|^System\.Configuration\b'),
    @('Threads / timing', '^System\.Threading\b|^System\.Timers\b'),
    @('Environment', '^System\.Environment\b'),
    @('Exceptions', 'Exception$|Exception::')
)

function Get-NetCategory {
    param([string]$FullName)
    foreach ($r in $script:NetNsRules) { if ($FullName -match $r[1]) { return $r[0] } }
    return 'Other'
}

# ---------------------------------------------------------------------
#  Dependency resolution (why "X.dll was not found" errors happen)
# ---------------------------------------------------------------------
$script:KnownDllCache = $null
$script:SxsDirCache = $null

function Get-KnownDlls {
    if ($null -ne $script:KnownDllCache) { return $script:KnownDllCache }
    $set = @{}
    foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs', 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32') {
        try {
            $item = Get-ItemProperty -Path $k -ErrorAction Stop
            foreach ($p in $item.PSObject.Properties) { if ($p.Value -is [string] -and $p.Value -like '*.dll') { $set[$p.Value.ToLower()] = $true } }
        } catch { }
    }
    $script:KnownDllCache = $set
    return $set
}

function Get-SystemDirForImage {
    param([bool]$Image64)
    $win = $env:windir
    if (-not $win) { return $null }
    $is64Os = [Environment]::Is64BitOperatingSystem
    $is64Proc = [Environment]::Is64BitProcess
    if ($Image64) {
        if ($is64Proc) { return (Join-Path $win 'System32') }
        if (Test-Path (Join-Path $win 'Sysnative')) { return (Join-Path $win 'Sysnative') }
        return (Join-Path $win 'System32')
    } else {
        if ($is64Os -and $is64Proc) { return (Join-Path $win 'SysWOW64') }
        return (Join-Path $win 'System32')
    }
}

function Get-PEMachineOfFile {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $buf = New-Object byte[] 4096
            $n = $fs.Read($buf, 0, 4096)
        } finally { $fs.Dispose() }
        if ($n -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return $null }
        $l = Get-U32 $buf 0x3C
        if ($l + 6 -gt $n) { return $null }
        return (Get-U16 $buf ($l + 4))
    } catch { return $null }
}

function Find-InSxS {
    param([string]$Dll, [bool]$Image64)
    if ($null -eq $script:SxsDirCache) {
        $script:SxsDirCache = @()
        try {
            $sxs = Join-Path $env:windir 'WinSxS'
            $script:SxsDirCache = @([System.IO.Directory]::GetDirectories($sxs) | Where-Object { $_ -match '(?i)microsoft\.vc\d|common-controls|gdiplus|\.mfc|\.atl|microsoft\.windows\.c\+\+' })
        } catch { }
    }
    $prefix = if ($Image64) { '(?i)\\(amd64|arm64)_' } else { '(?i)\\x86_' }
    foreach ($d in $script:SxsDirCache) {
        if ($d -notmatch $prefix) { continue }
        $p = Join-Path $d $Dll
        if ([System.IO.File]::Exists($p)) { return $p }
    }
    return $null
}

function Resolve-DllLocation {
    param([string]$Dll, [string]$ExeDir, [bool]$Image64, [int]$ImageMachine)
    $lower = $Dll.ToLower()
    # Program hard-codes a full path (e.g. DllImport("C:\ProgramData\Vendor\x.dll")): test that exact path only
    $rooted = ($Dll -match '^[A-Za-z]:[\\/]' -or $Dll -match '^\\\\')
    if (-not $rooted) { try { $rooted = [System.IO.Path]::IsPathRooted($Dll) } catch { $rooted = $false } }
    if ($rooted) {
        $full = [Environment]::ExpandEnvironmentVariables($Dll)
        $exists = $false
        try { $exists = [System.IO.File]::Exists($full) } catch { }
        if (-not $exists) { return [pscustomobject]@{ Status = 'NOT FOUND - program expects it at this exact path (hard-coded)'; Path = $full; IsSystem = $false } }
        $m = Get-PEMachineOfFile $full
        if ($null -ne $m -and $ImageMachine -ne 0 -and $m -ne $ImageMachine) {
            return [pscustomobject]@{ Status = ('WRONG BITNESS - found {0} but EXE needs {1}' -f $script:MachineNames[[int]$m], $script:MachineNames[[int]$ImageMachine]); Path = $full; IsSystem = $false }
        }
        return [pscustomobject]@{ Status = 'OK - found at hard-coded path'; Path = $full; IsSystem = $false }
    }
    $sysDir = Get-SystemDirForImage $Image64
    if ($lower -match '^api-ms-win-crt-') {
        # Windows 10+ always has the Universal C Runtime; Windows 7/8.1/2008R2/2012 need it installed (KB2999226 or a VC++ 2015+ redistributable)
        if ($sysDir -and -not [System.IO.File]::Exists((Join-Path $sysDir 'ucrtbase.dll')) -and -not ($ExeDir -and [System.IO.File]::Exists((Join-Path $ExeDir 'ucrtbase.dll')))) {
            return [pscustomobject]@{ Status = 'NOT FOUND - Universal C Runtime missing (install KB2999226 or the VC++ 2015-2022 redistributable)'; Path = ''; IsSystem = $false }
        }
        return [pscustomobject]@{ Status = 'OK - API set (Universal C Runtime)'; Path = ''; IsSystem = $true }
    }
    if ($lower -match '^(api-ms-win-|ext-ms-)') { return [pscustomobject]@{ Status = 'OK - API set (virtual, provided by Windows)'; Path = '' ; IsSystem = $true } }
    $known = Get-KnownDlls
    $candidates = New-Object System.Collections.Generic.List[object]
    if ($known.ContainsKey($lower) -and $sysDir) { $candidates.Add(@((Join-Path $sysDir $Dll), $true)) }
    if ($ExeDir) { $candidates.Add(@((Join-Path $ExeDir $Dll), $false)) }
    if ($sysDir) { $candidates.Add(@((Join-Path $sysDir $Dll), $true)) }
    if ($env:windir) { $candidates.Add(@((Join-Path (Join-Path $env:windir 'System') $Dll), $true)); $candidates.Add(@((Join-Path $env:windir $Dll), $true)) }
    foreach ($p in ($env:PATH -split ';')) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        try { $candidates.Add(@((Join-Path ([Environment]::ExpandEnvironmentVariables($p.Trim('"'))) $Dll), $false)) } catch { }
    }
    foreach ($c in $candidates) {
        if ([System.IO.File]::Exists($c[0])) {
            $m = Get-PEMachineOfFile $c[0]
            $isSys = $c[1]
            if ($null -ne $m -and $ImageMachine -ne 0 -and $m -ne $ImageMachine -and -not $isSys) {
                return [pscustomobject]@{ Status = ('WRONG BITNESS - found {0} but EXE needs {1}' -f $script:MachineNames[[int]$m], $script:MachineNames[[int]$ImageMachine]); Path = $c[0]; IsSystem = $false }
            }
            return [pscustomobject]@{ Status = 'OK - found'; Path = $c[0]; IsSystem = $isSys }
        }
    }
    $sx = Find-InSxS $Dll $Image64
    if ($sx) { return [pscustomobject]@{ Status = 'OK - side-by-side (WinSxS) assembly'; Path = $sx; IsSystem = $true } }
    $hint = ''
    $bits = if ($Image64) { 'x64' } else { 'x86' }
    if ($lower -match '^(msvcr|msvcp|mfc|mfcm|vcomp|vccorlib|atl)(\d{2,3})u?d?\.dll$' -or $lower -match '^(vcruntime|concrt)(140)(_1)?\.dll$') {
        $year = switch ($Matches[2]) { '71' { '2003' } '70' { '2002' } '80' { '2005' } '90' { '2008' } '100' { '2010' } '110' { '2012' } '120' { '2013' } '140' { '2015-2022' } default { '' } }
        if ($year) { $hint = " - install Microsoft Visual C++ $year Redistributable ($bits)" }
        if ($lower -match 'd\.dll$') { $hint = ' - DEBUG runtime: the program was built in Debug mode and only runs where Visual Studio is installed' }
    } elseif ($lower -eq 'msvbvm60.dll') { $hint = ' - Visual Basic 6 runtime missing' }
    elseif ($lower -eq 'mscoree.dll') { $hint = ' - .NET Framework is not installed' }
    return [pscustomobject]@{ Status = ('NOT FOUND' + $hint); Path = ''; IsSystem = $false }
}

function Get-DependencyReport {
    # Returns one row per DLL. Recurses into DLLs that are NOT Windows system DLLs.
    param([string]$ExePath, $Imports, $pe, [bool]$Recursive = $true, [int]$MaxDepth = 3, $ExtraDlls = @())
    $exeDir = Split-Path -Parent $ExePath
    $rows = [ordered]@{}
    $queue = New-Object System.Collections.Generic.Queue[object]
    $byDll = @{}
    foreach ($i in $Imports) { $k = $i.Dll.ToLower(); if (-not $byDll.ContainsKey($k)) { $byDll[$k] = @($i.Dll, (New-Object System.Collections.Generic.List[object]), $i.Kind) }; $byDll[$k][1].Add($i) }
    foreach ($k in $byDll.Keys) { $queue.Enqueue(@($byDll[$k][0], (Split-Path -Leaf $ExePath), 1, $byDll[$k][1].Count, $byDll[$k][2])) }
    foreach ($x in $ExtraDlls) { $queue.Enqueue(@($x.Dll, ((Split-Path -Leaf $ExePath) + ' (P/Invoke)'), 1, $x.Count, 'P/Invoke')) }
    $img64 = [bool]$pe.Is64
    $machine = [int]$pe.Machine
    if ($pe.IsDotNet -and $pe.ClrAnyCpu) { $machine = 0 }  # AnyCPU: either bitness is acceptable for its own dependencies
    while ($queue.Count -gt 0) {
        $q = $queue.Dequeue()
        $dll = [string]$q[0]; $by = $q[1]; $depth = $q[2]
        if ([string]::IsNullOrWhiteSpace($dll)) { continue }
        $key = $dll.ToLower()
        if ($key -notmatch '\.(dll|drv|ocx|sys|exe|cpl)$') { $dll = $dll + '.dll'; $key = $key + '.dll' }
        if ($rows.Contains($key)) {
            if ($rows[$key].RequiredBy -notlike "*$by*") { $rows[$key].RequiredBy += ", $by" }
            continue
        }
        $r = Resolve-DllLocation $dll $exeDir $img64 $machine
        $row = [pscustomobject]@{ Dll = $dll; Status = $r.Status; Path = $r.Path; RequiredBy = $by; Functions = $q[3]; Kind = $q[4]; Level = $depth }
        $rows[$key] = $row
        if ($Recursive -and $depth -lt $MaxDepth -and $r.Path -and -not $r.IsSystem -and $r.Status -like 'OK*') {
            try {
                $b2 = Read-FileBytesShared $r.Path
                $pe2 = Get-PEInfo $b2
                if ($pe2.Valid) {
                    $imp2 = Get-PEImports $b2 $pe2
                    $g = @{}
                    foreach ($i in $imp2) { $k2 = $i.Dll.ToLower(); if (-not $g.ContainsKey($k2)) { $g[$k2] = @($i.Dll, 0, $i.Kind) }; $g[$k2][1]++ }
                    foreach ($k2 in $g.Keys) { $queue.Enqueue(@($g[$k2][0], $dll, $depth + 1, $g[$k2][1], $g[$k2][2])) }
                }
            } catch { }
        }
    }
    return , @($rows.Values)
}

# ---------------------------------------------------------------------
#  .NET metadata reader (ECMA-335 partition II, section 24)
# ---------------------------------------------------------------------
# Column codes: 1/2/4 fixed size, S string heap, G guid heap, B blob heap, T<n> table index, C<name> coded index
$script:MdSchema = @{
    0x00 = '2 S G G G'; 0x01 = 'CResolutionScope S S'; 0x02 = '4 S S CTypeDefOrRef T4 T6'; 0x03 = 'T4'; 0x04 = '2 S B'
    0x05 = 'T6'; 0x06 = '4 2 2 S B T8'; 0x07 = 'T8'; 0x08 = '2 2 S'; 0x09 = 'T2 CTypeDefOrRef'; 0x0A = 'CMemberRefParent S B'
    0x0B = '2 CHasConstant B'; 0x0C = 'CHasCustomAttribute CCustomAttributeType B'; 0x0D = 'CHasFieldMarshal B'
    0x0E = '2 CHasDeclSecurity B'; 0x0F = '2 4 T2'; 0x10 = '4 T4'; 0x11 = 'B'; 0x12 = 'T2 T20'; 0x13 = 'T20'
    0x14 = '2 S CTypeDefOrRef'; 0x15 = 'T2 T23'; 0x16 = 'T23'; 0x17 = '2 S B'; 0x18 = '2 T6 CHasSemantics'
    0x19 = 'T2 CMethodDefOrRef CMethodDefOrRef'; 0x1A = 'S'; 0x1B = 'B'; 0x1C = '2 CMemberForwarded S T26'; 0x1D = '4 T4'
    0x1E = '4 4'; 0x1F = '4'; 0x20 = '4 2 2 2 2 4 B S S'; 0x21 = '4'; 0x22 = '4 4 4'; 0x23 = '2 2 2 2 4 B S S B'
    0x24 = '4 T35'; 0x25 = '4 4 4 T35'; 0x26 = '4 S B'; 0x27 = '4 4 S S CImplementation'; 0x28 = '4 4 S CImplementation'
    0x29 = 'T2 T2'; 0x2A = '2 2 CTypeOrMethodDef S'; 0x2B = 'CMethodDefOrRef B'; 0x2C = 'T42 CTypeDefOrRef'
}
$script:MdCoded = @{
    TypeDefOrRef = @(2, @(0x02, 0x01, 0x1B)); HasConstant = @(2, @(0x04, 0x08, 0x17))
    HasCustomAttribute = @(5, @(0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B))
    HasFieldMarshal = @(1, @(0x04, 0x08)); HasDeclSecurity = @(2, @(0x02, 0x06, 0x20)); MemberRefParent = @(3, @(0x02, 0x01, 0x1A, 0x06, 0x1B))
    HasSemantics = @(1, @(0x14, 0x17)); MethodDefOrRef = @(1, @(0x06, 0x0A)); MemberForwarded = @(1, @(0x04, 0x06))
    Implementation = @(2, @(0x26, 0x23, 0x27)); CustomAttributeType = @(3, @(-1, -1, 0x06, 0x0A, -1))
    ResolutionScope = @(2, @(0x00, 0x1A, 0x23, 0x01)); TypeOrMethodDef = @(1, @(0x02, 0x06))
}

function Read-CompressedUInt {
    # returns @(value, bytesUsed)
    param($b, [int64]$o)
    $x = $b[$o]
    if (($x -band 0x80) -eq 0) { return @([int64]$x, 1) }
    if (($x -band 0xC0) -eq 0x80) { return @([int64](($x -band 0x3F) * 256 + $b[$o + 1]), 2) }
    return @([int64](($x -band 0x1F) * 16777216 + $b[$o + 1] * 65536 + $b[$o + 2] * 256 + $b[$o + 3]), 4)
}

function Read-DotNetMetadata {
    param([byte[]]$Bytes, $pe)
    $md = @{ Valid = $false; Error = '' }
    try {
        $cli = ConvertTo-FileOffset $pe $pe.Dirs[14][0]
        if ($cli -lt 0) { $md.Error = 'CLR header not readable'; return $md }
        $md.RuntimeHeader = '{0}.{1}' -f (Get-U16 $Bytes ($cli + 4)), (Get-U16 $Bytes ($cli + 6))
        $metaRva = Get-U32 $Bytes ($cli + 8)
        $md.Flags = Get-U32 $Bytes ($cli + 16)
        $md.EntryPointToken = Get-U32 $Bytes ($cli + 20)
        $md.ResourcesRva = Get-U32 $Bytes ($cli + 24); $md.ResourcesSize = Get-U32 $Bytes ($cli + 28)
        $md.ILOnly = [bool]($md.Flags -band 1)
        $md.Requires32 = [bool]($md.Flags -band 2)
        $md.Prefers32 = [bool]($md.Flags -band 0x20000)
        $md.StrongNamed = [bool]($md.Flags -band 8)
        $md.NativeEntry = [bool]($md.Flags -band 0x10)
        $root = ConvertTo-FileOffset $pe $metaRva
        if ($root -lt 0 -or (Get-U32 $Bytes $root) -ne 0x424A5342) { $md.Error = 'Metadata signature missing (obfuscated or damaged assembly)'; return $md }
        $vlen = Get-U32 $Bytes ($root + 12)
        $md.MetadataVersion = (Read-AsciiZ $Bytes ($root + 16) ([int]$vlen)).Trim()
        $p = $root + 16 + $vlen
        $nStreams = Get-U16 $Bytes ($p + 2)
        $p += 4
        $md.Streams = @{}
        for ($i = 0; $i -lt $nStreams; $i++) {
            $sOff = Get-U32 $Bytes $p; $sSize = Get-U32 $Bytes ($p + 4)
            $name = Read-AsciiZ $Bytes ($p + 8) 32
            $md.Streams[$name] = @(($root + $sOff), $sSize)
            $p += 8 + ([Math]::Floor(($name.Length + 1 + 3) / 4) * 4)
        }
        $tblKey = if ($md.Streams.ContainsKey('#~')) { '#~' } elseif ($md.Streams.ContainsKey('#-')) { '#-' } else { $null }
        if (-not $tblKey) { $md.Error = 'No metadata table stream'; return $md }
        $md.StringsOff = if ($md.Streams.ContainsKey('#Strings')) { $md.Streams['#Strings'][0] } else { -1 }
        $md.USOff = if ($md.Streams.ContainsKey('#US')) { $md.Streams['#US'][0] } else { -1 }
        $md.USSize = if ($md.Streams.ContainsKey('#US')) { $md.Streams['#US'][1] } else { 0 }
        $md.BlobOff = if ($md.Streams.ContainsKey('#Blob')) { $md.Streams['#Blob'][0] } else { -1 }
        $md.StringsSize = if ($md.Streams.ContainsKey('#Strings')) { $md.Streams['#Strings'][1] } else { 0 }
        $md.BlobSize = if ($md.Streams.ContainsKey('#Blob')) { $md.Streams['#Blob'][1] } else { 0 }
        foreach ($sk in @($md.Streams.Keys)) {
            $sv = $md.Streams[$sk]
            if ($sv[0] -lt 0 -or ($sv[0] + $sv[1]) -gt $Bytes.Length) { $md.Error = "Metadata stream $sk points outside the file (damaged or obfuscated)"; return $md }
        }
        $t = $md.Streams[$tblKey][0]
        $heapSizes = $Bytes[$t + 6]
        $valid = Get-U64 $Bytes ($t + 8)
        $rowsAt = $t + 24
        $rowCount = New-Object int[] 64
        for ($i = 0; $i -lt 64; $i++) {
            if (($valid -band ([uint64]1 -shl $i)) -ne 0) { $rowCount[$i] = [int](Get-U32 $Bytes $rowsAt); $rowsAt += 4 }
        }
        if ($heapSizes -band 0x40) { $rowsAt += 4 }
        $md.RowCount = $rowCount
        $strSize = if ($heapSizes -band 1) { 4 } else { 2 }
        $guidSize = if ($heapSizes -band 2) { 4 } else { 2 }
        $blobSize = if ($heapSizes -band 4) { 4 } else { 2 }
        $codedSize = @{}
        foreach ($k in $script:MdCoded.Keys) {
            $bits = $script:MdCoded[$k][0]; $max = 0
            foreach ($tb in $script:MdCoded[$k][1]) { if ($tb -ge 0 -and $rowCount[$tb] -gt $max) { $max = $rowCount[$tb] } }
            $codedSize[$k] = if ($max -lt [Math]::Pow(2, 16 - $bits)) { 2 } else { 4 }
        }
        $md.CodedSize = $codedSize
        $tblEnd = $md.Streams[$tblKey][0] + $md.Streams[$tblKey][1]
        $wanted = @(0x01, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0B, 0x0C, 0x1A, 0x1B, 0x1C, 0x20, 0x23, 0x28, 0x29, 0x2B, 0x05, 0x03, 0x07)   # v8: 0x0B Constant (enum values)
        $md.Tables = @{}
        $pos = $rowsAt
        for ($tb = 0; $tb -le 0x2C; $tb++) {
            if ($rowCount[$tb] -eq 0) { continue }
            if (-not $script:MdSchema.ContainsKey($tb)) { $md.Error = "Unknown metadata table 0x{0:X2}" -f $tb; return $md }
            $cols = $script:MdSchema[$tb].Split(' ')
            $sizes = @()
            foreach ($c in $cols) {
                switch -regex ($c) {
                    '^[124]$' { $sizes += [int]$c; break }
                    '^S$' { $sizes += $strSize; break }
                    '^G$' { $sizes += $guidSize; break }
                    '^B$' { $sizes += $blobSize; break }
                    '^T(\d+)$' { $sizes += $(if ($rowCount[[int]$Matches[1]] -lt 65536) { 2 } else { 4 }); break }
                    '^C(\w+)$' { $sizes += $codedSize[$Matches[1]]; break }
                }
            }
            $rowSize = ($sizes | Measure-Object -Sum).Sum
            if (($pos + [int64]$rowSize * $rowCount[$tb]) -gt $tblEnd -or $rowCount[$tb] -gt 16777215) { $md.Error = ("Metadata table 0x{0:X2} is larger than its stream (damaged or obfuscated)" -f $tb); return $md }
            if ($wanted -contains $tb) {
                $rows = New-Object 'object[]' ($rowCount[$tb] + 1)
                $rp = $pos
                for ($r = 1; $r -le $rowCount[$tb]; $r++) {
                    $vals = New-Object 'int64[]' $sizes.Count
                    $cp = $rp
                    for ($c = 0; $c -lt $sizes.Count; $c++) {
                        $sz = $sizes[$c]
                        if ($sz -eq 2) { $vals[$c] = [BitConverter]::ToUInt16($Bytes, [int]$cp) }
                        elseif ($sz -eq 4) { $vals[$c] = [BitConverter]::ToUInt32($Bytes, [int]$cp) }
                        else { $vals[$c] = $Bytes[$cp] }
                        $cp += $sz
                    }
                    $rows[$r] = $vals
                    $rp += $rowSize
                }
                $md.Tables[$tb] = $rows
            }
            $pos += [int64]$rowSize * $rowCount[$tb]
        }
        $md.Bytes = $Bytes
        $md.PE = $pe
        $md.StrCache = @{}
        # ownership maps: method -> type, field -> type
        $nT = $rowCount[2]; $nM = $rowCount[6]; $nF = $rowCount[4]
        $md.MethodOwner = New-Object int[] ($nM + 2)
        $md.FieldOwner = New-Object int[] ($nF + 2)
        for ($i = 1; $i -le $nT; $i++) {
            $mStart = $md.Tables[2][$i][5]; $mEnd = if ($i -lt $nT) { $md.Tables[2][$i + 1][5] } else { $nM + 1 }
            for ($m = $mStart; $m -lt $mEnd -and $m -le $nM; $m++) { $md.MethodOwner[$m] = $i }
            $fStart = $md.Tables[2][$i][4]; $fEnd = if ($i -lt $nT) { $md.Tables[2][$i + 1][4] } else { $nF + 1 }
            for ($f = $fStart; $f -lt $fEnd -and $f -le $nF; $f++) { $md.FieldOwner[$f] = $i }
        }
        $md.Enclosing = @{}
        if ($rowCount[0x29] -gt 0) { for ($i = 1; $i -le $rowCount[0x29]; $i++) { $md.Enclosing[[int]$md.Tables[0x29][$i][0]] = [int]$md.Tables[0x29][$i][1] } }
        $md.Valid = $true
    } catch { $md.Error = "Metadata parse error: $($_.Exception.Message)" }
    return $md
}

function Get-MdString {
    param($md, [int64]$idx)
    if ($idx -eq 0 -or $md.StringsOff -lt 0) { return '' }
    if ($idx -lt 0 -or $idx -ge $md.StringsSize) { return '?bad-name?' }
    if ($md.StrCache.ContainsKey($idx)) { return $md.StrCache[$idx] }
    $o = $md.StringsOff + $idx
    $end = [Array]::IndexOf($md.Bytes, [byte]0, [int]$o, [int][Math]::Min(4096, $md.StringsOff + $md.StringsSize - $o))
    $s = if ($end -gt $o) { [System.Text.Encoding]::UTF8.GetString($md.Bytes, [int]$o, [int]($end - $o)) } else { '' }
    $md.StrCache[$idx] = $s
    return $s
}

function Get-MdBlob {
    param($md, [int64]$idx)
    if ($md.BlobOff -lt 0 -or $idx -lt 0 -or $idx -ge $md.BlobSize) { return , (New-Object byte[] 0) }
    $o = $md.BlobOff + $idx
    $cu = Read-CompressedUInt $md.Bytes $o
    if (($o + $cu[1] + $cu[0]) -gt ($md.BlobOff + $md.BlobSize)) { return , (New-Object byte[] 0) }
    $buf = New-Object byte[] $cu[0]
    if ($cu[0] -gt 0) { [Array]::Copy($md.Bytes, $o + $cu[1], $buf, 0, $cu[0]) }
    return , $buf
}

function Get-MdUserString {
    param($md, [int64]$off)
    if ($md.USOff -lt 0 -or $off -ge $md.USSize) { return '' }
    $o = $md.USOff + $off
    $cu = Read-CompressedUInt $md.Bytes $o
    $len = $cu[0] - 1
    if ($len -le 0 -or ($off + $cu[1] + $len) -gt $md.USSize) { return '' }
    return [System.Text.Encoding]::Unicode.GetString($md.Bytes, [int]($o + $cu[1]), [int]($len - ($len % 2)))
}

function Get-AllUserStrings {
    param($md)
    $out = New-Object System.Collections.Generic.List[object]
    if ($md.USOff -lt 0) { return , $out }
    $p = 1
    while ($p -lt $md.USSize) {
        $cu = Read-CompressedUInt $md.Bytes ($md.USOff + $p)
        if ($cu[0] -eq 0) { $p += 1; continue }
        $len = $cu[0] - 1
        if (($p + $cu[1] + $cu[0]) -gt $md.USSize) { break }
        if ($len -gt 0) {
            $s = [System.Text.Encoding]::Unicode.GetString($md.Bytes, [int]($md.USOff + $p + $cu[1]), [int]($len - ($len % 2)))
            $out.Add([pscustomobject]@{ Token = (0x70000000 + $p); Text = $s })
        }
        $p += $cu[1] + $cu[0]
    }
    return , $out
}

function Resolve-Coded {
    param([string]$Kind, [int64]$v)
    $bits = $script:MdCoded[$Kind][0]
    $tag = $v -band ([int][Math]::Pow(2, $bits) - 1)
    $tables = $script:MdCoded[$Kind][1]
    if ($tag -ge $tables.Count) { return @(-1, 0) }
    return @($tables[$tag], ($v -shr $bits))
}

function Get-MdTypeDefName {
    param($md, [int]$rid)
    if ($rid -le 0 -or $rid -gt $md.RowCount[2]) { return '?' }
    $r = $md.Tables[2][$rid]
    $n = Get-MdString $md $r[1]; $ns = Get-MdString $md $r[2]
    if ($md.Enclosing.ContainsKey($rid)) { return (Get-MdTypeDefName $md $md.Enclosing[$rid]) + '+' + $n }
    if ($ns) { return "$ns.$n" }
    return $n
}

function Get-MdTypeRefName {
    param($md, [int]$rid)
    if ($rid -le 0 -or $rid -gt $md.RowCount[1]) { return '?' }
    $r = $md.Tables[1][$rid]
    $n = Get-MdString $md $r[1]; $ns = Get-MdString $md $r[2]
    $scope = Resolve-Coded 'ResolutionScope' $r[0]
    if ($scope[0] -eq 0x01 -and $scope[1] -gt 0 -and $scope[1] -ne $rid) { return (Get-MdTypeRefName $md $scope[1]) + '+' + $n }
    if ($ns) { return "$ns.$n" }
    return $n
}

$script:ElemNames = @{ 0x01 = 'void'; 0x02 = 'bool'; 0x03 = 'char'; 0x04 = 'sbyte'; 0x05 = 'byte'; 0x06 = 'short'; 0x07 = 'ushort'; 0x08 = 'int'; 0x09 = 'uint'; 0x0A = 'long'; 0x0B = 'ulong'; 0x0C = 'float'; 0x0D = 'double'; 0x0E = 'string'; 0x16 = 'TypedReference'; 0x18 = 'IntPtr'; 0x19 = 'UIntPtr'; 0x1C = 'object' }

function Read-SigType {
    # $st = @{ B = bytes; P = position }
    param($md, $st)
    $b = $st.B
    if ($st.P -ge $b.Length) { return '?' }
    $e = $b[$st.P]; $st.P++
    if ($script:ElemNames.ContainsKey([int]$e)) { return $script:ElemNames[[int]$e] }
    switch ($e) {
        0x0F { return (Read-SigType $md $st) + '*' }
        0x10 { return (Read-SigType $md $st) + '&' }
        { $_ -eq 0x11 -or $_ -eq 0x12 } {
            $cu = Read-CompressedUInt $b $st.P; $st.P += $cu[1]
            return (Get-MdTypeDefOrRefName $md $cu[0])
        }
        0x13 { $cu = Read-CompressedUInt $b $st.P; $st.P += $cu[1]; return "!$($cu[0])" }
        0x1E { $cu = Read-CompressedUInt $b $st.P; $st.P += $cu[1]; return "!!$($cu[0])" }
        0x14 {
            $t = Read-SigType $md $st
            $rank = Read-CompressedUInt $b $st.P; $st.P += $rank[1]
            $ns = Read-CompressedUInt $b $st.P; $st.P += $ns[1]
            for ($i = 0; $i -lt $ns[0]; $i++) { $x = Read-CompressedUInt $b $st.P; $st.P += $x[1] }
            $nl = Read-CompressedUInt $b $st.P; $st.P += $nl[1]
            for ($i = 0; $i -lt $nl[0]; $i++) { $x = Read-CompressedUInt $b $st.P; $st.P += $x[1] }
            return $t + '[' + (',' * [Math]::Max(0, $rank[0] - 1)) + ']'
        }
        0x15 {
            $t = Read-SigType $md $st
            $n = Read-CompressedUInt $b $st.P; $st.P += $n[1]
            $args2 = @(); for ($i = 0; $i -lt $n[0]; $i++) { $args2 += (Read-SigType $md $st) }
            $t = $t -replace '`\d+$', ''
            return $t + '<' + ($args2 -join ', ') + '>'
        }
        0x1B { return 'method*' }
        0x1D { return (Read-SigType $md $st) + '[]' }
        { $_ -eq 0x1F -or $_ -eq 0x20 } { $cu = Read-CompressedUInt $b $st.P; $st.P += $cu[1]; return (Read-SigType $md $st) }
        0x41 { return (Read-SigType $md $st) }
        0x45 { return (Read-SigType $md $st) }
        default { return ('?0x{0:X2}' -f $e) }
    }
}

function Get-MdTypeDefOrRefName {
    param($md, [int64]$encoded)
    $tbl = $encoded -band 3; $rid = [int]($encoded -shr 2)
    if ($tbl -eq 0) { return Get-MdTypeDefName $md $rid }
    if ($tbl -eq 1) { return Get-MdTypeRefName $md $rid }
    if ($tbl -eq 2) { return Get-MdTypeSpecName $md $rid }
    return '?'
}

function Get-MdTypeSpecName {
    param($md, [int]$rid)
    if ($rid -le 0 -or $rid -gt $md.RowCount[0x1B]) { return '?' }
    try { $st = @{ B = (Get-MdBlob $md $md.Tables[0x1B][$rid][0]); P = 0 }; return (Read-SigType $md $st) } catch { return 'TypeSpec' }
}

function Format-MethodSig {
    param($md, [byte[]]$Sig, [string[]]$ParamNames = $null)
    try {
        $st = @{ B = $Sig; P = 0 }
        $cc = $Sig[0]; $st.P = 1
        if ($cc -band 0x10) { $g = Read-CompressedUInt $Sig $st.P; $st.P += $g[1] }
        $n = Read-CompressedUInt $Sig $st.P; $st.P += $n[1]
        $ret = Read-SigType $md $st
        $ps = @()
        for ($i = 0; $i -lt $n[0]; $i++) {
            $t = Read-SigType $md $st
            if ($ParamNames -and $i -lt $ParamNames.Count -and $ParamNames[$i]) { $t = "$t $($ParamNames[$i])" }
            $ps += $t
        }
        return @(('(' + ($ps -join ', ') + ')'), $ret, [bool]($cc -band 0x20))
    } catch { return @('(...)', '?', $false) }
}

function Get-MdParamNames {
    param($md, [int]$rid)
    $nM = $md.RowCount[6]; $nP = $md.RowCount[8]
    if ($nP -eq 0) { return @() }
    $start = $md.Tables[6][$rid][5]
    $end = if ($rid -lt $nM) { $md.Tables[6][$rid + 1][5] } else { $nP + 1 }
    $names = @{}
    $maxSeq = 0
    for ($p = $start; $p -lt $end -and $p -le $nP; $p++) {
        $seq = [int]$md.Tables[8][$p][1]
        if ($seq -gt 0) { $names[$seq] = Get-MdString $md $md.Tables[8][$p][2]; if ($seq -gt $maxSeq) { $maxSeq = $seq } }
    }
    $arr = @(); for ($i = 1; $i -le $maxSeq; $i++) { $arr += $(if ($names.ContainsKey($i)) { $names[$i] } else { '' }) }
    return $arr
}

function Get-MdMethodDefName {
    param($md, [int]$rid, [switch]$WithSig)
    if ($rid -le 0 -or $rid -gt $md.RowCount[6]) { return '?' }
    $owner = Get-MdTypeDefName $md $md.MethodOwner[$rid]
    $name = Get-MdString $md $md.Tables[6][$rid][3]
    if ($WithSig) {
        $sig = Format-MethodSig $md (Get-MdBlob $md $md.Tables[6][$rid][4]) (Get-MdParamNames $md $rid)
        return "$owner::$name$($sig[0]) : $($sig[1])"
    }
    return "$owner::$name"
}

function Get-MdMemberRefName {
    param($md, [int]$rid, [switch]$WithSig)
    if ($rid -le 0 -or $rid -gt $md.RowCount[0x0A]) { return '?' }
    $r = $md.Tables[0x0A][$rid]
    $par = Resolve-Coded 'MemberRefParent' $r[0]
    $pn = switch ($par[0]) {
        0x02 { Get-MdTypeDefName $md $par[1] }
        0x01 { Get-MdTypeRefName $md $par[1] }
        0x1A { '[' + (Get-MdString $md $md.Tables[0x1A][$par[1]][0]) + ']' }
        0x06 { Get-MdMethodDefName $md $par[1] }
        0x1B { Get-MdTypeSpecName $md $par[1] }
        default { '?' }
    }
    $name = Get-MdString $md $r[1]
    if ($WithSig) {
        $blob = Get-MdBlob $md $r[2]
        if ($blob.Length -gt 0 -and $blob[0] -eq 0x06) {
            $st = @{ B = $blob; P = 1 }
            return "$pn::$name : $(Read-SigType $md $st)"
        }
        $sig = Format-MethodSig $md $blob
        return "$pn::$name$($sig[0]) : $($sig[1])"
    }
    return "$pn::$name"
}

function Get-MdFieldName {
    param($md, [int]$rid)
    if ($rid -le 0 -or $rid -gt $md.RowCount[4]) { return '?' }
    return (Get-MdTypeDefName $md $md.FieldOwner[$rid]) + '::' + (Get-MdString $md $md.Tables[4][$rid][1])
}

function Resolve-MdToken {
    param($md, [int64]$tok)
    $tbl = [int]($tok -shr 24); $rid = [int]($tok -band 0xFFFFFF)
    switch ($tbl) {
        0x70 { $s = Get-MdUserString $md $rid; $s = $s.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t'); return '"' + $s + '"' }
        0x06 { return Get-MdMethodDefName $md $rid -WithSig }
        0x0A { return Get-MdMemberRefName $md $rid -WithSig }
        0x04 { return Get-MdFieldName $md $rid }
        0x01 { return Get-MdTypeRefName $md $rid }
        0x02 { return Get-MdTypeDefName $md $rid }
        0x1B { return Get-MdTypeSpecName $md $rid }
        0x2B {
            $r = $md.Tables[0x2B][$rid]; $m = Resolve-Coded 'MethodDefOrRef' $r[0]
            $base = if ($m[0] -eq 0x06) { Get-MdMethodDefName $md $m[1] -WithSig } else { Get-MdMemberRefName $md $m[1] -WithSig }
            return "$base  [generic instance]"
        }
        0x11 { return "signature 0x{0:X8}" -f $tok }
        default { return "token 0x{0:X8}" -f $tok }
    }
}

$script:OpOne = $null; $script:OpTwo = $null
function Initialize-OpCodes {
    if ($null -ne $script:OpOne) { return }
    $script:OpOne = @{}; $script:OpTwo = @{}
    foreach ($f in [System.Reflection.Emit.OpCodes].GetFields([System.Reflection.BindingFlags]'Public,Static')) {
        $op = $f.GetValue($null)
        $v = [int]($op.Value -band 0xFFFF)
        if ($op.Size -eq 1) { $script:OpOne[$v] = $op } else { $script:OpTwo[$v -band 0xFF] = $op }
    }
}

function Get-MethodBody {
    # returns @(codeOffsetInFile, codeSize) or $null
    param($md, [int]$rid)
    $rva = $md.Tables[6][$rid][0]
    if ($rva -eq 0) { return $null }
    $o = ConvertTo-FileOffset $md.PE $rva
    if ($o -lt 0) { return $null }
    $b = $md.Bytes
    $h = $b[$o]
    if (($h -band 3) -eq 2) { return @(($o + 1), ($h -shr 2), 8) }
    if (($h -band 3) -eq 3) {
        $hsize = ($b[$o + 1] -shr 4) * 4
        $maxStack = Get-U16 $b ($o + 2)
        $size = Get-U32 $b ($o + 4)
        return @(($o + $hsize), $size, $maxStack)
    }
    return $null
}

function Get-ILInstructions {
    # Decodes one method body. Returns list of objects: Offset, Name, OperandType, Operand(int64/double/array)
    param($md, [int]$rid)
    Initialize-OpCodes
    $list = New-Object System.Collections.Generic.List[object]
    $body = Get-MethodBody $md $rid
    if ($null -eq $body) { return , $list }
    $b = $md.Bytes; $start = $body[0]; $end = $body[0] + $body[1]
    if ($end -gt $b.Length) { return , $list }
    $p = $start
    while ($p -lt $end) {
        $ilOff = $p - $start
        $c = $b[$p]; $p++
        if ($c -eq 0xFE) { $op = $script:OpTwo[[int]$b[$p]]; $p++ } else { $op = $script:OpOne[[int]$c] }
        if ($null -eq $op) { $list.Add([pscustomobject]@{ Offset = $ilOff; Name = ('??0x{0:X2}' -f $c); OperandType = 'InlineNone'; Operand = $null; Next = $p - $start }); continue }
        $ot = $op.OperandType.ToString()
        $operand = $null
        switch ($ot) {
            'InlineNone' { }
            { $_ -in 'ShortInlineBrTarget', 'ShortInlineI' } { $operand = [int][sbyte]$(if ($b[$p] -gt 127) { $b[$p] - 256 } else { $b[$p] }); $p += 1 }
            'ShortInlineVar' { $operand = [int]$b[$p]; $p += 1 }
            'InlineVar' { $operand = Get-U16 $b $p; $p += 2 }
            { $_ -in 'InlineI', 'InlineBrTarget' } { $operand = [BitConverter]::ToInt32($b, [int]$p); $p += 4 }
            'ShortInlineR' { $operand = [BitConverter]::ToSingle($b, [int]$p); $p += 4 }
            'InlineI8' { $operand = [BitConverter]::ToInt64($b, [int]$p); $p += 8 }
            'InlineR' { $operand = [BitConverter]::ToDouble($b, [int]$p); $p += 8 }
            'InlineSwitch' {
                $n = Get-U32 $b $p; $p += 4
                $arr = @(); for ($i = 0; $i -lt [Math]::Min($n, 10000); $i++) { $arr += [BitConverter]::ToInt32($b, [int]$p); $p += 4 }
                $operand = $arr
            }
            default { $operand = Get-U32 $b $p; $p += 4 }   # tokens: Method, Field, Type, Tok, String, Sig
        }
        $list.Add([pscustomobject]@{ Offset = $ilOff; Name = $op.Name; OperandType = $ot; Operand = $operand; Next = $p - $start })
    }
    return , $list
}

function Format-ILListing {
    param($md, [int]$rid)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('// ' + (Get-MdMethodDefName $md $rid -WithSig))
    $flags = $md.Tables[6][$rid][2]; $impl = $md.Tables[6][$rid][1]
    $attrs = @()
    if ($flags -band 0x10) { $attrs += 'static' }
    if ($flags -band 0x40) { $attrs += 'virtual' }
    if ($flags -band 0x400) { $attrs += 'abstract' }
    if ($flags -band 0x2000) { $attrs += 'P/Invoke (native DLL call)' }
    switch ($flags -band 7) { 1 { $attrs += 'private' } 3 { $attrs += 'internal' } 6 { $attrs += 'public' } 4 { $attrs += 'protected' } }
    if ($attrs) { [void]$sb.AppendLine('// ' + ($attrs -join ', ')) }
    if (($md.EntryPointToken -band 0xFFFFFF) -eq $rid -and ($md.EntryPointToken -shr 24) -eq 6) { [void]$sb.AppendLine('// >>> PROGRAM ENTRY POINT - execution starts here <<<') }
    if ($flags -band 0x2000) {
        foreach ($im in (Get-PInvokeList $md)) { if ($im.MethodRid -eq $rid) { [void]$sb.AppendLine("// calls native: $($im.Dll) ! $($im.Function)") } }
        return $sb.ToString()
    }
    $body = Get-MethodBody $md $rid
    if ($null -eq $body) { [void]$sb.AppendLine('// (no IL body - abstract, extern, or runtime-implemented)'); return $sb.ToString() }
    [void]$sb.AppendLine("// code size: $($body[1]) bytes")
    [void]$sb.AppendLine('')
    $insList = Get-ILInstructions $md $rid
    $ilAnn = @{}; try { $ilAnn = Get-ILEnumAnnotations $md $insList } catch { }      # v8 (F19)
    $ilEh = $null; try { $ilEh = Get-MethodEHClauses $md $rid } catch { }            # v8 (F19)
    foreach ($ins in $insList) {
        if ($ilEh -and $ilEh.Count -gt 0) { foreach ($mk in (Get-EHMarkers $ilEh ([int]$ins.Offset) 'before')) { [void]$sb.AppendLine($mk) } }
        $txt = ''
        switch -regex ($ins.OperandType) {
            '^(ShortInlineBrTarget|InlineBrTarget)$' { $txt = 'IL_{0:X4}' -f ($ins.Next + $ins.Operand) }
            '^InlineSwitch$' { $txt = '(' + (($ins.Operand | ForEach-Object { 'IL_{0:X4}' -f ($ins.Next + $_) }) -join ', ') + ')' }
            '^(InlineMethod|InlineField|InlineType|InlineTok|InlineString|InlineSig)$' { $txt = Resolve-MdToken $md $ins.Operand }
            '^InlineNone$' { $txt = '' }
            default { $txt = [string]$ins.Operand }
        }
        $line = ('  IL_{0:X4}:  {1,-12} {2}' -f $ins.Offset, $ins.Name, $txt).TrimEnd()
        if ($ins.Name -in 'call', 'callvirt', 'newobj') {
            $cat = Get-NetCategory $txt; if ($cat -notin 'Other', 'Exceptions', 'Threads / timing', 'XML / config', 'Windows UI') { $line += '    <-- ' + $cat }
        }
        if ($ins.Name -eq 'throw') { $line += '    <-- raises an exception' }
        if ($ilAnn.ContainsKey([int]$ins.Offset)) { $line += '    // = ' + $ilAnn[[int]$ins.Offset] }
        [void]$sb.AppendLine($line)
        if ($ilEh -and $ilEh.Count -gt 0) { foreach ($mk in (Get-EHMarkers $ilEh ([int]$ins.Next) 'after')) { [void]$sb.AppendLine($mk) } }
    }
    return $sb.ToString()
}

function Find-TokenUsage {
    # Which methods reference this metadata token (string literal, member ref, method)?
    param($md, [int64]$Token, [int]$Max = 500)
    $hits = New-Object System.Collections.Generic.List[string]
    for ($m = 1; $m -le $md.RowCount[6]; $m++) {
        $found = $false
        foreach ($ins in (Get-ILInstructions $md $m)) {
            if ($ins.OperandType -match '^(InlineMethod|InlineField|InlineType|InlineTok|InlineString)$' -and $ins.Operand -eq $Token) { $found = $true; break }
        }
        if ($found) { $hits.Add((Get-MdMethodDefName $md $m)); if ($hits.Count -ge $Max) { break } }
    }
    return , $hits
}

function Get-PInvokeList {
    param($md)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -le $md.RowCount[0x1C]; $i++) {
        $r = $md.Tables[0x1C][$i]
        $fwd = Resolve-Coded 'MemberForwarded' $r[1]
        $dll = Get-MdString $md $md.Tables[0x1A][$r[3]][0]
        $out.Add([pscustomobject]@{ Dll = $dll; Function = (Get-MdString $md $r[2]); Managed = $(if ($fwd[0] -eq 0x06) { Get-MdMethodDefName $md $fwd[1] } else { '?' }); MethodRid = $(if ($fwd[0] -eq 0x06) { $fwd[1] } else { 0 }) })
    }
    return , $out
}

function Get-AssemblyRefs {
    param($md)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -le $md.RowCount[0x23]; $i++) {
        $r = $md.Tables[0x23][$i]
        $pk = Get-MdBlob $md $r[5]
        $tok = if ($pk.Length -eq 8) { ($pk | ForEach-Object { '{0:x2}' -f $_ }) -join '' } else { '' }
        $out.Add([pscustomobject]@{ Name = (Get-MdString $md $r[6]); Version = ('{0}.{1}.{2}.{3}' -f $r[0], $r[1], $r[2], $r[3]); PublicKeyToken = $tok })
    }
    return , $out
}

function Get-AssemblyIdentity {
    param($md)
    if ($md.RowCount[0x20] -lt 1) { return '' }
    $r = $md.Tables[0x20][1]
    return ('{0}, Version={1}.{2}.{3}.{4}' -f (Get-MdString $md $r[7]), $r[1], $r[2], $r[3], $r[4])
}

function Get-ManagedResources {
    param($md)
    $out = New-Object System.Collections.Generic.List[object]
    $base = if ($md.ResourcesRva -ne 0) { ConvertTo-FileOffset $md.PE $md.ResourcesRva } else { -1 }
    for ($i = 1; $i -le $md.RowCount[0x28]; $i++) {
        $r = $md.Tables[0x28][$i]
        $name = Get-MdString $md $r[2]
        $impl = Resolve-Coded 'Implementation' $r[3]
        if ($r[3] -ne 0) { $out.Add([pscustomobject]@{ Source = '.NET'; Type = 'linked (external)'; Name = $name; Lang = ''; Size = 0; Offset = -1 }); continue }
        $o = $base + $r[0]
        if ($base -lt 0 -or $o + 4 -gt $md.Bytes.Length) { continue }
        $len = Get-U32 $md.Bytes $o
        $type = if ($name -like '*.resources') { '.resources (key/value)' } else { 'embedded file' }
        $out.Add([pscustomobject]@{ Source = '.NET'; Type = $type; Name = $name; Lang = ''; Size = $len; Offset = ($o + 4) })
    }
    return , $out
}

function Get-TargetFramework {
    param($md)
    for ($i = 1; $i -le $md.RowCount[0x0C]; $i++) {
        $r = $md.Tables[0x0C][$i]
        $ct = Resolve-Coded 'CustomAttributeType' $r[1]
        if ($ct[0] -ne 0x0A) { continue }
        $mr = $md.Tables[0x0A][$ct[1]]
        $par = Resolve-Coded 'MemberRefParent' $mr[0]
        if ($par[0] -ne 0x01) { continue }
        if ((Get-MdString $md $md.Tables[1][$par[1]][1]) -ne 'TargetFrameworkAttribute') { continue }
        $v = Get-MdBlob $md $r[2]
        if ($v.Length -gt 3 -and $v[0] -eq 1) {
            $cu = Read-CompressedUInt $v 2
            return [System.Text.Encoding]::UTF8.GetString($v, 2 + $cu[1], $cu[0])
        }
    }
    return ''
}

function Get-DotNetResourceEntries {
    # Lists keys of a .resources blob WITHOUT deserialising objects (safe).
    param([byte[]]$Data)
    $out = New-Object System.Collections.Generic.List[object]
    $ms = New-Object System.IO.MemoryStream(, $Data)
    $rr = $null
    try {
        $rr = New-Object System.Resources.ResourceReader($ms)
        $en = $rr.GetEnumerator()
        $keys = @()
        while ($en.MoveNext()) { $keys += [string]$en.Key }
        foreach ($k in $keys) {
            $type = ''; $raw = $null; $val = ''
            try {
                $rr.GetResourceData($k, [ref]$type, [ref]$raw)
                if ($type -eq 'ResourceTypeCode.String' -and $raw.Length -gt 0) {
                    $cu = 0; $shift = 0; $p = 0
                    do { $x = $raw[$p]; $cu = $cu -bor (($x -band 0x7F) -shl $shift); $shift += 7; $p++ } while (($x -band 0x80) -and $p -lt 5)
                    $val = [System.Text.Encoding]::UTF8.GetString($raw, $p, [Math]::Min($cu, $raw.Length - $p))
                } else { $val = "($($raw.Length) bytes)" }
            } catch { $val = '(unreadable)' }
            $out.Add([pscustomobject]@{ Key = $k; Type = $type; Value = $val })
        }
    } catch {
        $out.Add([pscustomobject]@{ Key = '(error)'; Type = ''; Value = $_.Exception.Message })
    } finally { if ($rr) { $rr.Close() }; $ms.Dispose() }
    return , $out
}

# ---------------------------------------------------------------------
#  PS2EXE / embedded PowerShell recovery (static - the EXE is never run)
# ---------------------------------------------------------------------
function Find-EmbeddedPowerShell {
    param($md, [byte[]]$Bytes, $ManagedResources)
    $res = [ordered]@{ Found = $false; Method = ''; Name = ''; Script = ''; IsPS2EXE = $false; Markers = @() }
    $typeNames = @()
    for ($i = 1; $i -le $md.RowCount[2]; $i++) { $typeNames += (Get-MdTypeDefName $md $i) }
    if ($typeNames -contains 'ModuleNameSpace.MainModule' -or $typeNames -contains 'ModuleNameSpace.MainModuleRawUI') { $res.Markers += 'PS2EXE host classes (ModuleNameSpace.MainModule)'; $res.IsPS2EXE = $true }
    if ($typeNames -match '^ik\.PowerShell\.PS2EXE') { $res.Markers += 'legacy PS2EXE host classes (ik.PowerShell.PS2EXE*)'; $res.IsPS2EXE = $true }
    $refsSma = $false
    foreach ($a in (Get-AssemblyRefs $md)) { if ($a.Name -eq 'System.Management.Automation') { $refsSma = $true } }
    if ($refsSma) { $res.Markers += 'references System.Management.Automation (PowerShell engine)' }
    # 1) Current PS2EXE: script stored as plain UTF-8 manifest resource named <script>.ps1
    foreach ($r in $ManagedResources) {
        if ($r.Name -match '(?i)\.(ps1|psm1|psd1)$' -and $r.Offset -ge 0) {
            $data = Get-ResourceBytes $Bytes $r
            $res.Found = $true; $res.Method = 'Embedded resource (current PS2EXE format)'; $res.Name = $r.Name
            $res.Script = [System.Text.Encoding]::UTF8.GetString($data).TrimStart([char]0xFEFF)
            return $res
        }
    }
    # 2) Legacy PS2EXE: Base64(UTF-8 script) as a string literal in the code
    $best = $null
    foreach ($u in (Get-AllUserStrings $md)) {
        if ($u.Text.Length -lt 40 -or $u.Text -notmatch '^[A-Za-z0-9+/\r\n]+={0,2}$') { continue }
        try {
            $raw = [Convert]::FromBase64String(($u.Text -replace '\s', ''))
            if (-not (Test-PrintableText $raw)) { continue }
            $txt = (Convert-BytesToText $raw)
            if ($null -eq $best -or $txt.Length -gt $best.Length) { $best = $txt }
        } catch { }
    }
    if ($best -and ($refsSma -or $res.IsPS2EXE -or $best -match '(?im)^\s*(param\s*\(|function\s|\$\w+\s*=|Write-|Get-|Set-|Import-|Add-Type)')) {
        $res.Found = $true; $res.Method = 'Base64 string literal (legacy PS2EXE format)'; $res.Name = '(decoded from code)'; $res.Script = $best.TrimStart([char]0xFEFF)
    }
    return $res
}

function Get-ScriptOutline {
    param([string]$Script)
    $o = [ordered]@{ Functions = @(); Steps = @(); Commands = @(); ParseErrors = @() }
    try {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Script, [ref]$tokens, [ref]$errs)
        $o.ParseErrors = @($errs | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" })
        $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $o.Functions = @($funcs | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Line = $_.Extent.StartLineNumber; EndLine = $_.Extent.EndLineNumber } })
        $steps = @()
        if ($ast.ParamBlock) { $steps += [pscustomobject]@{ Line = $ast.ParamBlock.Extent.StartLineNumber; Text = 'param(...)  - script parameters' } }
        foreach ($blk in @($ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) {
            if ($null -eq $blk) { continue }
            foreach ($s in $blk.Statements) {
                if ($s -is [System.Management.Automation.Language.FunctionDefinitionAst]) { continue }
                $first = ($s.Extent.Text -split "`r?`n")[0].Trim()
                if ($first.Length -gt 140) { $first = $first.Substring(0, 137) + '...' }
                $steps += [pscustomobject]@{ Line = $s.Extent.StartLineNumber; Text = $first }
            }
        }
        $o.Steps = $steps
        $cmds = @{}
        foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
            $n = $c.GetCommandName()
            if (-not $n) { $n = ($c.CommandElements[0].Extent.Text) }
            if (-not $cmds.ContainsKey($n)) { $cmds[$n] = @(0, $c.Extent.StartLineNumber) }
            $cmds[$n][0]++
        }
        $o.Commands = @($cmds.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ Name = $_; Count = $cmds[$_][0]; FirstLine = $cmds[$_][1] } })
    } catch { $o.ParseErrors = @("Outline failed: $($_.Exception.Message)") }
    return $o
}

# ---------------------------------------------------------------------
#  Type / packer hints
# ---------------------------------------------------------------------
function Get-ExeHints {
    param([byte[]]$Bytes, $pe, $Imports, [string]$Path)
    $h = New-Object System.Collections.Generic.List[string]
    $secNames = @($pe.Sections | ForEach-Object { $_.Name })
    if ($secNames -match '^UPX') { $h.Add('Packed with UPX - imports/strings are hidden until it runs. Code cannot be inspected statically.') }
    if ($secNames -match '^(\.aspack|\.adata|\.MPRESS|\.themida|\.vmp|\.enigma|\.petite|\.nsp)') { $h.Add('Packed/protected section names found (' + (($secNames -match '^(\.aspack|\.adata|\.MPRESS|\.themida|\.vmp|\.enigma|\.petite|\.nsp)') -join ', ') + ') - static analysis will be limited.') }
    $dlls = @($Imports | ForEach-Object { $_.Dll.ToLower() } | Select-Object -Unique)
    if ($dlls -contains 'msvbvm60.dll' -or $dlls -contains 'msvbvm50.dll') { $h.Add('Visual Basic 5/6 program (needs MSVBVM60.DLL runtime). Its forms and code are compiled; check RCDATA/strings for messages.') }
    $sample = $script:Latin1.GetString($Bytes, 0, [Math]::Min($Bytes.Length, 4MB))
    if ($sample -match 'Nullsoft\.NSIS|NullsoftInst') { $h.Add('NSIS installer (Nullsoft). Real payload is compressed in the overlay.') }
    if ($sample -match 'Inno Setup') { $h.Add('Inno Setup installer. Real payload is compressed in the overlay.') }
    if ($sample -match 'InstallShield') { $h.Add('InstallShield installer/launcher.') }
    if ($sample -match 'AU3!EA06|AutoIt v3') { $h.Add('AutoIt script compiled to EXE (script is embedded, usually compressed).') }
    if ($sample -match 'PyInstaller|_MEIPASS|pyi-windows-manifest') { $h.Add('Python program packed with PyInstaller (Python code is in the overlay archive).') }
    if ($sample -match 'hostfxr' -and -not $pe.IsDotNet) {
        $dll = [System.IO.Path]::ChangeExtension($Path, '.dll')
        if (Test-Path $dll) { $h.Add(".NET (Core/5+) apphost launcher. The real program is '$([System.IO.Path]::GetFileName($dll))' next to it - open that file in this tool to see its code.") }
        else { $h.Add('.NET (Core/5+) apphost launcher - the real program is a .dll next to it, or bundled inside (single-file publish).') }
    }
    if ($sample -match 'Borland|Embarcadero|TPF0') { $h.Add('Delphi / C++Builder program (forms stored as RCDATA resources, look for TPF0).') }
    if ($sample -match 'Go build ID:') { $h.Add('Go (golang) program.') }
    if ($pe.OverlaySize -gt 0) { $h.Add(('Overlay: {0:N0} bytes of extra data appended after the last section (installers, self-extractors and packers keep their payload here).' -f $pe.OverlaySize)) }
    return , $h
}

$script:ExitCodeInfo = @{
    0 = 'Success (exit code 0)'
    1 = 'Generic failure (program-defined meaning)'
    3 = 'abort()/assert() in a C/C++ program, or "path not found" for some tools'
    5 = 'Access denied (Win32 error 5)'
    740 = 'ERROR_ELEVATION_REQUIRED - the EXE needs "Run as administrator"'
    3221225477 = 'STATUS_ACCESS_VIOLATION (0xC0000005) - the program crashed reading/writing invalid memory'
    3221225781 = 'STATUS_DLL_NOT_FOUND (0xC0000135) - a required DLL is missing. See the Imports & DLLs tab'
    3221225785 = 'STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139) - a DLL was found but is the wrong version (missing function)'
    3221225784 = 'STATUS_ORDINAL_NOT_FOUND (0xC0000138) - a DLL is the wrong version (missing function by ordinal)'
    3221225595 = 'STATUS_INVALID_IMAGE_FORMAT (0xC000007B) - usually a 32-bit/64-bit mismatch between the EXE and a DLL'
    3221225794 = 'STATUS_DLL_INIT_FAILED (0xC0000142) - a DLL failed to initialise (DllMain returned FALSE)'
    3221226505 = 'STATUS_STACK_BUFFER_OVERRUN (0xC0000409) - stack corruption / fail-fast'
    3221226356 = 'STATUS_HEAP_CORRUPTION (0xC0000374) - heap corruption detected'
    3221225725 = 'STATUS_STACK_OVERFLOW (0xC00000FD) - endless recursion or very large stack use'
    3221225506 = 'STATUS_ACCESS_DENIED (0xC0000022)'
    3221225786 = 'STATUS_CONTROL_C_EXIT (0xC000013A) - terminated by Ctrl+C / console closed'
    3221226519 = 'STATUS_INVALID_CRUNTIME_PARAMETER (0xC0000417) - invalid parameter passed to a C runtime function'
    3762504530 = 'CLR unhandled exception (0xE0434352) - a .NET exception was not caught. Check Error History for the ".NET Runtime" event with the exception text'
}

function Get-ExitCodeText {
    param([int64]$Code)
    $u = if ($Code -lt 0) { $Code + 4294967296 } else { $Code }
    $hex = '0x{0:X8}' -f [int64]$u
    foreach ($k in $script:ExitCodeInfo.Keys) { if ([int64]$k -eq [int64]$u) { return "$Code ($hex): $($script:ExitCodeInfo[$k])" } }
    if ($u -ge 3221225472 -and $u -le 3489660927) { return "$Code ($hex): NTSTATUS error code - look it up in Microsoft's NTSTATUS reference" }
    if ($Code -lt 0 -and $Code -gt -65536) { return "$Code ($hex): negative program-defined exit code (the program's own error number)" }
    if ($u -ge 2147483648 -and $u -lt 3221225472) { return "$Code ($hex): HRESULT-style error code (0x8xxxxxxx) - look it up as an HRESULT" }
    return "$Code ($hex): program-defined exit code"
}
#endregion ENGINE

#region ENGINE2
# =====================================================================
#  ENGINE v3 additions - related-file decoding and message-source search.
#  Read-only like the rest of the engine: files are parsed as bytes, never loaded or run.
# =====================================================================

# ---- Windows Installer exit codes (learn.microsoft.com/windows/win32/msi/error-codes) ----
$script:ExitCodeInfo[1602] = 'ERROR_INSTALL_USEREXIT - the installation was cancelled'
$script:ExitCodeInfo[1603] = 'ERROR_INSTALL_FAILURE - fatal error during installation (re-run with an MSI log: /l*v "C:\Temp\install.log" and search the log for "Return value 3")'
$script:ExitCodeInfo[1605] = 'ERROR_UNKNOWN_PRODUCT - action only valid for an installed product'
$script:ExitCodeInfo[1618] = 'ERROR_INSTALL_ALREADY_RUNNING - another installation is in progress; wait for it (or a stuck msiexec.exe) to finish'
$script:ExitCodeInfo[1619] = 'ERROR_INSTALL_PACKAGE_OPEN_FAILED - the installation package could not be opened (path/permissions)'
$script:ExitCodeInfo[1620] = 'ERROR_INSTALL_PACKAGE_INVALID - the installation package is not a valid Windows Installer package'
$script:ExitCodeInfo[1625] = 'ERROR_INSTALL_PACKAGE_REJECTED - installation forbidden by system policy'
$script:ExitCodeInfo[1638] = 'ERROR_PRODUCT_VERSION - another version of this product is already installed'
$script:ExitCodeInfo[1641] = 'ERROR_SUCCESS_REBOOT_INITIATED - success; the installer started a restart'
$script:ExitCodeInfo[3010] = 'ERROR_SUCCESS_REBOOT_REQUIRED - success; a restart is needed to finish'

# ---- embedded files (Costura.Fody packs DLLs as raw Deflate: costura.<name>.compressed) ----
function Expand-EmbeddedBytes {
    param([byte[]]$Data, [string]$Name)
    if ($Data.Length -ge 2 -and $Data[0] -eq 0x4D -and $Data[1] -eq 0x5A) { return , $Data }
    $mode = $null
    if ($Data.Length -ge 2 -and $Data[0] -eq 0x1F -and $Data[1] -eq 0x8B) { $mode = 'gzip' }
    elseif ($Name -match '(?i)\.compressed$') { $mode = 'deflate' }
    if (-not $mode) { return , $Data }
    $in = New-Object System.IO.MemoryStream(, $Data)
    $out = New-Object System.IO.MemoryStream
    try {
        if ($mode -eq 'gzip') { $z = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress) }
        else { $z = New-Object System.IO.Compression.DeflateStream($in, [System.IO.Compression.CompressionMode]::Decompress) }
        $buf = New-Object byte[] 81920
        while (($n = $z.Read($buf, 0, $buf.Length)) -gt 0) {
            $out.Write($buf, 0, $n)
            if ($out.Length -gt 300MB) { break }
        }
        $z.Dispose()
        return , $out.ToArray()
    } catch { return , $Data } finally { $in.Dispose(); $out.Dispose() }
}

function Test-EmbeddedProgram {
    # resource that is (or decompresses to) an EXE/DLL
    param([byte[]]$Bytes, $Res)
    if ($Res.Offset -lt 0 -or $Res.Size -lt 2) { return $false }
    if ($Bytes[$Res.Offset] -eq 0x4D -and $Bytes[$Res.Offset + 1] -eq 0x5A) { return $true }
    if ($Res.Name -match '(?i)\.(dll|exe)(\.compressed)?$' -or $Res.Name -match '(?i)^costura\..*\.compressed$') { return $true }
    return $false
}

# ---- search candidates ----
function New-Candidate {
    param([string]$Text, [string]$Kind, [string]$Where, [int]$Rank, $Token = $null, $Line = $null)
    return [pscustomobject]@{ Text = $Text; Kind = $Kind; Where = $Where; Rank = $Rank; Token = $Token; Line = $Line }
}

function Get-ScriptStringCandidates {
    param([string]$Script, [string]$Kind = 'PowerShell script')
    $out = New-Object System.Collections.Generic.List[object]
    try {
        $tokens = $null; $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($Script, [ref]$tokens, [ref]$errs)
        foreach ($t in $tokens) {
            if ($t -is [System.Management.Automation.Language.StringToken]) {
                $raw = if ($t -is [System.Management.Automation.Language.StringExpandableToken]) {
                    # keep $variables visible so they can act as placeholders
                    $tx = $t.Text
                    if ($tx.Length -ge 2 -and $tx[0] -eq '"' -and $tx[$tx.Length - 1] -eq '"') { $tx.Substring(1, $tx.Length - 2) }
                    elseif ($tx.StartsWith('@"')) { $tx.Substring(2).TrimEnd('@').TrimEnd('"') }
                    else { $t.Value }
                } else { $t.Value }
                if ($raw -and $raw.Length -ge 4) { $out.Add((New-Candidate $raw $Kind ("line {0}" -f $t.Extent.StartLineNumber) 0 $null $t.Extent.StartLineNumber)) }
            }
        }
    } catch { }
    return , $out
}

function Get-SearchSources {
    # Returns a list of "sources" (the file itself plus programs embedded in it), each with its candidates.
    param([byte[]]$Bytes, [string]$Label, [string]$Path, [int]$Depth = 0)
    $sources = New-Object System.Collections.Generic.List[object]
    $cands = New-Object System.Collections.Generic.List[object]
    $src = [pscustomobject]@{ Label = $Label; Path = $Path; MD = $null; Script = $null; Text = $null; Bytes = $Bytes; Candidates = $cands; Note = '' }
    $sources.Add($src)
    $pe = Get-PEInfo $Bytes
    if (-not $pe.Valid) {
        # plain text file (script / config / ini)
        if (-not (Test-PrintableText $Bytes)) { $src.Note = 'binary data, not searched'; return , $sources }
        $text = Convert-BytesToText $Bytes
        $src.Text = $text
        if ($Path -match '(?i)\.(ps1|psm1)$') {
            $src.Script = $text
            foreach ($c in (Get-ScriptStringCandidates $text)) { $cands.Add($c) }
        }
        $ln = 0
        foreach ($l in ($text -split "`r?`n")) {
            $ln++
            if ($l.Trim().Length -ge 6) { $cands.Add((New-Candidate $l.Trim() 'Text line' ("line $ln") 2 $null $ln)) }
        }
        return , $sources
    }
    try {
        $res = Get-PEResources $Bytes $pe
        foreach ($r in $res) {
            if ($r.TypeId -eq 6) { foreach ($e in (Get-StringTableEntries (Get-ResourceBytes $Bytes $r) ([int]$r.Name))) { $cands.Add((New-Candidate $e.Text 'String table' ("string ID $($e.Id)") 1)) } }
            elseif ($r.TypeId -eq 11) { foreach ($e in (Get-MessageTableEntries (Get-ResourceBytes $Bytes $r))) { $cands.Add((New-Candidate $e.Text 'Message table' ("message ID $($e.Id)") 1)) } }
            elseif ($Depth -eq 0 -and $r.TypeId -eq 10 -and (Test-EmbeddedProgram $Bytes $r)) {
                $inner = Expand-EmbeddedBytes (Get-ResourceBytes $Bytes $r) ([string]$r.Name)
                foreach ($s2 in (Get-SearchSources $inner ("$Label > RCDATA $($r.Name)") $null 1)) { $sources.Add($s2) }
            }
        }
    } catch { }
    if ($pe.IsDotNet) {
        try {
            $md = Read-DotNetMetadata $Bytes $pe
            if ($md.Valid) {
                $src.MD = $md
                foreach ($u in (Get-AllUserStrings $md)) { if ($u.Text.Length -ge 4) { $cands.Add((New-Candidate $u.Text '.NET string literal' ('token 0x{0:X8}' -f $u.Token) 0 $u.Token)) } }
                $mres = Get-ManagedResources $md
                foreach ($r in $mres) {
                    if ($r.Offset -lt 0) { continue }
                    if ($r.Type -like '.resources*') {
                        foreach ($e in (Get-DotNetResourceEntries (Get-ResourceBytes $Bytes $r))) {
                            if ($e.Type -eq 'ResourceTypeCode.String' -and $e.Value) { $cands.Add((New-Candidate $e.Value '.NET resource string' ("$($r.Name) / $($e.Key)") 1)) }
                        }
                    } elseif ($Depth -eq 0 -and (Test-EmbeddedProgram $Bytes $r)) {
                        $inner = Expand-EmbeddedBytes (Get-ResourceBytes $Bytes $r) $r.Name
                        foreach ($s2 in (Get-SearchSources $inner ("$Label > $($r.Name)") $null 1)) { $sources.Add($s2) }
                    } elseif ($r.Name -match '(?i)\.(ps1|psm1)$') {
                        $sc = [System.Text.Encoding]::UTF8.GetString((Get-ResourceBytes $Bytes $r)).TrimStart([char]0xFEFF)
                        $src.Script = $sc
                        foreach ($c in (Get-ScriptStringCandidates $sc)) { $cands.Add($c) }
                    } else {
                        $d = Get-ResourceBytes $Bytes $r
                        if ($d.Length -lt 5MB -and (Test-PrintableText $d)) {
                            $ln = 0
                            foreach ($l in ((Convert-BytesToText $d) -split "`r?`n")) { $ln++; if ($l.Trim().Length -ge 6) { $cands.Add((New-Candidate $l.Trim() 'Embedded text file' ("$($r.Name) line $ln") 2 $null $ln)) } }
                        }
                    }
                }
                if (-not $src.Script) {
                    $ps = Find-EmbeddedPowerShell $md $Bytes $mres
                    if ($ps.Found) { $src.Script = $ps.Script; foreach ($c in (Get-ScriptStringCandidates $ps.Script)) { $cands.Add($c) } }
                }
            }
        } catch { $src.Note = "metadata: $($_.Exception.Message)" }
    }
    $limit = [Math]::Min($Bytes.Length, 100MB)
    $b2 = $Bytes
    if ($Bytes.Length -gt $limit) { $b2 = New-Object byte[] $limit; [Array]::Copy($Bytes, $b2, $limit) }
    foreach ($s in (Get-ExeStrings $b2 6 150000)) {
        if (-not (Test-NoiseString $s.Text)) { $cands.Add((New-Candidate $s.Text 'Text in file' ('offset 0x{0:X8} ({1})' -f $s.Offset, $s.Encoding) 3)) }
    }
    return , $sources
}

# ---- matching ----
$script:PlaceholderRx = '(%%)|(%[-+ 0#]*(\d+|\*)?(\.(\d+|\*))?(hh|h|ll|l|I64|I32|w|z|j|t|L)?[sSdiuoxXcCfFeEgGpn])|(%\d+(![^!]*!)?)|(\{\d+(,\s*-?\d+)?(:[^}]*)?\})|(\$\{[^}]+\})|(\$\([^)]*\))|(\$[A-Za-z_][\w:]*(\.\w+)*)'

function Get-NormalText {
    param([string]$s)
    if (-not $s) { return '' }
    $t = $s.Replace('\r\n', ' ').Replace('\n', ' ').Replace('\t', ' ')
    $t = [regex]::Replace($t, '%[nrt0]', ' ')
    $t = [regex]::Replace($t, '\s+', ' ').Trim().ToLowerInvariant()
    return $t.Trim(' ', '.', ':', '!', '"', "'")
}

function Get-CandidateRegex {
    # returns @(regexString, literalCharCount) or $null when the text has no placeholders
    param([string]$Norm)
    $ms = [regex]::Matches($Norm, $script:PlaceholderRx)
    $real = @($ms | Where-Object { $_.Value -ne '%%' })
    if ($real.Count -eq 0) { return $null }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0; $lit = 0
    foreach ($m in $ms) {
        $chunk = $Norm.Substring($pos, $m.Index - $pos)
        $lit += ($chunk -replace '\s', '').Length
        [void]$sb.Append([regex]::Escape($chunk))
        if ($m.Value -eq '%%') { [void]$sb.Append('%') } else { [void]$sb.Append('.*?') }
        $pos = $m.Index + $m.Length
    }
    $tail = $Norm.Substring($pos)
    $lit += ($tail -replace '\s', '').Length
    [void]$sb.Append([regex]::Escape($tail))
    return @($sb.ToString(), $lit)
}

function Get-MessageMatchScore {
    param([string]$CandNorm, [string]$DialogNorm, [string[]]$DialogLines)
    if ($CandNorm.Length -lt 6) { return 0 }
    if ($CandNorm.IndexOf('%') -ge 0 -or $CandNorm.IndexOf('{') -ge 0 -or $CandNorm.IndexOf('$') -ge 0) {
        $rx = Get-CandidateRegex $CandNorm
        if ($rx -and $rx[1] -ge 8) {
            try { if ([regex]::IsMatch($DialogNorm, $rx[0])) { return [int](80 + [Math]::Min(15, $rx[1] / 6)) } } catch { }
        }
    }
    if ($CandNorm.Length -ge 10 -and $DialogNorm.Contains($CandNorm)) { return [int](55 + [Math]::Min(35, $CandNorm.Length / 3)) }
    foreach ($dl in $DialogLines) { if ($dl.Length -ge 14 -and $CandNorm.Contains($dl)) { return [int](50 + [Math]::Min(30, $dl.Length / 4)) } }
    return 0
}

function Find-MessageSource {
    param([string]$DialogText, $Sources, [int]$Max = 200)
    $results = New-Object System.Collections.Generic.List[object]
    $dn = Get-NormalText $DialogText
    if ($dn.Length -lt 4) { return , $results }
    $lines = @($DialogText -split "`r?`n" | ForEach-Object { Get-NormalText $_ } | Where-Object { $_.Length -ge 14 })
    foreach ($src in $Sources) {
        $best = @{}
        $structured = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($c in $src.Candidates) { if ($c.Rank -lt 3) { [void]$structured.Add((Get-NormalText $c.Text)) } }
        foreach ($c in $src.Candidates) {
            $cn = Get-NormalText $c.Text
            if ($c.Rank -ge 3) {
                $cn = $cn.TrimStart(',', ';', '.', ' ', '(', '[', '-', '*', '#')
                if ($structured.Contains($cn)) { continue }   # same text already found as literal/resource/table entry
            }
            $sc = Get-MessageMatchScore $cn $dn $lines
            if ($sc -le 0) { continue }
            if ($c.Rank -ge 3) {
                $dup = $false
                foreach ($sn in $structured) { if ($sn.StartsWith($cn) -or $cn.StartsWith($sn)) { if ($sn.Length -ge 8) { $dup = $true; break } } }
                if ($dup) { continue }
            }
            $sc -= $c.Rank * 2
            if (-not $best.ContainsKey($cn) -or $best[$cn].Score -lt $sc -or ($best[$cn].Score -eq $sc -and $best[$cn].Cand.Rank -gt $c.Rank)) {
                $best[$cn] = @{ Score = $sc; Cand = $c }
            }
        }
        foreach ($k in $best.Keys) {
            $c = $best[$k].Cand
            $results.Add([pscustomobject]@{ Score = $best[$k].Score; Source = $src.Label; Path = $src.Path; Kind = $c.Kind; Where = $c.Where; Text = $c.Text; Token = $c.Token; Line = $c.Line; SourceRef = $src })
        }
    }
    $sorted = @($results | Sort-Object @{ Expression = 'Score'; Descending = $true }, @{ Expression = { $_.Text.Length }; Descending = $true } | Select-Object -First $Max)
    return , $sorted
}

# ---- known Windows / runtime messages ----
$script:Vb6Errors = @{
    5 = 'Invalid procedure call or argument'; 6 = 'Overflow'; 7 = 'Out of memory'; 9 = 'Subscript out of range'; 11 = 'Division by zero'
    13 = 'Type mismatch'; 52 = 'Bad file name or number'; 53 = 'File not found'; 54 = 'Bad file mode'; 55 = 'File already open'
    58 = 'File already exists'; 61 = 'Disk full'; 62 = 'Input past end of file'; 70 = 'Permission denied'; 71 = 'Disk not ready'
    75 = 'Path/File access error'; 76 = 'Path not found'; 91 = 'Object variable or With block variable not set'; 94 = 'Invalid use of Null'
    339 = 'Component not correctly registered or a file is missing (an OCX/DLL is missing or not registered with regsvr32)'
    429 = 'ActiveX component cannot create object (a COM DLL is not registered, or 32/64-bit mismatch)'
    3024 = 'Could not find file (database file path is wrong)'; 3044 = 'Not a valid path (database path)'
}

function Get-KnownMessageExplanation {
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($t, $e) $out.Add([pscustomobject]@{ Title = $t; Explanation = $e }) }
    if ($Text -match '(?is)(code execution cannot proceed|program can.t start|application has failed to start|unable to locate component).*?because\s+(\S+\.dll)\s+(was not found|is missing)') {
        & $add 'Missing DLL (Windows loader)' ("Windows could not find '{0}' when starting the program. Check the Imports and DLLs tab for the full dependency chain; install the matching runtime or copy the DLL next to the EXE." -f $Matches[2])
    } elseif ($Text -match '(?i)(\S+\.dll)\s+(was not found|is missing from your computer)') {
        & $add 'Missing DLL (Windows loader)' ("'{0}' is missing. See the Imports and DLLs tab." -f $Matches[1])
    }
    if ($Text -match '(?i)procedure entry point\s+(\S+)\s+could not be located in the dynamic link library\s+(\S+)') {
        & $add 'Wrong DLL version' ("Function '{0}' is not in '{1}' - an older/different version of that DLL is being loaded (often a copy in the EXE folder or in PATH)." -f $Matches[1], $Matches[2])
    }
    if ($Text -match '(?i)unable to start correctly\s*\((0x[0-9a-f]{8})\)') {
        & $add 'Start-up failure code' (Get-ExitCodeText ([Convert]::ToInt64($Matches[1], 16)))
    }
    if ($Text -match '(?i)not a valid Win32 application|isn.t compatible with the version of Windows|can.t run on your PC') { & $add 'Wrong program type' 'The file is for a different processor/Windows version (e.g. a 64-bit program on 32-bit Windows, or a damaged download).' }
    if ($Text -match '(?i)side-by-side configuration is incorrect') { & $add 'Side-by-side (manifest) error' 'A Visual C++ runtime/assembly named in the manifest is missing. Look in Error History for the SideBySide event - it names the exact assembly and version; install that Visual C++ redistributable.' }
    if ($Text -match '(?i)\.NET Framework Initialization Error|requires.*\.NET Framework|To run this application, you (must|first need to) install') { & $add '.NET Framework missing' 'The required .NET Framework version is not installed. The Overview tab shows the target framework and what this PC has.' }
    if ($Text -match '(?i)Unhandled exception has occurred in (your application|a component)') { & $add '.NET unhandled exception (WinForms)' 'The program hit an error it does not handle. The exception type and the "at ..." lines in Details show where; matching methods are listed below as stack frames.' }
    if ($Text -match '(?i)Could not load file or assembly\s+''?([^'',]+)') { & $add 'Missing .NET assembly' ("The .NET DLL '{0}' (or one of its dependencies) could not be loaded. Check it exists next to the EXE / in the GAC, and its version." -f $Matches[1]) }
    if ($Text -match '(?i)(Access is denied|Access to the path .+? is denied|UnauthorizedAccessException|Permission denied)') { & $add 'Access denied' 'The program lacks rights to a file/folder/registry key. Try "Run as administrator", or check the permissions of the path in the message.' }
    if ($Text -match '(?i)(Could not find (a part of )?the (file|path)|system cannot find the (file|path) specified|FileNotFoundException|DirectoryNotFoundException)') { & $add 'File or folder not found' 'A path the program expects does not exist. The path is usually in the message; also check Related Files.' }
    if ($Text -match '(?i)Class not registered|REGDB_E_CLASSNOTREG|80040154') { & $add 'COM class not registered' 'A COM/ActiveX component is not registered, or is registered only for the other bitness (32 vs 64-bit). Register it with the matching regsvr32 (SysWOW64 for 32-bit).' }
    if ($Text -match '(?i)Microsoft Visual C\+\+ Runtime Library|Runtime Error!\s*.*R6\d{3}') { & $add 'C/C++ runtime error' 'The C runtime aborted the program (R6xxx code in the message). Often a corrupt runtime install or a bug triggered by bad input/config.' }
    if ($Text -match '(?i)Microsoft (Office )?Access Database Engine|Microsoft\.(Jet|ACE)\.OLEDB.*not registered|Provider cannot be found|Data source name not found') { & $add 'Database driver/provider missing' 'The database provider (Jet/ACE/ODBC) is missing or only installed for the other bitness. 32-bit Jet/ACE needs a 32-bit program.' }
    if ($Text -match '(?i)Run-time error\s+''?(-?\d+)''?') {
        $code = [int]$Matches[1]
        $desc = if ($script:Vb6Errors.ContainsKey($code)) { $script:Vb6Errors[$code] } else { 'see the VB6 run-time error list' }
        & $add ("VB6 run-time error {0}" -f $code) $desc
    }
    if ($Text -match '(?i)Another installation is (already )?in progress|1618') { & $add 'Installer busy' (Get-ExitCodeText 1618) }
    if ($Text -match '(?i)A restart is required|reboot') { & $add 'Restart needed' 'The installer/program needs a reboot to complete.' }
    return , $out
}

function Get-StackFrames {
    # "at Namespace.Class.Method(args)" lines from a .NET exception text (skips framework frames)
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($Text, '(?m)^\s*(at|bei|\u00E0|en)\s+([\w\.\+`<>\[\],]+)\.([\w<>`\.]+)\(')) {
        $type = $m.Groups[2].Value; $meth = $m.Groups[3].Value
        if ($type -match '^(System|Microsoft|MS\.Internal|Windows)\.' -or $type -like 'CallSite*') { continue }
        $out.Add([pscustomobject]@{ Type = $type; Method = $meth; Display = "$type.$meth" })
    }
    return , $out
}

function Find-MethodByFrame {
    # returns MethodDef rows whose "Type::Method" matches a stack frame
    param($md, $Frame)
    $hits = New-Object System.Collections.Generic.List[int]
    if (-not $md -or -not $md.Valid) { return , $hits }
    $want = ($Frame.Type -replace '/', '+') + '::' + $Frame.Method
    for ($m = 1; $m -le $md.RowCount[6]; $m++) {
        if ((Get-MdMethodDefName $md $m) -eq $want) { $hits.Add($m) }
    }
    return , $hits
}
#endregion ENGINE2

#region ENGINE3
# =====================================================================
#  ENGINE v8 additions (generic - works for any .NET / native program):
#  exception-handler tables, enum names for constant arguments, "how is this
#  text reached" analysis, message-box texts of a method, paths built from
#  pieces, program log files, deployment-tool / service run context.
#  Read-only like the rest of the engine.
# =====================================================================
$script:ILSimplePushRx = '^(ldarg(\.[0-3]|\.s)?|ldarga(\.s)?|ldloc(\.[0-3]|\.s)?|ldloca(\.s)?|ldstr|ldnull|ldc\.i4(\.[0-8]|\.s|\.m1)?|ldc\.i8|ldc\.r4|ldc\.r8|ldsfld|ldsflda|ldtoken|ldftn)$'
$script:ILCondBranchRx = '^(brfalse|brtrue|beq|bne\.un|bge|bge\.un|bgt|bgt\.un|ble|ble\.un|blt|blt\.un)(\.s)?$'
$script:ILStopRx = '^(br|br\.s|leave|leave\.s|ret|throw|rethrow|endfinally|endfilter|switch|jmp)$'
$script:PrimitiveTypeRx = '^(int|long|uint|ulong|short|ushort|byte|sbyte|bool|char|string|object|float|double|IntPtr|UIntPtr|void)$'

# ---- exception handler clauses (ECMA-335 II.25.4.5) ----
function Get-MethodEHClauses {
    param($md, [int]$rid)
    if (-not $md.ContainsKey('EHCache')) { $md.EHCache = @{} }
    if ($md.EHCache.ContainsKey($rid)) { return , $md.EHCache[$rid] }
    $list = New-Object System.Collections.Generic.List[object]
    $md.EHCache[$rid] = $list
    $rva = $md.Tables[6][$rid][0]
    if ($rva -eq 0) { return , $list }
    $o = ConvertTo-FileOffset $md.PE $rva
    if ($o -lt 0) { return , $list }
    $b = $md.Bytes
    if (($b[$o] -band 3) -ne 3) { return , $list }          # tiny header: no handlers
    $flags = Get-U16 $b $o
    if (($flags -band 0x08) -eq 0) { return , $list }       # no extra sections
    $hsize = ($b[$o + 1] -shr 4) * 4
    $codeSize = Get-U32 $b ($o + 4)
    $s = $o + $hsize + $codeSize
    $s = $s + ((4 - ($s % 4)) % 4)
    $guard = 0
    while ($s -lt $b.Length -and $guard -lt 16) {
        $guard++
        $kind = $b[$s]
        $fat = [bool]($kind -band 0x40)
        if ($fat) { $size = [int]$b[$s + 1] + ([int]$b[$s + 2] -shl 8) + ([int]$b[$s + 3] -shl 16) } else { $size = [int]$b[$s + 1] }
        if ($size -lt 4) { break }
        if ($kind -band 0x01) {
            if ($fat) {
                $n = [int](($size - 4) / 24)
                for ($i = 0; $i -lt $n; $i++) {
                    $c = $s + 4 + $i * 24
                    $list.Add([pscustomobject]@{ Flags = [int](Get-U32 $b $c); TryStart = [int](Get-U32 $b ($c + 4)); TryLen = [int](Get-U32 $b ($c + 8)); HandlerStart = [int](Get-U32 $b ($c + 12)); HandlerLen = [int](Get-U32 $b ($c + 16)); Token = [int64](Get-U32 $b ($c + 20)) })
                }
            } else {
                $n = [int](($size - 4) / 12)
                for ($i = 0; $i -lt $n; $i++) {
                    $c = $s + 4 + $i * 12
                    $list.Add([pscustomobject]@{ Flags = [int](Get-U16 $b $c); TryStart = [int](Get-U16 $b ($c + 2)); TryLen = [int]$b[$c + 4]; HandlerStart = [int](Get-U16 $b ($c + 5)); HandlerLen = [int]$b[$c + 7]; Token = [int64](Get-U32 $b ($c + 8)) })
                }
            }
        }
        if (($kind -band 0x80) -eq 0) { break }
        $s += $size
        $s = $s + ((4 - ($s % 4)) % 4)
    }
    foreach ($c in $list) {
        $kindName = switch ($c.Flags -band 7) { 0 { 'catch' } 1 { 'filter' } 2 { 'finally' } 4 { 'fault' } default { 'handler' } }
        $cls = ''
        if ($kindName -eq 'catch' -and $c.Token -ne 0) { try { $cls = Resolve-MdToken $md $c.Token } catch { $cls = '' } }
        Add-Member -InputObject $c -NotePropertyName Kind -NotePropertyValue $kindName
        Add-Member -InputObject $c -NotePropertyName ClassName -NotePropertyValue $cls
        Add-Member -InputObject $c -NotePropertyName TryEnd -NotePropertyValue ($c.TryStart + $c.TryLen)
        Add-Member -InputObject $c -NotePropertyName HandlerEnd -NotePropertyValue ($c.HandlerStart + $c.HandlerLen)
    }
    return , $list
}

function Get-EHMarkers {
    # comment lines to print before (Where='before', offset = instruction start) or after (Where='after', offset = next instruction) an IL line
    param($Clauses, [int]$Offset, [string]$Where)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Clauses -or $Clauses.Count -eq 0) { return , $out }
    $tryDone = @{}
    foreach ($c in $Clauses) {
        $tk = "$($c.TryStart)-$($c.TryEnd)"
        if ($Where -eq 'before') {
            if ($c.TryStart -eq $Offset -and -not $tryDone.ContainsKey($tk)) { $tryDone[$tk] = $true; $out.Add(('  // ---- try {{   protected code IL_{0:X4}-IL_{1:X4}' -f $c.TryStart, $c.TryEnd)) }
            if ($c.HandlerStart -eq $Offset) {
                $what = switch ($c.Kind) {
                    'catch' { ("catch ({2}) {{   runs only when the protected code IL_{0:X4}-IL_{1:X4} throws" -f $c.TryStart, $c.TryEnd, $(if ($c.ClassName) { $c.ClassName } else { 'exception' })) }
                    'filter' { ("catch-when filter {{   runs when the protected code IL_{0:X4}-IL_{1:X4} throws and the filter agrees" -f $c.TryStart, $c.TryEnd) }
                    'finally' { ("finally {{   always runs after IL_{0:X4}-IL_{1:X4}" -f $c.TryStart, $c.TryEnd) }
                    default { ("fault {{   runs only when IL_{0:X4}-IL_{1:X4} throws" -f $c.TryStart, $c.TryEnd) }
                }
                $out.Add('  // ---- ' + $what)
            }
        } else {
            if ($c.TryEnd -eq $Offset -and -not $tryDone.ContainsKey($tk)) { $tryDone[$tk] = $true; $out.Add('  // ---- } end of protected code') }
            if ($c.HandlerEnd -eq $Offset) { $out.Add(('  // ---- }} end of {0}' -f $c.Kind)) }
        }
    }
    return , $out
}

# ---- enum names for constant arguments ----
function ConvertFrom-MdConstant {
    param($md, [int]$Type, [int64]$BlobIdx)
    $v = Get-MdBlob $md $BlobIdx
    try {
        switch ($Type) {
            0x02 { return [int64]$v[0] }
            0x04 { return [int64][sbyte]$(if ($v[0] -gt 127) { $v[0] - 256 } else { $v[0] }) }
            0x05 { return [int64]$v[0] }
            0x06 { return [int64][BitConverter]::ToInt16($v, 0) }
            0x07 { return [int64][BitConverter]::ToUInt16($v, 0) }
            0x08 { return [int64][BitConverter]::ToInt32($v, 0) }
            0x09 { return [int64][BitConverter]::ToUInt32($v, 0) }
            0x0A { return [int64][BitConverter]::ToInt64($v, 0) }
            0x0B { return [int64][BitConverter]::ToUInt64($v, 0) }
        }
    } catch { }
    return $null
}

function Get-MdEnumMaps {
    # "Namespace.Type[+Nested]" -> @{ [int64]value = 'MemberName' } for every enum defined in this module
    param($md)
    if ($md.ContainsKey('EnumMaps')) { return $md.EnumMaps }
    $maps = @{}
    try {
        $cv = @{}
        if ($md.Tables.ContainsKey(0x0B)) {
            for ($i = 1; $i -le $md.RowCount[0x0B]; $i++) {
                $r = $md.Tables[0x0B][$i]
                $par = Resolve-Coded 'HasConstant' $r[1]
                if ($par[0] -eq 0x04) { $cv[[int]$par[1]] = @(([int]($r[0] -band 0xFF)), $r[2]) }
            }
        }
        $nT = $md.RowCount[2]; $nF = $md.RowCount[4]
        for ($t = 1; $t -le $nT; $t++) {
            $ext = $md.Tables[2][$t][3]
            if ($ext -eq 0) { continue }
            if ((Get-MdTypeDefOrRefName $md $ext) -ne 'System.Enum') { continue }
            $name = Get-MdTypeDefName $md $t
            $fS = $md.Tables[2][$t][4]; $fE = if ($t -lt $nT) { $md.Tables[2][$t + 1][4] } else { $nF + 1 }
            $m = @{}; $seq = [int64]0
            for ($f = $fS; $f -lt $fE -and $f -le $nF; $f++) {
                $fn = Get-MdString $md $md.Tables[4][$f][1]
                if ($fn -eq 'value__') { continue }
                $v = $null
                if ($cv.ContainsKey([int]$f)) { $v = ConvertFrom-MdConstant $md $cv[[int]$f][0] $cv[[int]$f][1] }
                if ($null -eq $v) { $v = $seq }
                $k = [int64]$v
                if (-not $m.ContainsKey($k)) { $m[$k] = $fn }
                $seq = $k + 1
            }
            $maps[$name] = $m
        }
    } catch { }
    $md.EnumMaps = $maps
    return $maps
}

function Get-EnumSourceMds {
    # metadata of the analysed file and its related .NET files (enums used across assemblies)
    $S = $script:S
    $list = New-Object System.Collections.Generic.List[object]
    if (-not $S) { return , $list }
    $key = '{0}|{1}' -f $S.Path, $(if ($S.Related) { $S.Related.Count } else { 0 })
    if ($script:EnumMdKey -eq $key -and $script:EnumMds) { return , $script:EnumMds }
    if ($S.MD -and $S.MD.Valid) { $list.Add($S.MD) }
    $n = 0
    if ($S.Related) {
        foreach ($rf in $S.Related) {
            if ($rf.Res -or [string]$rf.Path -notmatch '(?i)\.(dll|exe)$' -or $rf.Size -gt 60MB) { continue }
            $n++; if ($n -gt 40) { break }
            try {
                $b = Read-FileBytesShared $rf.Path
                $pe2 = Get-PEInfo $b
                if ($pe2.Valid -and $pe2.IsDotNet) { $m2 = Read-DotNetMetadata $b $pe2; if ($m2.Valid) { $list.Add($m2) } }
            } catch { }
        }
    }
    $script:EnumMdKey = $key
    $script:EnumMds = $list
    return , $list
}

function Get-EnumNameFor {
    param($md, [string]$TypeName, [int64]$Value)
    if (-not $TypeName -or $TypeName -match $script:PrimitiveTypeRx) { return '' }
    $short = ($TypeName -split '[\.\+]')[-1]
    $maps = Get-MdEnumMaps $md
    if ($maps.ContainsKey($TypeName)) { $m = $maps[$TypeName]; if ($m.ContainsKey($Value)) { return "$short.$($m[$Value])" }; return '' }
    foreach ($o in (Get-EnumSourceMds)) {
        if ([object]::ReferenceEquals($o, $md)) { continue }
        $mp = Get-MdEnumMaps $o
        if ($mp.ContainsKey($TypeName)) { $m = $mp[$TypeName]; if ($m.ContainsKey($Value)) { return "$short.$($m[$Value])" }; return '' }
    }
    return ''
}

function Get-MethodSigParamTypes {
    # parameter type names of the method a call token points to
    param($md, [int64]$Tok)
    if (-not $md.ContainsKey('SigCache')) { $md.SigCache = @{} }
    if ($md.SigCache.ContainsKey($Tok)) { return , $md.SigCache[$Tok] }
    $types = New-Object System.Collections.Generic.List[string]
    $md.SigCache[$Tok] = $types
    $tbl = [int]($Tok -shr 24); $rid = [int]($Tok -band 0xFFFFFF)
    $blob = $null
    try {
        if ($tbl -eq 0x06 -and $rid -le $md.RowCount[6]) { $blob = Get-MdBlob $md $md.Tables[6][$rid][4] }
        elseif ($tbl -eq 0x0A -and $rid -le $md.RowCount[0x0A]) { $blob = Get-MdBlob $md $md.Tables[0x0A][$rid][2] }
        elseif ($tbl -eq 0x2B -and $rid -le $md.RowCount[0x2B]) {
            $m = Resolve-Coded 'MethodDefOrRef' $md.Tables[0x2B][$rid][0]
            $t2 = if ($m[0] -eq 0x06) { 0x06000000 + $m[1] } else { 0x0A000000 + $m[1] }
            foreach ($x in (Get-MethodSigParamTypes $md $t2)) { $types.Add($x) }
            return , $types
        }
        if ($blob -and $blob.Length -gt 1 -and $blob[0] -ne 0x06) {
            $st = @{ B = $blob; P = 1 }
            if ($blob[0] -band 0x10) { $g = Read-CompressedUInt $blob 1; $st.P += $g[1] }
            $n = Read-CompressedUInt $blob $st.P; $st.P += $n[1]
            $null = Read-SigType $md $st
            for ($i = 0; $i -lt $n[0]; $i++) { $types.Add((Read-SigType $md $st)) }
        }
    } catch { }
    return , $types
}

function Get-LdcValue {
    param($Ins)
    switch -regex ($Ins.Name) {
        '^ldc\.i4\.m1$' { return [int64]-1 }
        '^ldc\.i4\.([0-8])$' { return [int64]$Matches[1] }
        '^ldc\.i4(\.s)?$' { return [int64]$Ins.Operand }
        '^ldc\.i8$' { return [int64]$Ins.Operand }
    }
    return $null
}

function Get-PrevIndex {
    # previous instruction index, skipping nop
    param($InsList, [int]$i)
    $j = $i - 1
    while ($j -ge 0 -and $InsList[$j].Name -eq 'nop') { $j-- }
    return $j
}

function Get-LocalIndex {
    param($Ins)
    if ($Ins.Name -match '^(ldloc|stloc|ldloca)\.([0-3])$') { return [int]$Matches[2] }
    if ($Ins.Name -match '^(ldloc|stloc|ldloca)(\.s)?$') { return [int]$Ins.Operand }
    return -1
}

function Get-ILEnumAnnotations {
    # IL offset -> "EnumType.Member" for constants passed where an enum is expected
    param($md, $InsList)
    $ann = @{}
    for ($i = 0; $i -lt $InsList.Count; $i++) {
        $ins = $InsList[$i]
        try {
            if ($ins.Name -in 'call', 'callvirt', 'newobj' -and $ins.OperandType -eq 'InlineMethod') {
                $pt = Get-MethodSigParamTypes $md ([int64]$ins.Operand)
                if ($pt.Count -eq 0) { continue }
                $j = $i
                for ($p = $pt.Count - 1; $p -ge 0; $p--) {
                    $j = Get-PrevIndex $InsList $j
                    if ($j -lt 0) { break }
                    $pi = $InsList[$j]
                    if ($pi.Name -notmatch $script:ILSimplePushRx) { break }
                    $v = Get-LdcValue $pi
                    if ($null -ne $v) { $nm = Get-EnumNameFor $md $pt[$p] $v; if ($nm) { $ann[[int]$pi.Offset] = $nm } }
                }
            } elseif ($ins.Name -eq 'box' -or $ins.Name -eq 'constrained.') {
                $tn = Resolve-MdToken $md ([int64]$ins.Operand)
                $j = Get-PrevIndex $InsList $i
                if ($j -lt 0) { continue }
                if ($ins.Name -eq 'constrained.' -and $InsList[$j].Name -match '^ldloca') {
                    # enumValue.ToString(): ldc X; stloc N; ldloca N; constrained. T
                    $loc = Get-LocalIndex $InsList[$j]
                    $j = Get-PrevIndex $InsList $j
                    if ($j -lt 0 -or $InsList[$j].Name -notmatch '^stloc' -or (Get-LocalIndex $InsList[$j]) -ne $loc) { continue }
                    $j = Get-PrevIndex $InsList $j
                    if ($j -lt 0) { continue }
                }
                $v = Get-LdcValue $InsList[$j]
                if ($null -ne $v) { $nm = Get-EnumNameFor $md $tn $v; if ($nm) { $ann[[int]$InsList[$j].Offset] = $nm } }
            }
        } catch { }
    }
    return $ann
}

# ---- "how is this text reached" ----
function Get-ShortMemberName {
    param([string]$Resolved)
    $t = ($Resolved -split '\(', 2)[0].Trim()
    if ($t -notmatch '::') { return $t }
    $parts = $t -split '::', 2
    $type = ($parts[0] -split '[\.\+]')[-1]
    if ($parts[1] -eq '.ctor') { return "new $type" }
    return "$type.$($parts[1])"
}

function Get-ILArgName {
    param($md, [int]$rid, $Ins)
    $idx = -1
    if ($Ins.Name -match '^ldarga?\.([0-3])$') { $idx = [int]$Matches[1] } elseif ($Ins.Name -match '^ldarga?(\.s)?$') { $idx = [int]$Ins.Operand }
    if ($idx -lt 0) { return 'argument' }
    $static = [bool]($md.Tables[6][$rid][2] -band 0x10)
    if (-not $static) { if ($idx -eq 0) { return 'this' }; $idx-- }
    $names = @(Get-MdParamNames $md $rid)
    if ($idx -lt $names.Count -and $names[$idx]) { return "$($names[$idx]) (argument)" }
    return "argument $idx"
}

function Get-ILExpressionText {
    param($md, [int]$rid, $InsList, [int]$From, [int]$To, $LocalNames)
    $parts = New-Object System.Collections.Generic.List[string]
    for ($k = $From; $k -le $To; $k++) {
        if ($k -lt 0 -or $k -ge $InsList.Count) { continue }
        $x = $InsList[$k]
        $nm = $x.Name
        $txt = $null
        if ($nm -eq 'ldstr') { $s = Get-MdUserString $md ([int64]$x.Operand -band 0xFFFFFF); if ($s.Length -gt 80) { $s = $s.Substring(0, 77) + '...' }; $txt = '"' + $s + '"' }
        elseif ($nm -in 'call', 'callvirt', 'newobj') { $txt = Get-ShortMemberName (Resolve-MdToken $md ([int64]$x.Operand)) }
        elseif ($nm -match '^ldarga?') { $txt = Get-ILArgName $md $rid $x }
        elseif ($nm -match '^ldloca?') {
            $li = Get-LocalIndex $x
            $pj = $k - 1; while ($pj -ge $From -and $InsList[$pj].Name -eq 'nop') { $pj-- }
            if ($nm -match '^ldloc' -and -not ($LocalNames -and $LocalNames.ContainsKey($li)) -and $pj -ge $From -and $InsList[$pj].Name -match '^stloc' -and (Get-LocalIndex $InsList[$pj]) -eq $li) { continue }   # debug build: result stored then re-read
            $txt = if ($LocalNames -and $LocalNames.ContainsKey($li)) { $LocalNames[$li] } else { "local $li" }
        }
        elseif ($nm -match '^ldc\.') { $v = Get-LdcValue $x; $txt = if ($null -ne $v) { [string]$v } else { [string]$x.Operand } }
        elseif ($nm -match '^lds?fld') { $txt = Get-ShortMemberName (Resolve-MdToken $md ([int64]$x.Operand)) }
        elseif ($nm -eq 'ldnull') { $txt = 'null' }
        elseif ($nm -match '^(ceq|cgt|clt|cgt\.un|clt\.un)$') { $txt = @{ 'ceq' = '=='; 'cgt' = '>'; 'clt' = '<'; 'cgt.un' = '>'; 'clt.un' = '<' }[$nm] }
        elseif ($nm -in 'isinst') { $txt = 'is ' + (Get-ShortMemberName (Resolve-MdToken $md ([int64]$x.Operand))) }
        if ($txt) { $parts.Add($txt) }
    }
    $e = ($parts -join ' -> ')
    if ($e -match '^(.+) -> (0|null) -> ==$') { $e = 'NOT ' + $Matches[1] }   # "x == false" / "x == null"
    return $e
}

function Get-ILContextAt {
    # explains how execution reaches instruction index $Idx: enclosing catch/finally and the conditions checked just before it
    param($md, [int]$rid, $InsList, [int]$Idx)
    $lines = New-Object System.Collections.Generic.List[string]
    $off = [int]$InsList[$Idx].Offset
    $eh = Get-MethodEHClauses $md $rid
    $lower = 0
    $localNames = @{}
    $inner = $null
    foreach ($c in $eh) {
        if ($off -ge $c.HandlerStart -and $off -lt $c.HandlerEnd) { if (-not $inner -or $c.HandlerLen -lt $inner.HandlerLen) { $inner = $c } }
    }
    if ($inner) {
        for ($k = 0; $k -lt $InsList.Count; $k++) { if ($InsList[$k].Offset -ge $inner.HandlerStart) { $lower = $k; break } }
        if ($inner.Kind -eq 'catch' -and $InsList[$lower].Name -match '^stloc') { $localNames[(Get-LocalIndex $InsList[$lower])] = 'the exception' }
        $calls = New-Object System.Collections.Generic.List[string]
        foreach ($x in $InsList) {
            if ($x.Offset -ge $inner.TryStart -and $x.Offset -lt $inner.TryEnd -and $x.Name -in 'call', 'callvirt', 'newobj') {
                $sn = Get-ShortMemberName (Resolve-MdToken $md ([int64]$x.Operand))
                if (-not $calls.Contains($sn)) { $calls.Add($sn) }
            }
        }
        switch ($inner.Kind) {
            'catch' { $lines.Add(("inside a catch handler for {0}: reached only when the protected code IL_{1:X4}-IL_{2:X4} throws" -f $(if ($inner.ClassName) { $inner.ClassName } else { 'an exception' }), $inner.TryStart, $inner.TryEnd)) }
            'filter' { $lines.Add(("inside a catch-when handler: reached when the protected code IL_{0:X4}-IL_{1:X4} throws" -f $inner.TryStart, $inner.TryEnd)) }
            'finally' { $lines.Add(("inside a finally block (always runs after IL_{0:X4}-IL_{1:X4})" -f $inner.TryStart, $inner.TryEnd)) }
            default { $lines.Add(("inside a fault handler: reached only when IL_{0:X4}-IL_{1:X4} throws" -f $inner.TryStart, $inner.TryEnd)) }
        }
        if ($calls.Count -gt 0 -and $inner.Kind -ne 'finally') {
            $shown = @($calls | Select-Object -First 14)
            $lines.Add(('  the protected code calls: {0}{1}' -f ($shown -join ', '), $(if ($calls.Count -gt 14) { ", ... ($($calls.Count) calls)" } else { '' })))
        }
    }
    # conditions just before the instruction (branches that jump past it)
    $conds = New-Object System.Collections.Generic.List[object]
    $j = $Idx - 1; $steps = 0
    while ($j -ge $lower -and $conds.Count -lt 3 -and $steps -lt 60) {
        $steps++
        $x = $InsList[$j]
        if ($x.Name -match $script:ILStopRx) { break }
        if ($x.Name -match $script:ILCondBranchRx) {
            $target = [int]($x.Next + $x.Operand)
            if ($target -gt $off) { $conds.Insert(0, $j) } else { break }
        }
        $j--
    }
    $start = $j + 1
    foreach ($bi in $conds) {
        $br = $InsList[$bi]
        $expr = Get-ILExpressionText $md $rid $InsList $start ($bi - 1) $localNames
        if (-not $expr) { $expr = '(value computed earlier)' }
        $when = switch -regex ($br.Name) {
            '^brfalse' { 'reached when TRUE ' }
            '^brtrue' { 'reached when FALSE' }
            default { "reached unless ($($br.Name -replace '\.s$', ''))" }
        }
        $lines.Add(("{0}: {1}" -f $when, $expr))
        $start = $bi + 1
    }
    return , $lines
}

function Get-TokenUserRids {
    param($md, [int64]$Token, [int]$Max = 3)
    $out = New-Object System.Collections.Generic.List[int]
    for ($m = 1; $m -le $md.RowCount[6]; $m++) {
        foreach ($ins in (Get-ILInstructions $md $m)) {
            if ($ins.OperandType -match '^(InlineMethod|InlineField|InlineType|InlineTok|InlineString)$' -and [int64]$ins.Operand -eq $Token) { $out.Add($m); break }
        }
        if ($out.Count -ge $Max) { break }
    }
    return , $out
}

function Get-TokenContextText {
    # "How the program gets to this text" for every use of a token (string literal or resource getter) in one method
    param($md, [int]$rid, [int64]$Token)
    $insList = Get-ILInstructions $md $rid
    $sb = New-Object System.Text.StringBuilder
    $n = 0
    for ($i = 0; $i -lt $insList.Count; $i++) {
        $x = $insList[$i]
        if (-not ($x.OperandType -match '^(InlineMethod|InlineString)$' -and [int64]$x.Operand -eq $Token)) { continue }
        $n++; if ($n -gt 3) { break }
        $ctx = Get-ILContextAt $md $rid $insList $i
        [void]$sb.AppendLine(("  at IL_{0:X4} in {1}:" -f $x.Offset, (Get-MdMethodDefName $md $rid)))
        if ($ctx.Count -eq 0) { [void]$sb.AppendLine('    - no condition or exception handler found right before it (reached by the normal flow of the method)') }
        foreach ($l in $ctx) { [void]$sb.AppendLine('    - ' + $l) }
    }
    return $sb.ToString()
}

function Get-MessageBoxTexts {
    # texts a method passes to MessageBox.Show / MsgBox (literal or resource name), in code order
    param($md, [int]$rid)
    $out = New-Object System.Collections.Generic.List[string]
    $insList = Get-ILInstructions $md $rid
    for ($i = 0; $i -lt $insList.Count; $i++) {
        $x = $insList[$i]
        if ($x.Name -notin 'call', 'callvirt') { continue }
        $r = Resolve-MdToken $md ([int64]$x.Operand)
        if ($r -notmatch '(MessageBox::Show\(|Interaction::MsgBox\(|TaskDialog::Show)') { continue }
        $found = $null; $j = $i; $steps = 0; $concat = $false
        while ($steps -lt 14) {
            $j = Get-PrevIndex $insList $j; $steps++
            if ($j -lt 0) { break }
            $y = $insList[$j]
            if ($y.Name -match '^(pop|ret|br|br\.s|leave|leave\.s|throw)$' -or $y.Name -match $script:ILCondBranchRx) { break }   # stop at the start of this block
            if ($y.Name -in 'call', 'callvirt') {
                $r2 = Resolve-MdToken $md ([int64]$y.Operand)
                if ($r2 -match '(MessageBox::Show\(|Interaction::MsgBox\()') { break }
                if ($r2 -match 'String::(Concat|Format)\(') { $concat = $true }
                if ($r2 -match '::get_(\w+)\(\)\s*:\s*string$' -and -not $found) { $found = "(resource text $($Matches[1]))" }
            }
            if ($y.Name -eq 'ldstr') { $found = Get-MdUserString $md ([int64]$y.Operand -band 0xFFFFFF); if ($concat) { $found = $found.TrimEnd() + ' ...' } }
        }
        if ($found -and -not $out.Contains($found)) { $out.Add($found) }
    }
    return , $out
}

# ---- paths built from pieces (F16) and program log files (F17) ----
function ConvertTo-LocalPath {
    param([string]$p)
    $x = [Environment]::ExpandEnvironmentVariables($p.Trim())
    if ([System.IO.Path]::DirectorySeparatorChar -eq '/') { $x = $x.Replace('\', '/') }
    return $x
}

function Get-PathPieceCandidates {
    # Combines folder texts and file-name texts found in the program (and its .NET helper DLLs) into full paths.
    # Returns @{ Found = list of {Path; Why}; Logs = list of log paths (existing or not) }
    param($TextSets)   # list of @{ Label; Texts }
    $found = New-Object System.Collections.Generic.List[object]
    $logs = New-Object System.Collections.Generic.List[string]
    $nonWin = ([System.IO.Path]::DirectorySeparatorChar -eq '/')
    $folderRx = '^(?:[A-Za-z]:\\|%[A-Za-z_][\w]*%\\?)[^"*?<>|\r\n\t{}]{0,220}$'
    if ($nonWin) { $folderRx = '^(?:[A-Za-z]:\\|%[A-Za-z_][\w]*%\\?|/[\w.\- ]+/)[^"*?<>|\r\n\t{}]{0,220}$' }
    $extRx = '(?i)\.(' + $script:RelatedExts + ')$'
    $checks = 0
    foreach ($set in $TextSets) {
        $folders = New-Object System.Collections.Generic.List[string]
        $files = New-Object System.Collections.Generic.List[string]
        $fullFiles = New-Object System.Collections.Generic.List[string]
        foreach ($t in $set.Texts) {
            if (-not $t -or $t.Length -gt 240 -or $t.Length -lt 3) { continue }
            $tt = $t.Trim()
            if ($tt -match '^\{\d+\}[\\/](.+)$') { $rel = $Matches[1]; if ($rel -match $extRx -and $rel -notmatch '\{\d+\}') { if (-not $files.Contains($rel)) { $files.Add($rel) } }; continue }
            if ($tt -match $folderRx) {
                if ($tt -match $extRx) { if (-not $fullFiles.Contains($tt)) { $fullFiles.Add($tt) } }
                elseif ($tt -notmatch '\.[A-Za-z0-9]{1,5}$') { $f = $tt.TrimEnd('\', '/'); if (-not $folders.Contains($f)) { $folders.Add($f) } }
                continue
            }
            if ($tt -match ('(?i)^[\w\-. ]{1,100}' + $extRx.Substring(4)) -and $tt -notmatch '^\.') { if (-not $files.Contains($tt)) { $files.Add($tt) } }
        }
        foreach ($ff in $fullFiles) {
            if ($ff -match '(?i)\.log$') { $lp = ConvertTo-LocalPath $ff; if (-not $logs.Contains($lp)) { $logs.Add($lp) } }
        }
        $fi = 0
        foreach ($fo in ($folders | Select-Object -First 300)) {
            foreach ($fn in ($files | Select-Object -First 3000)) {
                $checks++
                if ($checks -gt 40000) { break }
                $p = ConvertTo-LocalPath ($fo + '\' + $fn)
                $isLog = ($fn -match '(?i)\.log$')
                $ok = $false
                try { $ok = [System.IO.File]::Exists($p) } catch { }
                if ($ok -and $isLog -and -not $logs.Contains($p)) { $logs.Add($p) }   # combined paths count as logs only when they exist
                if ($ok) { $found.Add([pscustomobject]@{ Path = $p; Why = ("path built in the program from '{0}' + '{1}' ({2})" -f $fo, $fn, $set.Label) }) }
            }
        }
    }
    return [pscustomobject]@{ Found = $found; Logs = $logs }
}

function Get-ProgramTextSets {
    # string literals of the analysed program and its .NET helper DLLs (+ extracted strings of a native program)
    param($ExtraDllPaths)
    $S = $script:S
    $sets = New-Object System.Collections.Generic.List[object]
    $label = [System.IO.Path]::GetFileName($S.Path)
    $texts = New-Object System.Collections.Generic.List[string]
    if ($S.MD -and $S.MD.Valid) { foreach ($u in (Get-AllUserStrings $S.MD)) { $texts.Add($u.Text) } }
    elseif ($S.Strings) { $n = 0; foreach ($x in $S.Strings) { $n++; if ($n -gt 60000) { break }; $texts.Add($x.Text) } }
    $sets.Add(@{ Label = $label; Texts = $texts })
    $k = 0
    foreach ($p in $ExtraDllPaths) {
        $k++; if ($k -gt 30) { break }
        try {
            $b = Read-FileBytesShared $p
            $pe2 = Get-PEInfo $b
            if (-not ($pe2.Valid -and $pe2.IsDotNet)) { continue }
            $m2 = Read-DotNetMetadata $b $pe2
            if (-not $m2.Valid) { continue }
            $t2 = New-Object System.Collections.Generic.List[string]
            foreach ($u in (Get-AllUserStrings $m2)) { $t2.Add($u.Text) }
            $sets.Add(@{ Label = [System.IO.Path]::GetFileName($p); Texts = $t2 })
        } catch { }
    }
    return , $sets
}

function Read-FileTail {
    param([string]$Path, [int]$Lines = 200)
    try {
        $fs = New-Object System.IO.FileStream($Path, 'Open', 'Read', ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try {
            $len = $fs.Length
            $take = [int][Math]::Min($len, 2MB)
            [void]$fs.Seek($len - $take, 'Begin')
            $buf = New-Object byte[] $take
            $got = $fs.Read($buf, 0, $take)
            $txt = [System.Text.Encoding]::Default.GetString($buf, 0, $got)
            if ($txt.Length -gt 0 -and [int]$txt[0] -eq 0xFEFF) { $txt = $txt.Substring(1) }
            if ($got -ge 2 -and $buf[1] -eq 0 -and $buf[0] -ne 0) { $txt = [System.Text.Encoding]::Unicode.GetString($buf, 0, $got) }
            $ls = @($txt -split "`r?`n")
            if ($ls.Count -gt $Lines) { $ls = $ls[($ls.Count - $Lines)..($ls.Count - 1)] }
            return ($ls -join "`r`n").TrimEnd()
        } finally { $fs.Dispose() }
    } catch { return '' }
}

function Read-FileFrom {
    # text appended to a file after byte offset $From (whole file when it was missing or got shorter)
    param([string]$Path, [int64]$From)
    try {
        if (-not [System.IO.File]::Exists($Path)) { return $null }
        $fs = New-Object System.IO.FileStream($Path, 'Open', 'Read', ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try {
            $len = $fs.Length
            if ($From -lt 0 -or $From -gt $len) { $From = 0 }
            if ($len -eq $From) { return '' }
            $take = [int][Math]::Min($len - $From, 2MB)
            [void]$fs.Seek($len - $take, 'Begin')
            $buf = New-Object byte[] $take
            $got = $fs.Read($buf, 0, $take)
            $txt = [System.Text.Encoding]::Default.GetString($buf, 0, $got)
            if ($got -ge 2 -and $buf[1] -eq 0 -and $buf[0] -ne 0) { $txt = [System.Text.Encoding]::Unicode.GetString($buf, 0, $got) }
            return $txt.TrimStart([char]0xFEFF).TrimEnd()
        } finally { $fs.Dispose() }
    } catch { return $null }
}

# ---- run context of a crashed process (F20) ----
$script:DeployPathRules = @(
    @('(?i)\\PDQDeployRunner\\', 'PDQ Deploy'),
    @('(?i)\\ccmcache\\', 'Microsoft Configuration Manager (SCCM / MECM)'),
    @('(?i)\\IMECache\\', 'Microsoft Intune'),
    @('(?i)\\AnsibleTemp|\\\.ansible', 'Ansible'),
    @('(?i)\\chocolatey\\', 'Chocolatey'),
    @('(?i)\\LTSvc\\', 'ConnectWise Automate'),
    @('(?i)\\Kaseya\\', 'Kaseya'),
    @('(?i)\\ManageEngine\\', 'ManageEngine'),
    @('(?i)\\Tanium\\', 'Tanium'),
    @('(?i)\\BigFix|\\BES Client\\', 'BigFix'),
    @('(?i)\\Puppet', 'Puppet'),
    @('(?i)\\salt\\', 'Salt'),
    @('(?i)\\System32\\config\\systemprofile\\', 'the SYSTEM account (service / scheduled task)'),
    @('(?i)\\Windows\\Temp\\', 'a service or deployment temp folder (C:\Windows\Temp)'),
    @('(?i)\\ProgramData\\Package Cache\\', 'an installer bootstrapper (Package Cache)')
)

function Get-ErrorRowAppPath {
    param($Row)
    $d = [string]$Row.Detail
    if ($d -match '(?im)^\s*Faulting application path:\s*(.+?)\s*$') { return $Matches[1] }
    if ($d -match '(?im)^\s*AppPath\s*=\s*(.+?)\s*$') { return $Matches[1] }
    return ''
}

function Get-RunContextLabel {
    param([string]$Path)
    if (-not $Path) { return '' }
    foreach ($r in $script:DeployPathRules) { if ($Path -match $r[0]) { return $r[1] } }
    return ''
}

$script:NoDesktopText = 'it ran without a desktop (service, scheduled task or deployment tool). Any message box or form the program shows then fails: .NET throws InvalidOperationException ("Showing a modal dialog box or form when the application is not running in UserInteractive mode is not a valid operation") or the program waits for a click nobody can give (hang). Run it once interactively, logged on, to see the box and its cause.'
#endregion ENGINE3


#region GUI
# =====================================================================
#  GUI
# =====================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:AppTitle = 'EXE Inspector v8'
$script:MonoFont = New-Object System.Drawing.Font('Consolas', 9.5)
$script:UiFont = New-Object System.Drawing.Font('Segoe UI', 9)
$script:BoldFont = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

$script:S = @{
    Path = $null; Bytes = $null; PE = $null; Imports = $null; Exports = $null; NativeRes = $null; ManagedRes = $null
    AllRes = $null; MD = $null; PS = $null; PInvoke = $null; AsmRefs = $null; Deps = $null; Strings = $null
    StringTable = $null; Overview = ''; Hints = $null; Manifest = $null; ErrorRows = $null; Related = $null
    RunLog = (New-Object System.Text.StringBuilder); Proc = $null
}
$script:Run = @{ Timer = $null; Proc = $null; OutFile = $null; ErrFile = $null; OutPos = 0; ErrPos = 0; Tick = 0; Start = $null
    Known = @{}; Modules = $null; Titles = @{}; WerSeen = @{}; ExeName = ''; CheckEvents = $true }

# ---------------- helpers ----------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '[{0}] {1,-5} {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    if ($script:txtLog) {
        $script:txtLog.AppendText($line + "`r`n")
        $script:txtLog.SelectionStart = $script:txtLog.TextLength
        $script:txtLog.ScrollToCaret()
    }
}

function Set-Status {
    param([string]$Text)
    if ($script:lblStatus) { $script:lblStatus.Text = $Text }
    [System.Windows.Forms.Application]::DoEvents()
}

function New-DataTableEx {
    # columns like 'Name' or 'Size:int'
    param([string[]]$Columns)
    $t = New-Object System.Data.DataTable
    foreach ($c in $Columns) {
        $parts = $c.Split(':')
        $type = [string]
        if ($parts.Count -gt 1) {
            switch ($parts[1]) { 'int' { $type = [int64] } 'bool' { $type = [bool] } }
        }
        [void]$t.Columns.Add($parts[0], $type)
    }
    return , $t
}

function New-Grid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.MultiSelect = $false
    $g.RowHeadersVisible = $false
    $g.AutoSizeColumnsMode = 'None'
    $g.BackgroundColor = [System.Drawing.SystemColors]::Window
    $g.Font = $script:UiFont
    $g.ColumnHeadersHeightSizeMode = 'AutoSize'
    $g.Add_DataBindingComplete({ param($s, $e) try { Apply-GridLayout $s } catch { } })
    return $g
}

function Set-GridColumnWidths {
    # Stores the wanted layout on the grid and applies it now (if columns exist) and again in
    # DataBindingComplete (WinForms only creates the columns once the grid's tab is first shown).
    param($Grid, [hashtable]$Widths, [string]$FillColumn)
    $Grid.Tag = @{ Widths = $Widths; Fill = $FillColumn }
    Apply-GridLayout $Grid
}

function Apply-GridLayout {
    param($Grid)
    $lay = $Grid.Tag
    if (-not ($lay -is [hashtable])) { return }
    foreach ($col in $Grid.Columns) {
        $name = [string]$col.Name
        try { if ($name -like '_*') { $col.Visible = $false; continue } } catch { }
        try {
            if ($name -eq $lay.Fill) { $col.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill }
            elseif ($lay.Widths.ContainsKey($name)) { $col.Width = [int]$lay.Widths[$name] }
        } catch { }
    }
}

function New-TextView {
    $t = New-Object System.Windows.Forms.RichTextBox
    $t.Dock = 'Fill'
    $t.ReadOnly = $true
    $t.WordWrap = $false
    $t.DetectUrls = $false
    $t.Font = $script:MonoFont
    $t.BackColor = [System.Drawing.SystemColors]::Window
    $t.HideSelection = $false
    return $t
}

function New-Button {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 110, [int]$H = 26)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = New-Object System.Drawing.Point($X, $Y); $b.Size = New-Object System.Drawing.Size($W, $H)
    $b.Font = $script:UiFont
    return $b
}

function New-Label {
    param([string]$Text, [int]$X, [int]$Y, [int]$W = 100, [int]$H = 20)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text; $l.Location = New-Object System.Drawing.Point($X, $Y); $l.Size = New-Object System.Drawing.Size($W, $H)
    $l.Font = $script:UiFont
    $l.TextAlign = 'MiddleLeft'
    return $l
}

function New-Strip {
    # a docked-top panel to hold buttons above a view
    param([int]$Height = 38)
    $p = New-Object System.Windows.Forms.Panel
    $p.Dock = 'Top'; $p.Height = $Height
    return $p
}

function Show-Text {
    param($Box, [string]$Text)
    $Box.Text = $Text
    $Box.SelectionStart = 0
    $Box.ScrollToCaret()
}

function Get-SafeFileName {
    param([string]$Name)
    $bad = [System.IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Name.ToCharArray()) { if ($bad -contains $c) { [void]$sb.Append('_') } else { [void]$sb.Append($c) } }
    return $sb.ToString()
}

function Format-Size {
    param([int64]$Bytes)
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return "$Bytes bytes"
}

# ---------------- environment checks ----------------
function Get-InstalledDotNetFramework {
    $res = [ordered]@{ V4 = ''; V4Release = 0; V35 = $false; V2 = $false }
    try {
        $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction Stop
        $rel = [int]$k.Release
        $res.V4Release = $rel
        $map = @(@(533320, '4.8.1'), @(528040, '4.8'), @(461808, '4.7.2'), @(461308, '4.7.1'), @(460798, '4.7'), @(394802, '4.6.2'), @(394254, '4.6.1'), @(393295, '4.6'), @(379893, '4.5.2'), @(378675, '4.5.1'), @(378389, '4.5'))
        $res.V4 = '4.0'
        foreach ($m in $map) { if ($rel -ge $m[0]) { $res.V4 = $m[1]; break } }
    } catch { }
    try { $res.V35 = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' -ErrorAction Stop).Install -eq 1) } catch { }
    try { $res.V2 = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727' -ErrorAction Stop).Install -eq 1) } catch { }
    return $res
}

function Test-AssemblyAvailable {
    param([string]$Name, [string]$ExeDir)
    foreach ($ext in '.dll', '.exe') { if (Test-Path -LiteralPath (Join-Path $ExeDir ($Name + $ext))) { return 'found next to EXE' } }
    $roots = @()
    if ($env:windir) {
        $roots += (Join-Path $env:windir 'Microsoft.NET\assembly'), (Join-Path $env:windir 'assembly')
    }
    foreach ($r in $roots) {
        foreach ($g in 'GAC_MSIL', 'GAC_32', 'GAC_64', 'GAC') {
            if (Test-Path -LiteralPath (Join-Path (Join-Path $r $g) $Name)) { return "in GAC ($g)" }
        }
    }
    if ($env:windir) {
        foreach ($fw in 'Framework\v4.0.30319', 'Framework64\v4.0.30319', 'Framework\v2.0.50727') {
            if (Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path $env:windir 'Microsoft.NET') $fw) ($Name + '.dll'))) { return 'in .NET Framework folder' }
        }
    }
    return 'NOT FOUND (next to EXE or in GAC)'
}

# ---------------- analysis ----------------
function Invoke-Analysis {
    param([string]$Path, [switch]$Navigate)
    $S = $script:S
    try { $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path.Trim().Trim('"')) } catch { }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        [void][System.Windows.Forms.MessageBox]::Show("File not found:`r`n$Path", $script:AppTitle, 'OK', 'Warning'); return
    }
    if ($Navigate -and $S.Path -and ($S.Path -ne $Path)) { $script:History.Push($S.Path) }
    $fi = Get-Item -LiteralPath $Path
    if ($fi.Length -gt 300MB) {
        $r = [System.Windows.Forms.MessageBox]::Show(("This file is {0}. Analysis may take a while and use a lot of memory. Continue?" -f (Format-Size $fi.Length)), $script:AppTitle, 'YesNo', 'Question')
        if ($r -ne 'Yes') { return }
    }
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        foreach ($k in @('Bytes', 'PE', 'Imports', 'Exports', 'NativeRes', 'ManagedRes', 'AllRes', 'MD', 'PS', 'PInvoke', 'AsmRefs', 'Deps', 'Strings', 'StringTable', 'Hints', 'Manifest', 'Related')) { $S[$k] = $null }
        $S.Path = $Path
        Write-Log "Analysing $Path"
        Set-Status 'Reading file...'
        $S.Bytes = Read-FileBytesShared $Path
        Set-Status 'Reading PE headers...'
        $S.PE = Get-PEInfo $S.Bytes
        $pe = $S.PE
        $S.Imports = New-Object System.Collections.Generic.List[object]
        $S.Exports = New-Object System.Collections.Generic.List[object]
        $S.NativeRes = New-Object System.Collections.Generic.List[object]
        $S.ManagedRes = New-Object System.Collections.Generic.List[object]
        $S.PInvoke = New-Object System.Collections.Generic.List[object]
        $S.AsmRefs = New-Object System.Collections.Generic.List[object]
        $S.Hints = New-Object System.Collections.Generic.List[string]
        $debugInfo = @{ PdbPath = ''; Reproducible = $false }
        if (-not $pe.Valid) {
            Write-Log $pe.Error 'WARN'
        } else {
            try { $S.Imports = Get-PEImports $S.Bytes $pe } catch { Write-Log "Imports: $($_.Exception.Message)" 'ERROR' }
            try { $S.Exports = Get-PEExports $S.Bytes $pe } catch { Write-Log "Exports: $($_.Exception.Message)" 'ERROR' }
            try { $debugInfo = Get-PEDebugInfo $S.Bytes $pe } catch { Write-Log "Debug info: $($_.Exception.Message)" 'ERROR' }
            try { $S.NativeRes = Get-PEResources $S.Bytes $pe } catch { Write-Log "Resources: $($_.Exception.Message)" 'ERROR' }
            $man = $null
            foreach ($r in $S.NativeRes) { if ($r.TypeId -eq 24) { $man = $r; break } }
            if ($man) { $S.Manifest = Get-ManifestInfo (Convert-BytesToText (Get-ResourceBytes $S.Bytes $man)) } else { $S.Manifest = Get-ManifestInfo '' }
            if ($pe.IsDotNet) {
                Set-Status 'Reading .NET metadata...'
                $S.MD = Read-DotNetMetadata $S.Bytes $pe
                if ($S.MD.Valid) {
                    $md = $S.MD
                    $pe.ClrAnyCpu = ($md.ILOnly -and -not $md.Requires32 -and $pe.Machine -eq 0x14c)
                    try { $S.PInvoke = Get-PInvokeList $md } catch { Write-Log "P/Invoke: $($_.Exception.Message)" 'ERROR' }
                    try { $S.AsmRefs = Get-AssemblyRefs $md } catch { Write-Log "Assembly refs: $($_.Exception.Message)" 'ERROR' }
                    try { $S.ManagedRes = Get-ManagedResources $md } catch { Write-Log "Managed resources: $($_.Exception.Message)" 'ERROR' }
                    try { $S.PS = Find-EmbeddedPowerShell $md $S.Bytes $S.ManagedRes } catch { Write-Log "PowerShell detection: $($_.Exception.Message)" 'ERROR' }
                } else { Write-Log ".NET metadata: $($S.MD.Error)" 'WARN' }
            }
            try { $S.Hints = Get-ExeHints $S.Bytes $pe $S.Imports $Path } catch { Write-Log "Hints: $($_.Exception.Message)" 'ERROR' }
            Set-Status 'Checking DLL dependencies...'
            Update-Dependencies
        }
        Set-Status 'Extracting strings...'
        $strBytes = $S.Bytes
        if ($strBytes.Length -gt 100MB) {
            $strBytes = New-Object byte[] 100MB; [Array]::Copy($S.Bytes, $strBytes, 100MB)
            Write-Log 'File is larger than 100 MB - strings are extracted from the first 100 MB only.' 'WARN'
        }
        $S.Strings = Get-ExeStrings $strBytes 5 200000
        if ($S.Strings.Count -ge 200000) { Write-Log 'Stopped at 200,000 strings.' 'WARN' }
        $S.AllRes = New-Object System.Collections.Generic.List[object]
        foreach ($r in $S.NativeRes) { $S.AllRes.Add($r) }
        foreach ($r in $S.ManagedRes) { $S.AllRes.Add($r) }

        Set-Status 'Building views...'
        foreach ($step in @(@('Overview', { Update-OverviewTab $debugInfo }), @('Script', { Update-ScriptTab }), @('.NET Code', { Update-DotNetTab }),
                @('Imports', { Update-ImportsTab }), @('Strings', { Update-StringsTab }), @('Resources', { Update-ResourcesTab }), @('Related files', { Update-RelatedTab }))) {
            try { & $step[1] } catch { Write-Log ("{0} view: {1}" -f $step[0], $_.Exception.Message) 'ERROR' }
        }
        $script:txtRunExe.Text = $Path
        $script:txtRunDir.Text = (Split-Path -Parent $Path)
        $script:form.Text = "$($script:AppTitle) - $([System.IO.Path]::GetFileName($Path))"
        if ($S.PS -and $S.PS.Found) { $script:tabs.SelectedTab = $script:tabScript }
        else { $script:tabs.SelectedTab = $script:tabOverview }
        Write-Log 'Analysis complete.'
        Set-Status ('Done - ' + [System.IO.Path]::GetFileName($Path))
    } catch {
        Write-Log "Analysis failed: $($_.Exception.Message)" 'ERROR'
        Set-Status 'Analysis failed - see Output'
    } finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Update-Dependencies {
    $S = $script:S
    if (-not $S.PE -or -not $S.PE.Valid) { return }
    $extra = @()
    if ($S.PInvoke -and $S.PInvoke.Count -gt 0) {
        $g = @{}
        foreach ($p in $S.PInvoke) { $k = $p.Dll; if (-not $g.ContainsKey($k)) { $g[$k] = 0 }; $g[$k]++ }
        foreach ($k in $g.Keys) { $extra += [pscustomobject]@{ Dll = $k; Count = $g[$k] } }
    }
    try {
        $S.Deps = Get-DependencyReport $S.Path $S.Imports $S.PE ([bool]$script:chkRecursive.Checked) 3 $extra
    } catch { Write-Log "Dependency check: $($_.Exception.Message)" 'ERROR'; $S.Deps = @() }
}

function Update-OverviewTab {
    param($DebugInfo)
    $S = $script:S; $pe = $S.PE
    $sb = New-Object System.Text.StringBuilder
    $line = { param($t) [void]$sb.AppendLine($t) }
    $fi = Get-Item -LiteralPath $S.Path
    & $line '=== FILE ==='
    & $line ("  Path            : {0}" -f $S.Path)
    & $line ("  Size            : {0:N0} bytes ({1})" -f $fi.Length, (Format-Size $fi.Length))
    & $line ("  Modified        : {0}" -f $fi.LastWriteTime)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hash = ($sha.ComputeHash($S.Bytes) | ForEach-Object { $_.ToString('X2') }) -join ''
        $sha.Dispose()
        & $line ("  SHA-256         : {0}" -f $hash)
    } catch { }
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($S.Path)
        if ($vi.FileVersion -and $vi.FileVersion.Trim()) { & $line ("  File version    : {0}" -f $vi.FileVersion) }
        if ($vi.ProductName -and $vi.ProductName.Trim()) { & $line ("  Product         : {0} {1}" -f $vi.ProductName, $vi.ProductVersion) }
        if ($vi.CompanyName -and $vi.CompanyName.Trim()) { & $line ("  Company         : {0}" -f $vi.CompanyName) }
        if ($vi.FileDescription -and $vi.FileDescription.Trim()) { & $line ("  Description     : {0}" -f $vi.FileDescription) }
        if ($vi.OriginalFilename -and $vi.OriginalFilename.Trim()) { & $line ("  Original name   : {0}" -f $vi.OriginalFilename) }
        if ($vi.LegalCopyright -and $vi.LegalCopyright.Trim()) { & $line ("  Copyright       : {0}" -f $vi.LegalCopyright) }
    } catch { }
    & $line ''
    & $line '=== WHAT KIND OF PROGRAM IS THIS ==='
    if (-not $pe.Valid) {
        & $line ("  " + $pe.Error)
        & $line '  Only the Strings tab is useful for this file.'
        Show-Text $script:txtOverview $sb.ToString(); $S.Overview = $sb.ToString(); return
    }
    $verdict = ''
    if ($S.PS -and $S.PS.Found) { $verdict = "PowerShell script packaged as an EXE (PS2EXE). The full script was recovered - see the 'Script' tab." }
    elseif ($S.PS -and $S.PS.IsPS2EXE) { $verdict = "PS2EXE-compiled PowerShell, but the script could not be located (modified/obfuscated build)." }
    elseif ($pe.IsDotNet -and $S.MD -and $S.MD.Valid) { $verdict = "Managed .NET program (C# / VB.NET). Classes, methods and their IL steps are in the '.NET Code' tab." }
    elseif ($pe.IsDotNet) { $verdict = ".NET program, but its metadata could not be read (likely obfuscated)." }
    else { $verdict = "Native Windows program (C/C++, VB6, Delphi or similar). Source code cannot be recovered from machine code; use Imports & DLLs, Strings, Resources, Run & Watch and Error History." }
    if ($pe.IsDll) { $verdict = "This is a DLL, not an EXE. " + $verdict }
    & $line ("  " + $verdict)
    $arch = $pe.MachineName
    if ($pe.IsDotNet -and $S.MD -and $S.MD.Valid) {
        if ($S.MD.Requires32) { $arch = 'x86 (32-bit only, .NET)' }
        elseif ($pe.ClrAnyCpu -and $S.MD.Prefers32) { $arch = 'AnyCPU, 32-bit preferred (runs as 32-bit)' }
        elseif ($pe.ClrAnyCpu) { $arch = 'AnyCPU (runs as 64-bit on 64-bit Windows)' }
    }
    & $line ("  Architecture    : {0}" -f $arch)
    & $line ("  Subsystem       : {0}{1}" -f $pe.SubsystemName, $(if ($pe.Subsystem -eq 3) { ' (opens a console window)' } elseif ($pe.Subsystem -eq 2) { ' (no console window)' } else { '' }))
    if ($pe.TimeDateStamp -eq 0) {
        & $line '  Build time      : not recorded'
    } elseif ($DebugInfo.Reproducible -or $pe.TimeDateStamp -gt 2000000000 -or $pe.TimeDateStamp -lt 631152000) {
        & $line ("  Build time      : not a real date (reproducible build / hash value 0x{0:X8})" -f $pe.TimeDateStamp)
    } else {
        & $line ("  Build time      : {0:yyyy-MM-dd HH:mm:ss} UTC" -f ([datetime]'1970-01-01').AddSeconds($pe.TimeDateStamp))
    }
    & $line ("  Linker version  : {0}    Min. OS version: {1}" -f $pe.LinkerVersion, $pe.OsVersion)
    if ($DebugInfo.PdbPath) { & $line ("  Debug symbols   : {0}   (original build path on the developer's PC)" -f $DebugInfo.PdbPath) }
    & $line ("  Signature       : {0}" -f $(if ($pe.Dirs[4][1] -gt 0) { 'Authenticode certificate present' } else { 'not digitally signed' }))
    if ($script:chkVerifySig.Checked -and $pe.Dirs[4][1] -gt 0) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $S.Path
            & $line ("                    Status: {0}  Signer: {1}" -f $sig.Status, $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '-' }))
        } catch { & $line "                    (verification failed: $($_.Exception.Message))" }
    }
    $m = $S.Manifest
    & $line ("  Privilege level : {0}" -f $m.ExecutionLevel)
    if ($m.ExecutionLevel -eq 'requireAdministrator') { & $line '                    -> Needs "Run as administrator". Started without admin it shows a UAC prompt, or fails with error 740.' }
    if ($m.Error) { & $line ("  Manifest        : {0}" -f $m.Error) }
    foreach ($d in $m.Dependencies) {
        $state = ''
        if ($env:windir -and $d.Name -and $d.Token -and $d.Version -and $d.Name -notlike 'Microsoft.Windows.Common-Controls') {
            $arch2 = if ($d.Arch -and $d.Arch -ne '*') { $d.Arch.ToLower() } elseif ($pe.Is64) { 'amd64' } else { 'x86' }
            $pattern = '{0}_{1}_{2}_{3}_*' -f $arch2, $d.Name.ToLower(), $d.Token, $d.Version
            $hit = $null
            try { $hit = Get-ChildItem -LiteralPath (Join-Path $env:windir 'WinSxS') -Filter $pattern -Directory -ErrorAction SilentlyContinue | Select-Object -First 1 } catch { }
            $state = if ($hit) { ' -> installed (WinSxS)' } else { ' -> NOT FOUND in WinSxS (install the matching Visual C++ runtime / redistributable)' }
        }
        & $line ("  Needs assembly  : {0} {1} ({2}){3}" -f $d.Name, $d.Version, $d.Arch, $state)
    }

    if ($pe.IsDotNet -and $S.MD -and $S.MD.Valid) {
        $md = $S.MD
        & $line ''
        & $line '=== .NET DETAILS ==='
        & $line ("  Assembly        : {0}" -f (Get-AssemblyIdentity $md))
        & $line ("  Runtime         : {0}" -f $md.MetadataVersion)
        $tfm = ''
        try { $tfm = Get-TargetFramework $md } catch { }
        if ($tfm) { & $line ("  Target framework: {0}" -f $tfm) }
        if (($md.EntryPointToken -shr 24) -eq 6) { & $line ("  Entry point     : {0}" -f (Get-MdMethodDefName $md ([int]($md.EntryPointToken -band 0xFFFFFF)) -WithSig)) }
        & $line ("  Strong-named    : {0}" -f $md.StrongNamed)
        & $line ("  Size            : {0:N0} types, {1:N0} methods, {2:N0} external member references" -f $md.RowCount[2], $md.RowCount[6], $md.RowCount[0x0A])
        $net = Get-InstalledDotNetFramework
        if ($env:windir) {
            & $line ("  This PC has     : .NET Framework {0}{1}{2}" -f $(if ($net.V4) { $net.V4 } else { '4.x NOT installed' }), $(if ($net.V35) { ', 3.5 (incl. 2.0)' } else { ', 3.5 not installed' }), '')
            $cfgPath = $S.Path + '.config'
            $hasV4Cfg = $false
            if (Test-Path -LiteralPath $cfgPath) {
                $cfgText = Get-Content -LiteralPath $cfgPath -Raw -ErrorAction SilentlyContinue
                $hasV4Cfg = ($cfgText -match 'supportedRuntime[^>]+v4\.0')
                & $line ("  Config file     : {0} (exists{1})" -f $cfgPath, $(if ($hasV4Cfg) { ', allows .NET 4' } else { '' }))
            }
            if ($md.MetadataVersion -like 'v2.0*' -and -not $net.V35 -and -not $hasV4Cfg) {
                & $line '  >>> PROBLEM     : Built for .NET 2.0/3.5 but .NET Framework 3.5 is not installed on this PC and no .config allows .NET 4. It will not start.'
            }
            if ($tfm -match '^\.NETFramework,Version=v(\d+\.\d+(\.\d+)?)') {
                $need = [version]$Matches[1]
                $have = if ($net.V4) { [version]$net.V4 } else { [version]'0.0' }
                if ($need -gt $have -and $need.Major -ge 4) { & $line ("  >>> PROBLEM     : Targets .NET Framework {0} but this PC has {1}. Install .NET Framework {0} or later." -f $need, $net.V4) }
            }
            if ($tfm -match '^\.NETCoreApp') {
                $shared = Join-Path $env:ProgramFiles 'dotnet\shared\Microsoft.NETCore.App'
                $vers = @()
                if (Test-Path -LiteralPath $shared) { $vers = @(Get-ChildItem -LiteralPath $shared -Directory | ForEach-Object { $_.Name }) }
                & $line ("  .NET runtimes   : {0}" -f $(if ($vers) { $vers -join ', ' } else { 'NONE installed under ' + $shared }))
            }
        }
        if ($S.AsmRefs.Count -gt 0) {
            & $line '  Assembly references (DLLs this program loads):'
            $exeDir = Split-Path -Parent $S.Path
            $isCore = ($tfm -match '^\.NET(CoreApp|Standard)' -or @($S.AsmRefs | Where-Object { $_.Name -in 'System.Runtime', 'netstandard', 'System.Private.CoreLib' }).Count -gt 0)
            foreach ($a in $S.AsmRefs) {
                $st = if (-not $env:windir) { '' } elseif ($isCore -and $a.Name -match '^(System|Microsoft|netstandard|mscorlib|WindowsBase|PresentationCore|PresentationFramework)(\.|$)') { 'provided by the .NET runtime' } else { Test-AssemblyAvailable $a.Name $exeDir }
                & $line ("    - {0} {1}  {2}" -f $a.Name, $a.Version, $st)
            }
        }
    }

    & $line ''
    & $line '=== HINTS ==='
    if ($S.Hints.Count -eq 0) { & $line '  (none)' }
    foreach ($h in $S.Hints) { & $line ("  - " + $h) }
    if ($S.PS) { foreach ($mk in $S.PS.Markers) { & $line ("  - PowerShell marker: " + $mk) } }

    & $line ''
    & $line '=== DLL DEPENDENCIES ==='
    if ($S.Deps) {
        $missing = @($S.Deps | Where-Object { $_.Status -like 'NOT FOUND*' })
        $wrong = @($S.Deps | Where-Object { $_.Status -like 'WRONG*' })
        & $line ("  {0} DLLs checked, {1} missing, {2} wrong bitness" -f @($S.Deps).Count, $missing.Count, $wrong.Count)
        foreach ($x in $missing) {
            $why = ($x.Status -replace '^NOT FOUND\s*-?\s*', '')
            & $line ("  >>> MISSING: {0}  (needed by {1}){2}" -f $x.Dll, $x.RequiredBy, $(if ($why) { "`r`n      -> $why" } else { '' }))
        }
        foreach ($x in $wrong) { & $line ("  >>> {0}: {1}" -f $x.Dll, $x.Status) }
        if (-not $env:windir) { & $line '  (not running on Windows - dependency locations could not be checked)' }
    }

    & $line ''
    & $line '=== WHAT IT CAN DO (from imported Windows functions) ==='
    if ($S.Imports.Count -gt 0) {
        $groups = @{}
        foreach ($i in $S.Imports) {
            $c = Get-ApiCategory $i.Dll $i.Function
            if (-not $groups.ContainsKey($c)) { $groups[$c] = New-Object System.Collections.Generic.List[string] }
            if ($groups[$c] -notcontains $i.Function) { $groups[$c].Add($i.Function) }
        }
        foreach ($c in ($groups.Keys | Sort-Object)) {
            if ($c -eq 'Other') { continue }
            $ex = ($groups[$c] | Select-Object -First 6) -join ', '
            & $line ("  {0,-34} {1,4}  e.g. {2}" -f $c, $groups[$c].Count, $ex)
        }
        if ($groups.ContainsKey('Other')) { & $line ("  {0,-34} {1,4}" -f 'Other', $groups['Other'].Count) }
    } elseif ($pe.IsDotNet) { & $line "  .NET programs import only mscoree.dll - see '.NET Code' > External calls by category." }

    if ($S.Exports.Count -gt 0) {
        & $line ''
        & $line ("=== EXPORTED FUNCTIONS ({0}) ===" -f $S.Exports.Count)
        foreach ($e in ($S.Exports | Select-Object -First 300)) { & $line ("  #{0,-5} {1}{2}" -f $e.Ordinal, $e.Name, $(if ($e.ForwardedTo) { "  -> $($e.ForwardedTo)" } else { '' })) }
        if ($S.Exports.Count -gt 300) { & $line '  ... (first 300 shown)' }
    }

    & $line ''
    & $line '=== SECTIONS ==='
    foreach ($sec in $pe.Sections) {
        $fl = @()
        if ($sec.Flags -band 0x20000000) { $fl += 'exec' }
        if ($sec.Flags -band 0x40000000) { $fl += 'read' }
        if ($sec.Flags -band 2147483648) { $fl += 'write' }
        & $line ("  {0,-9} virtual {1,10:N0}  file {2,10:N0}  {3}" -f $sec.Name, $sec.VirtualSize, $sec.RawSize, ($fl -join ','))
    }
    $S.Overview = $sb.ToString()
    Show-Text $script:txtOverview $S.Overview
}

function Update-ScriptTab {
    $S = $script:S
    $tv = $script:tvScript
    $tv.BeginUpdate()
    $tv.Nodes.Clear()
    if (-not ($S.PS -and $S.PS.Found)) {
        $msg = "No embedded PowerShell script found in this file.`r`n`r`n"
        if ($S.PE -and $S.PE.IsDotNet) { $msg += "This is a .NET program - see the '.NET Code' tab for its methods and steps." }
        elseif ($S.PE -and $S.PE.Valid) { $msg += "This is a native program - its source cannot be recovered. See 'Imports & DLLs', 'Strings' and 'Resources'." }
        Show-Text $script:txtScript $msg
        $script:lblScript.Text = 'No script'
        $script:btnSaveScript.Enabled = $false
        $tv.EndUpdate()
        return
    }
    $ps = $S.PS
    Show-Text $script:txtScript $ps.Script
    $script:lblScript.Text = "Recovered: $($ps.Name)  -  $($ps.Method)"
    $script:btnSaveScript.Enabled = $true
    $o = Get-ScriptOutline $ps.Script
    $nSteps = $tv.Nodes.Add("Steps in run order (top-level statements: $(@($o.Steps).Count))")
    foreach ($st in $o.Steps) { $n = $nSteps.Nodes.Add(('L{0}: {1}' -f $st.Line, $st.Text)); $n.Tag = $st.Line }
    $nFunc = $tv.Nodes.Add("Functions defined ($(@($o.Functions).Count))")
    foreach ($f in ($o.Functions | Sort-Object Line)) { $n = $nFunc.Nodes.Add(('{0}  (lines {1}-{2})' -f $f.Name, $f.Line, $f.EndLine)); $n.Tag = $f.Line }
    $nCmd = $tv.Nodes.Add("Commands / programs called ($(@($o.Commands).Count))")
    foreach ($c in $o.Commands) { $n = $nCmd.Nodes.Add(('{0}  x{1}' -f $c.Name, $c.Count)); $n.Tag = $c.FirstLine }
    if (@($o.ParseErrors).Count -gt 0) {
        $nErr = $tv.Nodes.Add("Parse warnings ($(@($o.ParseErrors).Count))")
        foreach ($e in $o.ParseErrors) { [void]$nErr.Nodes.Add($e) }
    }
    $nSteps.Expand()
    $tv.EndUpdate()
}

function Update-DotNetTab {
    $S = $script:S
    $tv = $script:tvNet
    $tv.BeginUpdate()
    $tv.Nodes.Clear()
    if (-not ($S.MD -and $S.MD.Valid)) {
        Show-Text $script:txtNet $(if ($S.PE -and $S.PE.IsDotNet) { ".NET metadata could not be read: $($S.MD.Error)" } else { 'Not a .NET program. (Native programs have no IL code to show - see Imports & DLLs and Strings.)' })
        $tv.EndUpdate(); return
    }
    $md = $S.MD
    if (($md.EntryPointToken -shr 24) -eq 6) {
        $rid = [int]($md.EntryPointToken -band 0xFFFFFF)
        $n = $tv.Nodes.Add('>> Entry point: ' + (Get-MdMethodDefName $md $rid))
        $n.Tag = @('method', $rid)
        $n.NodeFont = $script:BoldFont
        $n.Text = $n.Text + '          '
    }
    # namespaces -> types (methods are added when a type is expanded)
    $nsRoot = $tv.Nodes.Add("Classes and methods ($($md.RowCount[2]) types)")
    $byNs = @{}
    for ($i = 1; $i -le $md.RowCount[2]; $i++) {
        $r = $md.Tables[2][$i]
        $mStart = $r[5]; $mEnd = if ($i -lt $md.RowCount[2]) { $md.Tables[2][$i + 1][5] } else { $md.RowCount[6] + 1 }
        $name = Get-MdTypeDefName $md $i
        if ($name -eq '<Module>' -and $mEnd -le $mStart) { continue }
        $ns = Get-MdString $md $r[2]
        if ($md.Enclosing.ContainsKey($i)) { $outer = $md.Enclosing[$i]; while ($md.Enclosing.ContainsKey($outer)) { $outer = $md.Enclosing[$outer] }; $ns = Get-MdString $md $md.Tables[2][$outer][2] }
        if (-not $ns) { $ns = '(no namespace)' }
        if (-not $byNs.ContainsKey($ns)) { $byNs[$ns] = New-Object System.Collections.Generic.List[object] }
        $byNs[$ns].Add([pscustomobject]@{ Rid = $i; Name = $name; Count = [Math]::Max(0, $mEnd - $mStart) })
    }
    foreach ($ns in ($byNs.Keys | Sort-Object)) {
        $nsNode = $nsRoot.Nodes.Add($ns)
        foreach ($t in @($byNs[$ns] | Sort-Object Name)) {
            $short = $t.Name; if ($ns -ne '(no namespace)' -and $short.StartsWith($ns + '.')) { $short = $short.Substring($ns.Length + 1) }
            $tn = $nsNode.Nodes.Add("$short  ($($t.Count) methods)")
            $tn.Tag = @('type', $t.Rid)
            if ($t.Count -gt 0) { $d = $tn.Nodes.Add('...'); $d.Tag = @('dummy', 0) }
        }
    }
    if ($byNs.Count -le 3) { $nsRoot.Expand() }
    # external calls by category
    $extRoot = $tv.Nodes.Add("External calls by category ($($md.RowCount[0x0A]))")
    $cats = @{}
    for ($i = 1; $i -le $md.RowCount[0x0A]; $i++) {
        $nm = Get-MdMemberRefName $md $i
        if ($nm -match '::\.ctor$' -and $nm -match 'Attribute::') { continue }
        $c = Get-NetCategory $nm
        if (-not $cats.ContainsKey($c)) { $cats[$c] = New-Object System.Collections.Generic.List[object] }
        $cats[$c].Add([pscustomobject]@{ Rid = $i; Name = $nm })
    }
    foreach ($c in ($cats.Keys | Sort-Object)) {
        $cn = $extRoot.Nodes.Add("$c ($($cats[$c].Count))")
        foreach ($x in @($cats[$c] | Sort-Object Name)) { $n = $cn.Nodes.Add($x.Name); $n.Tag = @('token', (0x0A000000 + $x.Rid)) }
    }
    if ($S.PInvoke.Count -gt 0) {
        $pRoot = $tv.Nodes.Add("Native DLL calls - P/Invoke ($($S.PInvoke.Count))")
        foreach ($p in $S.PInvoke) { $n = $pRoot.Nodes.Add("$($p.Dll) ! $($p.Function)   <- $($p.Managed)"); if ($p.MethodRid) { $n.Tag = @('method', $p.MethodRid) } }
    }
    $us = Get-AllUserStrings $md
    $sRoot = $tv.Nodes.Add("String literals in code ($($us.Count))")
    $shown = 0
    foreach ($u in $us) {
        if ($shown -ge 5000) { [void]$sRoot.Nodes.Add('... more than 5000 - use Search'); break }
        $txt = $u.Text.Replace("`r", '\r').Replace("`n", '\n')
        if ($txt.Length -gt 200) { $txt = $txt.Substring(0, 197) + '...' }
        $n = $sRoot.Nodes.Add('"' + $txt + '"'); $n.Tag = @('token', $u.Token); $shown++
    }
    $aRoot = $tv.Nodes.Add("Assembly references ($($S.AsmRefs.Count))")
    foreach ($a in $S.AsmRefs) { [void]$aRoot.Nodes.Add("$($a.Name)  $($a.Version)") }
    $tv.EndUpdate()
    $intro = "Pick a method on the left to see its steps (IL instructions) in order.`r`n" +
    "Calls to other methods, string literals and fields are shown by name, so the logic can be followed.`r`n`r`n" +
    "Tips:`r`n  - Start at '>> Entry point' - that is where the program begins.`r`n" +
    "  - 'External calls by category' shows file, registry, network, process and database activity.`r`n" +
    "  - Select a string literal (e.g. an error message) or a call and press 'Find where used' to see which methods use it.`r`n" +
    "  - 'throw' instructions mark where exceptions are raised."
    Show-Text $script:txtNet $intro
}

function Update-ImportsTab {
    $S = $script:S
    $t = New-DataTableEx @('DLL', 'Status', 'Location', 'Required by', 'Kind', 'Functions:int', 'Level:int')
    if ($S.Deps) { foreach ($d in $S.Deps) { [void]$t.Rows.Add($d.Dll, $d.Status, $d.Path, $d.RequiredBy, $d.Kind, [int64]$d.Functions, [int64]$d.Level) } }
    $script:gridDeps.DataSource = $t
    Set-GridColumnWidths $script:gridDeps @{ 'DLL' = 190; 'Status' = 260; 'Required by' = 170; 'Kind' = 80; 'Functions' = 70; 'Level' = 50 } 'Location'
    $script:gridFuncs.DataSource = $null
    $missing = @($S.Deps | Where-Object { $_.Status -like 'NOT FOUND*' -or $_.Status -like 'WRONG*' }).Count
    $script:lblDeps.Text = if ($S.Deps) { "{0} DLLs.  Problems: {1}.  Level 1 = needed by the EXE itself; 2-3 = needed by its own DLLs." -f @($S.Deps).Count, $missing } else { 'No imports.' }
}

function Show-FunctionsForDll {
    $S = $script:S
    $row = $script:gridDeps.CurrentRow
    if (-not $row) { return }
    $dll = [string]$row.Cells['DLL'].Value
    $t = New-DataTableEx @('Function', 'Category', 'Kind')
    foreach ($i in $S.Imports) { if ($i.Dll -ieq $dll -or ($i.Dll + '.dll') -ieq $dll) { [void]$t.Rows.Add($i.Function, (Get-ApiCategory $i.Dll $i.Function), $i.Kind) } }
    foreach ($p in $S.PInvoke) { if ($p.Dll -ieq $dll -or ($p.Dll + '.dll') -ieq $dll) { [void]$t.Rows.Add($p.Function, (Get-ApiCategory $p.Dll $p.Function), "P/Invoke from $($p.Managed)") } }
    if ($t.Rows.Count -eq 0) { [void]$t.Rows.Add('(function list is shown for DLLs the EXE imports directly)', '', '') }
    $script:gridFuncs.DataSource = $t
    Set-GridColumnWidths $script:gridFuncs @{ 'Function' = 320; 'Category' = 240 } 'Kind'
}

function Update-StringsTab {
    $S = $script:S
    $t = New-DataTableEx @('Offset', 'Encoding', 'Category', 'Length:int', 'Text', '_Noise:bool')
    $t.BeginLoadData()
    $cnt = 0
    foreach ($str in $S.Strings) {
        $cnt++
        if ($cnt % 5000 -eq 0) { Set-Status ('Categorising strings {0:N0} / {1:N0}...' -f $cnt, $S.Strings.Count) }
        [void]$t.Rows.Add(('0x{0:X8}' -f $str.Offset), $str.Encoding, (Get-StringCategory $str.Text), [int64]$str.Text.Length, $str.Text, (Test-NoiseString $str.Text))
    }
    $t.EndLoadData()
    $S.StringTable = $t
    $script:gridStrings.DataSource = $t.DefaultView
    Set-GridColumnWidths $script:gridStrings @{ 'Offset' = 90; 'Encoding' = 70; 'Category' = 120; 'Length' = 60 } 'Text'
    Apply-StringFilter
}

function Apply-StringFilter {
    $S = $script:S
    if (-not $S.StringTable) { return }
    $parts = @()
    $parts += ('[Length] >= {0}' -f [int]$script:numMinLen.Value)
    if ($script:chkNoise.Checked) { $parts += '[_Noise] = false' }
    $cat = [string]$script:cmbCategory.SelectedItem
    if ($cat -and $cat -ne '(all categories)') { $parts += ("[Category] = '{0}'" -f $cat.Replace("'", "''")) }
    $q = $script:txtStrFilter.Text
    if ($q) {
        $esc = New-Object System.Text.StringBuilder
        foreach ($ch in $q.ToCharArray()) {
            if ('[]*%'.Contains([string]$ch)) { [void]$esc.Append('[').Append($ch).Append(']') }
            elseif ($ch -eq "'") { [void]$esc.Append("''") }
            else { [void]$esc.Append($ch) }
        }
        $parts += ("[Text] LIKE '%{0}%'" -f $esc.ToString())
    }
    try {
        $S.StringTable.DefaultView.RowFilter = ($parts -join ' AND ')
        $script:lblStrCount.Text = '{0:N0} of {1:N0} strings shown' -f $S.StringTable.DefaultView.Count, $S.StringTable.Rows.Count
    } catch { Write-Log "Filter error: $($_.Exception.Message)" 'WARN' }
}

function Update-ResourcesTab {
    $S = $script:S
    $t = New-DataTableEx @('Source', 'Type', 'Name', 'Language', 'Size:int', '_Idx:int')
    for ($i = 0; $i -lt $S.AllRes.Count; $i++) {
        $r = $S.AllRes[$i]
        [void]$t.Rows.Add($r.Source, $r.Type, [string]$r.Name, [string]$r.Lang, [int64]$r.Size, [int64]$i)
    }
    $script:gridRes.DataSource = $t
    Set-GridColumnWidths $script:gridRes @{ 'Source' = 60; 'Type' = 140; 'Language' = 70; 'Size' = 80 } 'Name'
    Show-Text $script:txtRes $(if ($S.AllRes.Count -eq 0) { 'No resources in this file.' } else { 'Select a resource to preview it. Manifests, string tables, message tables, version info and text are decoded.' })
}

function Get-SelectedResource {
    $row = $script:gridRes.CurrentRow
    if (-not $row) { return $null }
    return $script:S.AllRes[[int]$row.Cells['_Idx'].Value]
}

function Show-ResourcePreview {
    $S = $script:S
    $r = Get-SelectedResource
    if (-not $r) { return }
    $data = Get-ResourceBytes $S.Bytes $r
    $out = ''
    try {
        if ($r.Source -eq 'Native') {
            switch ([int]$r.TypeId) {
                24 { $out = Convert-BytesToText $data; $mi = Get-ManifestInfo $out; $out = "Requested privilege: $($mi.ExecutionLevel)`r`n`r`n" + $out }
                6 {
                    $sb = New-Object System.Text.StringBuilder
                    foreach ($e in (Get-StringTableEntries $data ([int]$r.Name))) { [void]$sb.AppendLine(('{0,6}  {1}' -f $e.Id, $e.Text)) }
                    $out = "String table block $($r.Name) (string IDs $(([int]$r.Name - 1) * 16)-$(([int]$r.Name) * 16 - 1)):`r`n`r`n" + $sb.ToString()
                }
                11 {
                    $sb = New-Object System.Text.StringBuilder
                    foreach ($e in (Get-MessageTableEntries $data)) { [void]$sb.AppendLine(('{0}  {1}' -f $e.Id, $e.Text)) }
                    $out = "Message table (texts the program can write to the event log or show as errors):`r`n`r`n" + $sb.ToString()
                }
                16 {
                    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($S.Path)
                    $out = ($vi | Format-List CompanyName, FileDescription, FileVersion, InternalName, OriginalFilename, ProductName, ProductVersion, LegalCopyright, Comments | Out-String).Trim()
                }
                { $_ -in 1, 2, 3, 12, 14, 21, 22 } { $out = "Image data ($($data.Length) bytes) - icons/cursors/bitmaps are not displayed.`r`n`r`n" + (Format-HexDump $data 256) }
                default {
                    if (Test-PrintableText $data) { $out = Convert-BytesToText $data }
                    else {
                        $note = ''
                        if ($data.Length -ge 4 -and $script:Latin1.GetString($data, 0, 4) -eq 'TPF0') { $note = "Delphi form (TPF0). Readable names in it:`r`n" + ((Get-ExeStrings $data 4 2000 | ForEach-Object { $_.Text }) -join "`r`n") + "`r`n`r`n" }
                        $out = $note + (Format-HexDump $data 2048)
                    }
                }
            }
        } else {
            if ($r.Type -like '.resources*') {
                $sb = New-Object System.Text.StringBuilder
                foreach ($e in (Get-DotNetResourceEntries $data)) { [void]$sb.AppendLine(('{0}  [{1}]  {2}' -f $e.Key, ($e.Type -replace '^ResourceTypeCode\.', ''), $e.Value)) }
                $out = "Keys in $($r.Name) (objects are listed, not deserialised):`r`n`r`n" + $sb.ToString()
            } elseif (Test-PrintableText $data) { $out = Convert-BytesToText $data }
            else { $out = Format-HexDump $data 2048 }
        }
    } catch { $out = "Preview failed: $($_.Exception.Message)" }
    Show-Text $script:txtRes $out
}

function Save-SelectedResource {
    $S = $script:S
    $r = Get-SelectedResource
    if (-not $r) { return }
    $data = Get-ResourceBytes $S.Bytes $r
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $ext = switch ([int]$r.TypeId) { 24 { '.manifest' } 16 { '.bin' } default { '.bin' } }
    if ($r.Source -eq '.NET') { $ext = '' }
    $dlg.FileName = Get-SafeFileName ("{0}_{1}{2}" -f $r.Type, $r.Name, $ext)
    if ($r.Source -eq '.NET') { $dlg.FileName = Get-SafeFileName $r.Name }
    if ($dlg.ShowDialog() -eq 'OK') {
        [System.IO.File]::WriteAllBytes($dlg.FileName, $data)
        Write-Log "Saved resource to $($dlg.FileName)"
    }
}

# ---------------- .NET tree actions ----------------
function Expand-TypeNode {
    param($Node)
    $md = $script:S.MD
    if (-not $md -or $Node.Nodes.Count -ne 1) { return }
    $first = $Node.Nodes[0]
    if (-not ($first.Tag -is [array]) -or $first.Tag[0] -ne 'dummy') { return }
    $Node.Nodes.Clear()
    $rid = [int]$Node.Tag[1]
    $mStart = $md.Tables[2][$rid][5]
    $mEnd = if ($rid -lt $md.RowCount[2]) { $md.Tables[2][$rid + 1][5] } else { $md.RowCount[6] + 1 }
    $epRid = if (($md.EntryPointToken -shr 24) -eq 6) { [int]($md.EntryPointToken -band 0xFFFFFF) } else { -1 }
    for ($m = $mStart; $m -lt $mEnd -and $m -le $md.RowCount[6]; $m++) {
        $name = Get-MdString $md $md.Tables[6][$m][3]
        $sig = Format-MethodSig $md (Get-MdBlob $md $md.Tables[6][$m][4]) (Get-MdParamNames $md $m)
        $txt = "$name$($sig[0]) : $($sig[1])"
        if ($m -eq $epRid) { $txt = '>> ' + $txt + '   [ENTRY POINT]' }
        if ($md.Tables[6][$m][2] -band 0x2000) { $txt += '   [native DLL call]' }
        $n = $Node.Nodes.Add($txt); $n.Tag = @('method', [int]$m)
    }
}

function Show-NetSelection {
    param($Node)
    $md = $script:S.MD
    if (-not $md -or -not ($Node.Tag -is [array])) { $script:btnFindUsage.Enabled = $false; return }
    $kind = $Node.Tag[0]
    $script:btnFindUsage.Enabled = ($kind -in 'method', 'token')
    try {
        if ($kind -eq 'method') {
            $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            Show-Text $script:txtNet (Format-ILListing $md ([int]$Node.Tag[1]))
        } elseif ($kind -eq 'token') {
            $tok = [int64]$Node.Tag[1]
            Show-Text $script:txtNet ((Resolve-MdToken $md $tok) + "`r`n`r`nPress 'Find where used' to list the methods that use this.")
        } elseif ($kind -eq 'type') {
            $rid = [int]$Node.Tag[1]
            $r = $md.Tables[2][$rid]
            $base = ''
            if ($r[3] -ne 0) { $c = Resolve-Coded 'TypeDefOrRef' $r[3]; $base = switch ($c[0]) { 2 { Get-MdTypeDefName $md $c[1] } 1 { Get-MdTypeRefName $md $c[1] } 27 { Get-MdTypeSpecName $md $c[1] } default { '' } } }
            Show-Text $script:txtNet ("Class: {0}`r`nBase type: {1}`r`n`r`nExpand it on the left to see its methods." -f (Get-MdTypeDefName $md $rid), $base)
        }
    } catch { Show-Text $script:txtNet "Could not decode: $($_.Exception.Message)" }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Invoke-FindUsage {
    $md = $script:S.MD
    $node = $script:tvNet.SelectedNode
    if (-not $md -or -not $node -or -not ($node.Tag -is [array])) { return }
    $tok = if ($node.Tag[0] -eq 'method') { 0x06000000 + [int64]$node.Tag[1] } else { [int64]$node.Tag[1] }
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Set-Status 'Scanning all methods...'
    try {
        $hits = Find-TokenUsage $md $tok
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('Used by ' + $hits.Count + ' method(s):  ' + (Resolve-MdToken $md $tok))
        [void]$sb.AppendLine('')
        foreach ($h in $hits) { [void]$sb.AppendLine('  ' + $h) }
        if ($hits.Count -eq 0) { [void]$sb.AppendLine('  (not referenced directly in any method body)') }
        Show-Text $script:txtNet $sb.ToString()
        # add clickable results
        $res = $null
        foreach ($n in $script:tvNet.Nodes) { if ($n.Text -like 'Search / usage results*') { $res = $n } }
        if (-not $res) { $res = $script:tvNet.Nodes.Add('Search / usage results') }
        $res.Nodes.Clear()
        for ($m = 1; $m -le $md.RowCount[6]; $m++) {
            $nm = Get-MdMethodDefName $md $m
            if ($hits -contains $nm) { $x = $res.Nodes.Add($nm); $x.Tag = @('method', $m) }
        }
        $res.Text = "Search / usage results ($($res.Nodes.Count))"
        $res.Expand()
    } catch { Write-Log "Find usage: $($_.Exception.Message)" 'ERROR' }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default; Set-Status 'Ready' }
}

function Invoke-NetSearch {
    $md = $script:S.MD
    $q = $script:txtNetSearch.Text.Trim()
    if (-not $md -or -not $q) { return }
    $res = $null
    foreach ($n in $script:tvNet.Nodes) { if ($n.Text -like 'Search / usage results*') { $res = $n } }
    if (-not $res) { $res = $script:tvNet.Nodes.Add('Search / usage results') }
    $res.Nodes.Clear()
    $script:tvNet.BeginUpdate()
    for ($m = 1; $m -le $md.RowCount[6] -and $res.Nodes.Count -lt 2000; $m++) {
        $nm = Get-MdMethodDefName $md $m
        if ($nm.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $x = $res.Nodes.Add('method: ' + $nm); $x.Tag = @('method', $m) }
    }
    for ($i = 1; $i -le $md.RowCount[0x0A] -and $res.Nodes.Count -lt 2000; $i++) {
        $nm = Get-MdMemberRefName $md $i
        if ($nm.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $x = $res.Nodes.Add('call: ' + $nm); $x.Tag = @('token', (0x0A000000 + $i)) }
    }
    foreach ($u in (Get-AllUserStrings $md)) {
        if ($res.Nodes.Count -ge 2000) { break }
        if ($u.Text.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $t = $u.Text.Replace("`r", '\r').Replace("`n", '\n'); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }
            $x = $res.Nodes.Add('string: "' + $t + '"'); $x.Tag = @('token', $u.Token)
        }
    }
    $res.Text = "Search / usage results ($($res.Nodes.Count)) for '$q'"
    $script:tvNet.EndUpdate()
    $res.Expand()
    $script:tvNet.SelectedNode = $res
}

# ---------------- Run & Watch ----------------
function Add-RunLog {
    param([string]$Text)
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss.fff'), $Text
    [void]$script:S.RunLog.AppendLine($line)
    $script:txtRun.AppendText($line + "`r`n")
    $script:txtRun.SelectionStart = $script:txtRun.TextLength
    $script:txtRun.ScrollToCaret()
}

function Read-NewFileText {
    # Which = 'Out' or 'Err'. Reads only the part of the capture file not read yet.
    param([string]$Which)
    $R = $script:Run
    $file = $R[$Which + 'File']
    if (-not $file -or -not (Test-Path -LiteralPath $file)) { return '' }
    try {
        $fs = New-Object System.IO.FileStream($file, 'Open', 'Read', ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try {
            $pos = [int64]$R[$Which + 'Pos']
            if ($fs.Length -le $pos) { return '' }
            [void]$fs.Seek($pos, 'Begin')
            $n = [int]([Math]::Min($fs.Length - $pos, 1MB))
            $buf = New-Object byte[] $n
            $got = $fs.Read($buf, 0, $n)
            $R[$Which + 'Pos'] = $pos + $got
            return [System.Text.Encoding]::Default.GetString($buf, 0, $got)
        } finally { $fs.Dispose() }
    } catch { return '' }
}

function Start-WatchedProcess {
    $exe = $script:txtRunExe.Text.Trim().Trim('"')
    if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { [void][System.Windows.Forms.MessageBox]::Show('Choose an existing EXE first.', $script:AppTitle, 'OK', 'Warning'); return }
    if ($script:Run.Proc -and -not $script:Run.Proc.HasExited) { [void][System.Windows.Forms.MessageBox]::Show('A watched process is still running. Stop it first.', $script:AppTitle, 'OK', 'Information'); return }
    $wd = $script:txtRunDir.Text.Trim().Trim('"')
    if (-not $wd -or -not (Test-Path -LiteralPath $wd -PathType Container)) { $wd = Split-Path -Parent $exe }
    $argText = $script:txtRunArgs.Text
    $msg = "This will really START the program on THIS computer:`r`n`r`n  $exe $argText`r`n  in: $wd`r`n`r`n" +
    "It will do whatever it normally does (change files, settings, talk to devices...).`r`nOnly continue if it is safe to run it here.`r`n`r`nStart it now?"
    if ([System.Windows.Forms.MessageBox]::Show($msg, "$($script:AppTitle) - confirm run", 'YesNo', 'Warning') -ne 'Yes') { return }
    $p = @{ FilePath = $exe; WorkingDirectory = $wd; PassThru = $true; ErrorAction = 'Stop' }
    if ($argText.Trim()) { $p.ArgumentList = $argText }
    $script:Run.OutFile = $null; $script:Run.ErrFile = $null; $script:Run.OutPos = 0; $script:Run.ErrPos = 0
    if ($script:chkCapture.Checked) {
        $tmp = [System.IO.Path]::GetTempPath()
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $script:Run.OutFile = Join-Path $tmp "ExeInspector_stdout_$stamp.txt"
        $script:Run.ErrFile = Join-Path $tmp "ExeInspector_stderr_$stamp.txt"
        $p.RedirectStandardOutput = $script:Run.OutFile
        $p.RedirectStandardError = $script:Run.ErrFile
    }
    $script:txtRun.Clear()
    [void]$script:S.RunLog.Clear()
    $script:Run.ExeName = [System.IO.Path]::GetFileName($exe)
    $script:Run.Start = Get-Date
    $rec = New-RunRecord $exe $argText $wd   # v5: created BEFORE Start-Process so start failures are recorded
    $rec.Start = $script:Run.Start; $rec.Captured = [bool]$script:chkCapture.Checked
    try { $rec.LogStart = Get-LogSnapshot } catch { }   # v8 (F17)
    Add-RunEvent 'Start requested' $script:Run.ExeName ("{0}   (start in: {1})" -f $rec.CommandLine, $wd)
    try {
        $proc = Start-Process @p
    } catch {
        $err = $_.Exception
        $inner = $err
        while ($inner.InnerException) { $inner = $inner.InnerException }
        Add-RunLog "FAILED TO START: $($err.Message)"
        if ($inner -is [System.ComponentModel.Win32Exception]) {
            Add-RunLog ("Windows error {0}: {1}" -f $inner.NativeErrorCode, (Get-ExitCodeText $inner.NativeErrorCode))
            if ($inner.NativeErrorCode -eq 740) { Add-RunLog 'Hint: untick "Capture console output" (that mode cannot show the UAC prompt) or run EXE Inspector as administrator.' }
            if ($inner.NativeErrorCode -eq 193 -or $inner.NativeErrorCode -eq 216) { Add-RunLog 'Hint: the file is not a valid program for this version/bitness of Windows.' }
            $rec.StartErrorCode = $inner.NativeErrorCode
        }
        $rec.StartError = $err.Message
        Close-RunRecord 'Start failed' $err.Message
        return
    }
    try { $null = $proc.Handle } catch { }   # caches the handle so ExitCode is available later
    $script:Run.Proc = $proc
    $script:Run.Tick = 0
    $script:Run.Known = @{ ([int]$proc.Id) = $script:Run.ExeName }
    $script:Run.Modules = $null
    $script:Run.Titles = @{}
    $script:Run.WerSeen = @{}
    $script:Run.CheckEvents = [bool]$script:chkAfterEvents.Checked
    $script:Run.Procs = @{ ([int]$proc.Id) = $proc }
    $script:Run.Done = @{}
    $script:Run.MainPid = [int]$proc.Id
    $script:Run.MainExited = $false
    $script:Run.DlgSeen = @{}
    $script:Run.MsiTip = @{}
    Add-RunLog "Started $($script:Run.ExeName)  PID $($proc.Id)  args: '$argText'  dir: $wd"
    $rec.MainPid = [int]$proc.Id; $rec.Status = 'Running'
    Add-RunProc ([int]$proc.Id) $script:Run.ExeName 0 $rec.CommandLine $true
    Add-RunEvent 'Started' $script:Run.ExeName ("PID {0}" -f $proc.Id)
    if ($script:chkCapture.Checked) { Add-RunLog 'Console output (stdout/stderr) is captured below as it appears.' }
    $imgBits = if ($script:S.PE -and $script:S.PE.Valid -and $script:S.Path -eq $exe) { if ($script:S.PE.Is64) { 64 } elseif ($script:S.PE.ClrAnyCpu -and -not $script:S.MD.Prefers32) { 0 } else { 32 } } else { 0 }
    if ($imgBits -eq 32 -and [Environment]::Is64BitProcess) { Add-RunLog 'Note: 32-bit program watched from 64-bit PowerShell - the loaded-DLL list may be incomplete.' }
    $script:btnRunStart.Enabled = $false
    $script:btnRunStop.Enabled = $true
    $script:Run.Timer.Start()
}

function Invoke-WatchTick {
    $R = $script:Run
    $proc = $R.Proc
    if (-not $proc) { $R.Timer.Stop(); return }
    $R.Tick++
    $o = Read-NewFileText 'Out'
    if ($o) { foreach ($l in ($o -split "`r?`n")) { if ($l -ne '') { Add-RunConsole 'OUT' $l } } }
    $e = Read-NewFileText 'Err'
    if ($e) { foreach ($l in ($e -split "`r?`n")) { if ($l -ne '') { Add-RunConsole 'ERR' $l } } }
    $exited = $false
    try { $exited = $proc.HasExited } catch { $exited = $true }
    if (-not $exited) {
        try {
            $proc.Refresh()
            $script:lblRunStatus.Text = ('Running  PID {0}   CPU {1:N1}s   Memory {2:N1} MB   Handles {3}   Threads {4}   Elapsed {5:N0}s' -f $proc.Id, $proc.TotalProcessorTime.TotalSeconds, ($proc.WorkingSet64 / 1MB), $proc.HandleCount, $proc.Threads.Count, ((Get-Date) - $R.Start).TotalSeconds)
            if ($proc.MainWindowTitle -and -not $R.Titles.ContainsKey($proc.MainWindowTitle)) { $R.Titles[$proc.MainWindowTitle] = $true; Add-RunLog "Window title: '$($proc.MainWindowTitle)'"; if ($script:CurRun) { $script:CurRun.Windows.Add("Main window title: '$($proc.MainWindowTitle)'") }; Add-RunEvent 'Window' $R.ExeName "Main window title: '$($proc.MainWindowTitle)'" }
        } catch { }
        if ($R.Tick -eq 2 -or ($R.Tick % 4 -eq 0)) {
            try {
                $mods = @($proc.Modules | ForEach-Object { $_.FileName })
                if ($null -eq $R.Modules) {
                    $R.Modules = @{}
                    foreach ($m in $mods) { $R.Modules[$m.ToLower()] = $true }
                    Add-RunLog "Loaded DLLs so far: $($mods.Count)"
                    foreach ($m in ($mods | Where-Object { $_ -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS|Microsoft\.NET|assembly)\\' })) { Add-RunLog "  DLL: $m"; if ($script:CurRun -and -not $script:CurRun.Dlls.Contains($m)) { $script:CurRun.Dlls.Add($m) }; Add-RunEvent 'DLL loaded' $R.ExeName $m }
                } else {
                    foreach ($m in $mods) { if (-not $R.Modules.ContainsKey($m.ToLower())) { $R.Modules[$m.ToLower()] = $true; Add-RunLog "  DLL loaded: $m"; if ($script:CurRun -and $m -notmatch $script:WinDirRx -and -not $script:CurRun.Dlls.Contains($m)) { $script:CurRun.Dlls.Add($m) }; Add-RunEvent 'DLL loaded' $R.ExeName $m } }
                }
            } catch { }
        }
        if ($R.Tick % 4 -eq 0) { Update-ChildProcesses }
        if ($R.Tick % 4 -eq 2) { Test-WatchDialogs }
        return
    }
    # ---- main process has exited ----
    if (-not $R.MainExited) {
        $R.MainExited = $true
        $R.Done[[int]$R.MainPid] = $true
        Update-ChildProcesses
        $code = $null
        try { $code = $proc.ExitCode } catch { }
        $R.MainCode = $code
        Set-RunProcExit ([int]$R.MainPid) $code
        if ($script:CurRun) { $script:CurRun.MainCode = $code }
        Add-RunEvent 'Main exit' $R.ExeName $(if ($null -ne $code) { Get-ExitCodeText ([int64]$code) } else { 'exit code not available' })
        $exName = Get-RunExitName $script:CurRun
        if ($exName -and $null -ne $code -and [int64]$code -ne 0) { Add-RunLog ("      The program printed '{0}' just before it exited - that is its name for exit code {1}." -f $exName, $code) }
        $dur = ((Get-Date) - $R.Start).TotalSeconds
        if ($null -ne $code) { Add-RunLog ("Main process exited after {0:N1}s with exit code {1}" -f $dur, (Get-ExitCodeText ([int64]$code))) }
        else { Add-RunLog ("Main process exited after {0:N1}s (exit code not available)" -f $dur) }
    }
    # keep watching while any child it started (installers, msiexec...) is still running
    if ($R.Tick % 2 -eq 0) { Update-ChildProcesses }
    $alive = Get-AliveTracked
    if ($alive.Count -gt 0) {
        $script:lblRunStatus.Text = ("Main exited (code {0}). Still running: {1}" -f $R.MainCode, (($alive | ForEach-Object { "$($R.Known[$_]) ($_)" }) -join ', '))
        if ($R.Tick % 4 -eq 2) { Test-WatchDialogs }
        return
    }
    # ---- everything has finished ----
    $R.Timer.Stop()
    Start-Sleep -Milliseconds 300
    $o = Read-NewFileText 'Out'; if ($o) { foreach ($l in ($o -split "`r?`n")) { if ($l -ne '') { Add-RunConsole 'OUT' $l } } }
    $e = Read-NewFileText 'Err'; if ($e) { foreach ($l in ($e -split "`r?`n")) { if ($l -ne '') { Add-RunConsole 'ERR' $l } } }
    $code = $R.MainCode
    $dur = ((Get-Date) - $R.Start).TotalSeconds
    if ($R.Known.Count -gt 1) { Add-RunLog ("All {0} watched processes finished after {1:N1}s." -f $R.Known.Count, $dur) }
    $script:lblRunStatus.Text = "Finished. Main exit code: $code"
    foreach ($f in $R.OutFile, $R.ErrFile) { if ($f -and (Test-Path -LiteralPath $f)) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } }
    $script:btnRunStart.Enabled = $true
    $script:btnRunStop.Enabled = $false
    if ($R.CheckEvents) {
        Add-RunLog 'Checking Windows event logs and crash reports for this run...'
        $since = $R.Start.AddSeconds(-5)
        $names = @($R.Known.Values | Select-Object -Unique)
        $rows = Get-RelatedErrorEvents $R.ExeName $since $true $false $names $true
        if ($rows.Count -eq 0) { Add-RunLog '  No related errors were logged by Windows.' }
        foreach ($x in $rows) {
            if ($script:CurRun) { $script:CurRun.WinEvents.Add($x) }
            Add-RunEvent 'Windows event' $x.Source ("[{0}] {1} ID {2}: {3}" -f $x.Log, $x.Level, $x.EventId, $x.Summary)
            Add-RunLog ("  [{0}] {1} / {2} (ID {3}): {4}" -f $x.Log, $x.Source, $x.Level, $x.EventId, $x.Summary)
            foreach ($dl in (($x.Detail -split "`r?`n") | Select-Object -First 25)) { if ($dl.Trim()) { Add-RunLog ('      ' + $dl.TrimEnd()) } }
        }
    }
    Close-RunRecord $(if ($script:CurRun -and $script:CurRun.StoppedByUser) { 'Stopped by user' } else { 'Finished' }) ("main exit code {0}, {1} process(es) watched" -f $code, $R.Known.Count)
    $R.Proc = $null
}

function Update-ChildProcesses {
    $R = $script:Run
    try {
        $all = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId, ParentProcessId, Name, CommandLine -ErrorAction Stop)
    } catch { return }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $all) {
            $id = [int]$p.ProcessId; $pp = [int]$p.ParentProcessId
            if ($R.Known.ContainsKey($pp) -and -not $R.Known.ContainsKey($id) -and $id -ne $pp) {
                $R.Known[$id] = $p.Name
                $changed = $true
                Add-RunLog "Child process started: $($p.Name) (PID $id, parent $pp)  $($p.CommandLine)"
                Add-RunProc $id ([string]$p.Name) $pp ([string]$p.CommandLine)
                Add-RunEvent 'Child started' ([string]$p.Name) ("PID {0}, parent {1}: {2}" -f $id, $pp, $p.CommandLine)
                try { $cp = Get-Process -Id $id -ErrorAction Stop; try { $null = $cp.Handle } catch { }; $R.Procs[$id] = $cp } catch { $R.Procs[$id] = $null }
                if ($p.Name -ieq 'msiexec.exe' -and $p.CommandLine -and $p.CommandLine -notmatch '(?i)\s[/-]l[*a-z+!]*\s' -and -not $R.MsiTip.ContainsKey($id)) {
                    $R.MsiTip[$id] = $true
                    Add-RunLog '      TIP: an MSI install started. Windows Installer steps are only visible in an MSI log. To get one, run that same command with a log switch, e.g.:'
                    Add-RunLog ('      ' + $p.CommandLine.Trim() + ' /l*v "C:\Temp\install.log"')
                    Add-RunLog '      Then search the log for "Return value 3" - the lines just above it show the failing step.'
                }
            }
        }
    }
    foreach ($p in $all) {
        if ($p.Name -match '^(WerFault|WerFaultSecure)\.exe$' -and $p.CommandLine) {
            foreach ($id in @($R.Known.Keys)) {
                if ($p.CommandLine -match ('-p\s+' + $id + '\b') -and -not $R.WerSeen.ContainsKey([int]$p.ProcessId)) {
                    $R.WerSeen[[int]$p.ProcessId] = $true
                    Add-RunLog "!!! Windows Error Reporting started for PID $id ($($R.Known[$id])) - the program has CRASHED or HUNG. Details will appear in Error History."
                    $werTxt = "WerFault started for PID $id ($($R.Known[$id])): $($p.CommandLine)"
                    if ($script:CurRun) { $script:CurRun.WerSeen.Add($werTxt) }
                    Add-RunEvent 'WER (crash/hang)' ([string]$R.Known[$id]) $werTxt
                }
            }
        }
    }
}

function Stop-WatchedProcess {
    $proc = $script:Run.Proc
    if (-not $proc) { return }
    $mainAlive = $false
    try { $mainAlive = -not $proc.HasExited } catch { }
    $alive = Get-AliveTracked
    if (-not $mainAlive -and $alive.Count -eq 0) { return }
    $r = [System.Windows.Forms.MessageBox]::Show("Force-stop $($script:Run.ExeName) and the processes it started?`r`n`r`nYes = stop it and all its child processes`r`nNo  = stop only the main process", $script:AppTitle, 'YesNoCancel', 'Warning')
    if ($r -eq 'Cancel') { return }
    if ($script:CurRun) { $script:CurRun.StoppedByUser = $true }
    Add-RunEvent 'Stop requested' $script:Run.ExeName $(if ($r -eq 'Yes') { 'main process and all child processes' } else { 'main process only' })
    try {
        $tk = Join-Path $env:windir 'System32\taskkill.exe'
        if ($r -eq 'Yes') {
            $ids = New-Object System.Collections.Generic.List[int]
            if ($mainAlive) { $ids.Add([int]$proc.Id) }
            foreach ($a in $alive) { $ids.Add([int]$a) }
            foreach ($id in ($ids | Select-Object -Unique)) {
                $outp = & $tk /PID $id /T /F 2>&1
                Add-RunLog ("Stop requested for PID {0} (taskkill /T /F): {1}" -f $id, (($outp | Out-String).Trim()))
            }
        } elseif ($mainAlive) { $proc.Kill(); Add-RunLog 'Stop requested (main process only).' }
    } catch { Add-RunLog "Stop failed: $($_.Exception.Message)" }
}

# ---------------- Error history ----------------
function Get-RelatedErrorEvents {
    param([string]$ExeName, [datetime]$Since, [bool]$IncludeWer = $true, [bool]$IncludeSystem = $false, [string[]]$ExtraNames = @(), [bool]$IncludeMsi = $false)
    $rows = New-Object System.Collections.Generic.List[object]
    $base = [System.IO.Path]::GetFileNameWithoutExtension($ExeName)
    $queries = @(@{ LogName = 'Application'; StartTime = $Since; Level = 1, 2, 3 }, @{ LogName = 'Application'; StartTime = $Since; ProviderName = 'Windows Error Reporting' })
    if ($IncludeSystem) { $queries += @{ LogName = 'System'; StartTime = $Since; Level = 1, 2, 3 } }
    if ($IncludeMsi) { $queries += @{ LogName = 'Application'; StartTime = $Since; ProviderName = 'MsiInstaller' } }
    $names = @($ExeName) + @($ExtraNames | Where-Object { $_ -and $_ -ine $ExeName })
    $seen = @{}
    foreach ($q in $queries) {
        $evts = @()
        try { $evts = @(Get-WinEvent -FilterHashtable $q -MaxEvents 20000 -ErrorAction Stop) } catch { }
        foreach ($ev in $evts) {
            $key = "$($ev.LogName)|$($ev.RecordId)"
            if ($seen.ContainsKey($key)) { continue }
            $msg = $null
            try { $msg = $ev.Message } catch { }
            if (-not $msg) { try { $msg = (($ev.Properties | ForEach-Object { $_.Value }) -join ' | ') } catch { $msg = '' } }
            if ($null -eq $msg) { $msg = '' }
            $hit = $false
            foreach ($nm in $names) { if ($msg.IndexOf($nm, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break } }
            if (-not $hit -and $IncludeMsi -and $ev.ProviderName -eq 'MsiInstaller') { $hit = $true }
            if (-not $hit -and $ev.ProviderName -eq 'SideBySide' -and $msg.IndexOf($base, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true }
            if (-not $hit) { continue }
            $seen[$key] = $true
            $first = ($msg -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
            $explain = switch ($ev.ProviderName) {
                'Application Error' { 'CRASH: ' } 'Application Hang' { 'HANG (stopped responding): ' } '.NET Runtime' { '.NET UNHANDLED EXCEPTION: ' }
                'SideBySide' { 'SIDE-BY-SIDE / VC++ RUNTIME PROBLEM: ' } 'Windows Error Reporting' { 'Crash report: ' } 'MsiInstaller' { 'Windows Installer: ' } default { '' }
            }
            $rows.Add([pscustomobject]@{ Time = $ev.TimeCreated; Log = $ev.LogName; Source = $ev.ProviderName; EventId = $ev.Id; Level = $ev.LevelDisplayName; Summary = ($explain + $first); Detail = $msg })
        }
    }
    if ($IncludeWer) {
        foreach ($w in (Get-WerReports $ExeName $Since)) { $rows.Add($w) }
    }
    return , @($rows | Sort-Object Time -Descending)
}

function Get-WerReports {
    param([string]$ExeName, [datetime]$Since)
    $out = New-Object System.Collections.Generic.List[object]
    $roots = @()
    if ($env:ProgramData) { $roots += (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportArchive'), (Join-Path $env:ProgramData 'Microsoft\Windows\WER\ReportQueue') }
    if ($env:LOCALAPPDATA) { $roots += (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive'), (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportQueue') }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $dirs = @()
        try { $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $Since } | Sort-Object LastWriteTime -Descending | Select-Object -First 500) } catch { continue }
        foreach ($d in $dirs) {
            $wer = Join-Path $d.FullName 'Report.wer'
            if (-not (Test-Path -LiteralPath $wer)) { continue }
            $text = $null
            try { $text = Get-Content -LiteralPath $wer -Raw -ErrorAction Stop } catch { continue }
            if (-not $text) { continue }
            $kv = @{}
            foreach ($ln in ($text -split "`r?`n")) { $i = $ln.IndexOf('='); if ($i -gt 0) { $kv[$ln.Substring(0, $i)] = $ln.Substring($i + 1) } }
            $appMatch = $false
            foreach ($k in 'AppName', 'OriginalFilename', 'Sig[0].Value') { if ($kv.ContainsKey($k) -and $kv[$k] -ieq $ExeName) { $appMatch = $true } }
            if ($kv.ContainsKey('AppPath') -and ([System.IO.Path]::GetFileName($kv['AppPath']) -ieq $ExeName)) { $appMatch = $true }
            if (-not $appMatch -and $d.Name.IndexOf([System.IO.Path]::GetFileNameWithoutExtension($ExeName), [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            if (-not $appMatch -and $d.Name -notmatch '(?i)^(AppCrash|AppHang|BEX|BEX64|CLR20r3|APPCRASH|MoAppCrash|Critical)_') { continue }
            $sig = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt 12; $i++) { $n = "Sig[$i].Name"; $v = "Sig[$i].Value"; if ($kv.ContainsKey($n) -and $kv.ContainsKey($v)) { $sig.Add("$($kv[$n]) = $($kv[$v])") } }
            $evtType = if ($kv.ContainsKey('EventType')) { $kv['EventType'] } else { $d.Name.Split('_')[0] }
            $short = @()
            foreach ($s in $sig) { if ($s -match '^(Fault Module Name|Exception Code|Problem Signature 0[59]|P[59]|Exception Offset)') { $short += $s } }
            $detail = "Report folder: $($d.FullName)`r`nEvent type: $evtType`r`n" + ($sig -join "`r`n")
            if ($evtType -eq 'CLR20r3') { $detail += "`r`n(CLR20r3: Problem Signature 09 is the .NET exception type, 07/08 locate the failing method)" }
            $mods = @($kv.Keys | Where-Object { $_ -like 'LoadedModule*' } | ForEach-Object { $kv[$_] } | Where-Object { $_ -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS|Microsoft\.NET|assembly)\\' })
            if ($mods.Count -gt 0) { $detail += "`r`nNon-Windows modules loaded at crash time:`r`n  " + ($mods -join "`r`n  ") }
            $out.Add([pscustomobject]@{ Time = $d.LastWriteTime; Log = 'WER'; Source = (Split-Path -Leaf $root); EventId = 0; Level = 'Report'; Summary = ("{0}: {1}" -f $evtType, ($short -join '; ')); Detail = $detail })
        }
    }
    return , $out
}

function Invoke-ErrorHistorySearch {
    $S = $script:S
    $name = $script:txtErrExe.Text.Trim()
    if (-not $name) { [void][System.Windows.Forms.MessageBox]::Show('Enter the EXE file name (for example dconvert.exe).', $script:AppTitle, 'OK', 'Information'); return }
    if ($name -notmatch '\.(exe|dll)$') { $name += '.exe' }
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    Set-Status 'Searching event logs...'
    try {
        $since = (Get-Date).AddDays(-[int]$script:numDays.Value)
        $rows = Get-RelatedErrorEvents $name $since ([bool]$script:chkWer.Checked) ([bool]$script:chkSysLog.Checked)
        $S.ErrorRows = $rows
        $S.ErrorSearch = [pscustomobject]@{ Name = $name; Days = [int]$script:numDays.Value; Wer = [bool]$script:chkWer.Checked; SysLog = [bool]$script:chkSysLog.Checked; Time = (Get-Date) }
        $t = New-DataTableEx @('Time', 'Log', 'Source', 'Event ID:int', 'Level', 'Summary', '_Idx:int')
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $x = $rows[$i]
            [void]$t.Rows.Add(('{0:yyyy-MM-dd HH:mm:ss}' -f $x.Time), $x.Log, $x.Source, [int64]$x.EventId, $x.Level, $x.Summary, [int64]$i)
        }
        $script:gridErr.DataSource = $t
        Set-GridColumnWidths $script:gridErr @{ 'Time' = 135; 'Log' = 85; 'Source' = 150; 'Event ID' = 65; 'Level' = 70 } 'Summary'
        Show-Text $script:txtErr $(if ($rows.Count -eq 0) { "No events or crash reports mentioning $name in the last $($script:numDays.Value) day(s).`r`n(Reading some logs/reports needs administrator rights.)" } else { 'Select a row to see the full event text.' })
        Write-Log "Error History: $($rows.Count) item(s) for $name"
    } catch { Write-Log "Error History: $($_.Exception.Message)" 'ERROR' }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default; Set-Status 'Ready' }
}

# ---------------- Export ----------------
function Export-Report {
    $S = $script:S
    if (-not $S.Path) { [void][System.Windows.Forms.MessageBox]::Show('Analyse a file first.', $script:AppTitle, 'OK', 'Information'); return }
    if ($script:CurRun -and -not $script:CurRun.End) {
        # v6 (F12): a watched run is still in progress
        $q = "Run #$($script:CurRun.No) ($($script:CurRun.ExeName)) is still being watched.`r`n`r`nExport now? That run will be marked PARTIAL - its exit codes, later dialogs and the Windows events checked after it exits are not in the report yet.`r`n`r`nYes = export now`r`nNo  = cancel (export again when it has finished)"
        if ([System.Windows.Forms.MessageBox]::Show($q, $script:AppTitle, 'YesNo', 'Warning') -ne 'Yes') { return }
        $script:CurRun.PartialExports++
    }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Choose where to save the report folder'
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $withIL = $false
    if ($S.MD -and $S.MD.Valid) {
        $withIL = ([System.Windows.Forms.MessageBox]::Show("Also write the IL steps of ALL $($S.MD.RowCount[6]) methods? (can take a while for big programs)", $script:AppTitle, 'YesNo', 'Question') -eq 'Yes')
    }
    $dir = Join-Path $dlg.SelectedPath ('ExeInspector_{0}_{1}' -f (Get-SafeFileName ([System.IO.Path]::GetFileNameWithoutExtension($S.Path))), (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir '01_Overview.txt') -Value $S.Overview -Encoding UTF8
        if ($S.Deps) { $S.Deps | Select-Object Dll, Status, Path, RequiredBy, Kind, Functions, Level | Export-Csv -LiteralPath (Join-Path $dir '02_Dependencies.csv') -NoTypeInformation -Encoding UTF8 }
        if ($S.Imports.Count -gt 0) { $S.Imports | Select-Object Dll, Function, Kind, @{ n = 'Category'; e = { Get-ApiCategory $_.Dll $_.Function } } | Export-Csv -LiteralPath (Join-Path $dir '03_Imports.csv') -NoTypeInformation -Encoding UTF8 }
        if ($S.StringTable) {
            $S.StringTable.Rows | ForEach-Object { [pscustomobject]@{ Offset = $_['Offset']; Encoding = $_['Encoding']; Category = $_['Category']; LikelyNoise = $_['_Noise']; Text = $_['Text'] } } |
                Export-Csv -LiteralPath (Join-Path $dir '04_Strings.csv') -NoTypeInformation -Encoding UTF8
        }
        if ($S.AllRes.Count -gt 0) { $S.AllRes | Select-Object Source, Type, Name, Lang, Size | Export-Csv -LiteralPath (Join-Path $dir '05_Resources.csv') -NoTypeInformation -Encoding UTF8 }
        if ($S.PS -and $S.PS.Found) { Set-Content -LiteralPath (Join-Path $dir ('06_Recovered_' + (Get-SafeFileName $(if ($S.PS.Name -like '*.ps1') { $S.PS.Name } else { 'script.ps1' })))) -Value $S.PS.Script -Encoding UTF8 }
        if ($S.MD -and $S.MD.Valid) {
            $md = $S.MD
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('=== EXTERNAL CALLS ===')
            for ($i = 1; $i -le $md.RowCount[0x0A]; $i++) { $n = Get-MdMemberRefName $md $i -WithSig; [void]$sb.AppendLine(('{0,-28} {1}' -f (Get-NetCategory $n), $n)) }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('=== P/INVOKE (native DLL calls) ===')
            foreach ($p in $S.PInvoke) { [void]$sb.AppendLine("$($p.Dll) ! $($p.Function)  <- $($p.Managed)") }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('=== ASSEMBLY REFERENCES ===')
            foreach ($a in $S.AsmRefs) { [void]$sb.AppendLine("$($a.Name) $($a.Version) $($a.PublicKeyToken)") }
            [void]$sb.AppendLine(''); [void]$sb.AppendLine('=== STRING LITERALS ===')
            foreach ($u in (Get-AllUserStrings $md)) { [void]$sb.AppendLine($u.Text.Replace("`r", '\r').Replace("`n", '\n')) }
            Set-Content -LiteralPath (Join-Path $dir '07_DotNet_Members.txt') -Value $sb.ToString() -Encoding UTF8
            if ($withIL) {
                $w = New-Object System.IO.StreamWriter((Join-Path $dir '08_DotNet_IL_AllMethods.txt'), $false, [System.Text.Encoding]::UTF8)
                try {
                    for ($m = 1; $m -le $md.RowCount[6]; $m++) {
                        if ($m % 200 -eq 0) { Set-Status ("Writing IL {0}/{1}..." -f $m, $md.RowCount[6]) }
                        try { $w.WriteLine((Format-ILListing $md $m)) } catch { $w.WriteLine("// method $m could not be decoded: $($_.Exception.Message)") }
                    }
                } finally { $w.Dispose() }
            }
        }
        if ($S.RunLog.Length -gt 0) { Set-Content -LiteralPath (Join-Path $dir '09_RunWatch_Log.txt') -Value $S.RunLog.ToString() -Encoding UTF8 }
        if ($S.ErrorRows -and $S.ErrorRows.Count -gt 0) { $S.ErrorRows | Select-Object Time, Log, Source, EventId, Level, Summary, Detail | Export-Csv -LiteralPath (Join-Path $dir '10_ErrorHistory.csv') -NoTypeInformation -Encoding UTF8 }
        $null = Export-ReportAnalysis $dir   # v5: 00_Findings.txt + 11-14
        Write-Log "Report saved to $dir"
        if ([System.Windows.Forms.MessageBox]::Show("Report saved to:`r`n$dir`r`n`r`nOpen the folder?", $script:AppTitle, 'YesNo', 'Information') -eq 'Yes') { Start-Process explorer.exe -ArgumentList "`"$dir`"" }
    } catch { Write-Log "Export failed: $($_.Exception.Message)" 'ERROR' }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default; Set-Status 'Ready' }
}


# =====================================================================
#  v3 GUI additions: Related Files, Dialog Finder, UI Automation capture
# =====================================================================
$script:History = New-Object System.Collections.Generic.Stack[string]
$script:CandCache = @{}
$script:CauseRows = $null
$script:DlgWindows = $null
$script:UiaReady = $null
$script:RelatedExts = 'dll|exe|ocx|sys|ps1|psm1|bat|cmd|vbs|js|ini|cfg|config|xml|json|txt|mdb|accdb|csv|sql|reg|msi|env|acl|log'   # v8: + log
$script:LastLogCandidates = $null

# ---------------- related files ----------------
function Get-RelatedFiles {
    $S = $script:S
    $list = New-Object System.Collections.Generic.List[object]
    if (-not $S.Path) { return , $list }
    $exeDir = Split-Path -Parent $S.Path
    $seen = @{}
    $seen[$S.Path.ToLower()] = $true
    $win = if ($env:windir) { $env:windir.ToLower() } else { '' }
    $add = {
        param([string]$p, [string]$why)
        try {
            if (-not $p) { return }
            $full = [System.IO.Path]::GetFullPath($p)
            $k = $full.ToLower()
            if ($seen.ContainsKey($k)) { return }
            if ($win -and $k.StartsWith($win + '\')) { return }   # Windows' own files are not decoded
            if (-not [System.IO.File]::Exists($full)) { return }
            $seen[$k] = $true
            $fi = New-Object System.IO.FileInfo($full)
            $list.Add([pscustomobject]@{ Name = $fi.Name; Why = $why; Size = $fi.Length; Path = $full; Res = $null })
        } catch { }
    }
    if ($S.Deps) { foreach ($d in $S.Deps) { if ($d.Path -and $d.Status -like 'OK*') { & $add $d.Path ("DLL it loads ({0}, level {1})" -f $d.Kind, $d.Level) } } }
    foreach ($a in $S.AsmRefs) { foreach ($ext in '.dll', '.exe') { & $add (Join-Path $exeDir ($a.Name + $ext)) '.NET assembly reference' } }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($S.Path)
    & $add ($S.Path + '.config') 'configuration file (.exe.config)'
    foreach ($ext in '.ini', '.cfg', '.xml', '.json', '.config') { & $add (Join-Path $exeDir ($base + $ext)) 'same-name settings file' }
    # file names / paths written in the program's text (and in a recovered script)
    $texts = New-Object System.Collections.Generic.List[string]
    if ($S.Strings) { foreach ($s1 in $S.Strings) { if ($s1.Text -match ('(?i)\.(' + $script:RelatedExts + ')\b')) { $texts.Add($s1.Text) } } }
    if ($S.PS -and $S.PS.Found) { $texts.Add($S.PS.Script) }
    $tested = 0
    $rxAbs = '(?i)[A-Za-z]:\\[^"*?<>|\r\n\t]{1,240}?\.(' + $script:RelatedExts + ')\b'
    $rxRel = '(?i)(?<![\w\\:/.-])([\w\- ]{1,80}\\)*[\w\-.]{1,100}\.(' + $script:RelatedExts + ')\b'
    foreach ($t in $texts) {
        if ($tested -gt 3000) { break }
        foreach ($m in [regex]::Matches($t, $rxAbs)) { $tested++; & $add $m.Value 'named in the program (full path)' }
        foreach ($m in [regex]::Matches($t, $rxRel)) {
            $tested++
            $v = $m.Value.Trim()
            if ($v -match '^\.') { continue }
            & $add (Join-Path $exeDir $v) 'named in the program'
        }
    }
    # v8 (F16): paths the program builds from pieces (folder text + file text), also inside its .NET helper DLLs
    try {
        $dllPaths = @($list | Where-Object { $_.Path -match '(?i)\.(dll|exe)$' -and $_.Path -ne '<embedded>' } | ForEach-Object { $_.Path })
        $pc = Get-PathPieceCandidates (Get-ProgramTextSets $dllPaths)
        foreach ($x in $pc.Found) { & $add $x.Path $x.Why }
        $script:LastLogCandidates = $pc.Logs
    } catch { $script:LastLogCandidates = $null }
    # programs packed inside this file (embedded resources / Costura)
    foreach ($r in $S.ManagedRes) {
        if (Test-EmbeddedProgram $S.Bytes $r) { $list.Add([pscustomobject]@{ Name = $r.Name; Why = 'embedded inside this file (.NET resource)'; Size = $r.Size; Path = '<embedded>'; Res = $r }) }
    }
    foreach ($r in $S.NativeRes) {
        if ($r.TypeId -eq 10 -and (Test-EmbeddedProgram $S.Bytes $r)) { $list.Add([pscustomobject]@{ Name = "RCDATA $($r.Name)"; Why = 'embedded inside this file (native resource)'; Size = $r.Size; Path = '<embedded>'; Res = $r }) }
    }
    return , $list
}

function Update-RelatedTab {
    $S = $script:S
    $S.Related = Get-RelatedFiles
    try { $S.ProgramLogs = Get-ProgramLogs } catch { $S.ProgramLogs = $null }   # v8 (F17)
    $t = New-DataTableEx @('Name', 'Why it is related', 'Size:int', 'Path', '_Idx:int')
    for ($i = 0; $i -lt $S.Related.Count; $i++) { $r = $S.Related[$i]; [void]$t.Rows.Add($r.Name, $r.Why, [int64]$r.Size, $r.Path, [int64]$i) }
    $script:gridRel.DataSource = $t
    Set-GridColumnWidths $script:gridRel @{ 'Name' = 220; 'Why it is related' = 280; 'Size' = 90 } 'Path'
    $script:lblRel.Text = "{0} related file(s). Double-click one (or 'Decode selected') to analyse it; 'Back' returns here. Dialog Finder searches all of them." -f $S.Related.Count
    $script:btnBack.Enabled = ($script:History.Count -gt 0)
}

function Save-EmbeddedToTemp {
    param([byte[]]$Data, [string]$Name)
    $dir = Join-Path ([System.IO.Path]::GetTempPath()) 'ExeInspector'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $n = Get-SafeFileName (($Name -replace '(?i)^costura\.', '') -replace '(?i)\.compressed$', '')
    if ($n -notmatch '\.(dll|exe)$') { $n += '.bin' }
    $p = Join-Path $dir $n
    [System.IO.File]::WriteAllBytes($p, $Data)
    return $p
}

function Open-RelatedSelected {
    $row = $script:gridRel.CurrentRow
    if (-not $row) { return }
    $r = $script:S.Related[[int]$row.Cells['_Idx'].Value]
    $target = $r.Path
    if ($r.Res) {
        $data = Expand-EmbeddedBytes (Get-ResourceBytes $script:S.Bytes $r.Res) ([string]$r.Res.Name)
        $target = Save-EmbeddedToTemp $data ([string]$r.Res.Name)
        Write-Log "Extracted embedded file to $target"
    }
    $script:txtPath.Text = $target
    Invoke-Analysis $target -Navigate
}

function Invoke-Back {
    if ($script:History.Count -eq 0) { return }
    $p = $script:History.Pop()
    $script:txtPath.Text = $p
    Invoke-Analysis $p
}

# ---------------- UI Automation (built into Windows / .NET) ----------------
function Initialize-Uia {
    if ($null -ne $script:UiaReady) { return $script:UiaReady }
    try {
        Add-Type -AssemblyName UIAutomationClient -ErrorAction Stop
        Add-Type -AssemblyName UIAutomationTypes -ErrorAction Stop
        $script:UiaReady = $true
    } catch {
        $script:UiaReady = $false
        Write-Log "UI Automation is not available on this PC ($($_.Exception.Message)). Paste the dialog text instead (Ctrl+C on a message box copies it)." 'WARN'
    }
    return $script:UiaReady
}

function Get-OpenWindows {
    param([bool]$DialogsOnly = $true, $OnlyPids = $null)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Initialize-Uia)) { return , $out }
    $AE = [System.Windows.Automation.AutomationElement]
    $winCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, [System.Windows.Automation.ControlType]::Window)
    $tops = $AE::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
    $names = @{}
    $seenH = @{}
    foreach ($w in $tops) {
        $els = New-Object System.Collections.Generic.List[object]
        $els.Add($w)
        try { foreach ($cw in $w.FindAll([System.Windows.Automation.TreeScope]::Children, $winCond)) { $els.Add($cw) } } catch { }
        foreach ($el in $els) {
            try {
                $cur = $el.Current
                $wpid = [int]$cur.ProcessId
                if ($wpid -eq $PID) { continue }
                if ($OnlyPids -and ($OnlyPids -notcontains $wpid)) { continue }
                $h = [int64]$cur.NativeWindowHandle
                if ($h -ne 0 -and $seenH.ContainsKey($h)) { continue }
                $seenH[$h] = $true
                $cls = [string]$cur.ClassName; $title = [string]$cur.Name
                $isDlg = ($cls -eq '#32770') -or ($title -match '(?i)error|warning|exception|fail|problem|cannot|unable|alert|setup|install|message')
                if ($DialogsOnly -and -not $isDlg) { continue }
                if (-not $names.ContainsKey($wpid)) { $pn = '?'; try { $pn = (Get-Process -Id $wpid -ErrorAction Stop).ProcessName } catch { }; $names[$wpid] = $pn }
                $out.Add([pscustomobject]@{ Process = $names[$wpid]; Pid = $wpid; Title = $title; Class = $cls; Handle = $h; IsDialog = $isDlg; Element = $el })
            } catch { }
        }
    }
    return , $out
}

function Get-UiaWindowText {
    param($Element)
    $res = [pscustomobject]@{ Title = ''; Lines = (New-Object System.Collections.Generic.List[string]); Buttons = (New-Object System.Collections.Generic.List[string]) }
    try { $res.Title = [string]$Element.Current.Name } catch { }
    $seen = @{}
    $all = $null
    try { $all = $Element.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition) } catch { try { foreach ($l in (Get-UiaRawText $Element $res.Title $res.Buttons)) { $res.Lines.Add($l) } } catch { }; return $res }
    $n = 0
    foreach ($d in $all) {
        $n++
        if ($n -gt 1500) { break }
        try {
            $ct = $d.Current.ControlType.ProgrammaticName
            $nm = [string]$d.Current.Name
            $val = $null
            if ($ct -eq 'ControlType.Button') { if ($nm.Trim()) { $res.Buttons.Add($nm.Replace('&', '')) }; continue }
            if ($ct -eq 'ControlType.Edit' -or $ct -eq 'ControlType.Document') {
                $pat = $null
                if ($d.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pat)) { $val = $pat.Current.Value }
                if (-not $val) {
                    $pat = $null
                    if ($d.TryGetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern, [ref]$pat)) { $val = $pat.DocumentRange.GetText(50000) }
                }
            } elseif ($ct -eq 'ControlType.Text' -or $ct -eq 'ControlType.ListItem' -or $ct -eq 'ControlType.Hyperlink') { $val = $nm }
            if ($val -and $val.Trim() -and -not $seen.ContainsKey($val)) { $seen[$val] = $true; $res.Lines.Add($val.Trim()) }
        } catch { }
    }
    if ($res.Lines.Count -eq 0) {
        # v7 (F14): nothing readable in the normal pass - try the raw tree
        try { foreach ($l in (Get-UiaRawText $Element $res.Title $res.Buttons)) { $res.Lines.Add($l) } } catch { }
    }
    return $res
}

function Get-UiaRawText {
    # v7 (F14): second pass over the RAW UI Automation tree. Some message boxes expose their text as an element the
    # normal pass skips (not a Text control, or only visible in the raw view). Any named element that is not a
    # button / title bar / menu / scroll bar is taken as text.
    param($Element, [string]$Title, $Buttons)
    $lines = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    if ($Title) { $seen[$Title] = $true }
    foreach ($b in $Buttons) { $seen[[string]$b] = $true }
    $skip = '^ControlType\.(Button|TitleBar|MenuBar|Menu|MenuItem|ScrollBar|Thumb|Window|SplitButton|ToolBar|StatusBar)$'
    try { $walker = [System.Windows.Automation.TreeWalker]::RawViewWalker } catch { return , $lines }
    $stack = New-Object System.Collections.Generic.Stack[object]
    try { $c = $walker.GetFirstChild($Element) } catch { $c = $null }
    while ($null -ne $c) { $stack.Push($c); try { $c = $walker.GetNextSibling($c) } catch { $c = $null } }
    $n = 0
    while ($stack.Count -gt 0 -and $n -lt 2000) {
        $el = $stack.Pop(); $n++
        try {
            $ct = [string]$el.Current.ControlType.ProgrammaticName
            $nm = [string]$el.Current.Name
            $val = $null
            $pat = $null
            try { if ($el.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pat)) { $val = [string]$pat.Current.Value } } catch { }
            foreach ($t in @($nm, $val)) {
                if (-not $t -or -not $t.Trim()) { continue }
                if ($ct -match $skip -and $t -eq $nm) { continue }
                $tt = $t.Trim()
                if ($seen.ContainsKey($tt) -or $seen.ContainsKey($tt.Replace('&', ''))) { continue }
                $seen[$tt] = $true
                $lines.Add($tt)
            }
        } catch { }
        $kids = New-Object System.Collections.Generic.List[object]
        try { $k = $walker.GetFirstChild($el) } catch { $k = $null }
        while ($null -ne $k) { $kids.Add($k); try { $k = $walker.GetNextSibling($k) } catch { $k = $null } }
        for ($i = $kids.Count - 1; $i -ge 0; $i--) { $stack.Push($kids[$i]) }
    }
    return , $lines
}

function Format-CapturedDialog {
    param($Win, $Cap)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine($Cap.Title)
    foreach ($l in $Cap.Lines) { [void]$sb.AppendLine($l) }
    if ($Cap.Buttons.Count) { [void]$sb.AppendLine('[Buttons: ' + ($Cap.Buttons -join ', ') + ']') }
    return $sb.ToString()
}

function Update-WindowList {
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        $wins = Get-OpenWindows ([bool]$script:chkDlgOnly.Checked)
        $script:DlgWindows = $wins
        $t = New-DataTableEx @('Process', 'PID:int', 'Title', 'Class', '_Idx:int')
        for ($i = 0; $i -lt $wins.Count; $i++) { $w = $wins[$i]; [void]$t.Rows.Add($w.Process, [int64]$w.Pid, $w.Title, $w.Class, [int64]$i) }
        $script:gridWin.DataSource = $t
        Set-GridColumnWidths $script:gridWin @{ 'Process' = 120; 'PID' = 55; 'Class' = 140 } 'Title'
        $script:lblDlg.Text = "$($wins.Count) window(s). Select the error/warning box and press 'Capture text'. (Untick 'Only dialog boxes' to see every window.)"
    } catch { Write-Log "Window list: $($_.Exception.Message)" 'ERROR' }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Invoke-CaptureSelectedWindow {
    $row = $script:gridWin.CurrentRow
    if (-not $row -or -not $script:DlgWindows) { return }
    $w = $script:DlgWindows[[int]$row.Cells['_Idx'].Value]
    $cap = Get-UiaWindowText $w.Element
    $txt = Format-CapturedDialog $w $cap
    if ($cap.Lines.Count -eq 0) {
        Write-Log "No readable text in '$($w.Title)'. If that program runs as administrator, run EXE Inspector as administrator too, or click the box and press Ctrl+C, then paste here." 'WARN'
    }
    $script:txtDlgText.Text = $txt
    $exe = $null
    try { $exe = (Get-Process -Id $w.Pid -ErrorAction Stop).Path } catch { }
    if (-not $exe) { try { $exe = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($w.Pid)" -ErrorAction Stop).ExecutablePath } catch { } }
    $script:DlgOwnerExe = $exe
    $null = Add-DialogCapture 'Dialog Finder - captured window' $w.Process $w.Pid $w.Title $txt $exe
    $msg = "Captured '$($w.Title)' from $($w.Process) (PID $($w.Pid))"
    if ($exe) { $msg += " - $exe" }
    Write-Log $msg
    if ($exe -and $script:S.Path -and ($exe -ine $script:S.Path)) {
        $r = [System.Windows.Forms.MessageBox]::Show("This box belongs to:`r`n$exe`r`n`r`nThe file currently analysed is:`r`n$($script:S.Path)`r`n`r`nAnalyse the program that owns the box first? (recommended)", $script:AppTitle, 'YesNo', 'Question')
        if ($r -eq 'Yes') { $script:txtPath.Text = $exe; Invoke-Analysis $exe -Navigate; $script:tabs.SelectedTab = $script:tabDlg; $script:txtDlgText.Text = $txt }
    }
}

# ---------------- message source search ----------------
function Get-CachedSources {
    param([string]$Path, [byte[]]$Bytes = $null)
    $key = $Path.ToLower()
    try { $fi = New-Object System.IO.FileInfo($Path); $key = "$key|$($fi.Length)|$($fi.LastWriteTimeUtc.Ticks)" } catch { }
    if ($script:CandCache.ContainsKey($key)) { return $script:CandCache[$key] }
    if ($null -eq $Bytes) { $Bytes = Read-FileBytesShared $Path }
    $src = Get-SearchSources $Bytes ([System.IO.Path]::GetFileName($Path)) $Path 0
    $script:CandCache[$key] = $src
    return $src
}

function Invoke-FindCause {
    param([switch]$Quiet)
    $S = $script:S
    $text = $script:txtDlgText.Text
    if (-not $text -or -not $text.Trim()) { if (-not $Quiet) { [void][System.Windows.Forms.MessageBox]::Show('Capture a dialog box or paste its text first.', $script:AppTitle, 'OK', 'Information') }; return @() }
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($k in (Get-KnownMessageExplanation $text)) {
            $rows.Add([pscustomobject]@{ Score = 100; Kind = 'Known Windows/runtime message'; Where = $k.Title; Source = '(built-in knowledge)'; Text = $k.Explanation; R = $null; Frame = $null })
        }
        $sources = New-Object System.Collections.Generic.List[object]
        if ($S.Path -and $S.Bytes) {
            Set-Status 'Decoding the analysed file...'
            foreach ($x in (Get-CachedSources $S.Path $S.Bytes)) { $sources.Add($x) }
        }
        if ($script:chkDlgRelated.Checked -and $S.Related) {
            $n = 0
            foreach ($rf in $S.Related) {
                if ($rf.Res -or $rf.Size -gt 60MB) { continue }   # embedded programs are already searched with their parent
                $n++
                if ($n -gt 60) { Write-Log 'Searched the first 60 related files only.' 'WARN'; break }
                Set-Status ("Decoding related file {0}: {1}" -f $n, $rf.Name)
                try { foreach ($x in (Get-CachedSources $rf.Path)) { $sources.Add($x) } } catch { Write-Log "Could not read $($rf.Path): $($_.Exception.Message)" 'WARN' }
            }
        }
        Set-Status 'Matching the message...'
        foreach ($m in (Find-MessageSource $text $sources)) {
            $rows.Add([pscustomobject]@{ Score = $m.Score; Kind = $m.Kind; Where = $m.Where; Source = $m.Source; Text = $m.Text; R = $m; Frame = $null })
        }
        foreach ($f in (Get-StackFrames $text)) {
            foreach ($src in $sources) {
                if (-not $src.MD) { continue }
                foreach ($rid in (Find-MethodByFrame $src.MD $f)) {
                    $rows.Add([pscustomobject]@{ Score = 95; Kind = 'Stack frame (where it failed)'; Where = $f.Display; Source = $src.Label; Text = (Get-MdMethodDefName $src.MD $rid -WithSig); R = [pscustomobject]@{ SourceRef = $src; Path = $src.Path }; Frame = $rid })
                }
            }
        }
        $sorted = @($rows | Sort-Object @{ Expression = 'Score'; Descending = $true })
        $script:CauseRows = $sorted
        try { Register-FindCause $text $sorted $sources.Count } catch { }   # v5: session history
        $t = New-DataTableEx @('Score:int', 'Found as', 'Where', 'In file', 'Text', '_Idx:int')
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            $x = $sorted[$i]
            [void]$t.Rows.Add([int64]$x.Score, $x.Kind, $x.Where, $x.Source, ($x.Text -replace "`r?`n", ' | '), [int64]$i)
        }
        $script:gridCause.DataSource = $t
        Set-GridColumnWidths $script:gridCause @{ 'Score' = 50; 'Found as' = 170; 'Where' = 170; 'In file' = 170 } 'Text'
        $srcCount = $sources.Count
        if ($sorted.Count -eq 0) {
            Show-Text $script:txtCause ("No match in the analysed file or its {0} decoded source(s).`r`n`r`nPossible reasons:`r`n  - the box comes from another program (check the owner shown in Output and analyse that EXE),`r`n  - the text is built at run time from pieces, or comes from Windows itself,`r`n  - the program's text is compressed/encrypted (packers, obfuscators).`r`nTry pasting a shorter, distinctive part of the message." -f $srcCount)
        } else {
            Show-Text $script:txtCause ("{0} possible source(s) found across {1} decoded file part(s). Select a row to see the code / context that produces the message." -f $sorted.Count, $srcCount)
        }
        Write-Log "Find cause: $($sorted.Count) result(s) from $srcCount source(s)."
        return $sorted
    } catch { Write-Log "Find cause: $($_.Exception.Message)" 'ERROR'; try { Register-FindCause $text @() 0 $_.Exception.Message } catch { }; return @() }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default; Set-Status 'Ready' }
}

function Get-CauseDetail {
    param($Row)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(("{0}  |  {1}  |  {2}" -f $Row.Kind, $Row.Where, $Row.Source))
    [void]$sb.AppendLine('')
    if ($Row.Kind -eq 'Known Windows/runtime message') { [void]$sb.AppendLine($Row.Text); return $sb.ToString() }
    $m = $Row.R
    $src = if ($m) { $m.SourceRef } else { $null }
    if ($m -and $m.Path) { [void]$sb.AppendLine("File: $($m.Path)") } elseif ($src) { [void]$sb.AppendLine("File: (embedded) $($src.Label)") }
    if ($Row.Frame) {
        [void]$sb.AppendLine('The .NET exception passed through this method. Its steps:')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine((Format-ILListing $src.MD ([int]$Row.Frame)))
        return $sb.ToString()
    }
    [void]$sb.AppendLine("Matched text: $($Row.Text)")
    [void]$sb.AppendLine('')
    switch ($Row.Kind) {
        '.NET string literal' {
            $md = $src.MD
            $hits = Find-TokenUsage $md ([int64]$m.Token)
            [void]$sb.AppendLine("Methods that use this text ($($hits.Count)):")
            foreach ($h in $hits) { [void]$sb.AppendLine("  $h") }
            if ($hits.Count -gt 0) {
                $lit = Resolve-MdToken $md ([int64]$m.Token)
                for ($mm = 1; $mm -le $md.RowCount[6]; $mm++) {
                    if ((Get-MdMethodDefName $md $mm) -ne $hits[0]) { continue }
                    try {   # v8 (F18): how the program gets to this text
                        $ctxT = Get-TokenContextText $md $mm ([int64]$m.Token)
                        if ($ctxT) { [void]$sb.AppendLine(''); [void]$sb.AppendLine('How the program gets to this text:'); [void]$sb.Append($ctxT) }
                    } catch { }
                    [void]$sb.AppendLine('')
                    [void]$sb.AppendLine("Steps of $($hits[0])  (>> marks where the message text is used; look at the branches/conditions just above it):")
                    [void]$sb.AppendLine('')
                    foreach ($ln in ((Format-ILListing $md $mm) -split "`r?`n")) {
                        if ($ln -match '\bldstr\b' -and $ln.Contains($lit)) { [void]$sb.AppendLine('>>' + $ln) } else { [void]$sb.AppendLine('  ' + $ln) }
                    }
                    break
                }
            }
        }
        'PowerShell script' {
            $lines = $src.Script -split "`r?`n"
            $ln = [int]$m.Line
            [void]$sb.AppendLine("The script produces this text at line $ln. The lines above show the condition that leads to it:")
            [void]$sb.AppendLine('')
            for ($i = [Math]::Max(1, $ln - 12); $i -le [Math]::Min($lines.Count, $ln + 3); $i++) {
                [void]$sb.AppendLine(('{0}{1,5}: {2}' -f $(if ($i -eq $ln) { '>>' } else { '  ' }), $i, $lines[$i - 1]))
            }
        }
        { $_ -in 'Text line', 'Embedded text file' } {
            if ($src.Text -and $m.Line) {
                $lines = $src.Text -split "`r?`n"; $ln = [int]$m.Line
                for ($i = [Math]::Max(1, $ln - 8); $i -le [Math]::Min($lines.Count, $ln + 3); $i++) {
                    [void]$sb.AppendLine(('{0}{1,5}: {2}' -f $(if ($i -eq $ln) { '>>' } else { '  ' }), $i, $lines[$i - 1]))
                }
            }
        }
        '.NET resource string' {
            [void]$sb.AppendLine('The text is stored in a .NET resource and loaded by its key name.')
            $key = ($m.Where -split ' / ', 2)[-1]
            $md = $src.MD
            if ($md -and $key) {
                $users = New-Object System.Collections.Generic.List[string]
                foreach ($u in (Get-AllUserStrings $md)) { if ($u.Text -eq $key) { foreach ($h in (Find-TokenUsage $md $u.Token)) { $users.Add($h) } } }
                $getterTok = $null
                for ($mm = 1; $mm -le $md.RowCount[6]; $mm++) {
                    if ((Get-MdString $md $md.Tables[6][$mm][3]) -eq ('get_' + $key)) { $getterTok = [int64](0x06000000 + $mm); foreach ($h in (Find-TokenUsage $md (0x06000000 + $mm))) { $users.Add($h) } }
                }
                if ($getterTok) {
                    try {   # v8 (F18)
                        $ctxAll = ''
                        foreach ($ur in (Get-TokenUserRids $md $getterTok 3)) { $ctxAll += (Get-TokenContextText $md $ur $getterTok) }
                        if ($ctxAll) { [void]$sb.AppendLine("How the program gets to the place that loads key '$key':"); [void]$sb.Append($ctxAll); [void]$sb.AppendLine('') }
                    } catch { }
                }
                if ($users.Count -gt 0) { [void]$sb.AppendLine("Methods that load key '$key':"); foreach ($h in ($users | Select-Object -Unique)) { [void]$sb.AppendLine("  $h") } }
                else { [void]$sb.AppendLine("No direct use of key '$key' found - it may be loaded by a generated Resources class or by name built at run time. Search the key in '.NET Code'.") }
            }
        }
        'String table' { [void]$sb.AppendLine('Native code loads this text by its string ID (LoadString). Machine code cannot be decompiled to the exact line, but the ID and the file that owns it are known - useful for vendor support and for finding related settings.') }
        'Message table' { [void]$sb.AppendLine('This text comes from a message table (FormatMessage / event log). The ID identifies the exact error the program reports.') }
        default { [void]$sb.AppendLine('Found as plain text inside the file. For native programs this is as precise as static analysis can get; the surrounding strings on the Strings tab (filter by nearby offset) often show related messages and file names.') }
    }
    return $sb.ToString()
}

function Show-CauseDetail {
    $row = $script:gridCause.CurrentRow
    if (-not $row -or -not $script:CauseRows) { return }
    $x = $script:CauseRows[[int]$row.Cells['_Idx'].Value]
    $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try { Show-Text $script:txtCause (Get-CauseDetail $x) } catch { Show-Text $script:txtCause "Could not build detail: $($_.Exception.Message)" }
    finally { $script:form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Open-CauseSourceFile {
    $row = $script:gridCause.CurrentRow
    if (-not $row -or -not $script:CauseRows) { return }
    $x = $script:CauseRows[[int]$row.Cells['_Idx'].Value]
    if (-not $x.R) { return }
    $p = $x.R.Path
    if (-not $p -and $x.R.SourceRef -and $x.R.SourceRef.Bytes) { $p = Save-EmbeddedToTemp $x.R.SourceRef.Bytes (($x.R.SourceRef.Label -split ' > ')[-1]) }
    if ($p -and $p -ne $script:S.Path) { $script:txtPath.Text = $p; Invoke-Analysis $p -Navigate }
}

# ---------------- Run & Watch: dialogs of watched processes ----------------
function Test-WatchDialogs {
    $R = $script:Run
    if (-not $script:chkWatchDlg.Checked) { return }
    if ($R.Known.Count -eq 0 -or -not (Initialize-Uia)) { return }
    $wins = Get-OpenWindows $false @($R.Known.Keys | ForEach-Object { [int]$_ })
    foreach ($w in $wins) {
        $key = "$($w.Pid)|$($w.Handle)|$($w.Title)"
        if ($R.DlgSeen.ContainsKey($key)) { continue }
        # v6 (F11): windows are re-read on later checks until they show text. Only a real message box (#32770)
        # or a window whose text looks like an error counts as an error box.
        if (-not $R.DlgTries) { $R.DlgTries = @{} }
        if (-not $R.DlgTries.ContainsKey($key)) { $R.DlgTries[$key] = 0 }
        $R.DlgTries[$key]++
        $tries = [int]$R.DlgTries[$key]
        if ($tries -gt 30 -and ($tries % 5) -ne 0) { continue }   # long-lived windows: re-read every 5th check after the first 30
        $cap = Get-UiaWindowText $w.Element
        $txt = Format-CapturedDialog $w $cap
        $isMsgBox = ([string]$w.Class -eq '#32770')
        $looksError = $isMsgBox -or (Test-DialogErrorText $w.Title $cap)
        if ($isMsgBox -and $cap.Lines.Count -eq 0 -and $tries -lt 5) { continue }   # message text not readable yet - try again (v7: 5 checks)
        if (-not $looksError) {
            if ($tries -eq 1) {
                Add-RunLog "Window shown: '$($w.Title)' ($($w.Process), class $($w.Class))"
                if ($script:CurRun) { $script:CurRun.Windows.Add("'$($w.Title)' ($($w.Process), class $($w.Class))") }
                Add-RunEvent 'Window' $w.Process ("'{0}' class {1}" -f $w.Title, $w.Class)
            }
            continue
        }
        $R.DlgSeen[$key] = $true
        Add-RunLog "!!! DIALOG from $($w.Process) (PID $($w.Pid)): '$($w.Title)'"
        $ownerExe = $null
        try { $ownerExe = (Get-Process -Id $w.Pid -ErrorAction Stop).Path } catch { }
        $runNo = if ($script:CurRun) { $script:CurRun.No } else { 0 }
        $dEntry = Add-DialogCapture ("Run and Watch (automatic), run #{0}" -f $runNo) $w.Process $w.Pid $w.Title $txt $ownerExe $runNo
        foreach ($l in $cap.Lines) { foreach ($l2 in ($l -split "`r?`n" | Select-Object -First 15)) { if ($l2.Trim()) { Add-RunLog "      | $($l2.Trim())" } } }
        if ($cap.Buttons.Count) { Add-RunLog ("      | [Buttons: {0}]" -f ($cap.Buttons -join ', ')) }
        $script:txtDlgText.Text = $txt
        $res = @(Invoke-FindCause -Quiet | Where-Object { $null -ne $_ })
        if ($res.Count -eq 0) { Add-RunLog '      Cause search: no match in the program or its related files (see Dialog Finder tab).' }
        foreach ($x in ($res | Select-Object -First 3)) { Add-RunLog ("      Likely source [{0}]: {1} - {2} in {3}" -f $x.Score, $x.Kind, $x.Where, $x.Source) }
        if ($res.Count -gt 0) { Add-RunLog '      Full details: tab 10. Dialog Finder.' }
        $top3 = New-Object System.Collections.Generic.List[string]
        foreach ($x in ($res | Select-Object -First 3)) { $top3.Add((Format-CauseLine $x 140)) }
        if ($script:CurRun) { $script:CurRun.Dialogs.Add([pscustomobject]@{ Time = $dEntry.Time; Process = $w.Process; Pid = $w.Pid; Title = $w.Title; Text = $txt; Top3 = $top3; EntryNo = $dEntry.No }) }
        Add-RunEvent 'Dialog' $w.Process ("'{0}': {1}" -f $w.Title, (($txt -replace "`r?`n", ' | ').Trim()))
    }
}

function Get-AliveTracked {
    # returns ids of watched processes still running; logs the ones that ended (with exit code when known)
    $R = $script:Run
    $alive = New-Object System.Collections.Generic.List[int]
    foreach ($id in @($R.Known.Keys)) {
        $id = [int]$id
        if ($R.Done.ContainsKey($id)) { continue }
        $p = $null
        if ($R.Procs.ContainsKey($id)) { $p = $R.Procs[$id] }
        $ended = $false; $code = $null
        if ($p) { try { $ended = $p.HasExited; if ($ended) { try { $code = $p.ExitCode } catch { } } } catch { $ended = $true } }
        else { $ended = (@(Get-Process -Id $id -ErrorAction SilentlyContinue).Count -eq 0) }
        if ($ended) {
            $R.Done[$id] = $true
            Set-RunProcExit $id $code
            if ($id -ne [int]$R.MainPid) {
                Add-RunEvent 'Child exit' ([string]$R.Known[$id]) $(if ($null -ne $code) { "PID $id exit code " + (Get-ExitCodeText ([int64]$code)) } else { "PID $id (exit code not available)" })
                if ($null -ne $code) { Add-RunLog ("Child process ended: {0} (PID {1}) exit code {2}" -f $R.Known[$id], $id, (Get-ExitCodeText ([int64]$code))) }
                else { Add-RunLog ("Child process ended: {0} (PID {1})" -f $R.Known[$id], $id) }
            }
        } else { $alive.Add($id) }
    }
    return , $alive
}

# =====================================================================
#  v5 additions (F10): structured session history for Run and Watch and
#  Dialog Finder, and the findings report (00_Findings.txt + files 11-14).
#  The report functions only read state - they never touch the GUI controls.
# =====================================================================
$script:RunHistory = New-Object System.Collections.Generic.List[object]
$script:DialogHistory = New-Object System.Collections.Generic.List[object]
$script:CurRun = $null
$script:LastCapture = $null
$script:ReportSrcCache = @{}
$script:ErrLineRx = '(?i)\b(error|errors|exception|failed|failure|fatal|denied|not found|cannot|can''t|unable|invalid|missing|aborted|timed out|timeout)\b|\bERROR_[A-Z0-9_]+\b|\b0x8[0-9A-F]{7}\b|\b0xC0[0-9A-F]{6}\b'
$script:ErrLineIgnoreRx = '(?i)\b(0|no|zero)\s+(errors?|failures?|warnings?)\b|\b(errors?|failures?|failed)\s*[:=]\s*0\b|\bwithout errors?\b'
$script:WinDirRx = '(?i)\\Windows\\(System32|SysWOW64|WinSxS|Microsoft\.NET|assembly)\\'

# ---------------- session state helpers ----------------
function Test-IsElevated {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return ([System.Security.Principal.WindowsPrincipal]$id).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $null }
}

function New-RunRecord {
    param([string]$Exe, [string]$ArgText, [string]$Dir)
    $cl = '"' + $Exe + '"'
    if ($ArgText -and $ArgText.Trim()) { $cl += ' ' + $ArgText.Trim() }
    $rec = [pscustomobject]@{
        No = ($script:RunHistory.Count + 1); Exe = $Exe; ExeName = [System.IO.Path]::GetFileName($Exe); Args = $ArgText; Dir = $Dir; CommandLine = $cl
        Start = (Get-Date); End = $null; Status = 'Starting'; StartError = ''; StartErrorCode = $null
        Captured = $false; Elevated = (Test-IsElevated); MainPid = 0; MainCode = $null; StoppedByUser = $false; WatchError = ''; PartialExports = 0
        Procs = (New-Object System.Collections.Generic.List[object])
        Console = (New-Object System.Collections.Generic.List[object])
        Events = (New-Object System.Collections.Generic.List[object])
        Dialogs = (New-Object System.Collections.Generic.List[object])
        Dlls = (New-Object System.Collections.Generic.List[string])
        Windows = (New-Object System.Collections.Generic.List[string])
        WinEvents = (New-Object System.Collections.Generic.List[object])
        WerSeen = (New-Object System.Collections.Generic.List[string])
        LogStart = @{}; LogTexts = $null
    }
    $script:RunHistory.Add($rec)
    $script:CurRun = $rec
    return $rec
}

function Add-RunEvent {
    param([string]$Type, [string]$Process, [string]$Detail)
    $rec = $script:CurRun
    if (-not $rec) { return }
    try { $rec.Events.Add([pscustomobject]@{ Time = (Get-Date); Run = $rec.No; Type = $Type; Process = $Process; Detail = $Detail }) } catch { }
}

function Add-RunConsole {
    # same log line as v4 ("  OUT> ..." / "  ERR> ...") plus a structured record
    param([string]$Stream, [string]$Text)
    Add-RunLog ("  {0}> {1}" -f $Stream, $Text)
    $rec = $script:CurRun
    if (-not $rec) { return }
    try {
        $rec.Console.Add([pscustomobject]@{ Time = (Get-Date); Stream = $Stream; Text = $Text })
        Add-RunEvent ('Console ' + $Stream) $rec.ExeName $Text
    } catch { }
}

function Add-RunProc {
    param([int]$ProcId, [string]$Name, [int]$ParentId, [string]$CmdLine, [bool]$IsMain = $false)
    $rec = $script:CurRun
    if (-not $rec) { return }
    foreach ($p in $rec.Procs) { if ($p.Pid -eq $ProcId) { return } }
    $rec.Procs.Add([pscustomobject]@{ Pid = $ProcId; Name = $Name; Parent = $ParentId; CommandLine = $CmdLine; IsMain = $IsMain; Started = (Get-Date); Ended = $null; ExitCode = $null; Meaning = '' })
}

function Set-RunProcExit {
    param([int]$ProcId, $Code)
    $rec = $script:CurRun
    if (-not $rec) { return }
    foreach ($p in $rec.Procs) {
        if ($p.Pid -ne $ProcId) { continue }
        if (-not $p.Ended) { $p.Ended = Get-Date }
        if ($null -ne $Code) { $p.ExitCode = $Code; $p.Meaning = Get-ExitCodeText ([int64]$Code) }
        return
    }
}

function Get-RunExitName {
    # v7 (F15): the ERROR_... / SUCCESS name the program printed just before it exited (many installers print their return-code name)
    param($Rec)
    if (-not $Rec -or $Rec.Console.Count -eq 0) { return '' }
    $n = $Rec.Console.Count
    for ($i = $n - 1; $i -ge 0; $i--) {
        $t = ([string]$Rec.Console[$i].Text).Trim()
        if ($t -match '^(ERROR_[A-Z0-9_]+|[A-Z][A-Z0-9]*_SUCCESS[A-Z0-9_]*|SUCCESS)$') { return $Matches[1] }
    }
    for ($i = $n - 1; $i -ge [Math]::Max(0, $n - 5); $i--) {
        if (([string]$Rec.Console[$i].Text) -match '\b(ERROR_[A-Z0-9_]+)\b') { return $Matches[1] }
    }
    return ''
}

function Close-RunRecord {
    param([string]$Status, [string]$Detail = '')
    $rec = $script:CurRun
    if (-not $rec) { return }
    $rec.End = Get-Date
    $rec.Status = $Status
    try { $rec.LogTexts = Get-RunLogTexts $rec } catch { }   # v8 (F17)
    if ($Status -eq 'Watch error') { $rec.WatchError = $Detail }
    Add-RunEvent $Status $rec.ExeName $Detail
    $script:CurRun = $null
}

function Add-DialogCapture {
    param([string]$Origin, [string]$Process, [int]$ProcId, [string]$Title, [string]$Text, [string]$OwnerExe, $RunNo = $null)
    $e = [pscustomobject]@{
        No = ($script:DialogHistory.Count + 1); Time = (Get-Date); Origin = $Origin; Run = $RunNo; Process = $Process; Pid = $ProcId; Title = $Title
        OwnerExe = $OwnerExe; Text = $Text; AnalysedFile = $script:S.Path; Searched = $false; SearchTime = $null; SearchCount = 0; SourceCount = 0
        ResultCount = 0; Known = (New-Object System.Collections.Generic.List[object]); Top = (New-Object System.Collections.Generic.List[object]); Error = ''; SearchedAtExport = $false
    }
    $script:DialogHistory.Add($e)
    $script:LastCapture = $e
    return $e
}

function Set-DialogResults {
    param($Entry, $Rows, [int]$SourceCount)
    $Entry.Known.Clear(); $Entry.Top.Clear()
    $n = 0
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        if ($r.Kind -eq 'Known Windows/runtime message') { $Entry.Known.Add($r); continue }
        $n++
        if ($Entry.Top.Count -lt 5) { $Entry.Top.Add($r) }
    }
    $Entry.ResultCount = $n
    $Entry.SourceCount = $SourceCount
}

function Register-FindCause {
    # called by Invoke-FindCause: attaches the results to the capture they belong to (or records pasted text as a new entry)
    param([string]$Text, $Rows, [int]$SourceCount, [string]$ErrorText = '')
    $e = $script:LastCapture
    if (-not $e -or ((Get-NormalText $e.Text) -ne (Get-NormalText $Text))) {
        $first = @($Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        $t1 = if ($first.Count -gt 0) { $first[0].Trim() } else { '' }
        $e = Add-DialogCapture 'Dialog Finder - pasted/typed text' '' 0 $t1 $Text ''
    }
    $e.Searched = $true
    $e.SearchTime = Get-Date
    $e.SearchCount++
    $e.AnalysedFile = $script:S.Path
    $e.Error = $ErrorText
    Set-DialogResults $e $Rows $SourceCount
}

function Test-DialogErrorText {
    # v6 (F11): error words in the window's text, or a title that itself names an error/warning
    param([string]$Title, $Cap)
    $body = ''
    if ($Cap -and $Cap.Lines) { $body = ($Cap.Lines -join "`n") }
    if ($body -match '(?i)\b(error|warning|exception|fail(ed|ure|s)?|cannot|can''t|unable|denied|not found|missing|invalid|not responding)\b') { return $true }
    if ($Title -match '(?i)\b(error|warning|exception|fail(ed|ure)?|problem|alert)\b') { return $true }
    return $false
}

# ---------------- report helpers (read-only) ----------------
function Get-ProgramLogs {
    # v8 (F17): log files the analysed program writes - existing ones from Related Files, plus log paths found in its
    # text (they may not exist until the program runs)
    $S = $script:S
    $out = New-Object System.Collections.Generic.List[string]
    if ($S.Related) { foreach ($rf in $S.Related) { $pp = [string]$rf.Path; if ($pp -ne '<embedded>' -and ($pp -match '(?i)\.log$' -or ([System.IO.Path]::GetFileName($pp) -match '(?i)log' -and $pp -match '(?i)\.txt$'))) { if (-not $out.Contains($pp)) { $out.Add($pp) } } } }
    if ($script:LastLogCandidates) { foreach ($lp in $script:LastLogCandidates) { if ($out.Count -ge 25) { break }; if (-not $out.Contains($lp)) { $out.Add($lp) } } }
    if ($S.Strings) {
        $rx = '(?i)[A-Za-z]:\\[^"*?<>|\r\n\t]{1,240}?\.log\b'
        foreach ($x in $S.Strings) { if ($out.Count -ge 25) { break }; foreach ($m in [regex]::Matches($x.Text, $rx)) { $lp = ConvertTo-LocalPath $m.Value; if (-not $out.Contains($lp)) { $out.Add($lp) } } }
    }
    return , $out
}

function Get-LogSnapshot {
    $snap = @{}
    $S = $script:S
    if (-not $S -or -not $S.ProgramLogs) { return $snap }
    foreach ($lp in $S.ProgramLogs) { try { $snap[$lp] = $(if ([System.IO.File]::Exists($lp)) { [int64](New-Object System.IO.FileInfo($lp)).Length } else { [int64]-1 }) } catch { } }
    return $snap
}

function Get-RunLogTexts {
    # lines each program log got during a run (stored when the run ended, read live for a run still in progress)
    param($Rec)
    if ($null -ne $Rec.LogTexts -and $Rec.End) { return $Rec.LogTexts }
    $res = [ordered]@{}
    if (-not $Rec.LogStart) { return $res }
    foreach ($lp in @($Rec.LogStart.Keys)) {
        $t = Read-FileFrom $lp ([int64]$Rec.LogStart[$lp])
        if ($t) { $res[$lp] = $t }
    }
    return $res
}

function Format-ReportTime {
    param($T, [string]$Fmt = 'yyyy-MM-dd HH:mm:ss')
    if ($null -eq $T) { return '-' }
    try { return ([datetime]$T).ToString($Fmt) } catch { return [string]$T }
}

function Get-OverviewSection {
    # lines of one "=== NAME ===" section of the Overview text
    param([string]$Name)
    $out = New-Object System.Collections.Generic.List[string]
    $text = [string]$script:S.Overview
    if (-not $text) { return , $out }
    $on = $false
    foreach ($l in ($text -split "`r?`n")) {
        if ($l -match '^=== (.+) ===$') { $on = ($Matches[1] -eq $Name -or $Matches[1] -like ($Name + ' (*')); continue }
        if ($on -and $l.Trim()) { $out.Add($l) }
    }
    return , $out
}

function Get-ReportSources {
    # decoded search sources for a program (+ the related files when it is the analysed file); cached per export
    param([string]$ExePath)
    $list = New-Object System.Collections.Generic.List[object]
    if (-not $ExePath) { return , $list }
    $key = $ExePath.ToLower()
    if ($script:ReportSrcCache.ContainsKey($key)) { return , $script:ReportSrcCache[$key] }
    $S = $script:S
    try {
        if ($S.Path -and $S.Bytes -and ($ExePath -ieq $S.Path)) {
            foreach ($x in (Get-CachedSources $S.Path $S.Bytes)) { $list.Add($x) }
            $n = 0
            if ($S.Related) {
                foreach ($rf in $S.Related) {
                    if ($rf.Res -or $rf.Size -gt 60MB) { continue }
                    $n++
                    if ($n -gt 60) { break }
                    try { foreach ($x in (Get-CachedSources $rf.Path)) { $list.Add($x) } } catch { }
                }
            }
        } elseif (Test-Path -LiteralPath $ExePath -PathType Leaf) {
            foreach ($x in (Get-CachedSources $ExePath)) { $list.Add($x) }
        }
    } catch { }
    $script:ReportSrcCache[$key] = $list
    return , $list
}

function Get-RunSources {
    # the run's / dialog owner's program, plus the analysed file and its related files when that is a different file
    param([string]$ExePath)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($x in (Get-ReportSources $ExePath)) { $list.Add($x) }
    $S = $script:S
    if ($S.Path -and ($S.Path -ine $ExePath)) { foreach ($x in (Get-ReportSources $S.Path)) { $list.Add($x) } }
    return , $list
}

function Get-CauseRowsForText {
    # same result rows as Invoke-FindCause, without the GUI (used for captures never searched in the session)
    param([string]$Text, $Sources)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($k in (Get-KnownMessageExplanation $Text)) {
        $rows.Add([pscustomobject]@{ Score = 100; Kind = 'Known Windows/runtime message'; Where = $k.Title; Source = '(built-in knowledge)'; Text = $k.Explanation; R = $null; Frame = $null })
    }
    foreach ($m in (Find-MessageSource $Text $Sources)) {
        $rows.Add([pscustomobject]@{ Score = $m.Score; Kind = $m.Kind; Where = $m.Where; Source = $m.Source; Text = $m.Text; R = $m; Frame = $null })
    }
    foreach ($f in (Get-StackFrames $Text)) {
        foreach ($src in $Sources) {
            if (-not $src.MD) { continue }
            foreach ($rid in (Find-MethodByFrame $src.MD $f)) {
                $rows.Add([pscustomobject]@{ Score = 95; Kind = 'Stack frame (where it failed)'; Where = $f.Display; Source = $src.Label; Text = (Get-MdMethodDefName $src.MD $rid -WithSig); R = [pscustomobject]@{ SourceRef = $src; Path = $src.Path }; Frame = $rid })
            }
        }
    }
    $sorted = @($rows | Sort-Object @{ Expression = 'Score'; Descending = $true })
    return , $sorted
}

function Format-CauseLine {
    param($Row, [int]$Max = 160)
    $t = ([string]$Row.Text) -replace "`r?`n", ' | '
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return ("[{0}] {1} - {2} in {3}: {4}" -f $Row.Score, $Row.Kind, $Row.Where, $Row.Source, $t)
}

function Get-CauseHowSummary {
    # v8 (F18): one-line "how is this text reached" for a Dialog Finder result row (string literals in .NET code)
    param($Row)
    try {
        if (-not $Row -or $Row.Kind -ne '.NET string literal' -or -not $Row.R -or -not $Row.R.SourceRef -or -not $Row.R.SourceRef.MD) { return '' }
        $md = $Row.R.SourceRef.MD
        $tok = [int64]$Row.R.Token
        foreach ($rid in (Get-TokenUserRids $md $tok 1)) {
            $insList = Get-ILInstructions $md $rid
            for ($i = 0; $i -lt $insList.Count; $i++) {
                if ($insList[$i].OperandType -eq 'InlineString' -and [int64]$insList[$i].Operand -eq $tok) {
                    $ctx = Get-ILContextAt $md $rid $insList $i
                    $parts = @($ctx | Where-Object { $_ -notmatch '^\s+the protected code calls' })
                    if ($parts.Count -eq 0) { return '' }
                    return ("in {0}: {1}" -f (Get-ShortMemberName (Get-MdMethodDefName $md $rid)), ($parts -join '; '))
                }
            }
        }
    } catch { }
    return ''
}

function Get-BestCauseDetail {
    param($Entry, [int]$MaxLines = 0)
    if ($Entry.Top.Count -eq 0) { return '' }
    $d = ''
    try { $d = Get-CauseDetail $Entry.Top[0] } catch { $d = "Could not build detail: $($_.Exception.Message)" }
    if ($MaxLines -gt 0) {
        $ls = @($d -split "`r?`n")
        if ($ls.Count -gt $MaxLines) { $d = (($ls | Select-Object -First $MaxLines) -join "`r`n") + "`r`n... ($($ls.Count - $MaxLines) more lines in 12_DialogFinder.txt)" }
    }
    return $d
}

function Complete-DialogHistory {
    # captures never searched with "Find cause" are searched now so the report explains every one of them
    foreach ($e in $script:DialogHistory) {
        if ($e.Searched -or -not ([string]$e.Text).Trim()) { continue }
        try {
            $exe = if ($e.OwnerExe) { $e.OwnerExe } else { $e.AnalysedFile }
            $src = Get-RunSources $exe
            Set-DialogResults $e (Get-CauseRowsForText $e.Text $src) $src.Count
            $e.SearchedAtExport = $true
        } catch { $e.Error = "search at export failed: $($_.Exception.Message)" }
    }
}

function Get-ErrorRowType {
    param($Row)
    if ($Row.Log -eq 'WER') { return 'WER report' }
    switch ($Row.Source) {
        'Application Error' { return 'Crash' }
        'Application Hang' { return 'Hang' }
        '.NET Runtime' { return '.NET exception' }
        'SideBySide' { return 'Side-by-side' }
        'MsiInstaller' { return 'Installer' }
        'Windows Error Reporting' { return 'WER event' }
    }
    return 'Other'
}

function Get-ErrorRowFacts {
    # faulting module / exception code / .NET exception type found in one event or WER report
    param($Row)
    $d = [string]$Row.Detail
    $f = [pscustomobject]@{ Module = ''; Code = ''; NetType = '' }
    if ($d -match '(?im)Faulting module name:\s*([^,\r\n]+)') { $f.Module = $Matches[1].Trim() }
    elseif ($d -match '(?im)^Fault Module Name\s*=\s*(.+)$') { $f.Module = $Matches[1].Trim() }
    if ($d -match '(?i)Exception code:\s*(0x[0-9a-f]{1,8})') { $f.Code = $Matches[1] }
    elseif ($d -match '(?im)^Exception Code\s*=\s*(?:0x)?([0-9a-f]{1,8})\s*$') { $f.Code = '0x' + $Matches[1] }
    if ($d -match '(?i)Exception Info:\s*([\w\.`+]+)') { $f.NetType = $Matches[1] }
    elseif ($d -match '(?im)^Problem Signature 09\s*=\s*(.+)$') { $f.NetType = $Matches[1].Trim() }
    return $f
}

function Get-Win32ErrorText {
    # Windows' own text for a Win32 error number (start failures), plus the tool's note when it has one
    param([int64]$Code)
    $t = ''
    try { $t = (New-Object System.ComponentModel.Win32Exception([int]$Code)).Message } catch { }
    foreach ($k in $script:ExitCodeInfo.Keys) { if ([int64]$k -eq $Code -and $Code -ne 0 -and $Code -ne 1) { $t += $(if ($t) { ' - ' } else { '' }) + $script:ExitCodeInfo[$k]; break } }
    if (-not $t) { $t = 'unknown Windows error' }
    return ("{0} (0x{1:X8}): {2}" -f $Code, $Code, $t)
}

function Get-EventKey {
    param($Row)
    return ("{0}|{1}|{2}|{3}" -f (Format-ReportTime $Row.Time 'yyyyMMddHHmmss'), $Row.Source, $Row.EventId, $Row.Summary)
}

function Get-CodeMeaning {
    param([string]$Hex)
    try { return (Get-ExitCodeText ([Convert]::ToInt64(($Hex -replace '^0x', ''), 16))) } catch { return $Hex }
}

function Get-TopCount {
    # "value (n)" of the most frequent non-empty value
    param([string[]]$Values)
    $v = @($Values | Where-Object { $_ })
    if ($v.Count -eq 0) { return $null }
    $g = @($v | Group-Object | Sort-Object Count -Descending)
    return [pscustomobject]@{ Value = $g[0].Name; Count = $g[0].Count; All = $g }
}

function Test-ErrorLikeLine {
    param([string]$Text)
    if (-not $Text) { return $false }
    if ($Text -notmatch $script:ErrLineRx) { return $false }
    if ($Text -match $script:ErrLineIgnoreRx -and $Text -notmatch '\bERROR_[A-Z0-9_]+\b') { return $false }
    return $true
}

function Get-RunErrorLines {
    # distinct console lines of a run that look like errors (max 15)
    param($Rec)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($c in $Rec.Console) {
        $t = ([string]$c.Text).Trim()
        if (-not (Test-ErrorLikeLine $t)) { continue }
        $k = $t.ToLower()
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out.Add($c)
        if ($out.Count -ge 15) { break }
    }
    return , $out
}

function Get-RelatedFileInfo {
    param($Rf)
    $info = [pscustomobject]@{ Kind = ''; Version = ''; Company = ''; Description = '' }
    if ($Rf.Res) { $info.Kind = 'program packed inside the analysed file'; return $info }
    $ext = ([System.IO.Path]::GetExtension([string]$Rf.Path)).ToLower()
    $info.Kind = switch -regex ($ext) {
        '^\.(dll|ocx)$' { 'DLL' } '^\.exe$' { 'program (EXE)' } '^\.sys$' { 'driver' } '^\.(ps1|psm1)$' { 'PowerShell script' }
        '^\.(bat|cmd)$' { 'batch file' } '^\.(vbs|js)$' { 'Windows Script Host script' } '^\.(ini|cfg|config|xml|json|env)$' { 'settings / configuration file' }
        '^\.(mdb|accdb)$' { 'Access database' } '^\.(csv|txt)$' { 'text / data file' } '^\.sql$' { 'SQL script' } '^\.reg$' { 'registry file' }
        '^\.msi$' { 'Windows Installer package' } '^\.log$' { 'log file' } '^\.acl$' { 'ACL file' } default { 'file' }
    }
    if ($ext -match '^\.(dll|ocx|exe|sys)$') {
        try {
            $fs = [System.IO.File]::Open($Rf.Path, 'Open', 'Read', 'ReadWrite')
            try { $buf = New-Object byte[] 4096; $n = $fs.Read($buf, 0, 4096) } finally { $fs.Dispose() }
            if ($n -lt 4096) { $b2 = New-Object byte[] $n; [Array]::Copy($buf, $b2, $n); $buf = $b2 }
            $pe = Get-PEInfo $buf
            if ($pe.Valid) {
                $info.Kind = "{0}, {1}{2}" -f $info.Kind, $pe.MachineName, $(if ($pe.IsDotNet) { ', .NET (managed; x86 header can also mean AnyCPU)' } else { ', native' })
            }
        } catch { }
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Rf.Path)
            if ($vi.FileVersion) { $info.Version = $vi.FileVersion.Trim() }
            if ($vi.CompanyName) { $info.Company = $vi.CompanyName.Trim() }
            if ($vi.FileDescription) { $info.Description = $vi.FileDescription.Trim() }
        } catch { }
    }
    return $info
}

# ---------------- findings ----------------
function Get-AllFindings {
    $S = $script:S
    $list = New-Object System.Collections.Generic.List[object]
    $add = { param($sev, $area, $issue, $ev) $list.Add([pscustomobject]@{ Severity = $sev; Area = $area; Issue = $issue; Evidence = $ev }) }
    $pe = $S.PE
    # --- static analysis ---
    if ($S.Path -and $pe -and -not $pe.Valid) { & $add 'WARNING' 'File' 'Not a Windows program file' ([string]$pe.Error) }
    if ($S.Deps) {
        foreach ($x in @($S.Deps | Where-Object { $_.Status -like 'NOT FOUND*' })) { & $add 'PROBLEM' 'DLL dependencies' ("Missing DLL: {0}" -f $x.Dll) ("needed by {0} (level {1}); {2}{3}" -f $x.RequiredBy, $x.Level, $x.Status, $(if ($x.Path) { "; expected at $($x.Path)" } else { '' })) }
        foreach ($x in @($S.Deps | Where-Object { $_.Status -like 'WRONG*' })) { & $add 'PROBLEM' 'DLL dependencies' ("Wrong-bitness DLL: {0}" -f $x.Dll) ("{0}; at {1}; needed by {2}" -f $x.Status, $x.Path, $x.RequiredBy) }
    }
    foreach ($l in (Get-OverviewSection '.NET DETAILS')) {
        if ($l -match '>>> PROBLEM\s*:\s*(.+)$') { & $add 'PROBLEM' '.NET Framework' '.NET version required is not installed' $Matches[1].Trim() }
        elseif ($l -match '^\s+-\s+(\S+)\s+(\S+)\s+NOT FOUND') { & $add 'WARNING' '.NET assembly reference' ("Referenced assembly not found next to the EXE or in the GAC: {0} {1}" -f $Matches[1], $Matches[2]) 'It may still load from a probing sub-folder or be resolved at run time (AssemblyResolve / Costura).' }
        elseif ($l -match 'NONE installed under') { & $add 'PROBLEM' '.NET runtime' 'No .NET (Core/5+) runtime installed' $l.Trim() }
    }
    foreach ($l in (Get-OverviewSection 'WHAT KIND OF PROGRAM IS THIS')) {
        if ($l -match 'Needs assembly\s*:\s*(.+?)\s*->\s*NOT FOUND') { & $add 'PROBLEM' 'Visual C++ / side-by-side' ("Side-by-side assembly from the manifest is not installed: {0}" -f $Matches[1]) 'Not found in C:\Windows\WinSxS - install the matching Visual C++ redistributable.' }
    }
    if ($S.Manifest -and $S.Manifest.ExecutionLevel -eq 'requireAdministrator') {
        $runs = @($script:RunHistory | Where-Object { $_.Exe -ieq $S.Path })
        $ev = 'Manifest requestedExecutionLevel = requireAdministrator. Started without admin it shows a UAC prompt, or fails with error 740 (when started without UAC, e.g. with console capture).'
        $notAdm = @($runs | Where-Object { $_.Elevated -eq $false })
        if ($notAdm.Count -gt 0) { $ev += (' {0} run(s) in this session were started while EXE Inspector was NOT elevated.' -f $notAdm.Count) }
        & $add 'WARNING' 'Privileges' 'Program requires "Run as administrator"' $ev
    }
    if ($S.Manifest -and $S.Manifest.Error) { & $add 'WARNING' 'Manifest' 'Manifest could not be read' ([string]$S.Manifest.Error) }
    if ($pe -and $pe.Valid -and $pe.IsDotNet -and -not ($S.MD -and $S.MD.Valid)) { & $add 'WARNING' '.NET metadata' '.NET metadata could not be read (likely obfuscated)' $(if ($S.MD) { [string]$S.MD.Error } else { '' }) }
    if ($S.PS -and $S.PS.IsPS2EXE -and -not $S.PS.Found) { & $add 'WARNING' 'Script' 'PS2EXE program, but the script could not be recovered' 'Modified or obfuscated PS2EXE build.' }
    if ($S.PS -and $S.PS.Found) {
        try { $o = Get-ScriptOutline $S.PS.Script; foreach ($pe2 in @($o.ParseErrors | Select-Object -First 5)) { & $add 'WARNING' 'Script' 'Recovered script has a parse error' $pe2 } } catch { }
    }
    if ($S.Hints) {
        foreach ($h in $S.Hints) {
            if ($h -match '(?i)packed|protected|cannot be inspected') { & $add 'WARNING' 'Static analysis' 'Packed / protected program - static analysis is limited' $h }
            else { & $add 'INFO' 'Program type' $h '' }
        }
    }
    if ($pe -and $pe.Valid -and $pe.Dirs -and $pe.Dirs[4][1] -eq 0) { & $add 'INFO' 'Signature' 'File is not digitally signed' 'No Authenticode certificate in the file.' }

    # --- Run and Watch ---
    $evSeen = @{}
    foreach ($rec in $script:RunHistory) {
        $area = "Run #$($rec.No) ($($rec.ExeName))"
        if ($rec.Status -eq 'Start failed') {
            $ev = $rec.StartError
            if ($null -ne $rec.StartErrorCode) { $ev += ' | Windows error ' + (Get-Win32ErrorText ([int64]$rec.StartErrorCode)) }
            & $add 'PROBLEM' $area 'Program did not start' $ev
        }
        if ($rec.Status -eq 'Watch error') { & $add 'WARNING' $area 'Watching stopped because of an internal error' $rec.WatchError }
        if (-not $rec.End) { & $add 'WARNING' $area 'Run was still in progress when the report was exported - its results are PARTIAL' ("started {0}; exit codes, later dialogs and after-exit Windows events are not included. Export again after it finishes." -f (Format-ReportTime $rec.Start)) }
        if ($rec.StoppedByUser) { & $add 'INFO' $area 'Stopped by the user (force-stop)' 'Exit codes after a force-stop are not the program''s own result.' }
        foreach ($p in $rec.Procs) {
            if ($null -eq $p.ExitCode) { continue }
            $c = [int64]$p.ExitCode
            $role = if ($p.IsMain) { 'Main process' } else { 'Child process' }
            if ($c -eq 0) { if ($p.IsMain) { & $add 'INFO' $area ("{0} {1} exited with 0 (success)" -f $role, $p.Name) '' } }
            elseif ($c -eq 3010 -or $c -eq 1641) { & $add 'INFO' $area ("{0} {1}: restart needed" -f $role, $p.Name) $p.Meaning }
            else {
                $xn = if ($p.IsMain) { Get-RunExitName $rec } else { '' }
                & $add 'PROBLEM' $area ("{0} {1} (PID {2}) failed - exit code {3}{4}" -f $role, $p.Name, $p.Pid, $c, $(if ($xn) { " = $xn" } else { '' })) $(if ($xn) { "$($p.Meaning); the program printed '$xn' just before it exited" } else { $p.Meaning })
            }
        }
        if ($rec.Status -ne 'Start failed' -and $null -eq $rec.MainCode -and $rec.End) { & $add 'INFO' $area 'Main process exit code was not available' 'Windows did not return the exit code (process started elevated / by another account, or handle lost).' }
        foreach ($c in (Get-RunErrorLines $rec)) { & $add 'WARNING' $area ("Console {0}: {1}" -f $c.Stream, $c.Text.Trim()) ("printed at {0}" -f (Format-ReportTime $c.Time 'HH:mm:ss')) }
        try {   # v8 (F17): error lines the program wrote to its own log during the run
            $lt = Get-RunLogTexts $rec
            foreach ($lp in $lt.Keys) {
                $nErr = 0
                foreach ($ll in ($lt[$lp] -split "`r?`n")) { if ($nErr -ge 8) { break }; if (Test-ErrorLikeLine $ll) { $nErr++; & $add 'WARNING' $area ("Program log {0}: {1}" -f [System.IO.Path]::GetFileName($lp), $ll.Trim()) ("written to {0} during the run" -f $lp) } }
            }
        } catch { }
        foreach ($d in $rec.Dialogs) {
            $first = @(([string]$d.Text) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Skip 1 -First 2) -join ' / '
            $ev = "{0} (PID {1}) at {2}: {3}" -f $d.Process, $d.Pid, (Format-ReportTime $d.Time 'HH:mm:ss'), $first
            if ($d.Top3.Count -gt 0) { $ev += ' | likely source: ' + $d.Top3[0] }
            try { if ($d.EntryNo -and $script:DialogHistory.Count -ge $d.EntryNo -and $script:DialogHistory[$d.EntryNo - 1].Top.Count -gt 0) { $hw = Get-CauseHowSummary $script:DialogHistory[$d.EntryNo - 1].Top[0]; if ($hw) { $ev += ' | shown ' + $hw } } } catch { }
            & $add 'PROBLEM' $area ("Error/warning box shown: '{0}'" -f $d.Title) $ev
        }
        foreach ($w in $rec.WerSeen) { & $add 'PROBLEM' $area 'Windows Error Reporting started - crash or hang' $w }
        foreach ($x in $rec.WinEvents) {
            $ek = Get-EventKey $x
            if ($evSeen.ContainsKey($ek)) { continue }   # same event already reported for an earlier run (event windows overlap)
            $evSeen[$ek] = $rec.No
            $t = Get-ErrorRowType $x
            if ($t -in 'Crash', 'Hang', '.NET exception', 'Side-by-side', 'WER report', 'WER event') { & $add 'PROBLEM' $area ("{0} logged by Windows during the run" -f $t) ("[{0}] {1} ID {2}: {3}" -f $x.Log, $x.Source, $x.EventId, $x.Summary) }
            elseif ($t -eq 'Installer' -and ($x.Level -match '(?i)error|warning' -or $x.Summary -match '(?i)error|fail|1603|return value 3')) { & $add 'WARNING' $area 'Windows Installer reported a problem during the run' ("ID {0}: {1}" -f $x.EventId, $x.Summary) }
            elseif ($t -eq 'Other') { & $add 'WARNING' $area ("Application log {0} from {1} during the run" -f $x.Level, $x.Source) $x.Summary }
        }
    }

    # --- Error History ---
    if ($S.ErrorRows -and $S.ErrorRows.Count -gt 0) {
        $byType = @($S.ErrorRows | Group-Object { Get-ErrorRowType $_ })
        foreach ($g in $byType) {
            $sev = if ($g.Name -in 'Crash', 'Hang', '.NET exception', 'Side-by-side', 'WER report') { 'PROBLEM' } else { 'WARNING' }
            $facts = @($g.Group | ForEach-Object { Get-ErrorRowFacts $_ })
            $ev = "first {0}, last {1}" -f (Format-ReportTime (($g.Group | Sort-Object Time | Select-Object -First 1).Time)), (Format-ReportTime (($g.Group | Sort-Object Time -Descending | Select-Object -First 1).Time))
            $tm = Get-TopCount @($facts | ForEach-Object { $_.Module }); if ($tm) { $ev += "; faulting module $($tm.Value) ($($tm.Count)x)" }
            $tc = Get-TopCount @($facts | ForEach-Object { $_.Code }); if ($tc) { $ev += "; exception " + (Get-CodeMeaning $tc.Value) }
            $tn = Get-TopCount @($facts | ForEach-Object { $_.NetType }); if ($tn) { $ev += "; .NET exception $($tn.Value)" }
            & $add $sev 'Error History' ("{0} x {1} in the event logs / WER" -f $g.Count, $g.Name) $ev
        }
    }

    # --- run context of crashed copies (v8, F20) ---
    try {
        if ($S.ErrorRows) {
            $byPath = @($S.ErrorRows | Where-Object { Get-ErrorRowAppPath $_ } | Group-Object { Get-ErrorRowAppPath $_ })
            foreach ($g in $byPath) {
                $lbl = Get-RunContextLabel $g.Name
                if ($lbl) { & $add 'WARNING' 'Error History' ("{0} crash/hang event(s) of copies started by {1}" -f $g.Count, $lbl) ("started from {0}; {1}" -f $g.Name, $script:NoDesktopText) }
            }
        }
    } catch { }

    # --- .NET exception stacks (v6, F13) ---
    try {
        $srcF = Get-RunSources $S.Path
        foreach ($st in (Get-ErrorStacks)) {
            $user = @($st.Frames | Where-Object { -not $_.IsFramework })
            $topFw = @($st.Frames | Select-Object -First 1)
            $first = $user[0]
            $h = Find-FrameMethods $first $srcF
            $inFile = if ($h.Count -gt 0) { 'code in ' + ((@($h | ForEach-Object { $_.Src.Label }) | Select-Object -Unique) -join ', ') } else { 'method not found in the analysed file or its related files' }
            $raisedBy = if ($topFw.Count -gt 0 -and $topFw[0].IsFramework) { " while calling $($topFw[0].Display)" } else { '' }
            $ev2 = "stack: {0}; {1}. See section 5 / 15_ErrorHistory_StackCode.txt." -f ((@($user | ForEach-Object { $_.Method }) -join ' <- ')), $inFile
            try {   # v8 (F20)
                $isBox = (@($st.Frames | Where-Object { $_.IsFramework -and $_.Display -match '(MessageBox\.Show|Form\.ShowDialog|Interaction\.MsgBox)' }).Count -gt 0)
                if ($isBox -and $st.NetType -match 'InvalidOperationException') { $ev2 += ' The program tried to show a message box / dialog and ' + $script:NoDesktopText }
                if ($isBox -and $h.Count -gt 0) { $bt = Get-MessageBoxTexts $h[0].Src.MD $h[0].Rid; if ($bt.Count -gt 0) { $ev2 += ' Boxes this method can show: ' + ((@($bt | ForEach-Object { "'$_'" })) -join ' | ') } }
            } catch { }
            & $add 'PROBLEM' 'Error History' ("{0} in {1}{2} ({3} time(s))" -f $(if ($st.NetType) { $st.NetType } else { '.NET exception' }), $first.Display, $raisedBy, $st.Rows.Count) $ev2
        }
    } catch { }

    # --- Dialog Finder (captures not already reported by a run) ---
    foreach ($e in $script:DialogHistory) {
        if ($null -ne $e.Run) { continue }
        $ev = ''
        if ($e.Known.Count -gt 0) { $ev = "known message: $($e.Known[0].Where) - $($e.Known[0].Text)" }
        if ($e.Top.Count -gt 0) { $ev += $(if ($ev) { ' | ' } else { '' }) + 'best source: ' + (Format-CauseLine $e.Top[0] 120); $hw = Get-CauseHowSummary $e.Top[0]; if ($hw) { $ev += ' | shown ' + $hw } }
        if (-not $ev) { $ev = 'no source found in the program or its related files' }
        $who = if ($e.Process) { " from $($e.Process)" } else { '' }
        & $add 'PROBLEM' "Dialog #$($e.No)" ("Error/warning box{0}: '{1}'" -f $who, $e.Title) $ev
    }

    $rank = @{ 'PROBLEM' = 0; 'WARNING' = 1; 'INFO' = 2 }
    $i = 0
    $sorted = @($list | ForEach-Object { $i++; [pscustomobject]@{ F = $_; R = $rank[$_.Severity]; I = $i } } | Sort-Object R, I | ForEach-Object { $_.F })
    return , $sorted
}

# ---------------- report sections ----------------
function Get-ProgramAnalysisText {
    $S = $script:S
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    foreach ($sec in 'FILE', 'WHAT KIND OF PROGRAM IS THIS', '.NET DETAILS', 'HINTS') {
        $ls = Get-OverviewSection $sec
        if ($ls.Count -eq 0) { continue }
        & $ln ("  [{0}]" -f $sec)
        foreach ($l in $ls) { & $ln ('  ' + $l) }
        & $ln ''
    }
    if ($S.PS -and $S.PS.Found) {
        & $ln '  [SCRIPT OUTLINE]  (full outline: 14_ScriptOutline.txt, script: 06_Recovered_*.ps1)'
        try {
            $o = Get-ScriptOutline $S.PS.Script
            & $ln ("  Recovered: {0} - {1}; {2} lines, {3} top-level steps, {4} functions, {5} distinct commands" -f $S.PS.Name, $S.PS.Method, @($S.PS.Script -split "`r?`n").Count, @($o.Steps).Count, @($o.Functions).Count, @($o.Commands).Count)
            & $ln '  Steps in run order (first 40):'
            foreach ($st in @($o.Steps | Select-Object -First 40)) { & $ln ('    L{0}: {1}' -f $st.Line, $st.Text) }
            if (@($o.Steps).Count -gt 40) { & $ln '    ...' }
            & $ln '  Functions:'
            foreach ($f in @($o.Functions | Sort-Object Line)) { & $ln ('    {0}  (lines {1}-{2})' -f $f.Name, $f.Line, $f.EndLine) }
        } catch { & $ln "  Outline failed: $($_.Exception.Message)" }
    } elseif ($S.MD -and $S.MD.Valid) {
        $md = $S.MD
        & $ln '  [.NET ENTRY POINT]'
        if (($md.EntryPointToken -shr 24) -eq 6) {
            $rid = [int]($md.EntryPointToken -band 0xFFFFFF)
            try {
                & $ln ('  ' + (Get-MdMethodDefName $md $rid -WithSig))
                $il = @((Format-ILListing $md $rid) -split "`r?`n")
                foreach ($l in @($il | Select-Object -First 60)) { & $ln ('    ' + $l) }
                if ($il.Count -gt 60) { & $ln ("    ... ({0} more lines - see 08_DotNet_IL_AllMethods.txt when exported with IL)" -f ($il.Count - 60)) }
            } catch { & $ln "  Entry point could not be decoded: $($_.Exception.Message)" }
        } else { & $ln '  No managed entry point (library / DLL).' }
        if ($S.PInvoke -and $S.PInvoke.Count -gt 0) {
            & $ln ''
            & $ln ("  [NATIVE DLL CALLS - P/Invoke ({0})]" -f $S.PInvoke.Count)
            foreach ($p in $S.PInvoke) { & $ln ("    {0} ! {1}   <- {2}" -f $p.Dll, $p.Function, $p.Managed) }
        }
    } else {
        $ls = Get-OverviewSection 'WHAT IT CAN DO (from imported Windows functions)'
        if ($ls.Count -gt 0) { & $ln '  [WHAT IT CAN DO (imported Windows functions)]'; foreach ($l in $ls) { & $ln ('  ' + $l) } }
        & $ln '  Native program: source code cannot be recovered from machine code.'
    }
    $dl = Get-OverviewSection 'DLL DEPENDENCIES'
    if ($dl.Count -gt 0) { & $ln ''; & $ln '  [DLL DEPENDENCIES]'; foreach ($l in $dl) { & $ln ('  ' + $l) } }
    return $sb.ToString()
}

function Get-RelatedFilesText {
    $S = $script:S
    $sb = New-Object System.Text.StringBuilder
    if (-not $S.Related -or $S.Related.Count -eq 0) { return "  No related files found (or the file was not analysed).`r`n" }
    [void]$sb.AppendLine(("  {0} related file(s):" -f $S.Related.Count))
    $i = 0
    foreach ($rf in $S.Related) {
        $i++
        $inf = Get-RelatedFileInfo $rf
        [void]$sb.AppendLine(("  {0,3}. {1}   [{2}]   {3}" -f $i, $rf.Name, $inf.Kind, (Format-Size ([int64]$rf.Size))))
        [void]$sb.AppendLine(("       Why related : {0}" -f $rf.Why))
        [void]$sb.AppendLine(("       Path        : {0}" -f $rf.Path))
        $meta = @()
        if ($inf.Description) { $meta += $inf.Description }
        if ($inf.Company) { $meta += $inf.Company }
        if ($inf.Version) { $meta += "version $($inf.Version)" }
        if ($meta.Count) { [void]$sb.AppendLine(("       File info   : {0}" -f ($meta -join ', '))) }
    }
    return $sb.ToString()
}

function Get-ProgramLogsText {
    $S = $script:S
    if (-not $S.ProgramLogs -or $S.ProgramLogs.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(("  Log files this program writes ({0}) - Run and Watch records what is written to them during each run:" -f $S.ProgramLogs.Count))
    foreach ($lp in $S.ProgramLogs) {
        $st = if ([System.IO.File]::Exists($lp)) { $fi = New-Object System.IO.FileInfo($lp); 'exists, {0}, modified {1}' -f (Format-Size $fi.Length), (Format-ReportTime $fi.LastWriteTime) } else { 'not created yet' }
        [void]$sb.AppendLine(("    {0}   ({1})" -f $lp, $st))
    }
    return $sb.ToString()
}

function Get-RunAnalysisText {
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    if ($script:RunHistory.Count -eq 0) { return "  No program was run with Run and Watch in this session.`r`n" }
    $evSeen = @{}
    foreach ($rec in $script:RunHistory) {
        & $ln ("  --- Run #{0}: {1} ---" -f $rec.No, $rec.ExeName)
        & $ln ("  Command line : {0}" -f $rec.CommandLine)
        & $ln ("  Start in     : {0}" -f $rec.Dir)
        $dur = if ($rec.End) { '{0:N1} s' -f ($rec.End - $rec.Start).TotalSeconds } else { '(still running when exported)' }
        & $ln ("  Started      : {0}    Ended: {1}    Duration: {2}" -f (Format-ReportTime $rec.Start), (Format-ReportTime $rec.End), $dur)
        if (-not $rec.End) { & $ln ("  Result       : PARTIAL - still {0} when the report was exported. Exit codes, later dialogs and the after-exit event check are missing; export again when it has finished." -f $rec.Status.ToLower()) }
        else { & $ln ("  Result       : {0}{1}" -f $rec.Status, $(if ($rec.StoppedByUser) { ' (force-stopped by the user)' } else { '' })) }
        $elev = if ($rec.Elevated -eq $true) { 'yes' } elseif ($rec.Elevated -eq $false) { 'NO' } else { 'unknown' }
        & $ln ("  Console capture: {0}    EXE Inspector running as administrator: {1}" -f $(if ($rec.Captured) { 'yes' } else { 'no' }), $elev)
        if ($rec.Status -eq 'Start failed') {
            & $ln ("  START FAILED : {0}" -f $rec.StartError)
            if ($null -ne $rec.StartErrorCode) { & $ln ("                 Windows error {0}" -f (Get-Win32ErrorText ([int64]$rec.StartErrorCode))) }
            if ($rec.StartErrorCode -eq 740) { & $ln '                 The program needs administrator rights: untick "Capture console output" (to get the UAC prompt) or run EXE Inspector as administrator.' }
        }
        if ($rec.WatchError) { & $ln ("  Watch error  : {0}" -f $rec.WatchError) }
        & $ln ''
        & $ln ("  Processes ({0}):" -f $rec.Procs.Count)
        foreach ($p in $rec.Procs) {
            $role = if ($p.IsMain) { 'main ' } else { 'child' }
            $codeTxt = if ($null -ne $p.ExitCode) { $p.Meaning } elseif ($p.Ended) { 'exit code not available' } else { 'still running / not seen ending' }
            if ($p.IsMain -and $null -ne $p.ExitCode) { $xn = Get-RunExitName $rec; if ($xn) { $codeTxt += "  = $xn (name printed by the program just before it exited)" } }
            $ran = if ($p.Ended) { '  ran {0:N1} s' -f ($p.Ended - $p.Started).TotalSeconds } else { '' }
            & $ln ("    [{0}] {1}  PID {2}{3}{4}" -f $role, $p.Name, $p.Pid, $(if (-not $p.IsMain) { "  (parent $($p.Parent))" } else { '' }), $ran)
            & $ln ("            exit: {0}" -f $codeTxt)
            if (-not $p.IsMain -and $p.CommandLine) { & $ln ("            cmd : {0}" -f $p.CommandLine) }
        }
        & $ln ''
        $errs = Get-RunErrorLines $rec
        & $ln ("  Console output: {0} line(s), {1} look like errors" -f $rec.Console.Count, $errs.Count)
        if ($errs.Count -gt 0) {
            $src = Get-RunSources $rec.Exe
            foreach ($c in $errs) {
                & $ln ("    {0} {1}> {2}" -f (Format-ReportTime $c.Time 'HH:mm:ss'), $c.Stream, $c.Text.Trim())
                foreach ($k in (Get-KnownMessageExplanation $c.Text)) { & $ln ("        Known meaning : {0} - {1}" -f $k.Title, $k.Explanation) }
                $hits = @()
                try { $hits = Find-MessageSource $c.Text $src 3 } catch { }
                if ($hits.Count -eq 0) { & $ln ("        Comes from    : not found in the {0} decoded source(s) (the program, the analysed file and its related files) - the text may come from Windows or another program" -f $src.Count) }
                foreach ($h in $hits) {
                    $t = ([string]$h.Text) -replace "`r?`n", ' | '; if ($t.Length -gt 140) { $t = $t.Substring(0, 137) + '...' }
                    $where = $h.Where
                    if ($h.Kind -eq '.NET string literal' -and $h.SourceRef -and $h.SourceRef.MD) {
                        try { $users = Find-TokenUsage $h.SourceRef.MD ([int64]$h.Token) 3; if ($users.Count) { $where += '; used in ' + (($users | Select-Object -First 3) -join ', ') } } catch { }
                    }
                    & $ln ("        Comes from    : [{0}] {1} in {2} ({3}): ""{4}""" -f $h.Score, $h.Kind, $h.Source, $where, $t)
                }
            }
            if ($src.Count -eq 0) { & $ln '        (the program file could not be searched - it no longer exists or was not readable)' }
        }
        try {   # v8 (F17)
            $lt = Get-RunLogTexts $rec
            if ($lt.Count -gt 0 -or ($rec.LogStart -and $rec.LogStart.Count -gt 0)) {
                & $ln ''
                & $ln ("  Program log files - lines written during this run ({0} log file(s) watched):" -f $rec.LogStart.Count)
                if ($lt.Count -eq 0) { & $ln '    (nothing was written to them during the run)' }
                foreach ($lp in $lt.Keys) {
                    $ls = @($lt[$lp] -split "`r?`n")
                    & $ln ("    {0}  ({1} line(s))" -f $lp, $ls.Count)
                    $show = if ($ls.Count -gt 60) { $ls[($ls.Count - 60)..($ls.Count - 1)] } else { $ls }
                    if ($ls.Count -gt 60) { & $ln '      ... (last 60 lines shown - all of them in 16_ProgramLogs.txt)' }
                    foreach ($ll in $show) { & $ln ('      {0} {1}' -f $(if (Test-ErrorLikeLine $ll) { '!' } else { ' ' }), $ll.TrimEnd()) }
                }
            }
        } catch { }
        & $ln ''
        & $ln ("  Dialogs detected: {0}" -f $rec.Dialogs.Count)
        foreach ($d in $rec.Dialogs) {
            & $ln ("    {0}  {1} (PID {2})  '{3}'" -f (Format-ReportTime $d.Time 'HH:mm:ss'), $d.Process, $d.Pid, $d.Title)
            foreach ($l in @(([string]$d.Text) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 12)) { & $ln ("        | {0}" -f $l.Trim()) }
            if ($d.Top3.Count -eq 0) { & $ln '        Top causes: no match in the program or its related files' }
            $j = 0
            foreach ($t3 in $d.Top3) { $j++; & $ln ("        Cause {0}: {1}" -f $j, $t3) }
            if ($d.EntryNo) { & $ln ("        Full detail: Dialog #{0} in section 6 / 12_DialogFinder.txt" -f $d.EntryNo) }
        }
        & $ln ''
        & $ln ("  Non-Windows DLLs loaded: {0}" -f $rec.Dlls.Count)
        foreach ($m in $rec.Dlls) { & $ln ("    {0}" -f $m) }
        if ($rec.Windows.Count -gt 0) {
            & $ln ("  Windows shown: {0}" -f $rec.Windows.Count)
            foreach ($w in $rec.Windows) { & $ln ("    {0}" -f $w) }
        }
        if ($rec.WerSeen.Count -gt 0) { & $ln '  Windows Error Reporting:'; foreach ($w in $rec.WerSeen) { & $ln ("    {0}" -f $w) } }
        & $ln ''
        & $ln ("  Windows / installer events from this run: {0}" -f $rec.WinEvents.Count)
        foreach ($x in $rec.WinEvents) {
            $ek = Get-EventKey $x
            if ($evSeen.ContainsKey($ek)) { & $ln ("    {0}  [{1}] {2} (ID {3}) - same event as listed under run #{4} (logged before this run started)" -f (Format-ReportTime $x.Time 'HH:mm:ss'), $x.Log, $x.Source, $x.EventId, $evSeen[$ek]); continue }
            $evSeen[$ek] = $rec.No
            & $ln ("    {0}  [{1}] {2} / {3} (ID {4}): {5}" -f (Format-ReportTime $x.Time 'HH:mm:ss'), $x.Log, $x.Source, $x.Level, $x.EventId, $x.Summary)
            foreach ($dl in @(([string]$x.Detail -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 10)) { & $ln ('        ' + $dl.TrimEnd()) }
        }
        & $ln ''
    }
    return $sb.ToString()
}

function Get-RunStackNote {
    # stacks from Run and Watch events when Error History itself has nothing to show
    $t = ''
    try { $t = Get-StackCodeText 150 } catch { }
    if (-not $t) { return '' }
    return ("`r`n  Code of the methods in the .NET exception stack(s) logged during Run and Watch:`r`n" + $t)
}

function Get-AllStackFrames {
    # v6 (F13): every "at Type.Method(" line of a .NET exception text, top of the stack first, framework frames included
    param([string]$Text)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Text) { return , $out }
    foreach ($m in [regex]::Matches($Text, '(?m)^\s*(at|bei|\u00E0|en)\s+([\w\.\+`<>\[\],]+)\.([\w<>`\.]+)\(')) {
        $type = $m.Groups[2].Value; $meth = $m.Groups[3].Value
        $fw = ($type -match '^(System|Microsoft|MS\.Internal|Windows)\.' -or $type -like 'CallSite*')
        $out.Add([pscustomobject]@{ Type = $type; Method = $meth; Display = "$type.$meth"; IsFramework = $fw })
    }
    return , $out
}

function Get-ErrorStacks {
    # distinct .NET exception stacks from Error History and from the Windows events of every run
    $S = $script:S
    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $all = New-Object System.Collections.Generic.List[object]
    if ($S.ErrorRows) { foreach ($x in $S.ErrorRows) { $all.Add($x) } }
    foreach ($rec in $script:RunHistory) { foreach ($x in $rec.WinEvents) { $all.Add($x) } }
    $byKey = [ordered]@{}
    foreach ($x in $all) {
        $ek = Get-EventKey $x
        if ($seen.ContainsKey($ek)) { continue }
        $seen[$ek] = $true
        $fr = Get-AllStackFrames ([string]$x.Detail)
        if (@($fr | Where-Object { -not $_.IsFramework }).Count -eq 0) { continue }
        $k = (@($fr | ForEach-Object { $_.Display }) -join ' <- ')
        if (-not $byKey.Contains($k)) { $byKey[$k] = [pscustomobject]@{ Key = $k; Frames = $fr; Rows = (New-Object System.Collections.Generic.List[object]); NetType = '' } }
        $byKey[$k].Rows.Add($x)
        if (-not $byKey[$k].NetType) { $byKey[$k].NetType = (Get-ErrorRowFacts $x).NetType }
    }
    foreach ($k in $byKey.Keys) { $rows.Add($byKey[$k]) }
    return , $rows
}

function Find-FrameMethods {
    # [pscustomobject]@{ Src; Rid } for every method matching a stack frame in the analysed file / related files
    param($Frame, $Sources)
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($src in $Sources) {
        if (-not $src.MD) { continue }
        foreach ($rid in (Find-MethodByFrame $src.MD $Frame)) { $hits.Add([pscustomobject]@{ Src = $src; Rid = $rid }) }
    }
    return , $hits
}

function Get-StackCodeText {
    # v6 (F13): each .NET exception stack with the IL of its methods; >> marks the call to the method above it in the stack
    param([int]$MaxLines = 150)
    $S = $script:S
    $stacks = Get-ErrorStacks
    if ($stacks.Count -eq 0) { return '' }
    $src = Get-RunSources $S.Path
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    $k = 0
    foreach ($st in $stacks) {
        $k++
        $times = @($st.Rows | Sort-Object Time)
        & $ln ("  --- .NET exception stack #{0}: {1}  ({2} time(s), first {3}, last {4}) ---" -f $k, $(if ($st.NetType) { $st.NetType } else { 'exception' }), $st.Rows.Count, (Format-ReportTime $times[0].Time), (Format-ReportTime $times[-1].Time))
        $found = @{}
        for ($i = 0; $i -lt $st.Frames.Count; $i++) {
            $f = $st.Frames[$i]
            if ($f.IsFramework) { & $ln ("    at {0}   (Windows / .NET Framework)" -f $f.Display); continue }
            $h = Find-FrameMethods $f $src
            $found[$i] = $h
            $where = if ($h.Count -gt 0) { 'in ' + ((@($h | ForEach-Object { $_.Src.Label }) | Select-Object -Unique) -join ', ') } else { 'NOT FOUND in the analysed file or its related files - analyse the DLL that contains it' }
            & $ln ("    at {0}   -> {1}" -f $f.Display, $where)
        }
        for ($i = 0; $i -lt $st.Frames.Count; $i++) {
            if (-not $found.ContainsKey($i)) { continue }
            $f = $st.Frames[$i]
            $callee = if ($i -gt 0) { $st.Frames[$i - 1] } else { $null }
            foreach ($h in $found[$i]) {
                & $ln ''
                $calleeTxt = if ($callee) { "  (>> = call to $($callee.Display), the next step towards the error)" } else { '  (top of the stack - the exception was raised in this method)' }
                & $ln ("    Method {0}  in {1}{2}" -f (Get-MdMethodDefName $h.Src.MD $h.Rid -WithSig), $h.Src.Label, $calleeTxt)
                try {   # v8 (F20): the boxes this method shows, and how each Show call is reached
                    if ($callee -and $callee.IsFramework -and $callee.Display -match '(MessageBox|Interaction|Form)') {
                        $bt = Get-MessageBoxTexts $h.Src.MD $h.Rid
                        foreach ($t in $bt) { & $ln ("      Box this method can show: '{0}'" -f $t) }
                    }
                    if ($callee) {
                        $il2 = Get-ILInstructions $h.Src.MD $h.Rid
                        $ct2 = $callee.Type -replace '/', '+'
                        $nShown = 0
                        for ($q = 0; $q -lt $il2.Count -and $nShown -lt 3; $q++) {
                            $qi = $il2[$q]
                            if ($qi.Name -notin 'call', 'callvirt', 'newobj') { continue }
                            $rq = Resolve-MdToken $h.Src.MD ([int64]$qi.Operand)
                            $hitq = if ($callee.IsFramework) { $rq.Contains($ct2 + '::') } else { $rq.Contains($ct2 + '::' + $callee.Method + '(') }
                            if (-not $hitq) { continue }
                            $nShown++
                            $cx = Get-ILContextAt $h.Src.MD $h.Rid $il2 $q
                            & $ln ("      How IL_{0:X4} (call to {1}) is reached:" -f $qi.Offset, (Get-ShortMemberName $rq))
                            if ($cx.Count -eq 0) { & $ln '        - by the normal flow of the method (no condition or handler right before it)' }
                            foreach ($cl in $cx) { & $ln ('        - ' + $cl) }
                        }
                    }
                } catch { }
                $il = @()
                try { $il = @((Format-ILListing $h.Src.MD $h.Rid) -split "`r?`n") } catch { & $ln "      (IL could not be decoded: $($_.Exception.Message))"; continue }
                $mark = New-Object System.Collections.Generic.List[int]
                for ($j = 0; $j -lt $il.Count; $j++) {
                    if (-not $callee) { if ($il[$j] -match '\bthrow\b') { $mark.Add($j) }; continue }
                    $ct = $callee.Type -replace '/', '+'
                    $hit = if ($callee.IsFramework) { $il[$j].Contains($ct + '::') } else { $il[$j].Contains($ct + '::' + $callee.Method + '(') }
                    if ($hit) { $mark.Add($j) }
                }
                $from = 0; $to = $il.Count - 1
                if ($MaxLines -gt 0 -and $il.Count -gt $MaxLines) {
                    if ($mark.Count -gt 0) { $from = [Math]::Max(0, $mark[0] - [int]($MaxLines * 0.7)); $to = [Math]::Min($il.Count - 1, $from + $MaxLines - 1) }
                    else { $to = $MaxLines - 1 }
                    & $ln ("      (lines {0}-{1} of {2} shown - full listing in 15_ErrorHistory_StackCode.txt)" -f ($from + 1), ($to + 1), $il.Count)
                }
                if ($mark.Count -eq 0 -and $callee) { & $ln '      (the call to the next method was not found by name - it may be called through a delegate, an interface or a compiler-generated helper)' }
                for ($j = $from; $j -le $to; $j++) { & $ln ($(if ($mark.Contains($j)) { '    >>' } else { '      ' }) + $il[$j]) }
            }
        }
        & $ln ''
    }
    return $sb.ToString()
}

function Get-ErrorHistoryText {
    $S = $script:S
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    $rows = @($S.ErrorRows)
    if ($S.ErrorSearch) { & $ln ("  Search: '{0}', last {1} day(s), WER reports {2}, System log {3}, searched at {4}" -f $S.ErrorSearch.Name, $S.ErrorSearch.Days, $(if ($S.ErrorSearch.Wer) { 'yes' } else { 'no' }), $(if ($S.ErrorSearch.SysLog) { 'yes' } else { 'no' }), (Format-ReportTime $S.ErrorSearch.Time)) }
    if (-not $S.ErrorSearch -and -not $S.ErrorRows) { & $ln '  Error History was not searched in this session (tab 8 > Search).'; return ($sb.ToString() + (Get-RunStackNote)) }
    if ($rows.Count -eq 0) { & $ln '  No events or crash reports were found.'; return ($sb.ToString() + (Get-RunStackNote)) }
    & $ln ("  {0} item(s) found." -f $rows.Count)
    & $ln '  Counts by type:'
    foreach ($t in 'Crash', 'Hang', '.NET exception', 'Side-by-side', 'Installer', 'WER report', 'WER event', 'Other') {
        $n = @($rows | Where-Object { (Get-ErrorRowType $_) -eq $t }).Count
        & $ln ("    {0,-16} {1}" -f $t, $n)
    }
    $facts = @($rows | ForEach-Object { Get-ErrorRowFacts $_ })
    $tm = Get-TopCount @($facts | ForEach-Object { $_.Module })
    $tc = Get-TopCount @($facts | ForEach-Object { $_.Code })
    $tn = Get-TopCount @($facts | ForEach-Object { $_.NetType })
    & $ln ("  Most frequent faulting module : {0}" -f $(if ($tm) { "$($tm.Value) ($($tm.Count) time(s))" } else { '(none recorded)' }))
    if ($tm -and $tm.All.Count -gt 1) { & $ln ("    others: {0}" -f ((@($tm.All | Select-Object -Skip 1 -First 5) | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')) }
    & $ln ("  Most frequent exception code  : {0}" -f $(if ($tc) { "$(Get-CodeMeaning $tc.Value)  ($($tc.Count) time(s))" } else { '(none recorded)' }))
    & $ln ("  Most frequent .NET exception  : {0}" -f $(if ($tn) { "$($tn.Value) ($($tn.Count) time(s))" } else { '(none recorded)' }))
    try {   # v8 (F20): where the crashed copies were started from
        $paths = @($rows | ForEach-Object { Get-ErrorRowAppPath $_ } | Where-Object { $_ })
        if ($paths.Count -gt 0) {
            & $ln '  Started from (faulting application path):'
            foreach ($g in @($paths | Group-Object | Sort-Object Count -Descending)) {
                $lbl = Get-RunContextLabel $g.Name
                & $ln ("    {0,3} x {1}{2}" -f $g.Count, $g.Name, $(if ($lbl) { "   <- started by $lbl" } else { '' }))
            }
            if (@($paths | Where-Object { Get-RunContextLabel $_ }).Count -gt 0) { & $ln ('    Note: copies started by a deployment tool or service usually have no desktop - ' + $script:NoDesktopText) }
        }
    } catch { }
    $sortedT = @($rows | Sort-Object Time)
    & $ln ("  First seen : {0}   ({1} / {2})" -f (Format-ReportTime $sortedT[0].Time), $sortedT[0].Source, $sortedT[0].Summary)
    & $ln ("  Last seen  : {0}   ({1} / {2})" -f (Format-ReportTime $sortedT[-1].Time), $sortedT[-1].Source, $sortedT[-1].Summary)
    & $ln ''
    & $ln '  Newest entries in full (up to 3):'
    foreach ($x in @($rows | Sort-Object Time -Descending | Select-Object -First 3)) {
        & $ln ("    --- {0}  [{1}] {2}  ID {3}  {4} ---" -f (Format-ReportTime $x.Time), $x.Log, $x.Source, $x.EventId, $x.Level)
        foreach ($dl in (([string]$x.Detail) -split "`r?`n")) { & $ln ('      ' + $dl.TrimEnd()) }
    }
    $stk = ''
    try { $stk = Get-StackCodeText 150 } catch { $stk = "  (stack code could not be built: $($_.Exception.Message))`r`n" }
    if ($stk) {
        & $ln ''
        & $ln '  Code of the methods in the .NET exception stack(s) (searched in the analysed file and its related files):'
        [void]$sb.Append($stk)
    }
    return $sb.ToString()
}

function Get-DialogEntryText {
    param($Entry, [bool]$Full, $SameAs = $null)
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    $e = $Entry
    & $ln ("  --- Dialog #{0}  ({1}, {2}) ---" -f $e.No, (Format-ReportTime $e.Time), $e.Origin)
    $owner = if ($e.Process) { "$($e.Process) (PID $($e.Pid))" } else { '(text pasted / typed - owner unknown)' }
    if ($e.OwnerExe) { $owner += "  $($e.OwnerExe)" }
    & $ln ("  Owner program : {0}" -f $owner)
    & $ln ("  Title         : {0}" -f $e.Title)
    & $ln '  Text          :'
    foreach ($l in (([string]$e.Text) -split "`r?`n")) { if ($l.Trim()) { & $ln ('    | ' + $l.TrimEnd()) } }
    if ($e.Searched) { & $ln ("  Searched      : {0} time(s), last at {1}, {2} decoded source(s), analysed file: {3}" -f $e.SearchCount, (Format-ReportTime $e.SearchTime 'HH:mm:ss'), $e.SourceCount, $e.AnalysedFile) }
    elseif ($e.SearchedAtExport) { & $ln ("  Searched      : not searched in the session - searched when the report was exported ({0} decoded source(s))" -f $e.SourceCount) }
    else { & $ln '  Searched      : no' }
    if ($e.Error) { & $ln ("  Search error  : {0}" -f $e.Error) }
    & $ln '  Known-message explanation:'
    if ($e.Known.Count -eq 0) { & $ln '    (not a known Windows/runtime message - it comes from the program itself or another program)' }
    foreach ($k in $e.Known) { & $ln ("    - {0}: {1}" -f $k.Where, $k.Text) }
    & $ln ("  Top sources ({0} of {1}):" -f $e.Top.Count, $e.ResultCount)
    if ($e.Top.Count -eq 0) { & $ln '    (no match in the analysed program or its related files)' }
    $i = 0
    foreach ($r in $e.Top) { $i++; & $ln ("    {0}) {1}" -f $i, (Format-CauseLine $r)) }
    if ($e.Top.Count -gt 0) {
        if ($Full) {
            $i = 0
            foreach ($r in $e.Top) {
                $i++
                & $ln ''
                & $ln ("  Detail of source {0}:" -f $i)
                $d = ''
                try { $d = Get-CauseDetail $r } catch { $d = "Could not build detail: $($_.Exception.Message)" }
                foreach ($l in ($d -split "`r?`n")) { & $ln ('    ' + $l) }
            }
        } elseif ($SameAs) {
            & $ln ("  Best match - code / script lines / IL: same text and source as Dialog #{0} (shown above)" -f $SameAs)
        } else {
            & $ln '  Best match - code / script lines / IL:'
            foreach ($l in ((Get-BestCauseDetail $e 80) -split "`r?`n")) { & $ln ('    ' + $l) }
        }
    }
    & $ln ''
    return $sb.ToString()
}

function Get-DialogHistoryText {
    param([bool]$Full = $false)
    if ($script:DialogHistory.Count -eq 0) { return "  No dialog was captured or searched in this session.`r`n" }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(("  {0} dialog(s) captured / searched in this session." -f $script:DialogHistory.Count))
    [void]$sb.AppendLine('')
    $shown = @{}
    foreach ($e in $script:DialogHistory) {
        $same = $null
        if (-not $Full -and $e.Top.Count -gt 0) {
            $k = (Get-NormalText $e.Text) + '|' + $e.Top[0].Source + '|' + $e.Top[0].Where
            if ($shown.ContainsKey($k)) { $same = $shown[$k] } else { $shown[$k] = $e.No }
        }
        [void]$sb.Append((Get-DialogEntryText $e $Full $same))
    }
    return $sb.ToString()
}

function Get-ScriptOutlineText {
    $S = $script:S
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    & $ln "Script outline - $($S.Path)"
    & $ln ''
    if (-not ($S.PS -and $S.PS.Found)) {
        & $ln 'No embedded PowerShell script was found in this file.'
        if ($S.PE -and $S.PE.IsDotNet) { & $ln 'It is a .NET program - its classes/methods are in 07_DotNet_Members.txt (and 08_DotNet_IL_AllMethods.txt when exported with IL).' }
        return $sb.ToString()
    }
    $o = Get-ScriptOutline $S.PS.Script
    & $ln ("Recovered : {0}  -  {1}" -f $S.PS.Name, $S.PS.Method)
    & $ln ("Lines     : {0}" -f @($S.PS.Script -split "`r?`n").Count)
    & $ln ''
    & $ln ("=== STEPS IN RUN ORDER (top-level statements: {0}) ===" -f @($o.Steps).Count)
    foreach ($st in $o.Steps) { & $ln ('  L{0}: {1}' -f $st.Line, $st.Text) }
    & $ln ''
    & $ln ("=== FUNCTIONS DEFINED ({0}) ===" -f @($o.Functions).Count)
    foreach ($f in @($o.Functions | Sort-Object Line)) { & $ln ('  {0}  (lines {1}-{2})' -f $f.Name, $f.Line, $f.EndLine) }
    & $ln ''
    & $ln ("=== COMMANDS / PROGRAMS CALLED ({0}) ===" -f @($o.Commands).Count)
    foreach ($c in $o.Commands) { & $ln ('  {0,-40} x{1,-4} first at line {2}' -f $c.Name, $c.Count, $c.FirstLine) }
    if (@($o.ParseErrors).Count -gt 0) {
        & $ln ''
        & $ln ("=== PARSE WARNINGS ({0}) ===" -f @($o.ParseErrors).Count)
        foreach ($e in $o.ParseErrors) { & $ln ('  ' + $e) }
    }
    return $sb.ToString()
}

function Get-FindingsReportText {
    $S = $script:S
    $sb = New-Object System.Text.StringBuilder
    $ln = { param($t) [void]$sb.AppendLine($t) }
    $bar = '=' * 100
    & $ln $bar
    & $ln ("  {0} - FINDINGS REPORT" -f $script:AppTitle)
    & $ln '  Developed by Isaac Sam Paul'
    & $ln $bar
    $elev = Test-IsElevated
    & $ln ("  Generated      : {0}" -f (Format-ReportTime (Get-Date)))
    & $ln ("  Computer / user: {0} / {1}   (EXE Inspector as administrator: {2})" -f $env:COMPUTERNAME, $env:USERNAME, $(if ($elev -eq $true) { 'yes' } elseif ($elev -eq $false) { 'no' } else { 'unknown' }))
    & $ln ("  Analysed file  : {0}" -f $S.Path)
    & $ln ("  Session        : {0} run(s) in Run and Watch, {1} dialog(s) in Dialog Finder, Error History {2}" -f $script:RunHistory.Count, $script:DialogHistory.Count, $(if ($S.ErrorSearch -or $S.ErrorRows) { "$(@($S.ErrorRows).Count) item(s)" } else { 'not searched' }))
    & $ln ''
    $sections = @(
        @('1) SUMMARY OF FINDINGS', {
                $f = Get-AllFindings
                $p = @($f | Where-Object { $_.Severity -eq 'PROBLEM' }).Count; $w = @($f | Where-Object { $_.Severity -eq 'WARNING' }).Count; $n = @($f | Where-Object { $_.Severity -eq 'INFO' }).Count
                $t = New-Object System.Text.StringBuilder
                [void]$t.AppendLine(("  {0} PROBLEM, {1} WARNING, {2} INFO" -f $p, $w, $n))
                [void]$t.AppendLine('')
                if ($f.Count -eq 0) { [void]$t.AppendLine('  No problems detected by the checks this tool can make.') }
                $i = 0
                foreach ($x in $f) {
                    $i++
                    [void]$t.AppendLine(("  {0,3}. [{1,-7}] {2}: {3}" -f $i, $x.Severity, $x.Area, $x.Issue))
                    if ($x.Evidence) { [void]$t.AppendLine(("                 Evidence: {0}" -f $x.Evidence)) }
                }
                $t.ToString() }),
        @('2) PROGRAM ANALYSIS', { Get-ProgramAnalysisText }),
        @('3) RELATED FILES', { (Get-RelatedFilesText) + (Get-ProgramLogsText) }),
        @('4) RUN AND WATCH ANALYSIS', { Get-RunAnalysisText }),
        @('5) ERROR HISTORY ANALYSIS', { Get-ErrorHistoryText }),
        @('6) DIALOG FINDER ANALYSIS', { Get-DialogHistoryText $false })
    )
    foreach ($sec in $sections) {
        & $ln $bar
        & $ln ('  ' + $sec[0])
        & $ln $bar
        $body = ''
        try { $body = [string](& $sec[1]) } catch { $body = "  (this section could not be built: $($_.Exception.Message))`r`n" }
        [void]$sb.Append($body)
        & $ln ''
    }
    & $ln $bar
    & $ln '  Other files in this folder: 01_Overview.txt, 02-05 (DLLs, imports, strings, resources), 06 recovered script,'
    & $ln '  07/08 .NET members/IL, 09 last Run and Watch log, 10 Error History, 11 related files, 12 Dialog Finder detail,'
    & $ln '  13 Run and Watch events (all runs), 14 script outline, 15 code of .NET exception stacks (when any),'
    & $ln '  16 program log files (when found).'
    & $ln $bar
    return $sb.ToString()
}

function Export-ReportAnalysis {
    # v5: writes 00_Findings.txt and 11-14 into an export folder. Each file is independent - one failing does not stop the others.
    param([string]$Dir)
    $S = $script:S
    $script:ReportSrcCache = @{}
    $written = New-Object System.Collections.Generic.List[string]
    try { Set-Status 'Searching captured dialogs not searched yet...'; Complete-DialogHistory } catch { Write-Log "Report: dialog search: $($_.Exception.Message)" 'WARN' }
    try {
        $rows = @()
        if ($S.Related) {
            $rows = @($S.Related | ForEach-Object {
                    $inf = Get-RelatedFileInfo $_
                    [pscustomobject]@{ Name = $_.Name; Kind = $inf.Kind; WhyRelated = $_.Why; Size = $_.Size; Path = $_.Path; FileVersion = $inf.Version; Company = $inf.Company; Description = $inf.Description }
                })
        }
        if ($rows.Count -gt 0) { $rows | Export-Csv -LiteralPath (Join-Path $Dir '11_RelatedFiles.csv') -NoTypeInformation -Encoding UTF8 }
        else { Set-Content -LiteralPath (Join-Path $Dir '11_RelatedFiles.csv') -Value '"Name","Kind","WhyRelated","Size","Path","FileVersion","Company","Description"' -Encoding UTF8 }
        $written.Add('11_RelatedFiles.csv')
    } catch { Write-Log "Report: 11_RelatedFiles.csv: $($_.Exception.Message)" 'WARN' }
    try {
        Set-Status 'Writing Dialog Finder detail...'
        $hdr = "Dialog Finder - every dialog captured or searched in this session (full detail per capture)`r`nAnalysed file: $($S.Path)`r`nGenerated: $(Format-ReportTime (Get-Date))`r`n`r`n"
        Set-Content -LiteralPath (Join-Path $Dir '12_DialogFinder.txt') -Value ($hdr + (Get-DialogHistoryText $true)) -Encoding UTF8
        $written.Add('12_DialogFinder.txt')
    } catch { Write-Log "Report: 12_DialogFinder.txt: $($_.Exception.Message)" 'WARN' }
    try {
        $ev = New-Object System.Collections.Generic.List[object]
        foreach ($rec in $script:RunHistory) { foreach ($x in $rec.Events) { $ev.Add([pscustomobject]@{ Time = (Format-ReportTime $x.Time 'yyyy-MM-dd HH:mm:ss.fff'); Run = $x.Run; Type = $x.Type; Process = $x.Process; Detail = $x.Detail }) } }
        if ($ev.Count -gt 0) { $ev | Export-Csv -LiteralPath (Join-Path $Dir '13_RunWatch_Events.csv') -NoTypeInformation -Encoding UTF8 }
        else { Set-Content -LiteralPath (Join-Path $Dir '13_RunWatch_Events.csv') -Value '"Time","Run","Type","Process","Detail"' -Encoding UTF8 }
        $written.Add('13_RunWatch_Events.csv')
    } catch { Write-Log "Report: 13_RunWatch_Events.csv: $($_.Exception.Message)" 'WARN' }
    try {
        Set-Content -LiteralPath (Join-Path $Dir '14_ScriptOutline.txt') -Value (Get-ScriptOutlineText) -Encoding UTF8
        $written.Add('14_ScriptOutline.txt')
    } catch { Write-Log "Report: 14_ScriptOutline.txt: $($_.Exception.Message)" 'WARN' }
    try {   # v8 (F17)
        $pl = $S.ProgramLogs
        $anyRun = @($script:RunHistory | Where-Object { (Get-RunLogTexts $_).Count -gt 0 }).Count -gt 0
        if (($pl -and $pl.Count -gt 0) -or $anyRun) {
            $sbl = New-Object System.Text.StringBuilder
            [void]$sbl.AppendLine("Log files the program writes (found in its text / folder + file names it builds)`r`nAnalysed file: $($S.Path)`r`nGenerated: $(Format-ReportTime (Get-Date))`r`n")
            foreach ($lp in $pl) {
                if ([System.IO.File]::Exists($lp)) {
                    $fiL = New-Object System.IO.FileInfo($lp)
                    [void]$sbl.AppendLine(("=== {0}   ({1}, modified {2}) - last 200 lines ===" -f $lp, (Format-Size $fiL.Length), (Format-ReportTime $fiL.LastWriteTime)))
                    [void]$sbl.AppendLine((Read-FileTail $lp 200)); [void]$sbl.AppendLine('')
                } else { [void]$sbl.AppendLine(("=== {0}   (does not exist now) ===" -f $lp)); [void]$sbl.AppendLine('') }
            }
            foreach ($rec in $script:RunHistory) {
                $lt = Get-RunLogTexts $rec
                foreach ($lp in $lt.Keys) { [void]$sbl.AppendLine(("=== Run #{0}: lines written to {1} during the run ===" -f $rec.No, $lp)); [void]$sbl.AppendLine($lt[$lp]); [void]$sbl.AppendLine('') }
            }
            Set-Content -LiteralPath (Join-Path $Dir '16_ProgramLogs.txt') -Value $sbl.ToString() -Encoding UTF8
            $written.Add('16_ProgramLogs.txt')
        }
    } catch { Write-Log "Report: 16_ProgramLogs.txt: $($_.Exception.Message)" 'WARN' }
    try {
        $stk = Get-StackCodeText 0
        if ($stk) {
            Set-Content -LiteralPath (Join-Path $Dir '15_ErrorHistory_StackCode.txt') -Value ("Code of the methods in every .NET exception stack (Error History + Run and Watch events)`r`nAnalysed file: $($S.Path)`r`nGenerated: $(Format-ReportTime (Get-Date))`r`n`r`n" + $stk) -Encoding UTF8
            $written.Add('15_ErrorHistory_StackCode.txt')
        }
    } catch { Write-Log "Report: 15_ErrorHistory_StackCode.txt: $($_.Exception.Message)" 'WARN' }
    try {
        Set-Status 'Writing findings report...'
        Set-Content -LiteralPath (Join-Path $Dir '00_Findings.txt') -Value (Get-FindingsReportText) -Encoding UTF8
        $written.Add('00_Findings.txt')
    } catch { Write-Log "Report: 00_Findings.txt: $($_.Exception.Message)" 'ERROR' }
    Write-Log ("Report analysis files written: {0}" -f ($written -join ', '))
    return , $written
}

# ---------------- build window ----------------
function Show-MainWindow {
    $form = New-Object System.Windows.Forms.Form
    $script:form = $form
    $form.Text = $script:AppTitle
    $form.Size = New-Object System.Drawing.Size(1300, 900)
    $form.MinimumSize = New-Object System.Drawing.Size(900, 600)
    $form.StartPosition = 'CenterScreen'
    $form.Font = $script:UiFont

    # --- tabs (Fill - added first so the top/bottom panels dock around it) ---
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $script:tabs = $tabs
    $form.Controls.Add($tabs)

    # --- top panel ---
    $top = New-Object System.Windows.Forms.Panel
    $top.Dock = 'Top'; $top.Height = 72
    $form.Controls.Add($top)
    $top.Controls.Add((New-Label 'EXE / DLL file:' 10 10 95))
    $txtPath = New-Object System.Windows.Forms.TextBox
    $txtPath.Location = New-Object System.Drawing.Point(108, 11); $txtPath.Size = New-Object System.Drawing.Size(880, 23)
    $txtPath.Anchor = 'Top,Left,Right'
    $txtPath.AllowDrop = $true
    $script:txtPath = $txtPath
    $top.Controls.Add($txtPath)
    $btnBrowse = New-Button 'Browse...' 996 9 90; $btnBrowse.Anchor = 'Top,Right'; $top.Controls.Add($btnBrowse)
    $btnAnalyze = New-Button 'Analyse' 1092 9 90; $btnAnalyze.Anchor = 'Top,Right'; $btnAnalyze.Font = $script:BoldFont; $top.Controls.Add($btnAnalyze)
    $btnExport = New-Button 'Export Report' 1188 9 95; $btnExport.Anchor = 'Top,Right'; $top.Controls.Add($btnExport)
    $chkRecursive = New-Object System.Windows.Forms.CheckBox
    $chkRecursive.Text = 'Check DLL dependencies recursively'; $chkRecursive.Checked = $true
    $chkRecursive.Location = New-Object System.Drawing.Point(108, 40); $chkRecursive.Size = New-Object System.Drawing.Size(240, 22)
    $script:chkRecursive = $chkRecursive; $top.Controls.Add($chkRecursive)
    $chkVerifySig = New-Object System.Windows.Forms.CheckBox
    $chkVerifySig.Text = 'Verify digital signature (slow when offline)'; $chkVerifySig.Checked = $false
    $chkVerifySig.Location = New-Object System.Drawing.Point(355, 40); $chkVerifySig.Size = New-Object System.Drawing.Size(280, 22)
    $script:chkVerifySig = $chkVerifySig; $top.Controls.Add($chkVerifySig)
    $lblStatus = New-Label 'Choose an EXE and press Analyse. The file is only read, never run.' 645 40 640 22
    $lblStatus.Anchor = 'Top,Left,Right'; $lblStatus.ForeColor = [System.Drawing.Color]::DimGray
    $script:lblStatus = $lblStatus; $top.Controls.Add($lblStatus)

    # --- bottom panel: output log + credit ---
    $bottom = New-Object System.Windows.Forms.Panel
    $bottom.Dock = 'Bottom'; $bottom.Height = 130
    $form.Controls.Add($bottom)
    $txtLog = New-TextView; $txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
    $script:txtLog = $txtLog
    $bottom.Controls.Add($txtLog)
    $lblOut = New-Object System.Windows.Forms.Label; $lblOut.Text = 'Output'; $lblOut.Dock = 'Top'; $lblOut.Height = 18; $lblOut.Font = $script:BoldFont
    $bottom.Controls.Add($lblOut)
    $lblCredit = New-Object System.Windows.Forms.Label; $lblCredit.Text = 'Developed by Isaac Sam Paul  |  EXE Inspector v8'; $lblCredit.Dock = 'Bottom'; $lblCredit.Height = 18
    $lblCredit.TextAlign = 'MiddleRight'; $lblCredit.ForeColor = [System.Drawing.Color]::Gray
    $bottom.Controls.Add($lblCredit)

    # ===== Tab 1: Overview =====
    $tabOverview = New-Object System.Windows.Forms.TabPage; $tabOverview.Text = '1. Overview'; $script:tabOverview = $tabOverview
    $txtOverview = New-TextView; $script:txtOverview = $txtOverview
    $txtOverview.Text = "EXE Inspector looks inside a Windows program without running it.`r`n`r`n" +
    "  1. Browse to (or drag in) an .exe or .dll and press Analyse.`r`n" +
    "  2. This tab tells you what kind of program it is and lists likely problems (missing DLLs, missing .NET version, admin rights...).`r`n" +
    "  3. 'Script' shows the original PowerShell of PS2EXE-made EXEs; '.NET Code' shows the steps of C#/VB.NET programs.`r`n" +
    "  4. 'Run & Watch' starts it (only when you press Start) and records what happens; 'Error History' finds its crash records.`r`n"
    $tabOverview.Controls.Add($txtOverview)
    [void]$tabs.TabPages.Add($tabOverview)

    # ===== Tab 2: Script =====
    $tabScript = New-Object System.Windows.Forms.TabPage; $tabScript.Text = '2. Script (PS2EXE)'; $script:tabScript = $tabScript
    $splitS = New-Object System.Windows.Forms.SplitContainer; $splitS.Dock = 'Fill'; $script:splitS = $splitS
    $tabScript.Controls.Add($splitS)
    $stripS = New-Strip; $tabScript.Controls.Add($stripS)
    $btnSaveScript = New-Button 'Save script as .ps1...' 6 6 160; $btnSaveScript.Enabled = $false; $script:btnSaveScript = $btnSaveScript; $stripS.Controls.Add($btnSaveScript)
    $lblScript = New-Label 'No script' 175 7 900 24; $script:lblScript = $lblScript; $stripS.Controls.Add($lblScript)
    $tvScript = New-Object System.Windows.Forms.TreeView; $tvScript.Dock = 'Fill'; $tvScript.HideSelection = $false; $script:tvScript = $tvScript
    $splitS.Panel1.Controls.Add($tvScript)
    $txtScript = New-TextView; $script:txtScript = $txtScript
    $splitS.Panel2.Controls.Add($txtScript)
    [void]$tabs.TabPages.Add($tabScript)

    # ===== Tab 3: .NET Code =====
    $tabNet = New-Object System.Windows.Forms.TabPage; $tabNet.Text = '3. .NET Code'
    $splitN = New-Object System.Windows.Forms.SplitContainer; $splitN.Dock = 'Fill'; $script:splitN = $splitN
    $tabNet.Controls.Add($splitN)
    $stripN = New-Strip; $tabNet.Controls.Add($stripN)
    $stripN.Controls.Add((New-Label 'Search methods, calls and strings:' 6 8 205))
    $txtNetSearch = New-Object System.Windows.Forms.TextBox; $txtNetSearch.Location = New-Object System.Drawing.Point(214, 8); $txtNetSearch.Size = New-Object System.Drawing.Size(260, 23)
    $script:txtNetSearch = $txtNetSearch; $stripN.Controls.Add($txtNetSearch)
    $btnNetSearch = New-Button 'Search' 480 6 80; $stripN.Controls.Add($btnNetSearch)
    $btnFindUsage = New-Button 'Find where used' 570 6 130; $btnFindUsage.Enabled = $false; $script:btnFindUsage = $btnFindUsage; $stripN.Controls.Add($btnFindUsage)
    $tvNet = New-Object System.Windows.Forms.TreeView; $tvNet.Dock = 'Fill'; $tvNet.HideSelection = $false; $script:tvNet = $tvNet
    $splitN.Panel1.Controls.Add($tvNet)
    $txtNet = New-TextView; $script:txtNet = $txtNet
    $splitN.Panel2.Controls.Add($txtNet)
    [void]$tabs.TabPages.Add($tabNet)

    # ===== Tab 4: Imports & DLLs =====
    $tabImp = New-Object System.Windows.Forms.TabPage; $tabImp.Text = '4. Imports and DLLs'
    $splitI = New-Object System.Windows.Forms.SplitContainer; $splitI.Dock = 'Fill'; $splitI.Orientation = 'Horizontal'; $script:splitI = $splitI
    $tabImp.Controls.Add($splitI)
    $stripI = New-Strip; $tabImp.Controls.Add($stripI)
    $btnRecheck = New-Button 'Re-check dependencies' 6 6 160; $stripI.Controls.Add($btnRecheck)
    $lblDeps = New-Label 'Analyse a file to list its DLLs.' 175 7 1000 24; $script:lblDeps = $lblDeps; $stripI.Controls.Add($lblDeps)
    $gridDeps = New-Grid; $script:gridDeps = $gridDeps; $splitI.Panel1.Controls.Add($gridDeps)
    $gridFuncs = New-Grid; $script:gridFuncs = $gridFuncs; $splitI.Panel2.Controls.Add($gridFuncs)
    [void]$tabs.TabPages.Add($tabImp)

    # ===== Tab 5: Strings =====
    $tabStr = New-Object System.Windows.Forms.TabPage; $tabStr.Text = '5. Strings'
    $gridStrings = New-Grid; $script:gridStrings = $gridStrings
    $tabStr.Controls.Add($gridStrings)
    $stripT = New-Strip; $tabStr.Controls.Add($stripT)
    $stripT.Controls.Add((New-Label 'Contains:' 6 8 60))
    $txtStrFilter = New-Object System.Windows.Forms.TextBox; $txtStrFilter.Location = New-Object System.Drawing.Point(68, 8); $txtStrFilter.Size = New-Object System.Drawing.Size(220, 23)
    $script:txtStrFilter = $txtStrFilter; $stripT.Controls.Add($txtStrFilter)
    $cmbCategory = New-Object System.Windows.Forms.ComboBox; $cmbCategory.DropDownStyle = 'DropDownList'
    $cmbCategory.Location = New-Object System.Drawing.Point(296, 8); $cmbCategory.Size = New-Object System.Drawing.Size(150, 23)
    [void]$cmbCategory.Items.Add('(all categories)')
    foreach ($r in $script:StrCategoryRules) { [void]$cmbCategory.Items.Add($r[0]) }
    [void]$cmbCategory.Items.Add('Other')
    $cmbCategory.SelectedIndex = 0
    $script:cmbCategory = $cmbCategory; $stripT.Controls.Add($cmbCategory)
    $stripT.Controls.Add((New-Label 'Min length:' 455 8 68))
    $numMinLen = New-Object System.Windows.Forms.NumericUpDown; $numMinLen.Location = New-Object System.Drawing.Point(525, 8); $numMinLen.Size = New-Object System.Drawing.Size(50, 23)
    $numMinLen.Minimum = 5; $numMinLen.Maximum = 200; $numMinLen.Value = 6; $script:numMinLen = $numMinLen; $stripT.Controls.Add($numMinLen)
    $chkNoise = New-Object System.Windows.Forms.CheckBox; $chkNoise.Text = 'Hide likely junk'; $chkNoise.Checked = $true
    $chkNoise.Location = New-Object System.Drawing.Point(585, 8); $chkNoise.Size = New-Object System.Drawing.Size(120, 23); $script:chkNoise = $chkNoise; $stripT.Controls.Add($chkNoise)
    $btnStrApply = New-Button 'Apply' 710 6 70; $stripT.Controls.Add($btnStrApply)
    $lblStrCount = New-Label '' 790 8 400 23; $script:lblStrCount = $lblStrCount; $stripT.Controls.Add($lblStrCount)
    [void]$tabs.TabPages.Add($tabStr)

    # ===== Tab 6: Resources =====
    $tabRes = New-Object System.Windows.Forms.TabPage; $tabRes.Text = '6. Resources'
    $splitR = New-Object System.Windows.Forms.SplitContainer; $splitR.Dock = 'Fill'; $script:splitR = $splitR
    $tabRes.Controls.Add($splitR)
    $stripR = New-Strip; $tabRes.Controls.Add($stripR)
    $btnSaveRes = New-Button 'Save selected resource...' 6 6 180; $stripR.Controls.Add($btnSaveRes)
    $gridRes = New-Grid; $script:gridRes = $gridRes; $splitR.Panel1.Controls.Add($gridRes)
    $txtRes = New-TextView; $script:txtRes = $txtRes; $splitR.Panel2.Controls.Add($txtRes)
    [void]$tabs.TabPages.Add($tabRes)

    # ===== Tab 7: Run & Watch =====
    $tabRun = New-Object System.Windows.Forms.TabPage; $tabRun.Text = '7. Run and Watch'
    $txtRun = New-TextView; $script:txtRun = $txtRun
    $tabRun.Controls.Add($txtRun)
    $stripRun = New-Strip 150; $tabRun.Controls.Add($stripRun)
    $stripRun.Controls.Add((New-Label 'Program:' 6 8 85))
    $txtRunExe = New-Object System.Windows.Forms.TextBox; $txtRunExe.Location = New-Object System.Drawing.Point(95, 8); $txtRunExe.Size = New-Object System.Drawing.Size(700, 23);
    $script:txtRunExe = $txtRunExe; $stripRun.Controls.Add($txtRunExe)
    $stripRun.Controls.Add((New-Label 'Arguments:' 6 36 85))
    $txtRunArgs = New-Object System.Windows.Forms.TextBox; $txtRunArgs.Location = New-Object System.Drawing.Point(95, 36); $txtRunArgs.Size = New-Object System.Drawing.Size(700, 23);
    $script:txtRunArgs = $txtRunArgs; $stripRun.Controls.Add($txtRunArgs)
    $stripRun.Controls.Add((New-Label 'Start in:' 6 64 85))
    $txtRunDir = New-Object System.Windows.Forms.TextBox; $txtRunDir.Location = New-Object System.Drawing.Point(95, 64); $txtRunDir.Size = New-Object System.Drawing.Size(700, 23);
    $script:txtRunDir = $txtRunDir; $stripRun.Controls.Add($txtRunDir)
    $btnRunDir = New-Button 'Browse...' 805 62 80; $stripRun.Controls.Add($btnRunDir)
    $chkCapture = New-Object System.Windows.Forms.CheckBox; $chkCapture.Text = 'Capture console output (no UAC prompt in this mode)'; $chkCapture.Checked = $true
    $chkCapture.Location = New-Object System.Drawing.Point(95, 94); $chkCapture.Size = New-Object System.Drawing.Size(330, 24); $script:chkCapture = $chkCapture; $stripRun.Controls.Add($chkCapture)
    $chkAfterEvents = New-Object System.Windows.Forms.CheckBox; $chkAfterEvents.Text = 'After it exits, check event logs and crash reports'; $chkAfterEvents.Checked = $true
    $chkAfterEvents.Location = New-Object System.Drawing.Point(430, 94); $chkAfterEvents.Size = New-Object System.Drawing.Size(320, 24); $script:chkAfterEvents = $chkAfterEvents; $stripRun.Controls.Add($chkAfterEvents)
    $chkWatchDlg = New-Object System.Windows.Forms.CheckBox; $chkWatchDlg.Text = 'Detect error/warning boxes it shows and find their cause (searches the program and its related files)'; $chkWatchDlg.Checked = $true
    $chkWatchDlg.Location = New-Object System.Drawing.Point(95, 120); $chkWatchDlg.Size = New-Object System.Drawing.Size(640, 24); $script:chkWatchDlg = $chkWatchDlg; $stripRun.Controls.Add($chkWatchDlg)
    $btnRunStart = New-Button 'Start' 895 8 100 30; $btnRunStart.Font = $script:BoldFont; $script:btnRunStart = $btnRunStart; $stripRun.Controls.Add($btnRunStart)
    $btnRunStop = New-Button 'Stop' 1000 8 80 30; $btnRunStop.Enabled = $false; $script:btnRunStop = $btnRunStop; $stripRun.Controls.Add($btnRunStop)
    $btnRunClear = New-Button 'Clear' 1085 8 70 30; $stripRun.Controls.Add($btnRunClear)
    $lblRunStatus = New-Label 'Not running. Nothing is started until you press Start.' 895 44 380 44; $lblRunStatus.ForeColor = [System.Drawing.Color]::DimGray
    $script:lblRunStatus = $lblRunStatus; $stripRun.Controls.Add($lblRunStatus)
    $txtRun.Text = "Run & Watch records what happens when the program starts:`r`n" +
    "  - console output (stdout/stderr) as it appears`r`n  - DLLs it loads (non-Windows ones listed by name)`r`n  - child processes it launches, window titles it shows`r`n" +
    "  - when it exits: the exit code and what it means (e.g. 0xC0000135 = missing DLL, 1603 = MSI install failed)`r`n  - it keeps watching until every child process it started (installers, msiexec) has finished`r`n" +
    "  - error/warning boxes it shows: their text, and where in the program (or its related files) that text comes from`r`n  - related Application event-log errors, Windows Installer events and crash reports for that run`r`n`r`n" +
    "Silent installs: put the installer in Program and its silent switches in Arguments. Installers that need admin: run EXE Inspector as administrator.`r`n" +
    "Not possible without extra tools: a full trace of every file/registry access (Process Monitor does that).`r`n"
    $script:Run.Timer = New-Object System.Windows.Forms.Timer
    $script:Run.Timer.Interval = 500
    [void]$tabs.TabPages.Add($tabRun)

    # ===== Tab 8: Error History =====
    $tabErr = New-Object System.Windows.Forms.TabPage; $tabErr.Text = '8. Error History'
    $splitE = New-Object System.Windows.Forms.SplitContainer; $splitE.Dock = 'Fill'; $splitE.Orientation = 'Horizontal'; $script:splitE = $splitE
    $tabErr.Controls.Add($splitE)
    $stripE = New-Strip; $tabErr.Controls.Add($stripE)
    $stripE.Controls.Add((New-Label 'EXE name:' 6 8 65))
    $txtErrExe = New-Object System.Windows.Forms.TextBox; $txtErrExe.Location = New-Object System.Drawing.Point(72, 8); $txtErrExe.Size = New-Object System.Drawing.Size(200, 23)
    $script:txtErrExe = $txtErrExe; $stripE.Controls.Add($txtErrExe)
    $stripE.Controls.Add((New-Label 'Last days:' 282 8 62))
    $numDays = New-Object System.Windows.Forms.NumericUpDown; $numDays.Location = New-Object System.Drawing.Point(346, 8); $numDays.Size = New-Object System.Drawing.Size(55, 23)
    $numDays.Minimum = 1; $numDays.Maximum = 365; $numDays.Value = 7; $script:numDays = $numDays; $stripE.Controls.Add($numDays)
    $chkWer = New-Object System.Windows.Forms.CheckBox; $chkWer.Text = 'WER crash reports'; $chkWer.Checked = $true
    $chkWer.Location = New-Object System.Drawing.Point(412, 8); $chkWer.Size = New-Object System.Drawing.Size(135, 23); $script:chkWer = $chkWer; $stripE.Controls.Add($chkWer)
    $chkSysLog = New-Object System.Windows.Forms.CheckBox; $chkSysLog.Text = 'Include System log'; $chkSysLog.Checked = $false
    $chkSysLog.Location = New-Object System.Drawing.Point(550, 8); $chkSysLog.Size = New-Object System.Drawing.Size(135, 23); $script:chkSysLog = $chkSysLog; $stripE.Controls.Add($chkSysLog)
    $btnErrSearch = New-Button 'Search' 692 6 90; $btnErrSearch.Font = $script:BoldFont; $stripE.Controls.Add($btnErrSearch)
    $gridErr = New-Grid; $script:gridErr = $gridErr; $splitE.Panel1.Controls.Add($gridErr)
    $txtErr = New-TextView; $txtErr.WordWrap = $true; $script:txtErr = $txtErr; $splitE.Panel2.Controls.Add($txtErr)
    $txtErr.Text = "Finds Application event-log errors that mention this EXE (crashes, hangs, .NET exceptions, side-by-side/VC++ runtime errors) and Windows Error Reporting crash folders.`r`nUse it after the program failed, even if it was started by someone else."
    [void]$tabs.TabPages.Add($tabErr)


    # ===== Tab 9: Related Files =====
    $tabRel = New-Object System.Windows.Forms.TabPage; $tabRel.Text = '9. Related Files'
    $gridRel = New-Grid; $script:gridRel = $gridRel
    $tabRel.Controls.Add($gridRel)
    $stripRel = New-Strip; $tabRel.Controls.Add($stripRel)
    $btnRelOpen = New-Button 'Decode selected' 6 6 130; $btnRelOpen.Font = $script:BoldFont; $stripRel.Controls.Add($btnRelOpen)
    $btnBack = New-Button '< Back' 142 6 80; $btnBack.Enabled = $false; $script:btnBack = $btnBack; $stripRel.Controls.Add($btnBack)
    $btnRelFolder = New-Button 'Open folder' 228 6 100; $stripRel.Controls.Add($btnRelFolder)
    $lblRel = New-Label 'Files this program uses: its own DLLs, .NET references, files named in its text, settings files, and programs packed inside it.' 336 7 950 24 $script:lblRel = $lblRel; $stripRel.Controls.Add($lblRel)
    [void]$tabs.TabPages.Add($tabRel)

    # ===== Tab 10: Dialog Finder =====
    $tabDlg = New-Object System.Windows.Forms.TabPage; $tabDlg.Text = '10. Dialog Finder'; $script:tabDlg = $tabDlg
    $splitD = New-Object System.Windows.Forms.SplitContainer; $splitD.Dock = 'Fill'; $splitD.Orientation = 'Horizontal'; $script:splitD = $splitD
    $tabDlg.Controls.Add($splitD)
    $stripD = New-Strip; $tabDlg.Controls.Add($stripD)
    $btnWinRefresh = New-Button 'Refresh open windows' 6 6 150; $stripD.Controls.Add($btnWinRefresh)
    $chkDlgOnly = New-Object System.Windows.Forms.CheckBox; $chkDlgOnly.Text = 'Only dialog boxes'; $chkDlgOnly.Checked = $true
    $chkDlgOnly.Location = New-Object System.Drawing.Point(162, 8); $chkDlgOnly.Size = New-Object System.Drawing.Size(125, 24); $script:chkDlgOnly = $chkDlgOnly; $stripD.Controls.Add($chkDlgOnly)
    $btnCapture = New-Button 'Capture text' 290 6 100; $stripD.Controls.Add($btnCapture)
    $btnFindCause = New-Button 'Find cause' 396 6 100; $btnFindCause.Font = $script:BoldFont; $stripD.Controls.Add($btnFindCause)
    $chkDlgRelated = New-Object System.Windows.Forms.CheckBox; $chkDlgRelated.Text = 'Search related files too'; $chkDlgRelated.Checked = $true
    $chkDlgRelated.Location = New-Object System.Drawing.Point(504, 8); $chkDlgRelated.Size = New-Object System.Drawing.Size(165, 24); $script:chkDlgRelated = $chkDlgRelated; $stripD.Controls.Add($chkDlgRelated)
    $btnCauseOpen = New-Button 'Decode that file' 672 6 120; $stripD.Controls.Add($btnCauseOpen)
    $lblDlg = New-Label '1) Make the program show its error box  2) Refresh  3) Select the box, Capture text (or paste it)  4) Find cause' 800 7 480 24 $lblDlg.ForeColor = [System.Drawing.Color]::DimGray; $script:lblDlg = $lblDlg; $stripD.Controls.Add($lblDlg)
    $splitDTop = New-Object System.Windows.Forms.SplitContainer; $splitDTop.Dock = 'Fill'; $script:splitDTop = $splitDTop
    $splitD.Panel1.Controls.Add($splitDTop)
    $gridWin = New-Grid; $script:gridWin = $gridWin; $splitDTop.Panel1.Controls.Add($gridWin)
    $txtDlgText = New-Object System.Windows.Forms.TextBox; $txtDlgText.Multiline = $true; $txtDlgText.ScrollBars = 'Both'; $txtDlgText.WordWrap = $true
    $txtDlgText.Dock = 'Fill'; $txtDlgText.Font = $script:MonoFont; $txtDlgText.MaxLength = 0; $script:txtDlgText = $txtDlgText
    $splitDTop.Panel2.Controls.Add($txtDlgText)
    $lblDlgText = New-Object System.Windows.Forms.Label; $lblDlgText.Text = 'Dialog text - captured, or paste it here (click a message box and press Ctrl+C to copy its text):'; $lblDlgText.Dock = 'Top'; $lblDlgText.Height = 18
    $splitDTop.Panel2.Controls.Add($lblDlgText)
    $splitDBot = New-Object System.Windows.Forms.SplitContainer; $splitDBot.Dock = 'Fill'; $script:splitDBot = $splitDBot
    $splitD.Panel2.Controls.Add($splitDBot)
    $gridCause = New-Grid; $script:gridCause = $gridCause; $splitDBot.Panel1.Controls.Add($gridCause)
    $txtCause = New-TextView; $script:txtCause = $txtCause; $splitDBot.Panel2.Controls.Add($txtCause)
    $txtCause.Text = "Dialog Finder reads the text of an error/warning box (Windows UI Automation, built into Windows) and searches for where that text lives:`r`n" +
    "  - in a PowerShell script (PS2EXE): the exact line and the condition above it`r`n  - in .NET code: the method that shows it, with its steps (>> marks the message)`r`n" +
    "  - in a .NET exception: the methods in the 'at ...' stack lines`r`n  - in native programs: the string/message table ID or text location`r`n" +
    "  - in related files: DLLs, configs, scripts and programs packed inside the EXE`r`nKnown Windows/runtime messages (missing DLL, side-by-side, VB6 run-time errors...) are explained directly."
    [void]$tabs.TabPages.Add($tabDlg)

    # ================= events =================
    $btnBrowse.Add_Click({ try {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Filter = 'Programs (*.exe;*.dll)|*.exe;*.dll|All files (*.*)|*.*'
            if ($script:txtPath.Text -and (Test-Path -LiteralPath (Split-Path -Parent $script:txtPath.Text) -ErrorAction SilentlyContinue)) { $dlg.InitialDirectory = Split-Path -Parent $script:txtPath.Text }
            if ($dlg.ShowDialog() -eq 'OK') { $script:txtPath.Text = $dlg.FileName; Invoke-Analysis $dlg.FileName }
        } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnAnalyze.Add_Click({ try { if ($script:txtPath.Text.Trim()) { Invoke-Analysis $script:txtPath.Text } } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $txtPath.Add_KeyDown({ param($s, $e) try { if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; if ($script:txtPath.Text.Trim()) { Invoke-Analysis $script:txtPath.Text } } } catch { Write-Log ("Event KeyDown: " + $_.Exception.Message) 'ERROR' } })
    $txtPath.Add_DragEnter({ param($s, $e) try { if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' } } catch { Write-Log ("Event DragEnter: " + $_.Exception.Message) 'ERROR' } })
    $txtPath.Add_DragDrop({ param($s, $e) try { $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop); if ($files) { $script:txtPath.Text = $files[0]; Invoke-Analysis $files[0] } } catch { Write-Log ("Event DragDrop: " + $_.Exception.Message) 'ERROR' } })
    $btnExport.Add_Click({ try { Export-Report } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })

    $btnSaveScript.Add_Click({ try {
            $dlg = New-Object System.Windows.Forms.SaveFileDialog
            $dlg.Filter = 'PowerShell script (*.ps1)|*.ps1|All files (*.*)|*.*'
            $dlg.FileName = if ($script:S.PS.Name -like '*.ps1') { $script:S.PS.Name } else { [System.IO.Path]::GetFileNameWithoutExtension($script:S.Path) + '.ps1' }
            if ($dlg.ShowDialog() -eq 'OK') {
                [System.IO.File]::WriteAllText($dlg.FileName, $script:S.PS.Script, (New-Object System.Text.UTF8Encoding($true)))
                Write-Log "Script saved to $($dlg.FileName)"
            }
        } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $tvScript.Add_AfterSelect({ param($s, $e) try {
            if ($e.Node.Tag -is [int]) {
                $ln = [int]$e.Node.Tag - 1
                if ($ln -ge 0 -and $ln -lt $script:txtScript.Lines.Length) {
                    $idx = $script:txtScript.GetFirstCharIndexFromLine($ln)
                    $script:txtScript.Focus() | Out-Null
                    $script:txtScript.Select($idx, $script:txtScript.Lines[$ln].Length)
                    $script:txtScript.ScrollToCaret()
                    $e.Node.TreeView.Focus() | Out-Null
                }
            }
        } catch { Write-Log ("Event AfterSelect: " + $_.Exception.Message) 'ERROR' } })

    $tvNet.Add_BeforeExpand({ param($s, $e) try { if ($e.Node.Tag -is [array] -and $e.Node.Tag[0] -eq 'type') { Expand-TypeNode $e.Node } } catch { Write-Log ("Event BeforeExpand: " + $_.Exception.Message) 'ERROR' } })
    $tvNet.Add_AfterSelect({ param($s, $e) try { Show-NetSelection $e.Node } catch { Write-Log ("Event AfterSelect: " + $_.Exception.Message) 'ERROR' } })
    $btnFindUsage.Add_Click({ try { Invoke-FindUsage } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnNetSearch.Add_Click({ try { Invoke-NetSearch } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $txtNetSearch.Add_KeyDown({ param($s, $e) try { if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Invoke-NetSearch } } catch { Write-Log ("Event KeyDown: " + $_.Exception.Message) 'ERROR' } })

    $gridDeps.Add_SelectionChanged({ try { Show-FunctionsForDll } catch { Write-Log ("Event SelectionChanged: " + $_.Exception.Message) 'ERROR' } })
    $gridDeps.Add_CellFormatting({ param($s, $e) try {
            try {
                $st = [string]$s.Rows[$e.RowIndex].Cells['Status'].Value
                if ($st -like 'NOT FOUND*' -or $st -like 'WRONG*') { $e.CellStyle.BackColor = [System.Drawing.Color]::MistyRose; $e.CellStyle.ForeColor = [System.Drawing.Color]::DarkRed }
            } catch { }
        } catch { Write-Log ("Event CellFormatting: " + $_.Exception.Message) 'ERROR' } })
    $btnRecheck.Add_Click({ try {
            if (-not $script:S.PE) { return }
            $script:form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
            $script:KnownDllCache = $null; $script:SxsDirCache = $null
            Update-Dependencies; Update-ImportsTab
            $script:form.Cursor = [System.Windows.Forms.Cursors]::Default
            Write-Log 'Dependencies re-checked.'
        } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })

    $btnStrApply.Add_Click({ try { Apply-StringFilter } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $txtStrFilter.Add_KeyDown({ param($s, $e) try { if ($e.KeyCode -eq 'Enter') { $e.SuppressKeyPress = $true; Apply-StringFilter } } catch { Write-Log ("Event KeyDown: " + $_.Exception.Message) 'ERROR' } })
    $cmbCategory.Add_SelectedIndexChanged({ try { Apply-StringFilter } catch { Write-Log ("Event SelectedIndexChanged: " + $_.Exception.Message) 'ERROR' } })
    $chkNoise.Add_CheckedChanged({ try { Apply-StringFilter } catch { Write-Log ("Event CheckedChanged: " + $_.Exception.Message) 'ERROR' } })

    $gridRes.Add_SelectionChanged({ try { Show-ResourcePreview } catch { Write-Log ("Event SelectionChanged: " + $_.Exception.Message) 'ERROR' } })
    $btnSaveRes.Add_Click({ try { Save-SelectedResource } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })

    $btnRunDir.Add_Click({ try {
            $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
            if ($dlg.ShowDialog() -eq 'OK') { $script:txtRunDir.Text = $dlg.SelectedPath }
        } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnRunStart.Add_Click({ try { Start-WatchedProcess } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnRunStop.Add_Click({ try { Stop-WatchedProcess } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnRunClear.Add_Click({ try { $script:txtRun.Clear(); [void]$script:S.RunLog.Clear() } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $script:Run.Timer.Add_Tick({ try {
            if ($script:Run.InTick) { return }
            $script:Run.InTick = $true
            try { Invoke-WatchTick } catch { $script:Run.Timer.Stop(); Add-RunLog "Watch error: $($_.Exception.Message)"; $script:btnRunStart.Enabled = $true; Close-RunRecord 'Watch error' $_.Exception.Message }
            finally { $script:Run.InTick = $false }
        } catch { Write-Log ("Event Tick: " + $_.Exception.Message) 'ERROR' } })

    $btnErrSearch.Add_Click({ try { Invoke-ErrorHistorySearch } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $gridErr.Add_SelectionChanged({ try {
            $row = $script:gridErr.CurrentRow
            if ($row -and $script:S.ErrorRows) {
                $x = $script:S.ErrorRows[[int]$row.Cells['_Idx'].Value]
                Show-Text $script:txtErr ("{0}  {1}  {2}  ID {3}  {4}`r`n`r`n{5}" -f $x.Time, $x.Log, $x.Source, $x.EventId, $x.Level, $x.Detail)
            }
        } catch { Write-Log ("Event SelectionChanged: " + $_.Exception.Message) 'ERROR' } })
    $tabs.Add_SelectedIndexChanged({ try {
            if ($script:tabs.SelectedIndex -eq 7 -and -not $script:txtErrExe.Text -and $script:S.Path) { $script:txtErrExe.Text = [System.IO.Path]::GetFileName($script:S.Path) }
        } catch { Write-Log ("Event SelectedIndexChanged: " + $_.Exception.Message) 'ERROR' } })

    $form.Add_Shown({ try {
            foreach ($sp in @($script:splitS, $script:splitN, $script:splitR)) { try { $sp.SplitterDistance = [int]($sp.Width * 0.32) } catch { } }
            foreach ($sp in @($script:splitI, $script:splitE)) { try { $sp.SplitterDistance = [int]($sp.Height * 0.55) } catch { } }
            try { $script:splitD.SplitterDistance = [int]($script:splitD.Height * 0.42) } catch { }
            foreach ($sp in @($script:splitDTop, $script:splitDBot)) { try { $sp.SplitterDistance = [int]($sp.Width * 0.45) } catch { } }
            $script:form.Activate()
        } catch { Write-Log ("Event Shown: " + $_.Exception.Message) 'ERROR' } })
    $form.Add_FormClosing({ param($s, $e) try {
            $p = $script:Run.Proc
            $running = $false
            try { $running = ($p -and -not $p.HasExited) } catch { }
            if ($running) {
                $r = [System.Windows.Forms.MessageBox]::Show('A watched program is still running. Close EXE Inspector anyway? (the program keeps running)', $script:AppTitle, 'YesNo', 'Question')
                if ($r -ne 'Yes') { $e.Cancel = $true; return }
            }
            $script:Run.Timer.Stop()
        } catch { Write-Log ("Event FormClosing: " + $_.Exception.Message) 'ERROR' } })

    $gridRel.Add_CellDoubleClick({ param($s, $e) try { if ($e.RowIndex -ge 0) { Open-RelatedSelected } } catch { Write-Log ("Event CellDoubleClick: " + $_.Exception.Message) 'ERROR' } })
    $btnRelOpen.Add_Click({ try { Open-RelatedSelected } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnBack.Add_Click({ try { Invoke-Back } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnRelFolder.Add_Click({ try {
                $row = $script:gridRel.CurrentRow
                $p = if ($row) { [string]$row.Cells['Path'].Value } else { '' }
                if (-not $p -or $p -eq '<embedded>') { $p = $script:S.Path }
                if ($p) { Start-Process explorer.exe -ArgumentList ('/select,"{0}"' -f $p) }
            } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $btnWinRefresh.Add_Click({ try { Update-WindowList } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $chkDlgOnly.Add_CheckedChanged({ try { if ($script:DlgWindows) { Update-WindowList } } catch { Write-Log ("Event CheckedChanged: " + $_.Exception.Message) 'ERROR' } })
    $btnCapture.Add_Click({ try { Invoke-CaptureSelectedWindow } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $gridWin.Add_CellDoubleClick({ param($s, $e) try { if ($e.RowIndex -ge 0) { Invoke-CaptureSelectedWindow } } catch { Write-Log ("Event CellDoubleClick: " + $_.Exception.Message) 'ERROR' } })
    $btnFindCause.Add_Click({ try { $null = Invoke-FindCause } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })
    $gridCause.Add_SelectionChanged({ try { Show-CauseDetail } catch { Write-Log ("Event SelectionChanged: " + $_.Exception.Message) 'ERROR' } })
    $btnCauseOpen.Add_Click({ try { Open-CauseSourceFile } catch { Write-Log ("Event Click: " + $_.Exception.Message) 'ERROR' } })

    # fit to the screen only after every control exists (a real resize event then re-lays-out docked/anchored controls)
    $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $form.Size = New-Object System.Drawing.Size([Math]::Min(1300, $wa.Width), [Math]::Min(900, $wa.Height))

    if ($script:StartupPath) { $txtPath.Text = $script:StartupPath; $form.Add_Shown({ Invoke-Analysis $script:txtPath.Text }) }
    [void]$form.ShowDialog()
    $form.Dispose()
}

# ---------------- start ----------------
$script:StartupPath = $null
if ($args.Count -gt 0 -and $args[0] -and (Test-Path -LiteralPath $args[0] -PathType Leaf -ErrorAction SilentlyContinue)) { $script:StartupPath = [string]$args[0] }
$null = Show-MainWindow
#endregion GUI
