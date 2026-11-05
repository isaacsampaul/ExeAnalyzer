$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot 'work/media8'
New-Item -ItemType Directory -Force (Join-Path $dir 'state') | Out-Null
Get-ChildItem $dir -File | Remove-Item -Force
$lib = @'
using System;
using System.IO;
namespace System.Windows.Forms { public static class MessageBox { public static int Show(string text, string caption, int buttons, int icon) { throw new InvalidOperationException("no desktop"); } } }
namespace IASeries.InstallCommon {
  public static class Util {
    public static string AcctError() { return "ERROR_INSTALLER_ACCT_REQUIRED"; }
    public static string Domain() { return "Unable to reach the domain controller for authentication. Check the network and try again."; }
  }
  public static class Strings { public static string STR_IAINSTALL { get { return "CCS Software Installation"; } } }
  public class InstallationInfo {
    public enum InstallInfoTag { CommitDrive, CommitOperation, CommitPath, IAStationList, InstallDir, WorkingDir, LaunchDir, InitialLaunchForm, CanceledInstall, StationType, UseOffMeshDC, OffMeshDCIPAddress, DomainName, RestartApp }
    static string XMLFileName;
    static void InitializeStorageFile() { XMLFileName = string.Format("{0}\\{1}", "__MEDIA__/state", "IASoftwareInstallInfo.xml"); }
    public static string readPropertyValue(InstallInfoTag p) { InitializeStorageFile(); return File.Exists(XMLFileName) ? p.ToString() : ""; }
  }
  public static class ADAccountHelper {
    public static bool AnonymousIsUserGroupMember(string domainName, string groupName, string memberName, string objectClass, bool silent) {
      bool ok = false;
      try {
        var d = new DirectoryInfo("LDAP://" + domainName);
        foreach (var f in d.GetFiles()) { if (f.Name.ToLower().Contains(memberName.ToLower())) ok = true; }
      } catch (Exception ex) {
        if (ex.Message.ToLower().StartsWith("the server is not operational")) {
          if (!silent) System.Windows.Forms.MessageBox.Show("Unable to reach the domain controller for authentication.  Please check the domain controller/network connection and retry later.", Strings.STR_IAINSTALL, 0, 48);
        } else if (!silent) System.Windows.Forms.MessageBox.Show("Unknown error authenticating the domain account: " + ex.Message, Strings.STR_IAINSTALL, 0, 48);
      }
      return ok;
    }
    public static bool AnonymousIsGroupMember(string domainName, string groupName, bool silent) { return AnonymousIsUserGroupMember(domainName, groupName, Environment.UserName, "user", silent); }
  }
}
'@
$lib = $lib.Replace('__MEDIA__', $dir)
Add-Type -TypeDefinition $lib -OutputAssembly "$dir/IASeries.InstallCommon.dll" -OutputType Library
$main = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using IASeries.InstallCommon;
namespace CcsSetup {
  public enum SetupEXEReturnVal { ERROR_SUCCESS = 0, ERROR_RESPONSE_FILE_PARSE_ERROR = -37, ERROR_INSTALLER_ACCT_REQUIRED = -33 }
  public enum StationType { Workstation = 1, Server = 2 }
  public static class Program {
    [DllImport(@"C:\Users\All Users\Invensys\IASeries\Installer\SupportFiles\StampLoc.dll")]
    static extern int StampLocation(string p);
    static string SilentLogFile = "__MEDIA__/state/SilentSetup.log";
    static SetupEXEReturnVal Report(SetupEXEReturnVal c) { Console.WriteLine(c.ToString()); return c; }
    public static int Main(string[] args) {
      if (args.Length > 0 && args[0].StartsWith("/q")) {
        string acct = IASeries.InstallCommon.Util.AcctError();
        if (acct.Length > 0) { Console.WriteLine("Setup failed: " + acct); return 1; }
      }
      ShowError("CCS Software Installation", "Unable to reach the domain controller for authentication. Please check that this station is connected to the domain.");
      Console.WriteLine("Reading settings from CCS_Day1.txt and Helper.ps1");
      return 0;
    }
    public static int Day1Check(string st) {
      string domain = InstallationInfo.readPropertyValue(InstallationInfo.InstallInfoTag.DomainName);
      if (st == StationType.Server.ToString().ToLower()) { Console.WriteLine("server"); }
      try { File.ReadAllText(SilentLogFile); } catch (IOException) { Console.WriteLine("log not readable"); }
      if (!ADAccountHelper.AnonymousIsGroupMember(domain, "CN=IA Installer", false)) return (int)Report(SetupEXEReturnVal.ERROR_INSTALLER_ACCT_REQUIRED);
      return 0;
    }
    static void ShowError(string t, string m) { Console.Error.WriteLine(t + ": " + m); }
  }
}
'@
$main = $main.Replace('__MEDIA__', $dir)
Add-Type -TypeDefinition $main -OutputAssembly "$dir/Setup.dll" -OutputType Library -ReferencedAssemblies "$dir/IASeries.InstallCommon.dll", 'System.Console', 'System.Runtime', 'System.Runtime.InteropServices'
Set-Content "$dir/Helper.ps1" -Value @'
param([string]$Answer)
function Test-Domain {
    if (-not (Test-Connection dc01 -Count 1 -Quiet)) { throw "Unable to reach the domain controller for authentication" }
}
Test-Domain
Write-Output "done"
'@
Set-Content "$dir/Setup.ini" -Value "[Install]`nAuthMessage=Unable to reach the domain controller for authentication`nRetry=3"
Set-Content "$dir/state/IASoftwareInstallInfo.xml" -Value '<IASoftwareInstall><InstallerProperty name="DomainName" value="QELNGONLR.DCS" /></IASoftwareInstall>'
Set-Content "$dir/state/SilentSetup.log" -Value "10/29/2026 10:07:27 AM ... Begin: Setup.exe /q:D:\Media\RPFiles\CCS_Day1.txt`n10/29/2026 10:07:29 AM ... ERROR_REBOOT_REQUIRED"
Get-ChildItem $dir -Recurse -File | ForEach-Object { "{0,-40} {1}" -f $_.FullName.Substring($dir.Length), $_.Length }

# ---- v9 (F21-F25): native (non-.NET) program, strings in a Delphi-style CODE section ----
# Minimal valid PE32: DOS header, PE header, one CODE section holding NUL-terminated ASCII strings + one UTF-16 string.
$nat = Join-Path $PSScriptRoot 'work/native9'
New-Item -ItemType Directory -Force $nat | Out-Null
$ascii = @(
    'E:\apps\plant\bin\tools\getval.exe',
    'E:\apps\plant\api\drv.tsk.exe',
    'E:\apps\plant\api\drv.tsk.exe -d 1 -o 7 >C:\tmp\BLK.TX',
    'E:/apps/plant/bin/tools/setval.exe -mDESC:%32d',
    'E:\apps\plant\bin\tools\lister.exe',
    'lister -p plant_server >C:\tmp\LST.TX',
    'C:\tmp\GET_DATA.SH',
    'The file E:\apps\plant\wp\editor.exe is missing, you cannot update displays',
    'Cannot read E:\apps\plant\data\cfg is missing. Please check settings.xml',
    'E:\apps\plant\lib\old.dll.bak',
    'C:\Program Files\Vendor Suite\bin\viewer.exe',
    '\\srv01\share\tools\sync.bat /x',
    'helperx3.dll',
    'Download from https://example.com/dl/tool.exe',
    'version 3.9.0.0',
    'System.Xml',
    'Use -p for printing'
)
$sec = New-Object System.Collections.Generic.List[byte]
foreach ($b in [byte[]](0x55, 0x8B, 0xEC, 0xC3)) { $sec.Add($b) }   # push ebp; mov ebp,esp; ret
foreach ($s in $ascii) { $sec.AddRange([System.Text.Encoding]::ASCII.GetBytes($s)); $sec.Add(0); $sec.Add(0) }
$sec.AddRange([System.Text.Encoding]::Unicode.GetBytes('E:\apps\plant\bin\report.exe')); $sec.Add(0); $sec.Add(0)
while ($sec.Count % 0x200) { $sec.Add(0) }
$img = New-Object byte[] (0x200 + $sec.Count)
$w16 = { param($o, $v) [BitConverter]::GetBytes([uint16]$v).CopyTo($img, $o) }
$w32 = { param($o, $v) [BitConverter]::GetBytes([uint32]$v).CopyTo($img, $o) }
$img[0] = 0x4D; $img[1] = 0x5A; & $w32 0x3C 0x80
$img[0x80] = 0x50; $img[0x81] = 0x45
& $w16 0x84 0x14C; & $w16 0x86 1; & $w32 0x88 0x2A425E19; & $w16 0x94 0xE0; & $w16 0x96 0x010E
$o = 0x98
& $w16 $o 0x10B; $img[$o + 2] = 2; $img[$o + 3] = 25
& $w32 ($o + 4) $sec.Count; & $w32 ($o + 16) 0x1000; & $w32 ($o + 20) 0x1000; & $w32 ($o + 28) 0x400000
& $w32 ($o + 32) 0x1000; & $w32 ($o + 36) 0x200; & $w16 ($o + 40) 4; & $w16 ($o + 48) 4
& $w32 ($o + 56) (0x1000 + [Math]::Ceiling($sec.Count / 0x1000) * 0x1000); & $w32 ($o + 60) 0x200; & $w16 ($o + 68) 2
& $w32 ($o + 72) 0x100000; & $w32 ($o + 76) 0x4000; & $w32 ($o + 80) 0x100000; & $w32 ($o + 84) 0x1000; & $w32 ($o + 92) 16
$sh = $o + 0xE0
[System.Text.Encoding]::ASCII.GetBytes('CODE').CopyTo($img, $sh)
& $w32 ($sh + 8) $sec.Count; & $w32 ($sh + 12) 0x1000; & $w32 ($sh + 16) $sec.Count; & $w32 ($sh + 20) 0x200; & $w32 ($sh + 36) 0x60000020
$sec.ToArray().CopyTo($img, 0x200)
[System.IO.File]::WriteAllBytes((Join-Path $nat 'PlantTool.exe'), $img)
"native9/PlantTool.exe                    $($img.Length)"
