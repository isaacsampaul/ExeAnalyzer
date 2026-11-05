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
