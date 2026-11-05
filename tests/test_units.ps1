param([string]$Target = (Join-Path $PSScriptRoot '../src/ExeInspector_v8.ps1'))
Add-Type -TypeDefinition @'
using System.Collections.Generic;
namespace System.Windows.Forms { public static class Application { public static void DoEvents() { } } }
namespace System.Windows.Automation {
  public class ControlType { public string ProgrammaticName; public ControlType(string n) { ProgrammaticName = "ControlType." + n; } }
  public class ElInfo { public string Name = ""; public ControlType ControlType; }
  public enum TreeScope { Children = 2, Descendants = 4 }
  public class Condition { public static Condition TrueCondition = new Condition(); }
  public class AutomationPattern { }
  public class ValueInfo { public string Value; }
  public class ValuePattern { public static AutomationPattern Pattern = new AutomationPattern(); public ValueInfo Current; }
  public class TextPattern { public static AutomationPattern Pattern = new AutomationPattern(); }
  public class AutomationElement {
    public ElInfo Current = new ElInfo();
    public List<AutomationElement> Kids = new List<AutomationElement>();
    public AutomationElement Parent; public bool RawOnly; public string Value;
    public AutomationElement Add(string ct, string name, bool rawOnly, string value) {
      var e = new AutomationElement(); e.Current.ControlType = new ControlType(ct); e.Current.Name = name; e.RawOnly = rawOnly; e.Value = value; e.Parent = this; Kids.Add(e); return e; }
    void Collect(List<AutomationElement> l) { foreach (var k in Kids) { if (!k.RawOnly) l.Add(k); k.Collect(l); } }
    public List<AutomationElement> FindAll(TreeScope s, Condition c) { var l = new List<AutomationElement>(); Collect(l); return l; }
    public bool TryGetCurrentPattern(AutomationPattern p, out object pat) {
      if (p == ValuePattern.Pattern && Value != null) { var v = new ValuePattern(); v.Current = new ValueInfo(); v.Current.Value = Value; pat = v; return true; }
      pat = null; return false; }
  }
  public class TreeWalker {
    public static TreeWalker RawViewWalker = new TreeWalker();
    public AutomationElement GetFirstChild(AutomationElement e) { return e.Kids.Count > 0 ? e.Kids[0] : null; }
    public AutomationElement GetNextSibling(AutomationElement e) { if (e.Parent == null) return null; int i = e.Parent.Kids.IndexOf(e); return i + 1 < e.Parent.Kids.Count ? e.Parent.Kids[i + 1] : null; }
  }
}
'@
# load only function definitions + the exit-code tables from the tool
$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Target, [ref]$tok, [ref]$err)
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) { . ([scriptblock]::Create($f.Extent.Text)) }
foreach ($st in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -like '$script:ExitCodeInfo*' -and $n.Parent -eq $ast.EndBlock }, $false)) { . ([scriptblock]::Create($st.Extent.Text)) }
$fail = 0
function Assert($c, $m) { if ($c) { "  PASS  $m" } else { "  FAIL  $m"; $script:fail++ } }
$box = 'Unable to reach the domain controller for authentication.  Please check the domain controller/network connection and retry later.'
function New-Box { $w = New-Object System.Windows.Automation.AutomationElement; $w.Current.Name = 'CCS Software Installation'; $w.Current.ControlType = New-Object System.Windows.Automation.ControlType 'Window'
    $tb = $w.Add('TitleBar', 'CCS Software Installation', $false, $null); $null = $tb.Add('Button', 'Close', $false, $null); return $w }

'== F14 UI Automation text reading'
$w = New-Box; $null = $w.Add('Text', $box, $false, $null); $null = $w.Add('Button', '&OK', $false, $null)
$c = Get-UiaWindowText $w
Assert ($c.Lines.Count -eq 1 -and $c.Lines[0] -eq $box) 'A: normal message box read by the first pass (unchanged behaviour)'
$w = New-Box; $p = $w.Add('Pane', '', $true, $null); $null = $p.Add('Text', $box, $true, $null); $null = $w.Add('Button', '&OK', $false, $null)
$c = Get-UiaWindowText $w
Assert ($c.Lines.Count -eq 1 -and $c.Lines[0] -eq $box) "B: text only in the raw tree recovered by the second pass ($($c.Lines -join ' / '))"
$w = New-Box; $null = $w.Add('Image', '', $false, $null); $null = $w.Add('Pane', $box, $false, $null); $null = $w.Add('Button', '&OK', $false, $null)
$c = Get-UiaWindowText $w
Assert ($c.Lines.Count -eq 1 -and $c.Lines[0] -eq $box) 'C: text exposed as a Pane name (not a Text control) recovered'
Assert (($c.Lines -notcontains 'OK') -and ($c.Lines -notcontains 'Close') -and ($c.Lines -notcontains 'CCS Software Installation')) 'C: buttons / title bar / title not taken as text'
Assert ($c.Buttons -contains 'OK') 'C: OK button still listed as a button'
$w = New-Box; $null = $w.Add('Edit', '', $true, 'value inside a raw-only edit box'); $c = Get-UiaWindowText $w
Assert ($c.Lines -contains 'value inside a raw-only edit box') 'D: value pattern text in the raw tree recovered'
$w = New-Box; $c = Get-UiaWindowText $w
Assert ($c.Lines.Count -eq 0) 'E: box with no text at all stays empty (no junk lines)'

'== F15 exit code text'
Assert ((Get-ExitCodeText -33) -match 'negative program-defined') ("-33 -> " + (Get-ExitCodeText -33))
Assert ((Get-ExitCodeText -37) -match 'negative program-defined') '-37 program-defined'
Assert ((Get-ExitCodeText -1073741819) -match 'ACCESS_VIOLATION') ("-1073741819 -> " + (Get-ExitCodeText -1073741819))
Assert ((Get-ExitCodeText 3221225781) -match 'DLL_NOT_FOUND') '0xC0000135 still DLL not found'
Assert ((Get-ExitCodeText 3221229000) -match 'NTSTATUS') '0xC0000DC8 still generic NTSTATUS'
Assert ((Get-ExitCodeText 3762504530) -match 'CLR unhandled') '0xE0434352 still CLR exception'
Assert ((Get-ExitCodeText -2147024891) -match 'HRESULT') ("0x80070005 -> " + (Get-ExitCodeText -2147024891))
Assert ((Get-ExitCodeText 1603) -match 'INSTALL_FAILURE') '1603 unchanged'
Assert ((Get-ExitCodeText 1) -match 'Generic failure') '1 unchanged'

'== F15 printed name'
function New-Rec { param([string[]]$Lines) $r = [pscustomobject]@{ Console = (New-Object System.Collections.Generic.List[object]) }; foreach ($l in $Lines) { $r.Console.Add([pscustomobject]@{ Text = $l }) }; $r }
Assert ((Get-RunExitName (New-Rec @('Processing Silent Install Actions', 'ERROR_INSTALLER_ACCT_REQUIRED'))) -eq 'ERROR_INSTALLER_ACCT_REQUIRED') 'bare name printed last (Setup.exe pattern)'
Assert ((Get-RunExitName (New-Rec @('ERROR_REBOOT_REQUIRED', 'more text'))) -eq 'ERROR_REBOOT_REQUIRED') 'bare name not last line'
Assert ((Get-RunExitName (New-Rec @('a', 'Setup failed: ERROR_ACCESS_DENIED (5)'))) -eq 'ERROR_ACCESS_DENIED') 'name inside the last lines'
Assert ((Get-RunExitName (New-Rec @('all good', 'done'))) -eq '') 'no name -> empty'
Assert ((Get-RunExitName (New-Rec @())) -eq '') 'no console -> empty'
""; if ($fail) { "RESULT: $fail FAILED" } else { 'RESULT: ALL PASSED' }
