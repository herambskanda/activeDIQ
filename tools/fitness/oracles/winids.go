package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Windows SID and GUID oracles (FF-SP6, safe-primitives §8): the relation is "every input we accept,
// Windows accepts, and on every accepted input the bytes and the rendered text are equal". The SID
// script calls ConvertStringSidToSidW and ConvertSidToStringSidW; the GUID script calls .NET
// Guid.Parse + ToByteArray and StringFromGUID2. They need Windows PowerShell 5.1 (the Windows
// runner); there is no Linux substitute, so on any other platform the job fails closed.
const winSidScript = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class SidApi {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool ConvertStringSidToSidW(string s, out IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern int GetLengthSid(IntPtr sid);
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr s);
  [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr p);
}
'@
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$cases = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$results = @(foreach ($c in $cases) {
  $ok = $false; $why = ''
  try {
    if ($c.dir -eq 'parse') {
      $p = [IntPtr]::Zero
      if (-not [SidApi]::ConvertStringSidToSidW([string]$c.text, [ref]$p)) { $why = 'Windows rejects an input we accept (error ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error() + ')' }
      else {
        $n = [SidApi]::GetLengthSid($p); $b = New-Object byte[] $n
        [Runtime.InteropServices.Marshal]::Copy($p, $b, 0, $n); [void][SidApi]::LocalFree($p)
        $h = ($b | ForEach-Object { $_.ToString('x2') }) -join ''
        if ($h -ceq ([string]$c.hex).ToLowerInvariant()) { $ok = $true } else { $why = 'bytes differ: Windows ' + $h }
      }
    } else {
      $b = [byte[]]@(for ($i = 0; $i -lt $c.hex.Length; $i += 2) { [Convert]::ToByte($c.hex.Substring($i, 2), 16) })
      $m = [Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length); [Runtime.InteropServices.Marshal]::Copy($b, 0, $m, $b.Length)
      $s = [IntPtr]::Zero
      if (-not [SidApi]::ConvertSidToStringSidW($m, [ref]$s)) { $why = 'Windows rejects the bytes' }
      else { $t = [Runtime.InteropServices.Marshal]::PtrToStringUni($s); [void][SidApi]::LocalFree($s); if ($t -ceq [string]$c.text) { $ok = $true } else { $why = 'text differs: Windows ' + $t } }
      [Runtime.InteropServices.Marshal]::FreeHGlobal($m)
    }
  } catch { $why = 'exception: ' + $_.Exception.GetType().Name }
  [pscustomobject]@{ id = [string]$c.id; ok = $ok; why = $why }
})
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`

const winGuidScript = `
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class GuidApi {
  [DllImport("ole32.dll")] public static extern int StringFromGUID2(ref Guid g, StringBuilder s, int max);
}
'@
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$cases = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$results = @(foreach ($c in $cases) {
  $ok = $false; $why = ''
  try {
    if ($c.dir -eq 'parse') {
      $g = [Guid]::Parse([string]$c.text)
      $h = ($g.ToByteArray() | ForEach-Object { $_.ToString('x2') }) -join ''
      if ($h -ceq ([string]$c.hex).ToLowerInvariant()) { $ok = $true } else { $why = 'bytes differ: Windows ' + $h }
    } else {
      $b = [byte[]]@(for ($i = 0; $i -lt $c.hex.Length; $i += 2) { [Convert]::ToByte($c.hex.Substring($i, 2), 16) })
      $g = New-Object Guid (,$b); $sb = New-Object System.Text.StringBuilder 64
      [void][GuidApi]::StringFromGUID2([ref]$g, $sb, 64)
      if ($sb.ToString().Trim('{', '}') -ieq [string]$c.text) { $ok = $true } else { $why = 'text differs: Windows ' + $sb.ToString() }
    }
  } catch { $why = 'Windows rejects an input we accept (' + $_.Exception.GetType().Name + ')' }
  [pscustomobject]@{ id = [string]$c.id; ok = $ok; why = $why }
})
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`

type winCase struct {
	ID   string `json:"id"`
	Dir  string `json:"dir"` // parse (text to bytes) or format (bytes to text)
	Text string `json:"text"`
	Hex  string `json:"hex"`
}

// checkWinIDs runs the SID or GUID oracle over the records that carry an accepted conversion. A
// record is a "parse" when its input is text and its expectation bytes_hex; a "format" when its input
// is hex bytes and its expectation render. Records that expect an error are ours to reject: the
// relation allows that, so they are not sent.
func checkWinIDs(e Engine, unit string, cases []Case) (ids []string, failures []string, err error) {
	var in []winCase
	for _, c := range cases {
		switch {
		case c.HexOut != "" && !c.Input.IsHex:
			in = append(in, winCase{c.Record.ID, "parse", c.Input.Text(), c.HexOut})
		case c.Output != "" && c.Input.IsHex:
			in = append(in, winCase{c.Record.ID, "format", c.Output, hex.EncodeToString(c.Input.Raw)})
		}
	}
	if len(in) == 0 {
		return nil, nil, fmt.Errorf("no %s record converts text to bytes or bytes to text (records are shaped: text input + bytes_hex expectation, or hex input + render expectation)", unit)
	}
	script := winSidScript
	if unit == "attr.guid" {
		script = winGuidScript
	}
	var res []oracleResult
	if err := e.Run(script, in, &res); err != nil {
		return nil, nil, err
	}
	if len(res) != len(in) {
		return nil, nil, fmt.Errorf("the oracle answered %d of %d records", len(res), len(in))
	}
	for i, r := range res {
		if r.OK {
			ids = append(ids, r.ID)
		} else {
			failures = append(failures, fmt.Sprintf("%s: %s (%s %s)", r.ID, strings.TrimSpace(r.Why), in[i].Dir, quoteASCII(in[i].Text)))
		}
	}
	return ids, failures, nil
}
