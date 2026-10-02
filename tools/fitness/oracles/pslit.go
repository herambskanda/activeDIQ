package main

import (
	"fmt"
	"strings"
)

// pslitScript is the FF-SP6 pslit oracle (safe-primitives §6.2): every output must parse, with
// [System.Management.Automation.Language.Parser]::ParseInput, to a script that is exactly one
// StringConstantExpressionAst, single-quoted, covering the whole text, whose Value equals the input.
// Equality is checked twice, with -ceq (the spec's operator) and ordinal, because -ceq is
// culture-aware and would let zero-width differences through. Output is ASCII: only ids, booleans and
// counts leave the script.
const pslitScript = `
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
$cases = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$results = @(foreach ($c in $cases) {
  $tokens = $null; $errs = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$c.output, [ref]$tokens, [ref]$errs)
  $ok = $false; $why = ''
  if ($errs.Count -gt 0) {
    $why = 'parse errors: ' + $errs.Count
  } elseif ($ast.EndBlock.Statements.Count -ne 1 -or $null -ne $ast.BeginBlock -or $null -ne $ast.ProcessBlock -or $null -ne $ast.ParamBlock) {
    $why = 'statements: ' + $ast.EndBlock.Statements.Count + ' (want exactly 1)'
  } else {
    $st = $ast.EndBlock.Statements[0]
    $strs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true))
    $expr = $null
    if ($st -is [System.Management.Automation.Language.PipelineAst] -and $st.PipelineElements.Count -eq 1 -and $st.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
      $expr = $st.PipelineElements[0].Expression
    }
    if ($null -eq $expr -or $expr -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
      $why = 'the statement is not a single string constant'
    } elseif ($strs.Count -ne 1) {
      $why = 'string constant nodes: ' + $strs.Count + ' (want exactly 1)'
    } elseif ($expr.StringConstantType -ne [System.Management.Automation.Language.StringConstantType]::SingleQuoted) {
      $why = 'not a single-quoted string'
    } elseif ($st.Extent.Text -cne [string]$c.output) {
      $why = 'the literal does not cover the whole output'
    } elseif (-not ($expr.Value -ceq [string]$c.input) -or -not [string]::Equals($expr.Value, [string]$c.input, [System.StringComparison]::Ordinal)) {
      $why = 'Value differs from the input'
    } else {
      $ok = $true
    }
  }
  [pscustomobject]@{ id = [string]$c.id; ok = $ok; why = $why }
})
[Console]::Out.Write((ConvertTo-Json -InputObject $results -Compress))
`

type oracleResult struct {
	ID  string `json:"id"`
	OK  bool   `json:"ok"`
	Why string `json:"why"`
}

type pslitCase struct {
	ID     string `json:"id"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// checkPslit parses every pslit output with PowerShell and returns the failures, one line each.
func checkPslit(e Engine, cases []Case) (checked int, failures []string, err error) {
	var in []pslitCase
	for _, c := range cases {
		if !c.Input.ValidUTF8() || strings.ContainsRune(c.Input.Text(), 0) {
			continue // such an input has no output to parse: the corpus expects an error
		}
		in = append(in, pslitCase{ID: c.Record.ID, Input: c.Input.Text(), Output: c.Output})
	}
	if len(in) == 0 {
		return 0, nil, fmt.Errorf("no pslit record with a rendered output to check")
	}
	var res []oracleResult
	if err := e.Run(pslitScript, in, &res); err != nil {
		return 0, nil, err
	}
	if len(res) != len(in) {
		return 0, nil, fmt.Errorf("the oracle answered %d of %d records", len(res), len(in))
	}
	for i, r := range res {
		if r.ID != in[i].ID {
			return 0, nil, fmt.Errorf("the oracle answered out of order at %d", i)
		}
		if !r.OK {
			failures = append(failures, fmt.Sprintf("%s: output %s is not exactly one string constant equal to the input: %s", r.ID, quoteASCII(in[i].Output), r.Why))
		}
	}
	return len(in), failures, nil
}
