package main

import (
	"fmt"
	"math"
	"strings"
)

// CVSS v3.1 base metrics and weights, from the FIRST specification
// (https://www.first.org/cvss/v3.1/specification-document §7.4). We publish base scores only:
// one vector, one number, in the advisory and the CVE record (runbook security-disclosure.md §3).
var cvssWeights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"PR": {"N": 0.85, "L": 0.62, "H": 0.27}, // scope-changed values applied in cvss31Base
	"UI": {"N": 0.85, "R": 0.62},
	"S":  {"U": 0, "C": 0},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvssOrder is the metric order the specification prescribes for a base vector string (§6).
var cvssOrder = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// roundup is the §Appendix A Roundup: smallest one-decimal number >= x, robust to float error.
func roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// cvss31Base parses a CVSS v3.1 base vector (exactly the eight base metrics, in specification
// order, nothing else) and returns its base score.
func cvss31Base(vector string) (float64, error) {
	rest, ok := strings.CutPrefix(vector, "CVSS:3.1/")
	if !ok {
		return 0, fmt.Errorf("vector %q does not start with CVSS:3.1/", vector)
	}
	parts := strings.Split(rest, "/")
	if len(parts) != len(cvssOrder) {
		return 0, fmt.Errorf("vector %q must carry exactly the 8 base metrics %v (no temporal or environmental metrics)", vector, cvssOrder)
	}
	m := map[string]string{}
	for i, p := range parts {
		k, v, ok := strings.Cut(p, ":")
		if !ok || k != cvssOrder[i] {
			return 0, fmt.Errorf("vector %q: metric %d is %q, want %s:<value>", vector, i+1, p, cvssOrder[i])
		}
		if _, ok := cvssWeights[k][v]; !ok {
			return 0, fmt.Errorf("vector %q: %s:%s is not a valid value", vector, k, v)
		}
		m[k] = v
	}
	changed := m["S"] == "C"
	pr := cvssWeights["PR"][m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	iss := 1 - (1-cvssWeights["C"][m["C"]])*(1-cvssWeights["I"][m["I"]])*(1-cvssWeights["A"][m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	expl := 8.22 * cvssWeights["AV"][m["AV"]] * cvssWeights["AC"][m["AC"]] * pr * cvssWeights["UI"][m["UI"]]
	if impact <= 0 {
		return 0, nil
	}
	if changed {
		return roundup(math.Min(1.08*(impact+expl), 10)), nil
	}
	return roundup(math.Min(impact+expl, 10)), nil
}

// cvssSeverity is the v3.1 qualitative rating (§5): the only severity label we publish.
func cvssSeverity(score float64) string {
	switch {
	case score == 0:
		return "none"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	default:
		return "critical"
	}
}

// fixTargetDays is the published fix target from triage, by severity (SECURITY.md "What we
// commit to"; medium and low are the internal targets of runbook security-disclosure.md §3).
var fixTargetDays = map[string]int{"critical": 14, "high": 30, "medium": 90, "low": 180}
