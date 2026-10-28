package main

import "testing"

func TestRefuseCrashTraceback(t *testing.T) {
	for v, wantErr := range map[string]bool{"": false, "none": false, "single": false, "all": false, "system": false,
		"crash": true, "CRASH": true, " crash ": true, "wer": true} {
		err := refuseCrashTraceback(func(string) string { return v })
		if (err != nil) != wantErr {
			t.Errorf("GOTRACEBACK=%q: err=%v, wantErr=%v", v, err, wantErr)
		}
	}
}
