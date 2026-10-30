// Command renewsecuritytxt is the T-0261 renewal job for .well-known/security.txt (RFC 9116 §2.5.5).
// When Expires is less than -within away (default 90 days, well before the 30-day failure of
// fitness-disclosure) it sets Expires to now plus -ahead (default 330 days) and, with -write, rewrites
// the file. The scheduled workflow runs it and proposes the change as a pull request.
// Exit status: 0 nothing to do or file rewritten, 1 error. Prints "renew" or "current" on stdout.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"
)

var expiresLine = regexp.MustCompile(`(?m)^Expires:[ \t]*(\S+)[ \t]*$`)

// Renew returns the file with a new Expires when the current one is within `within` of now (or
// unparseable or past). changed is false when the file is current. It refuses a file without exactly
// one Expires line: renewing something it cannot read would hide the problem.
func Renew(txt []byte, now time.Time, within, ahead time.Duration) (out []byte, changed bool, err error) {
	locs := expiresLine.FindAllSubmatchIndex(txt, -1)
	if len(locs) != 1 {
		return nil, false, fmt.Errorf("security.txt has %d Expires lines; want exactly 1", len(locs))
	}
	loc := locs[0]
	cur, perr := time.Parse(time.RFC3339, string(txt[loc[2]:loc[3]]))
	if perr == nil && cur.Sub(now) >= within {
		return txt, false, nil
	}
	next := now.Add(ahead).UTC().Truncate(24 * time.Hour).Format(time.RFC3339)
	out = append(append(append([]byte{}, txt[:loc[2]]...), next...), txt[loc[3]:]...)
	return out, true, nil
}

func main() {
	path := flag.String("file", ".well-known/security.txt", "security.txt to check")
	within := flag.Duration("within", 90*24*time.Hour, "renew when Expires is closer than this")
	ahead := flag.Duration("ahead", 330*24*time.Hour, "new Expires is this far ahead (RFC 9116: under a year)")
	write := flag.Bool("write", false, "rewrite the file when renewal is due")
	flag.Parse()
	b, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "renewsecuritytxt:", err)
		os.Exit(1)
	}
	out, changed, err := Renew(b, time.Now().UTC(), *within, *ahead)
	if err != nil {
		fmt.Fprintln(os.Stderr, "renewsecuritytxt:", err)
		os.Exit(1)
	}
	if !changed {
		fmt.Println("current")
		return
	}
	if *write {
		if err := os.WriteFile(*path, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "renewsecuritytxt:", err)
			os.Exit(1)
		}
	}
	fmt.Println("renew")
}
