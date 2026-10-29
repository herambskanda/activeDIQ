package ports

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// fixtureProc writes a fake /proc/<pid> holding one socket (inode 4242) listening on 127.0.0.1:8080, one
// foreign-owned listener (inode 9999, not in the fd table) and a connected (non-listening) socket.
func fixtureProc(t *testing.T, extra string) (root string) {
	t.Helper()
	root = t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "7", "fd"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "7", "net"), 0o755))
	must(os.Symlink("socket:[4242]", filepath.Join(root, "7", "fd", "3")))
	must(os.Symlink("/dev/null", filepath.Join(root, "7", "fd", "4")))
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tcp := hdr +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0\n" +
		"   1: 0100007F:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 9999 1 0 100 0 0\n" +
		"   2: 0100007F:1F91 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0\n" + extra
	must(os.WriteFile(filepath.Join(root, "7", "net", "tcp"), []byte(tcp), 0o644))
	for _, f := range []string{"tcp6", "udp", "udp6"} {
		must(os.WriteFile(filepath.Join(root, "7", "net", f), []byte(hdr), 0o644))
	}
	return root
}

func TestListeningReadsOnlyThisProcessesListeners(t *testing.T) {
	got, err := listening(fixtureProc(t, ""), "7")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "tcp 127.0.0.1:8080" {
		t.Fatalf("got %v, want only tcp 127.0.0.1:8080", got)
	}
}

func TestCompareFailsNamingAnUnlistedPort(t *testing.T) {
	// FAILING FIXTURE (acceptance 1): a second listener, tcp 6060 (a debug port), that §8.1 does not list.
	extra := "   3: 0100007F:17AC 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0\n"
	got, err := listening(fixtureProc(t, extra), "7")
	if err != nil {
		t.Fatal(err)
	}
	v := Compare(got, []Allowed{{Row: "L1", Proto: "tcp", Port: 8080}})
	if len(v) != 1 || !strings.Contains(v[0], "6060") {
		t.Fatalf("violations %q do not name port 6060", v)
	}
}

func TestComparePassesWhenEqual(t *testing.T) {
	got, _ := listening(fixtureProc(t, ""), "7")
	if v := Compare(got, []Allowed{{Row: "L1", Proto: "tcp", Port: 8080}}); len(v) != 0 {
		t.Fatal(v)
	}
}

func TestCompareFailsWhenADeclaredListenerIsMissing(t *testing.T) {
	v := Compare(nil, []Allowed{{Row: "L1", Proto: "tcp", Port: 8080}})
	if len(v) != 1 || !strings.Contains(v[0], "L1") {
		t.Fatal(v)
	}
}

func TestCompareHonoursLoopbackAndProtocol(t *testing.T) {
	pub := Socket{Proto: "tcp", Addr: mustAddr("0.0.0.0"), Port: 9100}
	if v := Compare([]Socket{pub}, []Allowed{{Row: "L4", Proto: "tcp", Port: 9100, Loopback: true}}); len(v) != 2 {
		t.Fatalf("a wildcard bind must not satisfy a loopback-only row: %q", v)
	}
	udp := Socket{Proto: "udp", Addr: mustAddr("127.0.0.1"), Port: 9100}
	if v := Compare([]Socket{udp}, []Allowed{{Row: "L4", Proto: "tcp", Port: 9100}}); len(v) != 2 {
		t.Fatalf("udp must not satisfy a tcp row: %q", v)
	}
}

// TestListeningSeesARealListener reads the kernel's view of this test process.
func TestListeningSeesARealListener(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc enumeration is Linux only")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	got, err := Listening(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if v := Compare(got, []Allowed{{Row: "X", Proto: "tcp", Port: port}}); len(v) != 0 {
		t.Fatalf("real listener not matched: %q (found %v)", v, got)
	}
	// A second, unlisted listener must be reported by number.
	rogue, _ := net.Listen("tcp", "127.0.0.1:0")
	defer rogue.Close()
	rp := rogue.Addr().(*net.TCPAddr).Port
	got, _ = Listening(os.Getpid())
	v := Compare(got, []Allowed{{Row: "X", Proto: "tcp", Port: port}})
	if len(v) != 1 || !strings.Contains(v[0], itoa(rp)) {
		t.Fatalf("rogue port %d not named: %q", rp, v)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
func itoa(n int) string            { return strconv.Itoa(n) }
