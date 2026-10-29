package ad

import (
	"context"
	"testing"

	"github.com/skenzeriq/activediq/internal/directory/dn"
	"github.com/skenzeriq/activediq/internal/directory/sd"
)

// An invalid (zero) DACLWrite is refused before the session is touched: nothing is read or sent.
func TestWriteDACLRefusesZeroWrite(t *testing.T) {
	var s Session
	d, err := dn.Parse("CN=x,DC=lab,DC=test", dn.Strict)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WriteDACL(context.Background(), dn.DNRef(d), sd.DACLWrite{})
	if CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("zero DACLWrite: %v", err)
	}
}
