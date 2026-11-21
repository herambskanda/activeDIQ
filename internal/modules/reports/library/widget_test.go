package library_test

import (
	"strings"
	"testing"

	"github.com/skenzeriq/activediq/internal/modules/reports/library"
	"github.com/skenzeriq/activediq/internal/platform/report"
)

// The widget profile is data in the definition file (home-report-widgets §3.1): decoded strictly and
// validated against the definition's own columns.
func Test_widget_profile_decodes_and_validates(t *testing.T) {
	good, _ := fsReadFile("usr-01.v1.json")
	with := func(w string) []byte {
		return []byte(strings.Replace(string(good), `"version": 1,`, `"version": 1, "widget": `+w+`,`, 1))
	}
	d, err := library.Decode(with(`{"views":["table","trend"],"tableColumns":["display_name","enabled"]}`))
	if err != nil {
		t.Fatalf("good profile: %v", err)
	}
	if d.Widget == nil || !d.SupportsWidget(report.WidgetTable) || !d.SupportsWidget(report.WidgetTrend) || !d.SupportsWidget(report.WidgetCount) ||
		len(d.Widget.TableColumns) != 2 {
		t.Fatalf("profile = %+v", d.Widget)
	}
	if d, err := library.Decode(good); err != nil || d.Widget != nil || !d.SupportsWidget(report.WidgetCount) || d.SupportsWidget(report.WidgetTable) {
		t.Fatalf("no profile means count only: %+v, %v", d.Widget, err)
	}
	for name, w := range map[string]string{
		"unknown view":       `{"views":["pie"],"tableColumns":[]}`,
		"no views":           `{"views":[],"tableColumns":[]}`,
		"table without cols": `{"views":["table"],"tableColumns":[]}`,
		"cols without table": `{"views":["trend"],"tableColumns":["display_name"]}`,
		"six columns":        `{"views":["table"],"tableColumns":["display_name","sam_account_name","user_principal_name","enabled","domain","dn"]}`,
		"not a column":       `{"views":["table"],"tableColumns":["password_hash"]}`,
		"duplicate column":   `{"views":["table"],"tableColumns":["enabled","enabled"]}`,
		"duplicate view":     `{"views":["trend","trend"],"tableColumns":[]}`,
		"unknown member":     `{"views":["count"],"tableColumns":[],"sql":"x"}`,
	} {
		if _, err := library.Decode(with(w)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
