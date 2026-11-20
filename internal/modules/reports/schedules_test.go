package reports

import (
	jsonv2 "encoding/json/v2"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/skenzeriq/activediq/internal/modules/reports/api"
	"github.com/skenzeriq/activediq/internal/modules/reports/schedule"
)

// The Action input is the request body: a body decoded through the generated strict decoder converts to the
// domain WriteInput without loss (ADR-0005 rule 10: one schema).
func TestScheduleWriteBodyEqualsActionInput(t *testing.T) {
	body := `{"name":"Weekly accounts","definitionId":"usr-01","presetId":"all","recurrence":{"kind":"weekly","time":"06:30","weekdays":[1,5]},
		"timeZone":"Europe/Berlin","notifyOnlyIfData":true,"confirmedExternal":["auditor@ext.example"],
		"recipients":[{"kind":"account","accountId":"00000000-0000-4000-8000-0000000000a1","asLink":true,"formats":["csv","xlsx"]},
		{"kind":"email","address":"auditor@ext.example","formats":["pdf"]}]}`
	var b api.ReportScheduleWrite
	if err := jsonv2.Unmarshal([]byte(body), &b); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{}
	got, err := h.toWrite("11111111-0000-4000-8000-000000000001", b)
	if err != nil {
		t.Fatal(err)
	}
	want := schedule.WriteInput{ScheduleID: "11111111-0000-4000-8000-000000000001", Name: "Weekly accounts", DefinitionID: "usr-01", PresetID: "all",
		Recurrence: schedule.Recurrence{Kind: "weekly", Time: "06:30", Weekdays: []int{1, 5}}, TimeZone: "Europe/Berlin", NotifyOnlyIfData: true,
		ConfirmedExternal: []string{"auditor@ext.example"}, Recipients: []schedule.Recipient{
			{Kind: "account", AccountID: "00000000-0000-4000-8000-0000000000a1", AsLink: true, Formats: []string{"csv", "xlsx"}},
			{Kind: "email", Address: "auditor@ext.example", Formats: []string{"pdf"}}}}
	got.Parameters = nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Every refusal code of the schedule rules answers the documented status with its code in errors[].
func TestScheduleRefusalStatuses(t *testing.T) {
	for code, status := range map[string]int{
		schedule.CodeNotOwner: http.StatusForbidden, schedule.CodeManageAllRequired: http.StatusForbidden,
		schedule.CodeExternalNotAllowed: http.StatusForbidden, schedule.CodeExternalUnconfirm: http.StatusBadRequest,
		schedule.CodePerDCDaily: http.StatusBadRequest, schedule.CodeScopeEmpty: http.StatusBadRequest,
		schedule.CodeSuperseded: http.StatusConflict, schedule.CodeUnknownDefinition: http.StatusNotFound,
	} {
		p := refusalProblem(code)
		if p.Status != int64(status) || len(p.Errors) != 1 || p.Errors[0].Code != code {
			t.Errorf("%s -> %d %+v, want %d", code, p.Status, p.Errors, status)
		}
	}
}

func TestScheduleCursorRoundTrip(t *testing.T) {
	c := schedule.Cursor{At: time.Date(2026, 11, 19, 3, 0, 0, 123456000, time.UTC), ID: "11111111-0000-4000-8000-000000000001"}
	got, err := decodeScheduleCursor(encodeScheduleCursor(c))
	if err != nil || !got.At.Equal(c.At) || got.ID != c.ID {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := decodeScheduleCursor("not a cursor"); err == nil {
		t.Fatal("a bad cursor was accepted")
	}
}

// A fire's recipient reasons map to the contract's delivery reasons; anything unknown is "internal".
func TestDeliveryReasonMapping(t *testing.T) {
	for in, want := range map[string]string{schedule.ReasonOwnerExternal: "external_not_permitted", schedule.ReasonBecameExternal: "address_no_longer_allowed",
		schedule.ReasonAccountExternal: "address_no_longer_allowed", schedule.ReasonTooLarge: "attachment_too_large", schedule.ReasonNoAddress: "internal"} {
		if got := deliveryReason(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
