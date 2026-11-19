package schedule

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/skenzeriq/activediq/internal/modules/reports/export"
	"github.com/skenzeriq/activediq/internal/platform/blob"
	"github.com/skenzeriq/activediq/internal/platform/notify/delivery"
	"github.com/skenzeriq/activediq/internal/platform/notify/mail"
	"github.com/skenzeriq/activediq/internal/platform/store"
	"github.com/skenzeriq/activediq/internal/platform/tenant"
)

// Renderer renders the two purposes a schedule makes: the delivery of a fire and the notice that a schedule
// was paused. A Delivery row holds ids only; the file is read here, at send time, so a retry renders anew
// and the row never carries data (DM-84).
type Renderer struct {
	Blob blob.Store
	// Origin is the canonical https origin the links are built on (no trailing slash).
	Origin string
}

// Renderers is the map a delivery.Dispatcher takes.
func (r Renderer) Renderers() map[string]delivery.Renderer {
	return map[string]delivery.Renderer{PurposeDelivery: r, PurposePaused: r}
}

var errRender = errors.New("schedule: cannot render the delivery")

func (r Renderer) Render(ctx context.Context, tx store.Tx, d delivery.Delivery) (delivery.Content, error) {
	s, err := (Store{}).Get(ctx, tx, d.Variables["schedule"], false)
	if err != nil {
		return delivery.Content{}, fmt.Errorf("%w: schedule", errRender)
	}
	switch d.Purpose {
	case PurposePaused:
		return delivery.Content{Subject: "activeDIQ: report schedule paused",
			Text: fmt.Sprintf("The report schedule %q was paused by the system (reason: %s). Nothing was sent. Resume it after the cause is fixed.\n", s.Name, d.Variables["reason"])}, nil
	case PurposeDelivery:
	default:
		return delivery.Content{}, errRender
	}
	var tid tenant.ID
	var raw string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(current_setting('app.tenant_id', true), '')`).Scan(&raw); err != nil {
		return delivery.Content{}, err
	}
	if tid, err = tenant.Parse(raw); err != nil {
		return delivery.Content{}, errRender
	}
	c := delivery.Content{Subject: "activeDIQ report: " + s.Name}
	var text strings.Builder
	fmt.Fprintf(&text, "Scheduled report %q.\n", s.Name)
	for _, id := range strings.Split(d.Variables["exports"], ",") {
		eid, err := export.ParseID(id)
		if err != nil {
			return delivery.Content{}, errRender
		}
		e, err := export.Peek(ctx, tx, eid)
		if err != nil || e.State != export.StateSucceeded {
			return delivery.Content{}, fmt.Errorf("%w: export", errRender)
		}
		if d.Variables["mode"] == "link" {
			fmt.Fprintf(&text, "Open (sign in required): %s/api/v1/reports/exports/%s/file\n", r.Origin, id)
			continue
		}
		rc, _, err := r.Blob.Get(ctx, tid, e.BlobKey)
		if err != nil {
			return delivery.Content{}, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxAttachmentBytes+1))
		_ = rc.Close()
		if err != nil {
			return delivery.Content{}, err
		}
		if len(data) > MaxAttachmentBytes {
			return delivery.Content{}, fmt.Errorf("%w: attachment too large", errRender)
		}
		name := "report"
		if e.FileName != nil {
			name = strings.TrimSuffix(*e.FileName, "."+e.Format.Ext())
		}
		c.Attachments = append(c.Attachments, mail.Attachment{Filename: name, Format: e.Format.HTTPX(), Data: data})
		fmt.Fprintf(&text, "Attached: %s (%s).\n", name, strings.ToUpper(e.Format.Ext()))
	}
	c.Text = text.String()
	return c, nil
}
