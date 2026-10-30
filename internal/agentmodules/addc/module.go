package addc

import (
	"context"
	"errors"
	"sync"

	"github.com/skenzeriq/activediq/internal/agenthost/hostapi"
	"github.com/skenzeriq/activediq/internal/platform/agentpolicy"
	addcv1 "github.com/skenzeriq/activediq/internal/proto/activediq/addc/v1"
)

// Module implements host module for domain controllers and serves activediq.addc.v1.Addc.
type Module struct {
	addcv1.UnimplementedAddcServer
	src  Source
	dc   string
	mu   sync.Mutex
	col  *Collector
	pol  *agentpolicy.AddcPolicy
	eng  *Engine
	have bool
}

// New returns the module. src is an event source for tests; nil (production) selects the host's read-only
// hostapi.EventSource from ModuleDeps; dcGUID is what the agent reports about
// its host (data to cross-check on the server, never identity).
func New(src Source, dcGUID string) *Module { return &Module{src: src, dc: dcGUID} }

// Validate implements host module: only the catalogue is module-specific.
func (m *Module) Validate(p agentpolicy.AddcPolicy) error { return checkCatalogue(p.Events) }

// Activate implements host module.
func (m *Module) Activate(p agentpolicy.AddcPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pol, m.eng, m.have = &p, Compile(p.Password), true
	if m.col != nil {
		m.col.Apply(p.Events)
	}
	return nil
}

// Rules returns the compiled password engine of the installed policy, or nil before one is installed.
// The M4 password-filter IPC reads it; nothing else does.
func (m *Module) Rules() *Engine {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eng
}

// Start implements host module.
func (m *Module) Start(ctx context.Context, d hostapi.ModuleDeps) error {
	if d.Events == nil || d.Blobs == nil || d.Log == nil || d.Now == nil {
		return errors.New("addc: incomplete dependencies")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.src
	if src == nil {
		if d.Source == nil {
			return errors.New("addc: no event source")
		}
		src = FromAPI(d.Source)
	}
	m.col = NewCollector(src, d, m.dc)
	m.col.setRoot(ctx)
	if m.pol != nil {
		m.col.Apply(m.pol.Events)
	}
	return nil
}

// Stop implements host module.
func (m *Module) Stop(context.Context) error {
	m.mu.Lock()
	c := m.col
	m.mu.Unlock()
	if c != nil {
		c.Stop()
	}
	return nil
}

// Collection implements host module.
func (m *Module) Collection() hostapi.CollectionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case !m.have:
		return hostapi.CollectionNoPolicy
	case !m.pol.Events.CollectionEnabled:
		return hostapi.CollectionStoppedByPolicy
	case m.col == nil:
		return hostapi.CollectionUnspecified
	}
	for _, s := range m.col.Snapshot() {
		if s.Status == addcv1.ChannelStatus_CHANNEL_STATUS_UNREADABLE {
			return hostapi.CollectionChannelUnreadable
		}
	}
	return hostapi.CollectionRunning
}

// Register implements host module.
func (m *Module) Register(reg hostapi.ServiceRegistrar) { addcv1.RegisterAddcServer(reg, m) }

// GetCollectionState implements Addc.
func (m *Module) GetCollectionState(context.Context, *addcv1.GetCollectionStateRequest) (*addcv1.GetCollectionStateResponse, error) {
	m.mu.Lock()
	c := m.col
	m.mu.Unlock()
	if c == nil {
		return &addcv1.GetCollectionStateResponse{}, nil
	}
	return &addcv1.GetCollectionStateResponse{Channels: c.Snapshot()}, nil
}
