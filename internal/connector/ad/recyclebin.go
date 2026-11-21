package ad

import (
	"context"
	"strings"

	"github.com/skenzeriq/activediq/internal/directory/dn"
)

// recycleBinFeatureCN is the CN of the Recycle Bin Feature optional-feature object. Its
// msDS-OptionalFeatureGUID is 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a (MS-ADTS 3.1.1.5.5); matching on the
// CN is what the restore path has always done.
const recycleBinFeatureCN = "Recycle Bin Feature"

// RecycleBin reports whether the AD Recycle Bin is enabled for the forest, by reading
// msDS-EnabledFeature on CN=Partitions in the configuration NC. The answer is read once per Session
// and cached: the feature cannot be disabled once enabled, and a Session is one connection. A
// directory that lacks the attribute or object answers false (the DC predates the feature, or is
// Samba); a read that fails for any other reason is an error and is not cached.
func (s *Session) RecycleBin(ctx context.Context) (bool, error) {
	s.binMu.Lock()
	defer s.binMu.Unlock()
	if s.binKnown {
		return s.binOn, nil
	}
	on, err := s.readRecycleBin(ctx)
	if err != nil {
		return false, err
	}
	s.binKnown, s.binOn = true, on
	return on, nil
}

func (s *Session) readRecycleBin(ctx context.Context) (bool, error) {
	rd, err := s.RootDSE(ctx)
	if err != nil {
		return false, err
	}
	cfg, err := dn.Parse(rd.ConfigurationNamingContext, dn.Strict)
	if err != nil {
		return false, nil
	}
	parts, err := dn.Child(cfg, dn.CN, "Partitions")
	if err != nil {
		return false, nil
	}
	e, err := s.Read(ctx, dn.DNRef(parts), []string{"msDS-EnabledFeature"}, ReadOptions{})
	if err != nil {
		if CodeOf(err) == CodeInvalidArgument || CodeOf(err) == CodeObjectNotFound {
			return false, nil
		}
		return false, err
	}
	return hasRecycleBinFeature(e.Strings("msDS-EnabledFeature")), nil
}

// hasRecycleBinFeature looks for the Recycle Bin Feature among msDS-EnabledFeature values.
func hasRecycleBinFeature(values []string) bool {
	for _, v := range values {
		fd, err := dn.Parse(v, dn.Strict)
		if err != nil || fd.Len() == 0 {
			continue // a value that does not parse is not the feature
		}
		if r := fd.RDNs()[0]; r.Type() == dn.CN && strings.EqualFold(r.Value(), recycleBinFeatureCN) {
			return true
		}
	}
	return false
}
