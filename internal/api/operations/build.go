package operations

import (
	"context"
	"runtime"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
)

func handleBuild(meta BuildMeta) handleFunc {
	return func(_ context.Context, snap *state.Snapshot, _ Input) (any, error) {
		if snap == nil {
			return nil, domain.NewError(domain.CodeUnavailable, "no published snapshot")
		}
		schema := config.SchemaVersion
		if settings := snap.Settings(); settings != nil && settings.SchemaVersion != 0 {
			schema = settings.SchemaVersion
		}
		return BuildInfo{
			Version:           fallback(meta.Version, "dev"),
			Commit:            fallback(meta.Commit, "unknown"),
			BuildTime:         fallback(meta.BuildTime, "unknown"),
			GoVersion:         runtime.Version(),
			UIVersion:         meta.UIVersion,
			SchemaVersion:     schema,
			TACACSConformance: TACACSConformance,
			MCPSpecification:  MCPSpecification,
			Protocols:         protocolConformance(),
		}, nil
	}
}

func protocolConformance() map[string]ProtocolConformance {
	return map[string]ProtocolConformance{
		string(domain.ProtocolTACACS): {
			Standards:         []string{"RFC 8907", "RFC 9887"},
			ConformanceStatus: ConformanceStatusPass,
		},
		string(domain.ProtocolRADIUS): {
			Standards:         []string{"RFC 2865", "RFC 2866", "RFC 2869", "RFC 3579", "RFC 5080", "RFC 6614"},
			ConformanceStatus: ConformanceStatusPartial,
		},
	}
}

func fallback(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
