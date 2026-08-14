package radius

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func TestGoldenTraces(t *testing.T) {
	t.Parallel()
	eng := personaEngine(t)
	cases := []struct {
		name string
		req  Request
	}{
		{
			name: "permit-lab-admins",
			req: Request{
				UserID:     "lab-admin",
				ClientID:   "lab-switches",
				EndpointID: "radius-udp",
				Method:     domain.AuthMethodPassword,
				Groups:     []string{"lab-admins"},
			},
		},
		{
			name: "deny-rest",
			req: Request{
				UserID:     "lab-guest",
				ClientID:   "lab-switches",
				EndpointID: "radius-udp",
				Method:     domain.AuthMethodCHAP,
				Groups:     []string{"lab-guests"},
			},
		},
		{
			name: "default-deny-unknown-client",
			req: Request{
				UserID:   "lab-admin",
				ClientID: "no-such-client",
				Method:   domain.AuthMethodPassword,
				Groups:   []string{"lab-admins"},
			},
		},
		{
			name: "attribute-equals",
			req: Request{
				UserID:     "nas-user",
				ClientID:   "lab-switches",
				EndpointID: "radius-udp",
				Method:     domain.AuthMethodPassword,
				Attributes: TypedSet{
					textAttr("NAS-Identifier", 32, "edge-1"),
					intAttr("Service-Type", 6, 1),
				},
			},
		},
	}
	dir := filepath.Join("goldens")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := eng.Evaluate(tc.req)
			got, err := json.MarshalIndent(res.Trace, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, '\n')
			path := filepath.Join(dir, tc.name+".json")
			want, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					if werr := os.WriteFile(path, got, 0o644); werr != nil {
						t.Fatal(werr)
					}
					t.Fatalf("wrote missing golden %s; re-run test", path)
				}
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
			}
		})
	}
}
