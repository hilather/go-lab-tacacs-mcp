package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenPersonas(t *testing.T) {
	t.Parallel()
	eng := mustCompileFile(t, "policies", "personas.yaml")
	cases := []struct {
		name string
		req  Request
	}{
		{"administrators-session", sessionReq("lab-admin", "lab-switches")},
		{"administrators-configure", cmdReq("lab-admin", "lab-switches", "configure")},
		{"readonly-session", sessionReq("lab-readonly", "lab-switches")},
		{"readonly-configure", cmdReq("lab-readonly", "lab-switches", "configure")},
	}
	dir := testdata(t, "policies", "goldens")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := eng.Authorize(tc.req)
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
