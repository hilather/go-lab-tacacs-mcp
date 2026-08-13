package operations

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzEvaluatePolicyRequest(f *testing.F) {
	f.Add([]byte(`{"user_id":"alice","service":"shell"}`))
	f.Add([]byte(`{"user_id":"alice","cmd":"configure","arguments":[{"name":"cmd","separator":"=","value":"configure"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16*1024 {
			data = data[:16*1024]
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		var req EvaluatePolicyRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		_ = toAuthorizationRequest(req)
	})
}
