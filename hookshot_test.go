package hookshot

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_Router(t *testing.T) {
	router := NewRouter("1234")

	router.Handle("deployment", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	tests := []struct {
		event     string
		body      string
		signature string

		status int
	}{
		{
			event:     "",
			body:      `{"event":"data"}`,
			signature: "invalid",
			status:    404,
		},
		{
			event:     "foobar",
			body:      `{"event":"data"}`,
			signature: "invalid",
			status:    404,
		},
		{
			event:     "deployment",
			body:      `{"event":"data"}`,
			signature: "invalid",
			status:    403,
		},
		{
			event:     "deployment",
			body:      `{"event":"data"}`,
			signature: "sha1=ade133892a181fba3a21c163cd5cbc3f5f8e915c",
			status:    200,
		},
	}

	for i, tt := range tests {
		resp := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/", bytes.NewReader([]byte(tt.body)))
		req.Header.Set("X-GitHub-Event", tt.event)
		req.Header.Set("X-Hub-Signature", tt.signature)

		router.ServeHTTP(resp, req)

		if resp.Code != tt.status {
			t.Errorf("Code %v: Want %v; Got %v", i, tt.status, resp.Code)
		}
	}
}

func Test_Signature(t *testing.T) {
	tests := []struct {
		in     string
		secret string

		signature string
	}{
		{
			`{"event":"data"}`,
			"1234",
			"ade133892a181fba3a21c163cd5cbc3f5f8e915c",
		},
	}

	for i, tt := range tests {
		signature := Signature([]byte(tt.in), tt.secret)

		if signature != tt.signature {
			t.Errorf("%v: Want %v; Got %v", i, tt.signature, signature)
		}
	}
}
