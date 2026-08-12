package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
)

func testdata(t testing.TB, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	parts := append([]string{filepath.Dir(file), "..", "..", "testdata"}, elems...)
	return filepath.Join(parts...)
}

func mustParseFile(t testing.TB, rel ...string) *config.Document {
	t.Helper()
	b, err := os.ReadFile(testdata(t, rel...))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := config.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func mustCompileFile(t testing.TB, rel ...string) *Engine {
	t.Helper()
	eng, err := CompileDocument(mustParseFile(t, rel...))
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func mustCompile(t testing.TB, in Input) *Engine {
	t.Helper()
	eng, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func av(name string, sep byte, value string) domain.AVPair {
	return domain.AVPair{Name: name, Separator: sep, Value: value}
}

func sessionReq(user, client string) Request {
	return Request{
		UserID:   user,
		ClientID: client,
		Service:  "shell",
		Arguments: domain.AVPairs{
			av("service", '=', "shell"),
			av("cmd", '=', ""),
		},
		AuthenMethod: domain.AuthenMethodTACACS,
	}
}

func cmdReq(user, client, cmd string, args ...string) Request {
	pairs := domain.AVPairs{
		av("service", '=', "shell"),
		av("cmd", '=', cmd),
	}
	for _, a := range args {
		pairs = append(pairs, av("cmd-arg", '=', a))
	}
	return Request{
		UserID:       user,
		ClientID:     client,
		Service:      "shell",
		Cmd:          cmd,
		CmdArgs:      append([]string(nil), args...),
		Arguments:    pairs,
		AuthenMethod: domain.AuthenMethodTACACS,
	}
}

func strPtr(s string) *string { return &s }
