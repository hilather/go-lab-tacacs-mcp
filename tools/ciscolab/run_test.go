package main

import (
	"context"
	"strings"
	"testing"
)

type fakeSess struct {
	cmds []string
}

func (f *fakeSess) CombinedOutput(cmd string) ([]byte, error) {
	f.cmds = append(f.cmds, cmd)
	switch {
	case strings.HasPrefix(cmd, "show privilege"):
		return []byte("Current privilege level is 1\n"), nil
	case strings.HasPrefix(cmd, "enable"):
		return []byte("Current privilege level is 15\n"), nil
	case strings.HasPrefix(cmd, "show version"):
		return []byte("Cisco IOS Software, IOL Software\n"), nil
	default:
		return []byte("ok"), nil
	}
}

func (f *fakeSess) Close() error { return nil }

func TestExerciseDeviceCallsLoginAndEnable(t *testing.T) {
	fake := &fakeSess{}
	login, enable, authz, notes, err := exerciseDevice(RunOptions{
		DialSSH: func(ctx context.Context, addr, user, password string) (sshSession, error) {
			if user != "lab-admin" || password != "pw-login" {
				t.Fatalf("ssh user/pass = %s %s", user, password)
			}
			if addr == "" {
				t.Fatal("empty addr")
			}
			return fake, nil
		},
	}, "172.20.20.11:22", "lab-admin", "pw-login", "pw-enable")
	if err != nil {
		t.Fatal(err)
	}
	if login != "ok" || enable != "ok" || authz != "ok" {
		t.Fatalf("login=%s enable=%s authz=%s notes=%v", login, enable, authz, notes)
	}
	if len(fake.cmds) < 2 {
		t.Fatalf("expected privilege/enable/version cmds, got %v", fake.cmds)
	}
}
