package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunShellExpressionBan(t *testing.T) {
	cases := []struct {
		name string
		src  string
		line string
	}{
		{
			name: "literal after blank line",
			src:  "steps:\n  - run: |\n      echo hi\n\n      tag=\"${{ github.ref_name }}\"\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "strip chomping",
			src:  "steps:\n  - run: |-\n      echo ${{ x }}\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "explicit indent",
			src:  "run: |2\n  echo ${{ x }}\n",
			line: "ci.yml:1: ${{ }} in run/shell",
		},
		{
			name: "folded keep",
			src:  "steps:\n  - run: >+\n      echo ${{ x }}\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "plain continuation",
			src:  "steps:\n  - run: echo hello\n      ${{ x }}\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "single line",
			src:  "steps:\n  - run: echo ${{ x }}\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "unicode escape",
			src:  "steps:\n  - run: \"\\u0024{{ x }}\"\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "step shell",
			src:  "steps:\n  - shell: ${{ x }}\n    run: echo ok\n",
			line: "ci.yml:2: ${{ }} in run/shell",
		},
		{
			name: "workflow defaults shell",
			src:  "defaults:\n  run:\n    shell: ${{ x }}\n",
			line: "ci.yml:3: ${{ }} in run/shell",
		},
		{
			name: "job defaults shell",
			src:  "jobs:\n  a:\n    defaults:\n      run:\n        shell: ${{ x }}\n    steps:\n      - run: echo ok\n",
			line: "ci.yml:5: ${{ }} in run/shell",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues := checkSource(t, "ci.yml", tc.src)
			if len(issues) != 1 || issues[0] != tc.line {
				t.Fatalf("got %q\nwant %q", issues, tc.line)
			}
		})
	}
}

func TestExpressionsOutsideRunShell(t *testing.T) {
	src := `
name: ${{ github.workflow }}
defaults:
  run:
    shell: bash
jobs:
  a:
    name: ${{ github.job }}
    if: ${{ always() }}
    defaults:
      run:
        shell: bash
    steps:
      - name: ${{ github.ref }}
        if: ${{ github.ref == 'refs/heads/main' }}
        env:
          FOO: ${{ github.sha }}
        with:
          ref: ${{ github.sha }}
        run: echo ok
`
	issues := checkSource(t, "ci.yml", src)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues:\n%s", strings.Join(issues, "\n"))
	}
}

func TestAliasAnchorMerge(t *testing.T) {
	t.Run("alias target has no expression", func(t *testing.T) {
		issues := checkSource(t, "ci.yml", "payload: &payload echo hello\nsteps:\n  - run: *payload\n")
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("shell alias", func(t *testing.T) {
		issues := checkSource(t, "ci.yml", "s: &s bash\nsteps:\n  - shell: *s\n    run: echo ok\n")
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("merge alias", func(t *testing.T) {
		src := "step: &step\n  run: echo ok\njobs:\n  a:\n    steps:\n      - <<: *step\n"
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustContain(t, issues, "YAML merge key")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("merge mapping without anchor", func(t *testing.T) {
		issues := checkSource(t, "ci.yml", "steps:\n  - <<: {run: echo ok}\n")
		mustContain(t, issues, "YAML merge key")
		mustNotContain(t, issues, "YAML alias")
		mustNotContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
}

func TestDuplicateMappingKey(t *testing.T) {
	src := "jobs:\n  a:\n    permissions: {contents: read}\n    permissions: {contents: read}\n"
	issues := checkSource(t, "ci.yml", src)
	want := `ci.yml:4: duplicate mapping key "permissions"`
	if len(issues) != 1 || issues[0] != want {
		t.Fatalf("got %q\nwant %q", issues, want)
	}
}

func TestReleasePermissions(t *testing.T) {
	pass := releaseWorkflow(
		"permissions: {}",
		"permissions: {contents: read}",
		"permissions: {actions: read, contents: read}",
		"permissions: {contents: read, id-token: write, packages: write}",
		"permissions: {contents: write}",
		"",
	)
	t.Run("flow style passes", func(t *testing.T) {
		issues := checkSource(t, "release.yml", pass)
		if len(issues) != 0 {
			t.Fatalf("unexpected issues:\n%s\n--- source ---\n%s", strings.Join(issues, "\n"), pass)
		}
	})
	t.Run("extra key", func(t *testing.T) {
		src := strings.Replace(pass, "permissions: {contents: read}", "permissions: {contents: read, actions: read}", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "job notes permissions:")
	})
	t.Run("notes contents write", func(t *testing.T) {
		src := strings.Replace(pass, "permissions: {contents: read}", "permissions: {contents: write}", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "job notes permissions: got contents=write want contents=read")
	})
	t.Run("missing publish permissions", func(t *testing.T) {
		src := strings.Replace(pass, "    permissions: {contents: write}\n", "", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "job publish missing permissions")
	})
	t.Run("extra job", func(t *testing.T) {
		src := pass + "  extra:\n    permissions: {contents: read}\n    steps:\n      - run: echo ok\n"
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, `unexpected job "extra"`)
	})
	t.Run("missing job", func(t *testing.T) {
		old := "  wait-ci:\n    permissions: {actions: read, contents: read}\n    steps:\n      - name: Wait for tag ci-gate\n        run: echo ok\n"
		src := strings.Replace(pass, old, "", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, `missing job "wait-ci"`)
	})
	t.Run("write-all", func(t *testing.T) {
		src := strings.Replace(pass, "permissions: {}", "permissions: write-all", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "permissions write-all is not allowed")
	})
	t.Run("read-all", func(t *testing.T) {
		src := strings.Replace(pass, "permissions: {}", "permissions: read-all", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "permissions read-all is not allowed")
	})
	t.Run("non-empty top-level", func(t *testing.T) {
		src := strings.Replace(pass, "permissions: {}", "permissions: {contents: read}", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "workflow permissions must be an empty mapping")
	})
	t.Run("permissions after steps", func(t *testing.T) {
		src := strings.Replace(pass, "    permissions: {contents: write}\n", "", 1)
		src += "    permissions: {contents: write}\n"
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "job publish permissions must appear before steps")
	})
}

func TestReleaseConcurrency(t *testing.T) {
	pass := releaseWorkflow(
		"permissions: {}",
		"permissions: {contents: read}",
		"permissions: {actions: read, contents: read}",
		"permissions: {contents: read, id-token: write, packages: write}",
		"permissions: {contents: write}",
		"",
	)
	block := "concurrency:\n  group: " + releaseConcurrencyGroup + "\n  cancel-in-progress: false\n"
	t.Run("missing concurrency", func(t *testing.T) {
		src := strings.Replace(pass, block, "", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("concurrency not a mapping", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency: release\n", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("legacy ref group", func(t *testing.T) {
		src := strings.Replace(pass, "group: "+releaseConcurrencyGroup, "group: release-${{ github.ref }}", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, `got "release-${{ github.ref }}"`)
		mustContain(t, issues, "concurrency group must be")
	})
	t.Run("cancel in progress true", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: false", "cancel-in-progress: true", 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "concurrency cancel-in-progress must be boolean false")
	})
	t.Run("cancel in progress string false", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: false", `cancel-in-progress: "false"`, 1)
		issues := checkSource(t, "release.yml", src)
		mustContain(t, issues, "concurrency cancel-in-progress must be boolean false")
	})
}

func TestRepoWorkflows(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root, err := findRoot(filepath.Dir(file))
	if err != nil {
		t.Fatal(err)
	}
	webRoot, err := findRoot(filepath.Join(root, "web"))
	if err != nil {
		t.Fatal(err)
	}
	if webRoot != root {
		t.Fatalf("findRoot(web) = %s, module root = %s", webRoot, root)
	}
	if _, err := os.Stat(filepath.Join(root, "web", "go.mod")); err != nil {
		t.Fatal(err)
	}
	issues, err := checkRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("repo workflows:\n%s", strings.Join(issues, "\n"))
	}
}

func checkSource(t *testing.T, name, src string) []string {
	t.Helper()
	issues, err := checkWorkflow(name, []byte(src))
	if err != nil {
		t.Fatalf("parse: %v\nsource:\n%s", err, src)
	}
	return issues
}

func mustContain(t *testing.T, issues []string, sub string) {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue, sub) {
			return
		}
	}
	t.Fatalf("missing %q in:\n%s", sub, strings.Join(issues, "\n"))
}

func mustNotContain(t *testing.T, issues []string, sub string) {
	t.Helper()
	for _, issue := range issues {
		if strings.Contains(issue, sub) {
			t.Fatalf("unexpected %q in %s\nall:\n%s", sub, issue, strings.Join(issues, "\n"))
		}
	}
}

func releaseWorkflow(top, notes, wait, images, publish, tail string) string {
	var b strings.Builder
	b.WriteString("name: release\n")
	b.WriteString("concurrency:\n")
	b.WriteString("  group: ")
	b.WriteString(releaseConcurrencyGroup)
	b.WriteString("\n")
	b.WriteString("  cancel-in-progress: false\n")
	b.WriteString(top)
	b.WriteString("\njobs:\n")
	writeJob(&b, "notes", notes)
	b.WriteString("    outputs:\n")
	b.WriteString("      version: \"${{ steps.ver.outputs.version }}\"\n")
	b.WriteString("    steps:\n")
	b.WriteString("      - id: ver\n")
	b.WriteString("        env:\n")
	b.WriteString("          RAW_VERSION: \"${{ github.event.inputs.version || github.ref_name }}\"\n")
	b.WriteString("        run: |\n")
	b.WriteString(indentScript(verRun, 10))
	b.WriteString("      - name: Generate release notes\n")
	b.WriteString("        env:\n")
	b.WriteString("          VERSION: \"${{ steps.ver.outputs.version }}\"\n")
	b.WriteString("        run: |\n")
	b.WriteString(indentScript(generateRun, 10))
	writeJob(&b, "wait-ci", wait)
	b.WriteString("    steps:\n")
	b.WriteString("      - name: Wait for tag ci-gate\n")
	b.WriteString("        run: echo ok\n")
	writeJob(&b, "images", images)
	b.WriteString("    steps:\n")
	b.WriteString("      - run: echo ok\n")
	writeJob(&b, "publish", publish)
	b.WriteString("    steps:\n")
	b.WriteString("      - name: Create GitHub Release\n")
	b.WriteString("        env:\n")
	b.WriteString("          GH_TOKEN: \"${{ secrets.GITHUB_TOKEN }}\"\n")
	b.WriteString("          RELEASE_REF: \"${{ github.ref_name }}\"\n")
	b.WriteString("        run: |\n")
	b.WriteString(indentScript(publishRun, 10))
	b.WriteString(tail)
	return b.String()
}

func writeJob(b *strings.Builder, name, perms string) {
	b.WriteString("  ")
	b.WriteString(name)
	b.WriteString(":\n")
	if perms != "" {
		b.WriteString("    ")
		b.WriteString(perms)
		b.WriteByte('\n')
	}
}

func indentScript(body string, spaces int) string {
	pad := strings.Repeat(" ", spaces)
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		b.WriteString(pad)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
