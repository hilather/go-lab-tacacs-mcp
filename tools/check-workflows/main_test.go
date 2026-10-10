package main

import (
	"fmt"
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
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "strip chomping",
			src:  "steps:\n  - run: |-\n      echo ${{ x }}\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "explicit indent",
			src:  "run: |2\n  echo ${{ x }}\n",
			line: "workflow.yml:1: ${{ }} in run/shell",
		},
		{
			name: "folded keep",
			src:  "steps:\n  - run: >+\n      echo ${{ x }}\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "plain continuation",
			src:  "steps:\n  - run: echo hello\n      ${{ x }}\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "single line",
			src:  "steps:\n  - run: echo ${{ x }}\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "unicode escape",
			src:  "steps:\n  - run: \"\\u0024{{ x }}\"\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "step shell",
			src:  "steps:\n  - shell: ${{ x }}\n    run: echo ok\n",
			line: "workflow.yml:2: ${{ }} in run/shell",
		},
		{
			name: "workflow defaults shell",
			src:  "defaults:\n  run:\n    shell: ${{ x }}\n",
			line: "workflow.yml:3: ${{ }} in run/shell",
		},
		{
			name: "job defaults shell",
			src:  "jobs:\n  a:\n    defaults:\n      run:\n        shell: ${{ x }}\n    steps:\n      - run: echo ok\n",
			line: "workflow.yml:5: ${{ }} in run/shell",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues := checkSource(t, "workflow.yml", tc.src)
			if len(issues) != 1 || issues[0] != tc.line {
				t.Fatalf("got %q\nwant %q", issues, tc.line)
			}
		})
	}
}

func TestExpressionsOutsideRunShell(t *testing.T) {
	src := ciConcurrencyBlock() + `
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
		issues := checkSource(t, "workflow.yml", "payload: &payload echo hello\nsteps:\n  - run: *payload\n")
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("shell alias", func(t *testing.T) {
		issues := checkSource(t, "workflow.yml", "s: &s bash\nsteps:\n  - shell: *s\n    run: echo ok\n")
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("merge alias", func(t *testing.T) {
		src := "step: &step\n  run: echo ok\njobs:\n  a:\n    steps:\n      - <<: *step\n"
		issues := checkSource(t, "workflow.yml", src)
		mustContain(t, issues, "YAML alias")
		mustContain(t, issues, "YAML anchor")
		mustContain(t, issues, "YAML merge key")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
	t.Run("merge mapping without anchor", func(t *testing.T) {
		issues := checkSource(t, "workflow.yml", "steps:\n  - <<: {run: echo ok}\n")
		mustContain(t, issues, "YAML merge key")
		mustNotContain(t, issues, "YAML alias")
		mustNotContain(t, issues, "YAML anchor")
		mustNotContain(t, issues, "${{ }} in run/shell")
	})
}

func TestDuplicateMappingKey(t *testing.T) {
	src := "jobs:\n  a:\n    permissions: {contents: read}\n    permissions: {contents: read}\n"
	issues := checkSource(t, "workflow.yml", src)
	want := `workflow.yml:4: duplicate mapping key "permissions"`
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
	for _, name := range []string{"notes", "wait-ci", "images", "publish"} {
		t.Run("job concurrency "+name, func(t *testing.T) {
			old := "  " + name + ":\n"
			repl := old + "    concurrency:\n      group: release-" + name + "\n      cancel-in-progress: true\n"
			src := strings.Replace(pass, old, repl, 1)
			if src == pass {
				t.Fatal("mutation did not change release workflow")
			}
			issues := checkSource(t, "release.yml", src)
			want := "job " + name + " concurrency is not allowed"
			if len(issues) != 1 || !strings.HasSuffix(issues[0], ": "+want) {
				t.Fatalf("got %q\nwant exactly %q", issues, want)
			}
		})
	}
}

func TestCIConcurrency(t *testing.T) {
	block := ciConcurrencyBlock()
	pass := ciWorkflow(block)
	cancelMsg := "concurrency cancel-in-progress must be " + fmt.Sprintf("%q", ciCancelInProgress)
	t.Run("missing concurrency", func(t *testing.T) {
		src := strings.Replace(pass, block, "", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("concurrency not a mapping", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency: ci\n", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("wrong group", func(t *testing.T) {
		src := strings.Replace(pass, "group: "+ciConcurrencyGroup, "group: ci-${{ github.ref }}", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, "concurrency group must be")
		mustContain(t, issues, `got "ci-${{ github.ref }}"`)
	})
	t.Run("omit group", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency:\n  cancel-in-progress: "+ciCancelInProgress+"\n", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, "concurrency group must be")
		mustContain(t, issues, `got "<missing>"`)
	})
	t.Run("omit cancel-in-progress", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency:\n  group: "+ciConcurrencyGroup+"\n", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, cancelMsg)
		mustContain(t, issues, `got "<missing>"`)
	})
	t.Run("cancel boolean true", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: "+ciCancelInProgress, "cancel-in-progress: true", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, cancelMsg)
		mustContain(t, issues, `got "true"`)
		mustNotContain(t, issues, "boolean false")
	})
	t.Run("cancel boolean false", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: "+ciCancelInProgress, "cancel-in-progress: false", 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, cancelMsg)
		mustContain(t, issues, `got "false"`)
		mustNotContain(t, issues, "boolean false")
	})
	t.Run("cancel quoted false", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: "+ciCancelInProgress, `cancel-in-progress: "false"`, 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, cancelMsg)
		mustContain(t, issues, `got "false"`)
		mustNotContain(t, issues, "boolean false")
	})
	t.Run("different expression", func(t *testing.T) {
		other := "${{ github.ref != 'refs/heads/master' }}"
		src := strings.Replace(pass, "cancel-in-progress: "+ciCancelInProgress, "cancel-in-progress: "+other, 1)
		issues := checkSource(t, "ci.yml", src)
		mustContain(t, issues, cancelMsg)
		mustContain(t, issues, `got "`+other+`"`)
		mustNotContain(t, issues, "boolean false")
	})
	t.Run("exact", func(t *testing.T) {
		requireEmpty(t, checkSource(t, "ci.yml", pass))
	})
	t.Run("quoted exact expression", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: "+ciCancelInProgress, `cancel-in-progress: "`+ciCancelInProgress+`"`, 1)
		requireEmpty(t, checkSource(t, "ci.yml", src))
	})
	t.Run("job concurrency", func(t *testing.T) {
		src := strings.Replace(pass, "  check:\n    steps:\n", "  check:\n    concurrency:\n      cancel-in-progress: true\n    steps:\n", 1)
		issues := checkSource(t, "ci.yml", src)
		if len(issues) != 1 || !strings.Contains(issues[0], "job check concurrency is not allowed") {
			t.Fatalf("got %q", issues)
		}
	})
	t.Run("later job concurrency", func(t *testing.T) {
		src := pass + "  lab:\n    concurrency:\n      cancel-in-progress: true\n    steps:\n      - run: echo ok\n"
		issues := checkSource(t, "ci.yml", src)
		if len(issues) != 1 || !strings.Contains(issues[0], "job lab concurrency is not allowed") {
			t.Fatalf("got %q", issues)
		}
	})
}

func TestPagesConcurrency(t *testing.T) {
	pass := validPages()
	block := pagesConcurrencyBlock()
	cancelMsg := "concurrency cancel-in-progress must be boolean false"
	t.Run("valid", func(t *testing.T) {
		requireEmpty(t, checkSource(t, "pages.yml", pass))
	})
	t.Run("missing concurrency", func(t *testing.T) {
		src := strings.Replace(pass, block, "", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("concurrency not a mapping", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency: pages\n", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, "concurrency must be a mapping")
	})
	t.Run("wrong group", func(t *testing.T) {
		src := strings.Replace(pass, "group: "+pagesConcurrencyGroup, "group: other", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, "concurrency group must be")
		mustContain(t, issues, `got "other"`)
	})
	t.Run("omit cancel-in-progress", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency:\n  group: "+pagesConcurrencyGroup+"\n", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, cancelMsg)
	})
	t.Run("cancel in progress true", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: false", "cancel-in-progress: true", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, cancelMsg)
	})
	t.Run("cancel in progress string false", func(t *testing.T) {
		src := strings.Replace(pass, "cancel-in-progress: false", `cancel-in-progress: "false"`, 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, cancelMsg)
	})
	t.Run("job concurrency deploy", func(t *testing.T) {
		old := "  deploy:\n"
		repl := old + "    concurrency:\n      group: x\n      cancel-in-progress: false\n"
		src := strings.Replace(pass, old, repl, 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		want := "job deploy concurrency is not allowed"
		if len(issues) != 1 || !strings.HasSuffix(issues[0], ": "+want) {
			t.Fatalf("got %q\nwant exactly %q", issues, want)
		}
	})
	t.Run("missing group", func(t *testing.T) {
		src := strings.Replace(pass, block, "concurrency:\n  cancel-in-progress: false\n", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		mustContain(t, issues, `concurrency group must be "pages", got "<missing>"`)
	})
	t.Run("job concurrency string", func(t *testing.T) {
		old := "  deploy:\n"
		src := strings.Replace(pass, old, old+"    concurrency: some-group\n", 1)
		if src == pass {
			t.Fatal("mutation did not change pages workflow")
		}
		issues := checkSource(t, "pages.yml", src)
		want := "job deploy concurrency is not allowed"
		if len(issues) != 1 || !strings.HasSuffix(issues[0], ": "+want) {
			t.Fatalf("got %q\nwant exactly %q", issues, want)
		}
	})
	t.Run("repo path dispatch", func(t *testing.T) {
		// Full .github/workflows/pages.yml path through checkRoot, so a
		// dispatch keyed on the bare name would fail this case.
		src := strings.Replace(pass, "cancel-in-progress: false", "cancel-in-progress: true", 1)
		issues := checkRepo(t, map[string]string{".github/workflows/pages.yml": src})
		mustContain(t, issues, ".github/workflows/pages.yml:")
		mustContain(t, issues, cancelMsg)
	})
	t.Run("second job concurrency", func(t *testing.T) {
		src := pass + "  preview:\n    name: preview-pages\n    concurrency:\n      group: pages\n      cancel-in-progress: false\n    steps:\n      - run: echo ok\n"
		issues := checkSource(t, "pages.yml", src)
		want := "job preview concurrency is not allowed"
		if len(issues) != 1 || !strings.HasSuffix(issues[0], ": "+want) {
			t.Fatalf("got %q\nwant exactly %q", issues, want)
		}
	})
}

func TestWorkflowFileNames(t *testing.T) {
	pagesCancel := strings.Replace(validPages(), "cancel-in-progress: false", "cancel-in-progress: true", 1)
	if pagesCancel == validPages() {
		t.Fatal("mutation did not change pages workflow")
	}
	ci := ciWorkflow(ciConcurrencyBlock())
	ciCancel := strings.Replace(ci, "cancel-in-progress: "+ciCancelInProgress, "cancel-in-progress: true", 1)
	if ciCancel == ci {
		t.Fatal("mutation did not change ci workflow")
	}
	release := validRelease()
	releaseCancel := strings.Replace(release, "cancel-in-progress: false", "cancel-in-progress: true", 1)
	if releaseCancel == release {
		t.Fatal("mutation did not change release workflow")
	}
	line := func(name string) string {
		return ".github/workflows/" + name + ":1: " + workflowFileNameMessage
	}
	exact := func(t *testing.T, files map[string]string, want ...string) {
		t.Helper()
		issues := checkRepo(t, files)
		if strings.Join(issues, "\n") != strings.Join(want, "\n") {
			t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(issues, "\n"), strings.Join(want, "\n"))
		}
	}

	t.Run("pages.yaml cancel true", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/pages.yaml": pagesCancel,
		}, line("pages.yaml"))
	})
	t.Run("pages.yml beside pages.yaml", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/pages.yml":  validPages(),
			".github/workflows/pages.yaml": pagesCancel,
		}, line("pages.yaml"))
	})
	t.Run("ci.yaml copy", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/ci.yml":  ci,
			".github/workflows/ci.yaml": ci,
		}, line("ci.yaml"))
	})
	t.Run("release.yaml copy", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/release.yml":  release,
			".github/workflows/release.yaml": release,
		}, line("release.yaml"))
	})
	t.Run("PAGES.YML", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/PAGES.YML": pagesCancel,
		}, line("PAGES.YML"))
	})
	t.Run("pages.YML", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/pages.YML": pagesCancel,
		}, line("pages.YML"))
	})
	t.Run("Pages.yml", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/Pages.yml": pagesCancel,
		}, line("Pages.yml"))
	})
	t.Run("CI.yml", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/CI.yml": ciCancel,
		}, line("CI.yml"))
	})
	t.Run("Release.yml", func(t *testing.T) {
		exact(t, map[string]string{
			".github/workflows/Release.yml": releaseCancel,
		}, line("Release.yml"))
	})
	t.Run("pages.yaml still parsed", func(t *testing.T) {
		src := strings.Replace(validPages(), "echo ok", "echo ${{ github.sha }}", 1)
		if src == validPages() {
			t.Fatal("mutation did not change pages workflow")
		}
		exact(t, map[string]string{
			".github/workflows/pages.yaml": src,
		},
			line("pages.yaml"),
			".github/workflows/pages.yaml:10: ${{ }} in run/shell",
		)
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
	issues, err := checkWorkflow(nil, name, []byte(src))
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

func ciConcurrencyBlock() string {
	return "concurrency:\n  group: " + ciConcurrencyGroup + "\n  cancel-in-progress: " + ciCancelInProgress + "\n"
}

func ciWorkflow(concurrency string) string {
	return "name: ci\n" + concurrency + "jobs:\n  check:\n    steps:\n      - run: echo ok\n"
}

func pagesConcurrencyBlock() string {
	return "concurrency:\n  group: " + pagesConcurrencyGroup + "\n  cancel-in-progress: false\n"
}

func validPages() string {
	return "name: pages\non: push\n" + pagesConcurrencyBlock() + "jobs:\n  deploy:\n    name: deploy-github-pages\n    steps:\n      - run: echo ok\n"
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
	b.WriteString("\nenv:\n  GOTOOLCHAIN: local\njobs:\n")
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

func validRelease() string {
	return releaseWorkflow(
		"permissions: {}",
		"permissions: {contents: read}",
		"permissions: {actions: read, contents: read}",
		"permissions: {contents: read, id-token: write, packages: write}",
		"permissions: {contents: write}",
		"",
	)
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	all := make(map[string]string, len(files)+1)
	for path, content := range files {
		all[path] = content
	}
	if _, ok := all[".github/workflows/release.yml"]; !ok {
		all[".github/workflows/release.yml"] = validRelease()
	}
	for path, content := range all {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func checkRepo(t *testing.T, files map[string]string) []string {
	t.Helper()
	return checkPrepared(t, t.TempDir(), files)
}

func checkPrepared(t *testing.T, dir string, files map[string]string) []string {
	t.Helper()
	writeTree(t, dir, files)
	issues, err := checkRoot(dir)
	if err != nil {
		t.Fatalf("checkRoot: %v", err)
	}
	return issues
}

func requireEmpty(t *testing.T, issues []string) {
	t.Helper()
	if len(issues) != 0 {
		t.Fatalf("unexpected issues:\n%s", strings.Join(issues, "\n"))
	}
}

// requireExactPins locks a former empty fixture to exactly the workflow-line
// pin messages, so a later sink or an action.yml pin cannot hide beside them.
func requireExactPins(t *testing.T, issues []string, paths ...string) {
	t.Helper()
	if len(issues) != len(paths) {
		t.Fatalf("got %d issues, want %d workflow pin messages:\n%s", len(issues), len(paths), strings.Join(issues, "\n"))
	}
	for i, issue := range issues {
		if !strings.HasPrefix(issue, paths[i]+":") || !strings.HasSuffix(issue, ": "+pinnedUsesMessage) {
			t.Fatalf("issue %d = %q, want %s: <line>: %s", i, issue, paths[i], pinnedUsesMessage)
		}
	}
	assertNoActionMetaPin(t, issues)
}

func assertNoActionMetaPin(t *testing.T, issues []string) {
	t.Helper()
	for _, issue := range issues {
		if !strings.Contains(issue, pinnedUsesMessage) {
			continue
		}
		colon := strings.IndexByte(issue, ':')
		if colon < 0 {
			t.Fatalf("pin issue missing path: %s", issue)
		}
		path := filepath.ToSlash(issue[:colon])
		base := filepath.Base(path)
		if (base == "action.yml" || base == "action.yaml") && !strings.Contains(path, ".github/workflows/") {
			t.Fatalf("action metadata must stay exempt from the pin rule: %s", issue)
		}
	}
}

func mustPinOn(t *testing.T, issues []string, path string) {
	t.Helper()
	prefix := path + ":"
	for _, issue := range issues {
		if strings.HasPrefix(issue, prefix) && strings.HasSuffix(issue, ": "+pinnedUsesMessage) {
			assertNoActionMetaPin(t, issues)
			return
		}
	}
	t.Fatalf("missing %q on %s in:\n%s", pinnedUsesMessage, path, strings.Join(issues, "\n"))
}

func mustNotSinkOn(t *testing.T, issues []string, path, sink string) {
	t.Helper()
	prefix := path + ":"
	for _, issue := range issues {
		if strings.HasPrefix(issue, prefix) && strings.Contains(issue, sink) {
			t.Fatalf("unexpected %q on %s in %s\nall:\n%s", sink, path, issue, strings.Join(issues, "\n"))
		}
	}
}

func usesWorkflow(uses string) string {
	return "name: extra\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n"
}

func compositeYAML(run string) string {
	return fmt.Sprintf(`name: act
description: act
runs:
  using: composite
  steps:
    - shell: bash
      run: %s
      env:
        FOO: ${{ github.sha }}
      if: ${{ always() }}
    - uses: actions/checkout@v4
      if: ${{ always() }}
      with:
        ref: ${{ github.sha }}
`, run)
}

const calledWorkflow = `name: called
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`

const imagesJob = "  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    steps:\n      - run: echo ok\n"

func TestSinks(t *testing.T) {
	t.Run("github-script safe", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/github-script@v7") + "        with:\n          script: console.log(1)\n",
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("github-script expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/github-script@v7") + "        with:\n          script: \"return ${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in github-script script")
	})
	t.Run("github-script ref and case", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("Actions/GitHub-Script@releases/v7") + "        with:\n          Script: \"${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in github-script script")
	})
	t.Run("github-script-evil is not github-script", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/github-script-evil@v1") + "        with:\n          script: \"${{ github.sha }}\"\n",
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
		mustNotContain(t, issues, "${{ }} in github-script script")
	})
	t.Run("docker args safe", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("docker://alpine:3.20") + "        with:\n          args: echo hello\n          entrypoint: /bin/sh\n",
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("docker args expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("docker://alpine:3.20") + "        with:\n          Args: \"echo ${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in docker args")
	})
	t.Run("docker entrypoint expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("docker://alpine:3.20") + "        with:\n          args: echo hello\n          entrypoint: \"${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in docker entrypoint")
		mustNotContain(t, issues, "${{ }} in docker args")
	})
	t.Run("docker uses expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("docker://${{ github.event.issue.title }}"),
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in uses")
		mustNotContain(t, issues, "parse error")
	})
	t.Run("step uses expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/checkout@${{ github.sha }}"),
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in uses")
		mustNotContain(t, issues, "parse error")
	})
	t.Run("github-script leading space", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow(`" actions/github-script@v7"`) + "        with:\n          script: \"return ${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in github-script script")
	})
	t.Run("docker leading space", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow(`" docker://alpine:3.20"`) + "        with:\n          args: \"echo ${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in docker args")
	})
	t.Run("with not a mapping", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/github-script@v7") + "        with: not-a-mapping\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "with must be a mapping")
	})
	t.Run("script not a scalar", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("actions/github-script@v7") + "        with:\n          script:\n            - echo\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "github-script script must be a scalar")
	})
	t.Run("docker args not a scalar", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("docker://alpine:3.20") + "        with:\n          args:\n            - echo\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "docker args must be a scalar")
	})
	t.Run("non-scalar uses before name match", func(t *testing.T) {
		src := "name: extra\non: push\njobs:\n  build:\n    steps:\n      - uses:\n          - actions/checkout@v4\n        run: echo ok\n"
		issues := checkRepo(t, map[string]string{".github/workflows/extra.yml": src})
		mustContain(t, issues, "uses must be a scalar")
		mustNotContain(t, issues, "github-script")
	})
}

func TestLocalActions(t *testing.T) {
	t.Run("composite safe", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/hello"),
			"actions/hello/action.yml":    compositeYAML("echo ok"),
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("composite run expression", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/hello"),
			"actions/hello/action.yml":    compositeYAML("echo ${{ github.sha }}"),
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "actions/hello/action.yml")
		mustContain(t, issues, "${{ }} in run/shell")
		mustNotSinkOn(t, issues, ".github/workflows/extra.yml", "${{ }} in run/shell")
	})
	t.Run("docker metadata safe args", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n  args:\n    - echo\n    - hello\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("docker metadata omits optional keys", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("docker metadata image expression", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: \"docker://${{ github.sha }}\"\n  args:\n    - echo\n    - hello\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in runs.image")
		mustNotContain(t, issues, "${{ }} in runs.args")
	})
	t.Run("docker metadata image wrong shape", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image:\n    - \"docker://${{ github.sha }}\"\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "runs.image must be a scalar")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("docker metadata args expression", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n  args:\n    - echo\n    - \"${{ github.sha }}\"\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in runs.args")
	})
	t.Run("docker metadata args wrong shape", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n  args: echo hello\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "runs.args must be a sequence of scalars")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("docker metadata entrypoint wrong shape", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n  entrypoint:\n    - /bin/sh\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "runs.entrypoint must be a scalar")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("docker metadata pre-entrypoint expression", func(t *testing.T) {
		action := "name: dkr\nruns:\n  using: docker\n  image: Dockerfile\n  pre-entrypoint: \"${{ github.sha }}\"\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/dkr"),
			"actions/dkr/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "${{ }} in runs.pre-entrypoint")
	})
	t.Run("node action", func(t *testing.T) {
		action := "name: n\nruns:\n  using: node20\n  main: index.js\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/node"),
			"actions/node/action.yml":     action,
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("missing runs.using", func(t *testing.T) {
		action := "name: n\nruns:\n  image: Dockerfile\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/bad"),
			"actions/bad/action.yml":      action,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "runs.using is not composite, docker, or node")
	})
	t.Run("missing action file", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/missing"),
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "local path escapes the repository")
	})
	t.Run("both action files", func(t *testing.T) {
		body := compositeYAML("echo ok")
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/both"),
			"actions/both/action.yml":     body,
			"actions/both/action.yaml":    body,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "both action.yml and action.yaml exist")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("unparseable action", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/bad"),
			"actions/bad/action.yml":      "runs: [\n",
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "parse error")
	})
}

func TestNestedAndDiamond(t *testing.T) {
	calleeBad := `name: callee
runs:
  using: composite
  steps:
    - shell: bash
      run: echo ok
    - uses: docker://alpine:3.20
      with:
        args: "echo ${{ github.sha }}"
`
	calleeOK := strings.Replace(calleeBad, "echo ${{ github.sha }}", "echo hello", 1)
	caller := `name: caller
runs:
  using: composite
  steps:
    - shell: bash
      run: echo ok
    - uses: ./actions/callee
`
	t.Run("nested docker args", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/caller"),
			"actions/caller/action.yml":   caller,
			"actions/callee/action.yml":   calleeBad,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "actions/callee/action.yml")
		mustContain(t, issues, "${{ }} in docker args")
		mustNotContain(t, issues, "${{ }} in run/shell")
		mustNotSinkOn(t, issues, ".github/workflows/extra.yml", "${{ }} in docker args")
	})
	t.Run("nested safe", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/caller"),
			"actions/caller/action.yml":   caller,
			"actions/callee/action.yml":   calleeOK,
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("diamond", func(t *testing.T) {
		shared := "name: shared\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n"
		side := func(name string) string {
			return "name: " + name + "\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n    - uses: ./actions/shared\n"
		}
		top := "name: top\nruns:\n  using: composite\n  steps:\n    - uses: ./actions/left\n    - uses: ./actions/right\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/top"),
			"actions/top/action.yml":      top,
			"actions/left/action.yml":     side("left"),
			"actions/right/action.yml":    side("right"),
			"actions/shared/action.yml":   shared,
		})
		requireExactPins(t, issues, ".github/workflows/extra.yml")
	})
	t.Run("cycle", func(t *testing.T) {
		a := "name: a\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n    - uses: ./actions/b\n"
		b := "name: b\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n    - uses: ./actions/a\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./actions/a"),
			"actions/a/action.yml":        a,
			"actions/b/action.yml":        b,
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "local action cycle")
		mustNotContain(t, issues, "${{ }}")
	})
}

func TestLocalPaths(t *testing.T) {
	outsideDoc := "name: outside\non: push\njobs:\n  build:\n    steps:\n      - run: echo ok\n"
	t.Run("dotdot", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "repo")
		target := filepath.Join(parent, "x")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "action.yml"), []byte(compositeYAML("echo ok")), 0o644); err != nil {
			t.Fatal(err)
		}
		writeTree(t, root, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./../x"),
		})
		issues, err := checkRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("symlink", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "repo")
		outside := filepath.Join(parent, "outside-action")
		if err := os.MkdirAll(outside, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, "action.yml"), []byte(compositeYAML("echo ok")), 0o644); err != nil {
			t.Fatal(err)
		}
		writeTree(t, root, map[string]string{
			".github/workflows/extra.yml": usesWorkflow("./linked"),
		})
		if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
			t.Fatal(err)
		}
		issues, err := checkRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("slash etc passwd", func(t *testing.T) {
		// .//etc/passwd strips to absolute /etc/passwd. Join would drop the
		// repo root and read the host file. Reject before any read.
		issues := checkRepo(t, map[string]string{
			".github/workflows/extra.yml": usesWorkflow(`".//etc/passwd"`),
		})
		mustPinOn(t, issues, ".github/workflows/extra.yml")
		mustContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "parse error")
		mustNotContain(t, issues, "runs.using")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("job workflow positive", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/called.yml": calledWorkflow,
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n",
		})
		requireExactPins(t, issues, ".github/workflows/caller.yml")
	})
	t.Run("job workflow dotdot", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "repo")
		if err := os.WriteFile(filepath.Join(parent, "outside.yml"), []byte(outsideDoc), 0o644); err != nil {
			t.Fatal(err)
		}
		writeTree(t, root, map[string]string{
			"outside.yml":                  outsideDoc,
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: ./.github/workflows/../../outside.yml\n",
		})
		issues, err := checkRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		mustPinOn(t, issues, ".github/workflows/caller.yml")
		mustContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "runs.using")
		mustNotContain(t, issues, "parse error")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("job local action is not a workflow", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: ./actions/hello\n",
			"actions/hello/action.yml":     compositeYAML("echo ok"),
		})
		mustPinOn(t, issues, ".github/workflows/caller.yml")
		mustContain(t, issues, "job uses path is not a top-level workflow file")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("non-scalar job uses", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/called.yml": calledWorkflow,
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses:\n      - ./.github/workflows/called.yml\n",
		})
		mustContain(t, issues, "uses must be a scalar")
		mustNotContain(t, issues, "local path escapes the repository")
	})
	t.Run("job workflow leading space", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/called.yml": calledWorkflow,
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: \" ./.github/workflows/called.yml\"\n",
		})
		requireExactPins(t, issues, ".github/workflows/caller.yml")
	})
	t.Run("job workflow leading space escapes", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: \" ./.github/workflows/../../x\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/caller.yml")
		mustContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "job uses path is not a top-level workflow file")
		mustNotContain(t, issues, "action file is missing")
		mustNotContain(t, issues, "${{ }}")
	})
	t.Run("job uses expression before local", func(t *testing.T) {
		issues := checkRepo(t, map[string]string{
			".github/workflows/caller.yml": "name: caller\non: push\njobs:\n  call:\n    uses: \" ./.github/workflows/../../${{ github.sha }}\"\n",
		})
		mustPinOn(t, issues, ".github/workflows/caller.yml")
		mustContain(t, issues, "${{ }} in uses")
		mustNotContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "job uses path")
		mustNotContain(t, issues, "parse error")
	})
}

func TestWriteAllEverywhere(t *testing.T) {
	t.Run("workflow", func(t *testing.T) {
		src := "name: pages\non: push\n" + pagesConcurrencyBlock() + "permissions: write-all\njobs:\n  deploy:\n    steps:\n      - run: echo ok\n"
		issues := checkRepo(t, map[string]string{".github/workflows/pages.yml": src})
		mustContain(t, issues, ".github/workflows/pages.yml")
		mustContain(t, issues, "permissions write-all is not allowed")
	})
	t.Run("job", func(t *testing.T) {
		src := "name: pages\non: push\n" + pagesConcurrencyBlock() + "permissions:\n  contents: read\njobs:\n  deploy:\n    permissions: write-all\n    steps:\n      - run: echo ok\n"
		issues := checkRepo(t, map[string]string{".github/workflows/pages.yml": src})
		mustContain(t, issues, ".github/workflows/pages.yml")
		mustContain(t, issues, "permissions write-all is not allowed")
	})
	t.Run("reusable call", func(t *testing.T) {
		src := "name: caller\non: push\njobs:\n  call:\n    permissions: write-all\n    uses: ./.github/workflows/called.yml\n"
		issues := checkRepo(t, map[string]string{
			".github/workflows/called.yml": calledWorkflow,
			".github/workflows/caller.yml": src,
		})
		mustContain(t, issues, ".github/workflows/caller.yml")
		mustContain(t, issues, "permissions write-all is not allowed")
		mustPinOn(t, issues, ".github/workflows/caller.yml")
		mustNotContain(t, issues, "local path escapes the repository")
		mustNotContain(t, issues, "action file is missing")
	})
	t.Run("read-all outside release", func(t *testing.T) {
		src := "name: pages\non: push\n" + pagesConcurrencyBlock() + "permissions: read-all\njobs:\n  deploy:\n    steps:\n      - run: echo ok\n"
		issues := checkRepo(t, map[string]string{".github/workflows/pages.yml": src})
		requireEmpty(t, issues)
	})
}

func TestReleaseGoToolchain(t *testing.T) {
	base := validRelease()
	if !strings.Contains(base, "GOTOOLCHAIN: local") || !strings.Contains(base, imagesJob) {
		t.Fatal("release fixture missing GOTOOLCHAIN or images job")
	}
	replaceImages := func(body string) string {
		out := strings.Replace(base, imagesJob, body, 1)
		if out == base {
			t.Fatal("images job was not replaced")
		}
		return out
	}
	cases := []struct {
		name   string
		src    string
		want   string
		absent string
	}{
		{
			name: "missing workflow key",
			src:  strings.Replace(base, "  GOTOOLCHAIN: local\n", "", 1),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name: "workflow go1.26.0",
			src:  strings.Replace(base, "GOTOOLCHAIN: local", "GOTOOLCHAIN: go1.26.0", 1),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name: "workflow auto",
			src:  strings.Replace(base, "GOTOOLCHAIN: local", "GOTOOLCHAIN: auto", 1),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name: "workflow not scalar",
			src:  strings.Replace(base, "GOTOOLCHAIN: local", "GOTOOLCHAIN:\n    - local", 1),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name: "job auto",
			src:  replaceImages("  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    env:\n      GOTOOLCHAIN: auto\n    steps:\n      - run: echo ok\n"),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name:   "step auto",
			src:    replaceImages("  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    steps:\n      - run: echo ok\n        env:\n          GOTOOLCHAIN: auto\n"),
			want:   "GOTOOLCHAIN must be scalar local",
			absent: "notes step ver",
		},
		{
			name: "container auto",
			src:  replaceImages("  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    container:\n      image: alpine\n      env:\n        GOTOOLCHAIN: auto\n    steps:\n      - run: echo ok\n"),
			want: "GOTOOLCHAIN must be scalar local",
		},
		{
			name: "services auto",
			src:  replaceImages("  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    services:\n      box:\n        image: alpine\n        env:\n          GOTOOLCHAIN: auto\n    steps:\n      - run: echo ok\n"),
			want: "GOTOOLCHAIN must be scalar local",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.src == base {
				t.Fatal("mutation did not change release workflow")
			}
			issues := checkRepo(t, map[string]string{".github/workflows/release.yml": tc.src})
			mustContain(t, issues, tc.want)
			if tc.absent != "" {
				mustNotContain(t, issues, tc.absent)
			}
		})
	}
	t.Run("local in every scope", func(t *testing.T) {
		src := replaceImages("  images:\n    permissions: {contents: read, id-token: write, packages: write}\n    env:\n      GOTOOLCHAIN: local\n    container:\n      image: alpine\n      env:\n        GOTOOLCHAIN: local\n    services:\n      box:\n        image: alpine\n        env:\n          GOTOOLCHAIN: local\n    steps:\n      - run: echo ok\n        env:\n          GOTOOLCHAIN: local\n")
		issues := checkRepo(t, map[string]string{".github/workflows/release.yml": src})
		requireEmpty(t, issues)
	})
	t.Run("non-release auto stays legal", func(t *testing.T) {
		src := ciConcurrencyBlock() + "name: ci\nenv:\n  GOTOOLCHAIN: auto\njobs:\n  build:\n    env:\n      GOTOOLCHAIN: auto\n    container:\n      image: alpine\n      env:\n        GOTOOLCHAIN: auto\n    services:\n      box:\n        image: alpine\n        env:\n          GOTOOLCHAIN: auto\n    steps:\n      - env:\n          GOTOOLCHAIN: auto\n        run: echo ok\n"
		issues := checkRepo(t, map[string]string{".github/workflows/ci.yml": src})
		requireEmpty(t, issues)
	})
}

func TestPinnedUses(t *testing.T) {
	const pin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	ciSteps := func(step string) string {
		return "name: ci\non: push\njobs:\n  build:\n    steps:\n" + step
	}
	t.Run("current pin shape", func(t *testing.T) {
		src := ciConcurrencyBlock() + ciSteps("      - uses: "+pin+"\n      - uses: \" "+pin+"\"\n")
		src += "  call:\n    uses: \" " + pin + "\"\n"
		requireEmpty(t, checkSource(t, "ci.yml", src))
	})
	t.Run("release current pin shape", func(t *testing.T) {
		src := strings.Replace(validRelease(), "      - run: echo ok\n", "      - uses: "+pin+"\n", 1)
		if src == validRelease() {
			t.Fatal("mutation did not change release workflow")
		}
		requireEmpty(t, checkSource(t, "release.yml", src))
	})
	forms := []struct {
		name string
		step string
	}{
		{name: "two-space main", step: "      -  uses: actions/checkout@main\n"},
		{name: "two-space master", step: "      -  uses: actions/checkout@master\n"},
		{name: "flow main", step: "      - {uses: actions/checkout@main}\n"},
		{name: "flow master", step: "      - {uses: actions/checkout@master}\n"},
	}
	for _, tc := range forms {
		t.Run(tc.name, func(t *testing.T) {
			issues := checkSource(t, "ci.yml", ciSteps(tc.step))
			mustContain(t, issues, pinnedUsesMessage)
		})
	}
	for _, ref := range []string{"main", "master"} {
		t.Run("tab "+ref, func(t *testing.T) {
			// A tab between "-" and "uses" is a real step. yaml.v3 rejects that
			// token, and checkRoot records a parse error. If it parses, the pin
			// rule still has to reject @main and @master.
			src := ciSteps("      -\tuses: actions/checkout@" + ref + "\n")
			issues := checkRepo(t, map[string]string{".github/workflows/ci.yml": src})
			if len(issues) == 0 {
				t.Fatal("tab form was accepted")
			}
			saw := false
			for _, issue := range issues {
				if strings.Contains(issue, pinnedUsesMessage) || strings.Contains(issue, "parse error") {
					saw = true
					break
				}
			}
			if !saw {
				t.Fatalf("tab form rejected for the wrong reason:\n%s", strings.Join(issues, "\n"))
			}
		})
	}
	t.Run("release two-space main", func(t *testing.T) {
		src := strings.Replace(validRelease(), "      - run: echo ok\n", "      -  uses: actions/checkout@main\n", 1)
		if src == validRelease() {
			t.Fatal("mutation did not change release workflow")
		}
		mustContain(t, checkSource(t, "release.yml", src), pinnedUsesMessage)
	})
	t.Run("job uses movable ref", func(t *testing.T) {
		src := "name: ci\non: push\njobs:\n  call:\n    uses: actions/checkout@main\n  call2: {uses: actions/checkout@master}\n"
		mustContain(t, checkSource(t, "ci.yml", src), pinnedUsesMessage)
	})
	t.Run("local and docker are not pins", func(t *testing.T) {
		for _, uses := range []string{"./actions/hello", "docker://alpine:3.20"} {
			issues := checkSource(t, "ci.yml", ciSteps("      - uses: "+uses+"\n"))
			mustContain(t, issues, pinnedUsesMessage)
		}
	})
	t.Run("pages not pinned", func(t *testing.T) {
		src := "name: pages\non: push\n" + pagesConcurrencyBlock() + "jobs:\n  deploy:\n    steps:\n      -  uses: actions/checkout@main\n      - {uses: actions/checkout@master}\n      - uses: ./actions/hello\n      - uses: docker://alpine:3.20\n"
		issues := checkSource(t, "pages.yml", src)
		requireExactPins(t, issues, "pages.yml", "pages.yml", "pages.yml", "pages.yml")
	})
	t.Run("workflow basename action metadata", func(t *testing.T) {
		src := "name: act\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
		t.Run("action.yml", func(t *testing.T) {
			issues := checkRepo(t, map[string]string{
				".github/workflows/action.yml": src,
			})
			requireExactPins(t, issues, ".github/workflows/action.yml")
		})
		t.Run("action.yaml", func(t *testing.T) {
			issues := checkRepo(t, map[string]string{
				".github/workflows/action.yaml": src,
			})
			wantName := ".github/workflows/action.yaml:1: " + workflowFileNameMessage
			pinOK := len(issues) == 2 &&
				strings.HasPrefix(issues[1], ".github/workflows/action.yaml:") &&
				strings.HasSuffix(issues[1], ": "+pinnedUsesMessage)
			if len(issues) != 2 || issues[0] != wantName || !pinOK {
				t.Fatalf("got %q\nwant name issue then pin", issues)
			}
		})
	})
	t.Run("current tree", func(t *testing.T) {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller failed")
		}
		root, err := findRoot(filepath.Dir(file))
		if err != nil {
			t.Fatal(err)
		}
		issues, err := checkRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		requireEmpty(t, issues)
	})
}
