// Command check-workflows rejects expression injection, permission drift,
// release concurrency drift, and release GOTOOLCHAIN drift in GitHub Actions
// workflows.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	rawVersionValue = "${{ github.event.inputs.version || github.ref_name }}"
	versionValue    = "${{ steps.ver.outputs.version }}"
	ghTokenValue    = "${{ secrets.GITHUB_TOKEN }}"
	releaseRefValue = "${{ github.ref_name }}"

	verRun = `set -euo pipefail
bash ./tools/release-version.sh "$RAW_VERSION" >> "$GITHUB_OUTPUT"`

	generateRun = `set -euo pipefail
chmod +x tools/release-notes.sh tools/release-notes_test.sh
./tools/release-notes_test.sh
./tools/release-notes.sh "$VERSION"`

	publishRun = `set -euo pipefail
out="$(bash ./tools/release-version.sh "$RELEASE_REF")"
tag="$(printf '%s\n' "$out" | sed -n 's/^tag=//p')"
if [ -z "$tag" ] || [ "$tag" != "$RELEASE_REF" ]; then
  echo "release tag is not a valid version tag" >&2
  exit 1
fi
if gh release view "$tag" >/dev/null 2>&1; then
  gh release edit "$tag" --title "TacLab ${tag}" --notes-file dist/RELEASE_NOTES.md
else
  gh release create "$tag" --title "TacLab ${tag}" --notes-file dist/RELEASE_NOTES.md
fi`

	// releaseConcurrencyGroup is the only accepted release.yml concurrency group.
	// A branch dispatch (github.ref refs/heads/main) previously did not share the
	// tag-push group; dispatch version vX.Y.Z or X.Y.Z now shares
	// release-<workflow>-refs/tags/vX.Y.Z with the tag push.
	releaseConcurrencyGroup = "release-${{ github.workflow }}-${{ github.event_name == 'workflow_dispatch' && (startsWith(github.event.inputs.version, 'v') && format('refs/tags/{0}', github.event.inputs.version) || format('refs/tags/v{0}', github.event.inputs.version)) || github.ref }}"
)

var jobPerms = map[string]map[string]string{
	"notes": {
		"contents": "read",
	},
	"wait-ci": {
		"actions":  "read",
		"contents": "read",
	},
	"images": {
		"contents": "read",
		"id-token": "write",
		"packages": "write",
	},
	"publish": {
		"contents": "write",
	},
}

var releaseJobs = []string{"images", "notes", "publish", "wait-ci"}

func main() {
	root, err := findRoot(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-workflows: %v\n", err)
		os.Exit(1)
	}
	issues, err := checkRoot(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-workflows: %v\n", err)
		os.Exit(1)
	}
	if len(issues) > 0 {
		for _, issue := range issues {
			fmt.Fprintln(os.Stderr, issue)
		}
		os.Exit(1)
	}
	fmt.Println("check-workflows: ok")
}

// findRoot walks up from start to the module that owns .github.
// web/go.mod is a nested module and is not the workflow root.
func findRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if isModuleRoot(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("module root not found from %s", start)
		}
		dir = parent
	}
}

func isModuleRoot(dir string) bool {
	mod, err := os.Stat(filepath.Join(dir, "go.mod"))
	if err != nil || mod.IsDir() {
		return false
	}
	github, err := os.Stat(filepath.Join(dir, ".github"))
	if err != nil || !github.IsDir() {
		return false
	}
	return true
}

func checkRoot(root string) ([]string, error) {
	loader, err := newActionLoader(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var issues []string
	sawRelease := false
	for _, name := range names {
		if name == "release.yml" {
			sawRelease = true
		}
		rel := filepath.Join(".github", "workflows", name)
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		found, err := checkWorkflow(loader, rel, data)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: parse error: %v", rel, err))
			continue
		}
		issues = append(issues, found...)
	}
	if !sawRelease {
		issues = append(issues, ".github/workflows/release.yml:1: release workflow is missing")
	}
	return issues, nil
}

func checkWorkflow(loader *actionLoader, name string, data []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var issues []string
	walk(name, &doc, &issues)
	issues = append(issues, checkDocument(loader, name, &doc)...)
	if filepath.Base(name) == "release.yml" {
		issues = append(issues, checkRelease(name, &doc)...)
	}
	return issues, nil
}

func walk(file string, n *yaml.Node, issues *[]string) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode {
		*issues = append(*issues, at(file, n.Line, "YAML alias"))
		return
	}
	if n.Anchor != "" {
		*issues = append(*issues, at(file, n.Line, "YAML anchor"))
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			walk(file, child, issues)
		}
	case yaml.MappingNode:
		seen := map[string]struct{}{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			val := n.Content[i+1]
			if isMergeKey(key) {
				*issues = append(*issues, at(file, key.Line, "YAML merge key"))
			}
			if key.Kind == yaml.ScalarNode {
				if _, ok := seen[key.Value]; ok {
					*issues = append(*issues, at(file, key.Line, fmt.Sprintf("duplicate mapping key %q", key.Value)))
				} else {
					seen[key.Value] = struct{}{}
				}
				if val.Kind == yaml.ScalarNode && (key.Value == "run" || key.Value == "shell") && strings.Contains(val.Value, "${{") {
					*issues = append(*issues, at(file, val.Line, "${{ }} in run/shell"))
				}
			}
			walk(file, key, issues)
			walk(file, val, issues)
		}
	}
}

func isMergeKey(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	return n.Tag == "!!merge" || n.Tag == "tag:yaml.org,2002:merge"
}

func checkRelease(file string, doc *yaml.Node) []string {
	root := mappingRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return []string{at(file, 1, "workflow document must be a mapping")}
	}
	var issues []string
	issues = append(issues, checkReleaseConcurrency(file, root)...)
	issues = append(issues, checkGoToolchain(file, root)...)
	_, perms := mapEntry(root, "permissions")
	issues = append(issues, checkWorkflowPerms(file, perms, root.Line)...)

	_, jobs := mapEntry(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		issues = append(issues, at(file, root.Line, "jobs must be a mapping"))
		return issues
	}

	type jobNode struct {
		key *yaml.Node
		val *yaml.Node
	}
	found := map[string]jobNode{}
	var names []string
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key := jobs.Content[i]
		val := jobs.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			issues = append(issues, at(file, key.Line, "job name must be a string"))
			continue
		}
		found[key.Value] = jobNode{key, val}
		names = append(names, key.Value)
	}
	wantSet := map[string]struct{}{}
	for _, name := range releaseJobs {
		wantSet[name] = struct{}{}
		if _, ok := found[name]; !ok {
			issues = append(issues, at(file, jobs.Line, fmt.Sprintf("missing job %q", name)))
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := wantSet[name]; !ok {
			issues = append(issues, at(file, found[name].key.Line, fmt.Sprintf("unexpected job %q", name)))
		}
	}
	for _, name := range releaseJobs {
		job, ok := found[name]
		if !ok {
			continue
		}
		if job.val.Kind != yaml.MappingNode {
			issues = append(issues, at(file, job.val.Line, fmt.Sprintf("job %s must be a mapping", name)))
			continue
		}
		if msg := checkPermBeforeSteps(file, name, job.val); msg != "" {
			issues = append(issues, msg)
		}
		_, perm := mapEntry(job.val, "permissions")
		if perm == nil {
			issues = append(issues, at(file, job.key.Line, fmt.Sprintf("job %s missing permissions", name)))
			continue
		}
		issues = append(issues, checkJobPerm(file, name, perm)...)
	}
	if notes, ok := found["notes"]; ok && notes.val.Kind == yaml.MappingNode {
		issues = append(issues, checkNotes(file, notes.val)...)
	}
	if publish, ok := found["publish"]; ok && publish.val.Kind == yaml.MappingNode {
		issues = append(issues, checkPublish(file, publish.val)...)
	}
	return issues
}

func checkReleaseConcurrency(file string, root *yaml.Node) []string {
	key, conc := mapEntry(root, "concurrency")
	if conc == nil || conc.Kind != yaml.MappingNode {
		line := root.Line
		if conc != nil {
			line = conc.Line
		} else if key != nil {
			line = key.Line
		}
		return []string{at(file, line, "concurrency must be a mapping")}
	}
	var issues []string
	gkey, group := mapEntry(conc, "group")
	if group == nil || group.Kind != yaml.ScalarNode || group.Value != releaseConcurrencyGroup {
		line := conc.Line
		if group != nil {
			line = group.Line
		} else if gkey != nil {
			line = gkey.Line
		}
		got := "<missing>"
		if group != nil {
			if group.Kind == yaml.ScalarNode {
				got = group.Value
			} else {
				got = "<not a scalar>"
			}
		}
		issues = append(issues, at(file, line, fmt.Sprintf("concurrency group must be %q, got %q", releaseConcurrencyGroup, got)))
	}
	ckey, cancel := mapEntry(conc, "cancel-in-progress")
	if !boolFalse(cancel) {
		line := conc.Line
		if cancel != nil {
			line = cancel.Line
		} else if ckey != nil {
			line = ckey.Line
		}
		issues = append(issues, at(file, line, "concurrency cancel-in-progress must be boolean false"))
	}
	return issues
}

func boolFalse(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!bool" && n.Value == "false"
}

func checkWorkflowPerms(file string, n *yaml.Node, fallback int) []string {
	if n == nil {
		return []string{at(file, fallback, "workflow permissions must be an empty mapping")}
	}
	if n.Kind == yaml.ScalarNode && (n.Value == "write-all" || n.Value == "read-all") {
		return []string{at(file, n.Line, fmt.Sprintf("permissions %s is not allowed", n.Value))}
	}
	if n.Kind != yaml.MappingNode || len(n.Content) != 0 {
		return []string{at(file, n.Line, "workflow permissions must be an empty mapping")}
	}
	return nil
}

func checkJobPerm(file, name string, n *yaml.Node) []string {
	if n.Kind == yaml.ScalarNode && (n.Value == "write-all" || n.Value == "read-all") {
		return []string{at(file, n.Line, fmt.Sprintf("permissions %s is not allowed", n.Value))}
	}
	got, ok := stringMap(n)
	want := jobPerms[name]
	if !ok || !mapsEqual(got, want) {
		return []string{at(file, n.Line, fmt.Sprintf("job %s permissions: got %s want %s", name, formatMap(got, ok), formatMap(want, true)))}
	}
	return nil
}

func checkPermBeforeSteps(file, name string, job *yaml.Node) string {
	permKey, _ := mapEntry(job, "permissions")
	stepsKey, _ := mapEntry(job, "steps")
	if permKey == nil || stepsKey == nil {
		return ""
	}
	if permKey.Line >= stepsKey.Line {
		return at(file, permKey.Line, fmt.Sprintf("job %s permissions must appear before steps", name))
	}
	return ""
}

func checkNotes(file string, job *yaml.Node) []string {
	var issues []string
	_, outputs := mapEntry(job, "outputs")
	_, version := mapEntry(outputs, "version")
	if version == nil || version.Kind != yaml.ScalarNode || version.Value != versionValue {
		line := job.Line
		if version != nil {
			line = version.Line
		}
		issues = append(issues, at(file, line, "jobs.notes.outputs.version must be ${{ steps.ver.outputs.version }}"))
	}
	_, steps := mapEntry(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		issues = append(issues, at(file, job.Line, "notes steps are missing"))
		return issues
	}
	ver := findStep(steps, "ver", "")
	if ver == nil {
		issues = append(issues, at(file, job.Line, "notes step id ver is missing"))
	} else {
		if msg := checkExactEnv(file, "notes step ver", ver, map[string]string{"RAW_VERSION": rawVersionValue}); msg != "" {
			issues = append(issues, msg)
		}
		if msg := checkExactRun(file, "notes step ver", ver, verRun); msg != "" {
			issues = append(issues, msg)
		}
	}
	generate := findStep(steps, "", "Generate release notes")
	if generate == nil {
		issues = append(issues, at(file, job.Line, "notes step Generate release notes is missing"))
	} else {
		if msg := checkExactEnv(file, "notes generate step", generate, map[string]string{"VERSION": versionValue}); msg != "" {
			issues = append(issues, msg)
		}
		if msg := checkExactRun(file, "notes generate step", generate, generateRun); msg != "" {
			issues = append(issues, msg)
		}
	}
	return issues
}

func checkPublish(file string, job *yaml.Node) []string {
	_, steps := mapEntry(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return []string{at(file, job.Line, "publish steps are missing")}
	}
	step := findStep(steps, "", "Create GitHub Release")
	if step == nil {
		return []string{at(file, job.Line, "publish step Create GitHub Release is missing")}
	}
	var issues []string
	if msg := checkExactEnv(file, "publish release step", step, map[string]string{
		"GH_TOKEN":    ghTokenValue,
		"RELEASE_REF": releaseRefValue,
	}); msg != "" {
		issues = append(issues, msg)
	}
	if msg := checkExactRun(file, "publish release step", step, publishRun); msg != "" {
		issues = append(issues, msg)
	}
	return issues
}

func checkExactEnv(file, what string, step *yaml.Node, want map[string]string) string {
	_, env := mapEntry(step, "env")
	if env == nil {
		return at(file, step.Line, what+" env is missing")
	}
	got, ok := stringMap(env)
	if !ok || !mapsEqual(got, want) {
		return at(file, env.Line, fmt.Sprintf("%s env: got %s want %s", what, formatMap(got, ok), formatMap(want, true)))
	}
	return ""
}

func checkExactRun(file, what string, step *yaml.Node, want string) string {
	_, run := mapEntry(step, "run")
	line := step.Line
	if run == nil || run.Kind != yaml.ScalarNode {
		return at(file, line, what+" run is missing")
	}
	if run.Line > 0 {
		line = run.Line
	}
	got := strings.TrimRight(run.Value, "\n")
	if got != want {
		return at(file, line, fmt.Sprintf("%s run mismatch: got %q want %q", what, got, want))
	}
	return ""
}

func findStep(steps *yaml.Node, id, name string) *yaml.Node {
	if steps == nil {
		return nil
	}
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		if id != "" && scalarAt(step, "id") == id {
			return step
		}
		if name != "" && scalarAt(step, "name") == name {
			return step
		}
	}
	return nil
}

func mappingRoot(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

func mapEntry(m *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return k, m.Content[i+1]
		}
	}
	return nil, nil
}

func scalarAt(m *yaml.Node, key string) string {
	_, v := mapEntry(m, key)
	if v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func stringMap(n *yaml.Node) (map[string]string, bool) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, false
	}
	out := make(map[string]string, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		v := n.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return nil, false
		}
		out[k.Value] = v.Value
	}
	return out, true
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func formatMap(m map[string]string, ok bool) string {
	if !ok {
		return "<invalid>"
	}
	if len(m) == 0 {
		return "<empty>"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + m[k]
	}
	return strings.Join(parts, ",")
}

func at(file string, line int, msg string) string {
	if line <= 0 {
		line = 1
	}
	return fmt.Sprintf("%s:%d: %s", file, line, msg)
}

func checkDocument(loader *actionLoader, file string, doc *yaml.Node) []string {
	root := mappingRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil
	}
	var issues []string
	_, perms := mapEntry(root, "permissions")
	issues = append(issues, checkWriteAll(file, perms)...)
	_, jobs := mapEntry(root, "jobs")
	if jobs == nil {
		return issues
	}
	if jobs.Kind != yaml.MappingNode {
		return append(issues, at(file, jobs.Line, "jobs must be a mapping"))
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		_, jobPerms := mapEntry(job, "permissions")
		issues = append(issues, checkWriteAll(file, jobPerms)...)
		_, steps := mapEntry(job, "steps")
		if steps != nil {
			if steps.Kind != yaml.SequenceNode {
				issues = append(issues, at(file, steps.Line, "steps must be a sequence"))
			} else {
				issues = append(issues, checkStepList(loader, file, steps)...)
			}
		}
		_, usesVal := mapEntry(job, "uses")
		if usesVal == nil {
			continue
		}
		if usesVal.Kind != yaml.ScalarNode {
			issues = append(issues, at(file, usesVal.Line, "uses must be a scalar"))
			continue
		}
		if strings.HasPrefix(usesVal.Value, "./") && loader != nil {
			issues = append(issues, loader.checkJobUses(file, usesVal)...)
		}
	}
	return issues
}

func checkWriteAll(file string, n *yaml.Node) []string {
	if n != nil && n.Kind == yaml.ScalarNode && n.Value == "write-all" {
		return []string{at(file, n.Line, "permissions write-all is not allowed")}
	}
	return nil
}

func checkStepList(loader *actionLoader, file string, steps *yaml.Node) []string {
	var issues []string
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			issues = append(issues, at(file, step.Line, "step must be a mapping"))
			continue
		}
		_, usesVal := mapEntry(step, "uses")
		if usesVal == nil {
			continue
		}
		if usesVal.Kind != yaml.ScalarNode {
			issues = append(issues, at(file, usesVal.Line, "uses must be a scalar"))
			continue
		}
		// Trim so a quoted leading space cannot skip github-script, docker://, or ./.
		// ${{ in the uses value is rejected; the runner expands it before resolving the action.
		uses := strings.TrimSpace(usesVal.Value)
		if strings.Contains(uses, "${{") {
			issues = append(issues, at(file, usesVal.Line, "${{ }} in uses"))
		}
		switch {
		case isGitHubScript(uses):
			issues = append(issues, checkGitHubScriptStep(file, step)...)
		case strings.HasPrefix(uses, "docker://"):
			issues = append(issues, checkDockerStep(file, step)...)
		case strings.HasPrefix(uses, "./") && loader != nil:
			issues = append(issues, loader.loadUses(file, uses, usesVal.Line)...)
		}
	}
	return issues
}

func isGitHubScript(uses string) bool {
	repo := uses
	if i := strings.Index(uses, "@"); i >= 0 {
		repo = uses[:i]
	}
	return strings.EqualFold(repo, "actions/github-script")
}

func checkGitHubScriptStep(file string, step *yaml.Node) []string {
	with, issues := requireWith(file, step)
	if with == nil {
		return issues
	}
	return append(issues, checkScalarSink(file, with, "script", "github-script script", "${{ }} in github-script script")...)
}

func checkDockerStep(file string, step *yaml.Node) []string {
	with, issues := requireWith(file, step)
	if with == nil {
		return issues
	}
	issues = append(issues, checkScalarSink(file, with, "args", "docker args", "${{ }} in docker args")...)
	issues = append(issues, checkScalarSink(file, with, "entrypoint", "docker entrypoint", "${{ }} in docker entrypoint")...)
	return issues
}

// requireWith returns the with mapping. A missing with block is success.
// A present non-mapping fails closed.
func requireWith(file string, step *yaml.Node) (*yaml.Node, []string) {
	_, with := mapEntry(step, "with")
	if with == nil {
		return nil, nil
	}
	if with.Kind != yaml.MappingNode {
		return nil, []string{at(file, with.Line, "with must be a mapping")}
	}
	return with, nil
}

func checkScalarSink(file string, with *yaml.Node, key, what, exprMsg string) []string {
	var issues []string
	if with == nil || with.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(with.Content); i += 2 {
		k := with.Content[i]
		if k.Kind != yaml.ScalarNode || !strings.EqualFold(k.Value, key) {
			continue
		}
		val := with.Content[i+1]
		if val.Kind != yaml.ScalarNode {
			issues = append(issues, at(file, val.Line, what+" must be a scalar"))
			continue
		}
		if strings.Contains(val.Value, "${{") {
			issues = append(issues, at(file, val.Line, exprMsg))
		}
	}
	return issues
}

// checkGoToolchain locks GOTOOLCHAIN in env maps only (workflow, job, step,
// container, and service). It does not cover GITHUB_ENV writes in run steps.
func checkGoToolchain(file string, root *yaml.Node) []string {
	var issues []string
	envKey, env := mapEntry(root, "env")
	line := root.Line
	if envKey != nil {
		line = envKey.Line
	}
	if env == nil || env.Kind != yaml.MappingNode {
		issues = append(issues, at(file, line, "GOTOOLCHAIN must be scalar local"))
	} else if vals := toolchainValues(env); len(vals) == 0 {
		issues = append(issues, at(file, env.Line, "GOTOOLCHAIN must be scalar local"))
	} else {
		for _, val := range vals {
			issues = append(issues, checkToolchainValue(file, val)...)
		}
	}
	_, jobs := mapEntry(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return issues
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		issues = append(issues, checkOptionalToolchain(file, job)...)
		issues = append(issues, checkContainerToolchain(file, job)...)
		issues = append(issues, checkServicesToolchain(file, job)...)
		_, steps := mapEntry(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			issues = append(issues, checkOptionalToolchain(file, step)...)
			issues = append(issues, checkContainerToolchain(file, step)...)
		}
	}
	return issues
}

func checkOptionalToolchain(file string, owner *yaml.Node) []string {
	_, env := mapEntry(owner, "env")
	if env == nil || env.Kind != yaml.MappingNode {
		return nil
	}
	var issues []string
	for _, val := range toolchainValues(env) {
		issues = append(issues, checkToolchainValue(file, val)...)
	}
	return issues
}

func checkContainerToolchain(file string, owner *yaml.Node) []string {
	_, container := mapEntry(owner, "container")
	if container == nil || container.Kind != yaml.MappingNode {
		return nil
	}
	return checkOptionalToolchain(file, container)
}

func checkServicesToolchain(file string, job *yaml.Node) []string {
	_, services := mapEntry(job, "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}
	var issues []string
	for i := 0; i+1 < len(services.Content); i += 2 {
		svc := services.Content[i+1]
		if svc.Kind != yaml.MappingNode {
			continue
		}
		issues = append(issues, checkOptionalToolchain(file, svc)...)
	}
	return issues
}

func toolchainValues(env *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	if env == nil || env.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(env.Content); i += 2 {
		k := env.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == "GOTOOLCHAIN" {
			out = append(out, env.Content[i+1])
		}
	}
	return out
}

func checkToolchainValue(file string, val *yaml.Node) []string {
	if val == nil || val.Kind != yaml.ScalarNode || val.Value != "local" {
		line := 1
		if val != nil && val.Line > 0 {
			line = val.Line
		}
		return []string{at(file, line, "GOTOOLCHAIN must be scalar local")}
	}
	return nil
}

// actionLoader resolves uses: ./ paths from the repository root.
// stack holds canonical action files currently being loaded (a repeat is a cycle).
// done holds canonical action files that already finished (a repeat is a diamond).
type actionLoader struct {
	root     string
	rootReal string
	stack    map[string]struct{}
	done     map[string]struct{}
}

func newActionLoader(root string) (*actionLoader, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	return &actionLoader{
		root:     root,
		rootReal: real,
		stack:    map[string]struct{}{},
		done:     map[string]struct{}{},
	}, nil
}

func (l *actionLoader) checkJobUses(file string, usesVal *yaml.Node) []string {
	uses := usesVal.Value
	if msg := localEscape(uses); msg != "" {
		return []string{at(file, usesVal.Line, msg)}
	}
	const prefix = "./.github/workflows/"
	if !strings.HasPrefix(uses, prefix) {
		return []string{at(file, usesVal.Line, "job uses path is not a top-level workflow file")}
	}
	name := strings.TrimPrefix(uses, prefix)
	if !singleWorkflowName(name) {
		return []string{at(file, usesVal.Line, "job uses path is not a top-level workflow file")}
	}
	full := filepath.Join(l.root, ".github", "workflows", name)
	info, err := os.Lstat(full)
	if err != nil || !info.Mode().IsRegular() {
		return []string{at(file, usesVal.Line, "job uses path is not a top-level workflow file")}
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return []string{at(file, usesVal.Line, "job uses path is not a top-level workflow file")}
	}
	wfReal, err := filepath.EvalSymlinks(filepath.Join(l.root, ".github", "workflows"))
	if err != nil {
		return []string{at(file, usesVal.Line, "job uses path is not a top-level workflow file")}
	}
	if err := withinRoot(wfReal, real); err != nil || filepath.Dir(real) != wfReal {
		return []string{at(file, usesVal.Line, "local path escapes the repository")}
	}
	return nil
}

func singleWorkflowName(name string) bool {
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, `\`) {
		return false
	}
	return strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")
}

func (l *actionLoader) loadUses(from, uses string, line int) []string {
	if msg := localEscape(uses); msg != "" {
		return []string{at(from, line, msg)}
	}
	cleaned := filepath.Clean(uses)
	if msg := localEscape(cleaned); msg != "" {
		return []string{at(from, line, msg)}
	}
	joined := filepath.Join(l.root, cleaned)
	if err := withinRoot(l.root, joined); err != nil {
		return []string{at(from, line, "local path escapes the repository")}
	}
	if _, err := os.Lstat(joined); err != nil {
		return []string{at(from, line, "action file is missing")}
	}
	realDir, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{at(from, line, "action file is missing")}
		}
		return []string{at(from, line, "local path escapes the repository")}
	}
	if err := withinRoot(l.rootReal, realDir); err != nil {
		return []string{at(from, line, "local path escapes the repository")}
	}
	st, err := os.Stat(realDir)
	if err != nil || !st.IsDir() {
		return []string{at(from, line, "action file is missing")}
	}
	return l.loadActionDir(from, line, realDir)
}

func (l *actionLoader) loadActionDir(from string, line int, realDir string) []string {
	yml := filepath.Join(realDir, "action.yml")
	yamlPath := filepath.Join(realDir, "action.yaml")
	_, ymlErr := os.Lstat(yml)
	_, yamlErr := os.Lstat(yamlPath)
	switch {
	case ymlErr == nil && yamlErr == nil:
		return []string{at(from, line, "both action.yml and action.yaml exist")}
	case ymlErr != nil && yamlErr != nil:
		return []string{at(from, line, "action file is missing")}
	}
	meta := yml
	if yamlErr == nil {
		meta = yamlPath
	}
	realMeta, err := filepath.EvalSymlinks(meta)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{at(from, line, "action file is missing")}
		}
		return []string{at(from, line, "local path escapes the repository")}
	}
	if err := withinRoot(l.rootReal, realMeta); err != nil {
		return []string{at(from, line, "local path escapes the repository")}
	}
	if _, on := l.stack[realMeta]; on {
		return []string{at(from, line, "local action cycle")}
	}
	if _, ok := l.done[realMeta]; ok {
		return nil
	}
	l.stack[realMeta] = struct{}{}
	defer delete(l.stack, realMeta)

	data, err := os.ReadFile(realMeta)
	if err != nil {
		return []string{at(from, line, "action file is missing")}
	}
	rel := l.displayPath(realMeta)
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		l.done[realMeta] = struct{}{}
		return []string{at(rel, 1, fmt.Sprintf("parse error: %v", err))}
	}
	var issues []string
	walk(rel, &doc, &issues)
	issues = append(issues, l.checkAction(rel, &doc)...)
	l.done[realMeta] = struct{}{}
	return issues
}

func (l *actionLoader) displayPath(real string) string {
	rel, err := filepath.Rel(l.rootReal, real)
	if err != nil {
		return filepath.ToSlash(real)
	}
	return filepath.ToSlash(rel)
}

func (l *actionLoader) checkAction(file string, doc *yaml.Node) []string {
	root := mappingRoot(doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return []string{at(file, 1, "runs.using is not composite, docker, or node")}
	}
	_, runs := mapEntry(root, "runs")
	if runs == nil || runs.Kind != yaml.MappingNode {
		line := root.Line
		if runs != nil {
			line = runs.Line
		}
		return []string{at(file, line, "runs.using is not composite, docker, or node")}
	}
	_, using := mapEntry(runs, "using")
	if using == nil || using.Kind != yaml.ScalarNode {
		line := runs.Line
		if using != nil {
			line = using.Line
		}
		return []string{at(file, line, "runs.using is not composite, docker, or node")}
	}
	switch {
	case using.Value == "composite":
		return l.checkComposite(file, runs)
	case using.Value == "docker":
		return checkDockerRuns(file, runs)
	case strings.HasPrefix(using.Value, "node"):
		return nil
	default:
		return []string{at(file, using.Line, "runs.using is not composite, docker, or node")}
	}
}

func (l *actionLoader) checkComposite(file string, runs *yaml.Node) []string {
	_, steps := mapEntry(runs, "steps")
	if steps == nil {
		return nil
	}
	if steps.Kind != yaml.SequenceNode {
		return []string{at(file, steps.Line, "composite steps must be a sequence")}
	}
	return checkStepList(l, file, steps)
}

func checkDockerRuns(file string, runs *yaml.Node) []string {
	var issues []string
	_, image := mapEntry(runs, "image")
	if image != nil && image.Kind == yaml.ScalarNode && strings.Contains(image.Value, "${{") {
		issues = append(issues, at(file, image.Line, "${{ }} in runs.image"))
	}
	_, args := mapEntry(runs, "args")
	if args != nil {
		if args.Kind != yaml.SequenceNode {
			issues = append(issues, at(file, args.Line, "runs.args must be a sequence of scalars"))
		} else {
			for _, el := range args.Content {
				if el.Kind != yaml.ScalarNode {
					issues = append(issues, at(file, el.Line, "runs.args must be a sequence of scalars"))
					continue
				}
				if strings.Contains(el.Value, "${{") {
					issues = append(issues, at(file, el.Line, "${{ }} in runs.args"))
				}
			}
		}
	}
	for _, key := range []string{"entrypoint", "pre-entrypoint", "post-entrypoint"} {
		_, val := mapEntry(runs, key)
		if val == nil {
			continue
		}
		if val.Kind != yaml.ScalarNode {
			issues = append(issues, at(file, val.Line, "runs."+key+" must be a scalar"))
			continue
		}
		if strings.Contains(val.Value, "${{") {
			issues = append(issues, at(file, val.Line, "${{ }} in runs."+key))
		}
	}
	return issues
}

// localEscape rejects uses values that must not be joined onto the repository
// root. Stripping one "./" from ".//etc/passwd" leaves absolute "/etc/passwd",
// and filepath.Join would then drop the root and open the host file. Any ".."
// segment is rejected before clean, including a job uses that cancels back
// inside the root. The function does not stat or read.
func localEscape(uses string) string {
	if filepath.IsAbs(uses) || strings.HasPrefix(uses, "/") || strings.HasPrefix(uses, `\`) {
		return "local path escapes the repository"
	}
	rest := uses
	if strings.HasPrefix(rest, "./") {
		rest = rest[len("./"):]
	}
	if strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, `\`) || filepath.IsAbs(rest) {
		return "local path escapes the repository"
	}
	if pathHasDotDot(uses) || pathHasDotDot(rest) {
		return "local path escapes the repository"
	}
	cleaned := filepath.Clean(uses)
	if filepath.IsAbs(cleaned) || pathHasDotDot(cleaned) {
		return "local path escapes the repository"
	}
	return ""
}

func pathHasDotDot(p string) bool {
	p = strings.ReplaceAll(p, `\`, "/")
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func withinRoot(root, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("local path escapes the repository")
	}
	return nil
}
