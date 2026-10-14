// Command check-workflows rejects expression injection and permission drift
// in GitHub Actions workflows.
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
		found, err := checkWorkflow(rel, data)
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

func checkWorkflow(name string, data []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var issues []string
	walk(name, &doc, &issues)
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
