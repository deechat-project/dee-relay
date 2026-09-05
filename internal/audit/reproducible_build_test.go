package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The second claim this package guards. TestNodeWritesNoDurableState makes
// "the relay keeps nothing" checkable; these tests make "and the binary you can
// check is the binary we published" checkable, which is what a reproducible
// build is for. Both are claims made to people who cannot inspect the host, and
// both rot silently: a build flag added in one place and not the other produces
// two honest binaries with different digests, and the published fingerprint then
// fails to reproduce for a reason that has nothing to do with trustworthiness.
//
// What is asserted here is only what can be asserted without a container
// runtime: that the two build paths agree, that the base images are pinned by
// digest, and that the toolchain the release is built with is fixed. Whether the
// digest actually reproduces is deploy/verify-artifact.sh's job, and it needs
// Docker or podman.
//
// Documented in deploy/FINGERPRINTS.md.

// buildFlagLine finds the single `go build` invocation in a build file. Exactly
// one, on purpose: a second one is a second build path, and a second build path
// is the thing these tests exist to notice.
func buildFlagLine(t *testing.T, root, relative string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	var found []string
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || !strings.Contains(trimmed, "go build") {
			continue
		}
		found = append(found, trimmed[strings.Index(trimmed, "go build"):])
	}
	if len(found) != 1 {
		t.Fatalf("%s: expected exactly one `go build` invocation, found %d", relative, len(found))
	}
	return found[0]
}

// buildFlags reduces an invocation to its flag set, dropping -o and its argument
// (the output path legitimately differs between callers) and the package path.
func buildFlags(t *testing.T, root, relative string) []string {
	t.Helper()
	var flags []string
	fields := strings.Fields(buildFlagLine(t, root, relative))
	for i := 0; i < len(fields); i++ {
		field := fields[i]
		if field == "-o" {
			i++ // skip the destination
			continue
		}
		if strings.HasPrefix(field, "-") {
			flags = append(flags, field)
		}
	}
	sort.Strings(flags)
	return flags
}

// buildFileEnv is the environment each build path sets on the compiler. GOARCH
// varies by target and is normalised out.
var envAssignment = regexp.MustCompile(`\b(CGO_ENABLED|GOOS|GOTOOLCHAIN)=([A-Za-z0-9_.${}]+)`)

func buildEnv(t *testing.T, root, relative string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, match := range envAssignment.FindAllStringSubmatch(trimmed, -1) {
			env[match[1]] = match[2]
		}
	}
	return env
}

// The three files that compile a release binary: the container build (the one the
// published digest comes from) and the two scripts an operator or a third party
// reaches for.
var buildPaths = []string{
	filepath.Join("deploy", "Dockerfile"),
	filepath.Join("deploy", "build.sh"),
	filepath.Join("deploy", "verify-artifact.sh"),
}

func TestEveryBuildPathUsesTheSameFlags(t *testing.T) {
	root := moduleRoot(t)

	reference := buildFlags(t, root, buildPaths[0])
	for _, path := range buildPaths[1:] {
		flags := buildFlags(t, root, path)
		if strings.Join(flags, " ") != strings.Join(reference, " ") {
			t.Errorf("%s builds with %v, %s builds with %v: two flag sets means two digests from the same source",
				buildPaths[0], reference, path, flags)
		}
	}

	// The flags the digest depends on, named individually so a removal reports
	// what was lost rather than just "they differ".
	required := map[string]string{
		"-trimpath":       "embeds the builder's absolute paths",
		"-buildvcs=false": "stamps vcs.revision/vcs.modified, so a clone, an export and a dirty tree all differ",
		`-ldflags="-s`:    "leaves the build id and symbol table in place",
		"-w":              "leaves DWARF in place",
		`-buildid="`:      "leaves the nondeterministic build id in place",
	}
	line := buildFlagLine(t, root, buildPaths[0])
	for flag, consequence := range required {
		if !strings.Contains(line, strings.Trim(flag, `"`)) {
			t.Errorf("%s: %s is missing — without it the build %s", buildPaths[0], flag, consequence)
		}
	}
}

func TestEveryBuildPathPinsTheToolchain(t *testing.T) {
	root := moduleRoot(t)
	for _, path := range buildPaths {
		env := buildEnv(t, root, path)
		if env["GOTOOLCHAIN"] != "local" {
			// auto (the default) downloads a different toolchain when go.mod asks
			// for one, which changes the compiler behind an unchanged digest pin
			// and fetches over the network during a build documented as fetching
			// nothing.
			t.Errorf("%s does not set GOTOOLCHAIN=local (got %q)", path, env["GOTOOLCHAIN"])
		}
		if env["CGO_ENABLED"] != "0" {
			t.Errorf("%s does not set CGO_ENABLED=0 (got %q): a dynamic binary carries the builder's libc",
				path, env["CGO_ENABLED"])
		}
	}
}

var pinnedFrom = regexp.MustCompile(`(?m)^FROM\s+(\S+)`)

func TestBaseImagesArePinnedByDigest(t *testing.T) {
	root := moduleRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	matches := pinnedFrom.FindAllStringSubmatch(string(body), -1)
	if len(matches) != 2 {
		t.Fatalf("expected two FROM lines (build, runtime), found %d", len(matches))
	}
	digest := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	for _, match := range matches {
		reference := match[1]
		if !digest.MatchString(reference) {
			t.Errorf("FROM %s is not pinned by digest: a tag is mutable, so the published SHA-256 would drift out from under it",
				reference)
		}
		if strings.Contains(reference, "${") {
			t.Errorf("FROM %s interpolates a build argument: a version an ARG can override is a version that can contradict the digest",
				reference)
		}
	}
}

// pinnedGoVersion is the builder version, read from the same place every script
// reads it.
func pinnedGoVersion(t *testing.T, root string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, "deploy", "Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	match := regexp.MustCompile(`(?m)^FROM golang:([0-9.]+)-alpine@sha256:`).FindStringSubmatch(string(body))
	if match == nil {
		t.Fatal("could not read the pinned Go version out of the builder FROM line")
	}
	return match[1]
}

func TestGoModFloorFitsThePinnedToolchain(t *testing.T) {
	root := moduleRoot(t)
	pinned := pinnedGoVersion(t, root)

	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	match := regexp.MustCompile(`(?m)^go ([0-9.]+)`).FindStringSubmatch(string(body))
	if match == nil {
		t.Fatal("go.mod has no go directive")
	}
	floor := match[1]

	// With GOTOOLCHAIN=local, a floor above the builder is not a warning, it is a
	// release build that fails — and it fails on the host doing the release,
	// long after the go.mod edit that caused it. Catch it in `go test ./...`.
	if compareVersions(t, floor, pinned) > 0 {
		t.Errorf("go.mod requires go >= %s but the release builder is pinned to go%s: with GOTOOLCHAIN=local the container build cannot compile this module",
			floor, pinned)
	}
}

func compareVersions(t *testing.T, a, b string) int {
	t.Helper()
	parse := func(version string) []int {
		var parts []int
		for _, field := range strings.Split(version, ".") {
			value, err := strconv.Atoi(field)
			if err != nil {
				t.Fatalf("unparsable version %q", version)
			}
			parts = append(parts, value)
		}
		return parts
	}
	left, right := parse(a), parse(b)
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l != r {
			if l < r {
				return -1
			}
			return 1
		}
	}
	return 0
}

func TestPublishedRecordStaysMachineReadable(t *testing.T) {
	root := moduleRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "deploy", "FINGERPRINTS.md"))
	if err != nil {
		t.Fatalf("read FINGERPRINTS.md: %v", err)
	}
	record := string(body)

	// deploy/verify-artifact.sh greps these lines. A digest published in some
	// other shape leaves the verifier reporting "none recorded" — a soft failure
	// that reads like "no release yet" forever.
	for _, arch := range []string{"amd64", "arm64"} {
		line := regexp.MustCompile(fmt.Sprintf(`(?m)^binary-sha256 linux/%s ([0-9a-f]{64}|pending)$`, arch))
		if !line.MatchString(record) {
			t.Errorf("FINGERPRINTS.md has no readable `binary-sha256 linux/%s <64 hex|pending>` line", arch)
		}
	}

	// A candidate digest is optional, but a malformed one is worse than none: the
	// verifier reads it with its own pattern, so a candidate written in a shape
	// that pattern misses reports "nothing recorded" while the record visibly
	// carries a number. Anything claiming to be a candidate line must parse.
	for _, line := range strings.Split(record, "\n") {
		if !strings.HasPrefix(line, "binary-sha256-candidate") {
			continue
		}
		if !regexp.MustCompile(`^binary-sha256-candidate linux/(amd64|arm64) [0-9a-f]{64}$`).MatchString(line) {
			t.Errorf("FINGERPRINTS.md candidate line is not readable by deploy/verify-artifact.sh: %q", line)
		}
	}

	// A candidate must never occupy a published line's slot. The two are read by
	// different code paths precisely so that "not published" cannot decay into
	// "published" through an edit, and this is the assertion that keeps it true.
	for _, arch := range []string{"amd64", "arm64"} {
		published := regexp.MustCompile(fmt.Sprintf(`(?m)^binary-sha256 linux/%s ([0-9a-f]{64})$`, arch))
		candidate := regexp.MustCompile(fmt.Sprintf(`(?m)^binary-sha256-candidate linux/%s [0-9a-f]{64}$`, arch))
		if !candidate.MatchString(record) {
			continue
		}
		if match := published.FindStringSubmatch(record); match != nil {
			t.Errorf("linux/%s records both a published digest and a candidate; "+
				"promoting a candidate means replacing the published line and deleting the "+
				"candidate, not keeping both", arch)
		}
	}

	// The published record has to name the toolchain a third party needs, and it
	// is the one thing they cannot derive from a digest.
	pinned := pinnedGoVersion(t, root)
	if !strings.Contains(record, "go"+pinned) {
		t.Errorf("FINGERPRINTS.md does not mention go%s, the pinned builder version a rebuild has to match", pinned)
	}
}
