package main

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// passportVersion is normally set at build time via
// -ldflags "-X main.passportVersion=<tag>" (see .github/workflows/release.yml).
// It is a var, not a const, so the linker can overwrite it.
var passportVersion = "development"

// reportedVersion returns the version to print in a report. A release binary
// already has passportVersion set by the linker. A binary built without that
// flag - notably one installed with "go install .../pet-passport@vX.Y.Z" -
// still carries its module version in the Go build info, so fall back to that
// before giving up and reporting "development".
func reportedVersion() string {
	if passportVersion != "development" {
		return passportVersion
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return passportVersion
}

//go:embed mappings/evidence.json
var evidenceJSON []byte

type evidenceTable struct {
	SchemaVersion  int        `json:"schema_version"`
	MappingVersion string     `json:"mapping_version"`
	Mapping        []evidence `json:"mapping"`
}
type evidence struct {
	DLL        string   `json:"dll"`
	DLLAliases []string `json:"dll_aliases"`
	Symbol     string   `json:"symbol"`
	Area       string   `json:"area"`
	Wording    string   `json:"wording"`
}
type identity struct{ ProductName, Version, Company string }
type importSymbol struct{ DLL, Symbol string }
type sectionObservation struct {
	Name    string
	Entropy float64
}
type inspection struct {
	File            *pe.File
	Raw             []byte
	SHA256          string
	Identity        identity
	Manifest        manifestObservation
	Imports         []importSymbol
	ImportReadErr   error
	TLSCallbacks    int
	TLSReadErr      error
	HighEntropy     []sectionObservation
	UnusualSections []string
	ImagePath       string
	Mapping         evidenceTable
}

const usageText = `Usage: pet-passport [path-to-windows-pe-binary]
  With a path argument: examine that one Windows PE binary.
  With no arguments: examine every Windows PE file in the current directory.`

// main only ever calls os.Exit once, from the outermost frame, after run has
// already returned. run itself never calls os.Exit: it defers maybePause,
// and a deferred call does not run if the function that deferred it is
// short-circuited by os.Exit instead of returning normally. Every exit path
// below therefore has to return an int instead.
func main() {
	os.Exit(run())
}

func run() int {
	defer maybePause()
	selfHash := runningExecutableSHA256()
	switch len(os.Args) {
	case 1:
		return runDirectoryScan(os.Stdout, ".", selfHash)
	case 2:
		return runSingleFile(os.Stdout, os.Args[1], selfHash)
	default:
		fmt.Fprintln(os.Stderr, usageText)
		return 2
	}
}

// runningExecutableSHA256 returns the SHA-256 of the file backing the
// currently running process, hex-encoded, or "" if it could not be
// determined (for instance, the executable has since been removed from
// disk, or the platform does not support locating it). Failing to determine
// it only means a report omits the "this is the copy that produced this
// report" sentence; it is not an error for the report as a whole.
func runningExecutableSHA256() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func runSingleFile(out io.Writer, path string, selfHash string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pet Passport could not read %q: %v\n", path, err)
		return 1
	}
	result, err := inspectPE(raw, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%q is not a PE file; Pet Passport examines Windows PE files only.\n", path)
		return 1
	}
	writeReport(out, result, selfHash)
	return 0
}

// peCandidate is a regular file from a directory scan whose first two bytes
// are the "MZ" DOS header, along with the bytes already read to check that,
// so runDirectoryScan does not have to read the file a second time.
type peCandidate struct {
	Name string
	Raw  []byte
}

// skippedFile is a regular file from a directory scan that was not examined,
// and why.
type skippedFile struct {
	Name   string
	Reason string
}

func hasMZHeader(raw []byte) bool {
	return len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z'
}

// scanDirectory lists the regular files directly in dir, in the order
// os.ReadDir returns them (by name; not recursive; nothing hidden-file
// special about it), and separates them by whether their first two bytes
// are "MZ". It does not attempt a full PE parse - a candidate whose MZ
// header turns out not to be a real PE image is handled by the caller,
// once it tries to build that file's report.
func scanDirectory(dir string) (candidates []peCandidate, skipped []skippedFile, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if candidate, skip := classifyRegularFile(dir, entry.Name()); skip != nil {
			skipped = append(skipped, *skip)
		} else {
			candidates = append(candidates, *candidate)
		}
	}
	return candidates, skipped, nil
}

// classifyRegularFile reads name from dir and reports whether its first two
// bytes are the "MZ" DOS header. Exactly one return value is non-nil: a
// *peCandidate for a file worth a full report, or a *skippedFile explaining
// why it is not (the read itself failed, or the header does not match).
func classifyRegularFile(dir, name string) (*peCandidate, *skippedFile) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, &skippedFile{Name: name, Reason: fmt.Sprintf("could not be opened: %v", err)}
	}
	if !hasMZHeader(raw) {
		return nil, &skippedFile{Name: name, Reason: "not a Windows PE image"}
	}
	return &peCandidate{Name: name, Raw: raw}, nil
}

// reportDelimiter separates one file's report from the next (or from the
// closing paragraph) when scanning a directory, so a reader can always tell
// where one report ends and another begins.
const reportDelimiter = "----------------------------------------------------------------------"

func writeDelimiter(out io.Writer) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, reportDelimiter)
	fmt.Fprintln(out)
}

func runDirectoryScan(out io.Writer, dir string, selfHash string) int {
	candidates, skipped, err := scanDirectory(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pet Passport could not list %q: %v\n", dir, err)
		return 1
	}
	var results []*inspection
	for _, c := range candidates {
		result, err := inspectPE(c.Raw, c.Name)
		if err != nil {
			skipped = append(skipped, skippedFile{Name: c.Name, Reason: fmt.Sprintf("has an MZ header but could not be read as a Windows PE image: %v", err)})
			continue
		}
		results = append(results, result)
	}
	pets, nonPets := partitionPets(results)
	skipped = append(skipped, nonPets...)
	pets = orderForReport(pets, selfHash)
	if len(pets) > 0 {
		writeTableOfContents(out, pets)
		fmt.Fprintln(out)
	}
	for _, result := range pets {
		writeReport(out, result, selfHash)
		writeDelimiter(out)
	}
	writeClosingParagraph(out, len(pets), skipped)
	return 0
}

// partitionPets splits examined PE files into the ones that declare
// themselves with a pet_passport_v1 export and the ones that do not. Only the
// first group gets a report in directory mode: a directory holding a pet
// usually also holds the runtime, the installer, and this passport's own
// copy, and a full report on each of those buries the file the reader
// actually came for.
//
// A file carrying an export whose payload did not parse is still a pet by
// this test. It declared itself; the report then says the declaration could
// not be read, which is a finding rather than a reason for silence. The
// second group is not discarded either - every name reappears in the closing
// paragraph, because a file examined and left out of the account is exactly
// the quiet this design refuses.
func partitionPets(results []*inspection) (pets []*inspection, others []skippedFile) {
	for _, r := range results {
		switch {
		case r.Manifest.Found:
			pets = append(pets, r)
		case r.Manifest.ExportErr != nil:
			others = append(others, skippedFile{
				Name:   filepath.Base(filepath.Clean(r.ImagePath)),
				Reason: fmt.Sprintf("examined; its export directory could not be read completely (%v), so no %s export could be confirmed either way", r.Manifest.ExportErr, manifestSymbolName),
			})
		default:
			others = append(others, skippedFile{
				Name:   filepath.Base(filepath.Clean(r.ImagePath)),
				Reason: fmt.Sprintf("examined; not a pet (no %s export)", manifestSymbolName),
			})
		}
	}
	return pets, others
}

// orderForReport reorders reported files so that a file whose SHA-256
// matches the running passport's own goes last, keeping the relative order
// of every other file (the name order scanDirectory already produced). It
// is the least interesting report to the person who ran the tool, since it
// is a report about the tool itself rather than about a pet; this only
// changes where it appears, not what its report says. If selfHash is
// unknown, or no file matches, the order is unchanged.
//
// Since directory mode reports only files carrying the manifest export, and
// this passport carries none, its own copy in a scanned directory is now
// named in the closing paragraph rather than reported. This ordering is what
// would happen if that ever changed, and it stays for that reason.
func orderForReport(results []*inspection, selfHash string) []*inspection {
	if selfHash == "" {
		return results
	}
	ordered := make([]*inspection, 0, len(results))
	var self []*inspection
	for _, r := range results {
		if r.SHA256 == selfHash {
			self = append(self, r)
		} else {
			ordered = append(ordered, r)
		}
	}
	return append(ordered, self...)
}

// writeTableOfContents prints one short paragraph naming the files that get
// a report, in the order those reports follow, each with what it declares
// about itself. It is a table of contents, not a summary of findings - every
// file listed here still gets its own full report below.
func writeTableOfContents(out io.Writer, results []*inspection) {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		parts = append(parts, fmt.Sprintf("%q (%s)", filepath.Clean(r.ImagePath), tocParenthetical(r)))
	}
	fmt.Fprintf(out, "This directory has %d file(s) carrying a %s export; their reports follow in this order: %s.\n", len(results), manifestSymbolName, joinProse(parts))
}

// tocParenthetical renders what a pet declares about itself for the table of
// contents. It reads from the manifest, not from VERSIONINFO: the manifest
// is the declaration that put the file in this list.
func tocParenthetical(r *inspection) string {
	m := r.Manifest.Manifest
	if m == nil {
		return fmt.Sprintf("carries a %s export whose contents could not be read as a v1 manifest", manifestSymbolName)
	}
	return fmt.Sprintf("declares itself %q, version %s", declaredOr(m.Has("name"), m.Name), declaredOr(m.Has("version"), m.Version))
}

// writeClosingParagraph reports, in prose, everything in the scanned
// directory that has no report above and why - the files examined and found
// not to declare themselves as pets included. No file is silently left out
// of the account, per the same "report what could not be examined" rule a
// single report follows for its own blind spots.
//
// Reasons are grouped rather than repeated per file because a directory of
// twenty non-pets otherwise prints the same clause twenty times, which reads
// as noise and hides the one file whose reason is different.
func writeClosingParagraph(out io.Writer, reported int, skipped []skippedFile) {
	switch {
	case reported == 0 && len(skipped) == 0:
		fmt.Fprintln(out, "The current directory has no regular files to account for.")
		return
	case reported == 0:
		fmt.Fprintf(out, "No file in the current directory carries a %s export, so there is no report above. That is not a statement about what these files do; it only means none of them declares itself to be a pet.\n", manifestSymbolName)
	case len(skipped) == 0:
		fmt.Fprintln(out, "Every regular file in the current directory declared itself and is reported above.")
		return
	default:
		fmt.Fprintln(out, "The following file(s) were present in the current directory and have no report above.")
	}
	byReason := make(map[string][]string)
	for _, s := range skipped {
		byReason[s.Reason] = append(byReason[s.Reason], s.Name)
	}
	reasons := make([]string, 0, len(byReason))
	for reason := range byReason {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		names := byReason[reason]
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
		quoted := make([]string, 0, len(names))
		for _, name := range names {
			quoted = append(quoted, fmt.Sprintf("%q", name))
		}
		fmt.Fprintf(out, "%s: %s.\n", capitalizeFirst(reason), joinProse(quoted))
	}
}

// capitalizeFirst uppercases the first rune of a sentence fragment so it can
// start one.
func capitalizeFirst(value string) string {
	for i, r := range value {
		return string(unicode.ToUpper(r)) + value[i+utf8.RuneLen(r):]
	}
	return value
}

func inspectPE(raw []byte, path string) (*inspection, error) {
	f, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	table, err := loadEvidence()
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	r := &inspection{File: f, Raw: raw, SHA256: hex.EncodeToString(hash[:]), ImagePath: path, Mapping: table}
	r.Imports, r.ImportReadErr = readImports(f)
	r.Identity = readVersionInfo(raw, f)
	r.Manifest = observeManifest(raw, f)
	r.TLSCallbacks, r.TLSReadErr = readTLSCallbacks(raw, f)
	r.HighEntropy, r.UnusualSections = observeSections(raw, f)
	return r, nil
}
func loadEvidence() (evidenceTable, error) {
	var table evidenceTable
	if err := json.Unmarshal(evidenceJSON, &table); err != nil {
		return evidenceTable{}, fmt.Errorf("read bundled evidence mapping: %w", err)
	}
	if table.SchemaVersion != 1 || table.MappingVersion == "" {
		return evidenceTable{}, errors.New("unsupported bundled evidence mapping schema")
	}
	return table, nil
}
func readImports(f *pe.File) ([]importSymbol, error) {
	values, err := f.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	imports := make([]importSymbol, 0, len(values))
	for _, value := range values {
		// debug/pe reports each entry as "Symbol:DLL". Split on the last colon:
		// a DLL name cannot contain one, but a decorated symbol name may.
		at := strings.LastIndex(value, ":")
		if at <= 0 || at == len(value)-1 {
			continue
		}
		imports = append(imports, importSymbol{DLL: value[at+1:], Symbol: value[:at]})
	}
	sort.Slice(imports, func(i, j int) bool {
		if strings.EqualFold(imports[i].DLL, imports[j].DLL) {
			return strings.ToLower(imports[i].Symbol) < strings.ToLower(imports[j].Symbol)
		}
		return strings.ToLower(imports[i].DLL) < strings.ToLower(imports[j].DLL)
	})
	return imports, nil
}

func writeReport(out io.Writer, r *inspection, selfHash string) {
	writeIdentityBlock(out, r, selfHash)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Described mechanisms")
	writeDescribedMechanisms(out, r)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Blind spots in this static reading")
	writeBlindSpots(out, r)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "What this tool cannot see")
	fmt.Fprintln(out, "This is a static reading of one file. It cannot see code produced after launch, decrypted or downloaded content, direct system calls, user-triggered paths, or what the program actually does on a particular machine. Dynamic and behavioral analysis tools, such as a sandbox, system-call monitor, network capture, or debugger, can observe kinds of runtime behavior that this report cannot.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Appendix: every imported symbol, by DLL")
	writeAppendix(out, r)
}

// writeIdentityBlock opens a report with which passport produced it and what
// the file says it is: a short labelled list, then the sentences that say
// what those labels are worth. The list is the one place in this report that
// is not prose, and that is a deliberate exception rather than a direction of
// travel - it is a handful of fields a reader wants to find at a glance, and
// none of them is an observation about behavior.
//
// Nothing in the list is verified, and the caveat under it says so in the
// same breath. Whether a name and publisher are true is a question about a
// checksum and a signature, which this tool does not answer.
func writeIdentityBlock(out io.Writer, r *inspection, selfHash string) {
	fmt.Fprintf(out, "Pet Passport %s\n\n", reportedVersion())
	m := r.Manifest.Manifest
	if m != nil {
		writeManifestIdentityList(out, r, m)
	} else {
		writeVersionInfoIdentityList(out, r)
	}
	fmt.Fprintln(out)
	if m != nil {
		fmt.Fprintln(out, "Name, version, publisher and build are what the file declares about itself; nothing here verifies them.")
		writeManifestDisagreements(out, r.Identity, m)
		if m.Has("homepage") && m.Homepage != "" {
			fmt.Fprintf(out, "The manifest also declares a homepage of %q, which was not visited.\n", oneLine(m.Homepage))
		}
		if len(m.Extra) > 0 {
			fmt.Fprintf(out, "The manifest declares %s, which schema v1 does not define; they were not read.\n", joinProse(quoteAll(m.Extra)))
		}
		if len(m.Missing) > 0 {
			fmt.Fprintf(out, "The manifest does not declare %s, which schema v1 does define.\n", joinProse(quoteAll(m.Missing)))
		}
	} else {
		switch {
		case r.Manifest.Found:
			fmt.Fprintf(out, "A %s export exists but its contents could not be read as a v1 manifest: %v. This file declares itself a pet; what it declares about itself could not be recovered.\n", manifestSymbolName, r.Manifest.ReadErr)
		case r.Manifest.ExportErr != nil:
			fmt.Fprintf(out, "No %s export was read, because this file's export directory could not be read completely: %v. Whether it carries one is unknown rather than settled.\n", manifestSymbolName, r.Manifest.ExportErr)
		default:
			fmt.Fprintf(out, "No %s export was found in this file, so nothing in it declares it to be a pet.\n", manifestSymbolName)
		}
		fmt.Fprintln(out, "Product, version and publisher above are what the file's VERSIONINFO resource declares about itself; nothing here verifies them.")
	}
	if selfHash != "" && r.SHA256 == selfHash {
		fmt.Fprintln(out, "This file is the copy of Pet Passport that produced this report.")
	}
}

// writeManifestIdentityList prints the labelled list for a file that carries
// a readable manifest. The slug follows the name in parentheses when the two
// differ, because the slug is the identifier other things key on and a
// display name can be anything at all.
func writeManifestIdentityList(out io.Writer, r *inspection, m *petManifest) {
	pet := declaredOr(m.Has("name"), m.Name)
	if m.Slug != "" && m.Slug != m.Name {
		pet += " (" + oneLine(m.Slug) + ")"
	}
	fmt.Fprintf(out, "* Pet: %s\n", pet)
	fmt.Fprintf(out, "* Version: %s\n", declaredOr(m.Has("version"), m.Version))
	fmt.Fprintf(out, "* Publisher: %s\n", declaredOr(m.Has("publisher"), m.Publisher))
	fmt.Fprintf(out, "* Build ID: %s\n", declaredOr(m.Has("build"), m.Build))
	fmt.Fprintf(out, "* File: %s\n", fileLine(r))
}

// writeVersionInfoIdentityList prints the labelled list for a file with no
// readable manifest, filled from the VERSIONINFO resource instead. The first
// label becomes "Product" because that is the field's actual name there and
// nothing here has declared itself a pet, and there is no Build ID line at
// all: VERSIONINFO has no such field, so a "(not declared)" against it would
// invent an omission rather than report one.
func writeVersionInfoIdentityList(out io.Writer, r *inspection) {
	fmt.Fprintf(out, "* Product: %s\n", orNotDeclared(r.Identity.ProductName))
	fmt.Fprintf(out, "* Version: %s\n", orNotDeclared(r.Identity.Version))
	fmt.Fprintf(out, "* Publisher: %s\n", orNotDeclared(r.Identity.Company))
	fmt.Fprintf(out, "* File: %s\n", fileLine(r))
}

// writeManifestDisagreements names each field where a file's two accounts of
// itself do not match. Both are self-reported, so neither wins; the
// disagreement is itself the observation, and one sentence per field keeps
// which field disagreed specific.
func writeManifestDisagreements(out io.Writer, id identity, m *petManifest) {
	pairs := []struct{ field, versionInfo, manifest string }{
		{"the product name", id.ProductName, m.Name},
		{"the product version", id.Version, m.Version},
		{"the company", id.Company, m.Publisher},
	}
	for _, pair := range pairs {
		if pair.versionInfo == "" || pair.manifest == "" || pair.versionInfo == pair.manifest {
			continue
		}
		fmt.Fprintf(out, "The VERSIONINFO resource says %s is %q while the manifest says %q.\n", pair.field, oneLine(pair.versionInfo), oneLine(pair.manifest))
	}
}

// fileLine renders the "File" entry: the base name, the size with thousands
// separators because a nine-digit byte count is unreadable without them, and
// the whole SHA-256 rather than a prefix, since a truncated digest is not
// something anyone can check a download against.
func fileLine(r *inspection) string {
	return fmt.Sprintf("%s (%s bytes, sha256:%s)", filepath.Base(filepath.Clean(r.ImagePath)), withThousands(len(r.Raw)), r.SHA256)
}

// declaredOr renders a manifest value, distinguishing a key that was absent
// from one declared as an empty string. They are different claims and a
// report that flattens them into one has lost a fact.
func declaredOr(present bool, value string) string {
	switch {
	case !present:
		return "(not declared)"
	case value == "":
		return "(declared empty)"
	default:
		return oneLine(value)
	}
}

// orNotDeclared renders a VERSIONINFO value, which has no such distinction:
// an absent field and an empty one are indistinguishable there.
func orNotDeclared(value string) string {
	if value == "" {
		return "(not declared)"
	}
	return oneLine(value)
}

func quoteAll(values []string) []string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf("%q", value))
	}
	return quoted
}

// maxDeclaredRunes caps how much of one declared value a report prints.
const maxDeclaredRunes = 200

// oneLine renders a string a file declared about itself so that the file
// cannot forge the shape of the report describing it. Everything in a
// manifest or a VERSIONINFO resource is attacker-controlled: a newline in a
// declared name would otherwise let a file print its own "* Publisher:"
// line, or a whole convincing extra section. Control characters are escaped
// and an over-long value is truncated, both visibly.
func oneLine(value string) string {
	runes := []rune(value)
	truncated := false
	if len(runes) > maxDeclaredRunes {
		runes, truncated = runes[:maxDeclaredRunes], true
	}
	var b strings.Builder
	for _, r := range runes {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	if truncated {
		b.WriteString(" [truncated by Pet Passport]")
	}
	return b.String()
}

// withThousands groups a byte count in threes.
func withThousands(value int) string {
	digits := strconv.Itoa(value)
	negative := strings.HasPrefix(digits, "-")
	if negative {
		digits = digits[1:]
	}
	var b strings.Builder
	if negative {
		b.WriteByte('-')
	}
	for i := 0; i < len(digits); i++ {
		if i > 0 && (len(digits)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteByte(digits[i])
	}
	return b.String()
}

// writeDescribedMechanisms prints one sentence for each observed import
// that has an entry in the published mapping table, in the existing
// wording. It says nothing about imports without a mapping entry - those
// are the appendix's job - so a report that mostly imports unmapped symbols
// no longer buries the few that are described among them.
func writeDescribedMechanisms(out io.Writer, r *inspection) {
	if r.ImportReadErr != nil {
		fmt.Fprintf(out, "The import table could not be read completely: %v. This does not make the static picture complete.\n", r.ImportReadErr)
		return
	}
	if len(r.Imports) == 0 {
		fmt.Fprintln(out, "The import table yielded no symbols for this static reading. Silence in an import table is not evidence about runtime behavior.")
		return
	}
	described := 0
	for _, imp := range r.Imports {
		if item, ok := evidenceFor(r.Mapping, imp); ok {
			fmt.Fprintf(out, "%s imports %s. %s\n", imp.DLL, imp.Symbol, item.Wording)
			described++
		}
	}
	if described == 0 {
		fmt.Fprintln(out, "None of the observed imports match an entry in the published mapping table. This is not evidence that the file does or does not use any particular mechanism; the appendix below lists everything that was observed.")
	}
}

// writeAppendix prints the full import inventory, one paragraph per DLL in
// name order, symbol names comma-separated, mapped symbols included so the
// appendix is a complete record on its own rather than requiring the
// described-mechanisms section above to be read alongside it.
func writeAppendix(out io.Writer, r *inspection) {
	if r.ImportReadErr != nil {
		fmt.Fprintf(out, "The import table could not be read completely: %v. This does not make the static picture complete.\n", r.ImportReadErr)
		return
	}
	if len(r.Imports) == 0 {
		fmt.Fprintln(out, "The import table yielded no symbols for this static reading. Silence in an import table is not evidence about runtime behavior.")
		return
	}
	fmt.Fprintln(out, "These are all of the imported symbols this static reading observed, grouped by the DLL that exports them. This tool has not assigned most of them a more specific description above; a name appearing here only means it was imported, not that it was examined.")
	byDLL := make(map[string][]importSymbol)
	for _, imp := range r.Imports {
		byDLL[imp.DLL] = append(byDLL[imp.DLL], imp)
	}
	dlls := make([]string, 0, len(byDLL))
	for dll := range byDLL {
		dlls = append(dlls, dll)
	}
	sort.Slice(dlls, func(i, j int) bool { return strings.ToLower(dlls[i]) < strings.ToLower(dlls[j]) })
	for _, dll := range dlls {
		names := make([]string, 0, len(byDLL[dll]))
		for _, imp := range byDLL[dll] {
			names = append(names, imp.Symbol)
		}
		fmt.Fprintf(out, "%s: %s.\n", dll, strings.Join(names, ", "))
	}
}
func evidenceFor(table evidenceTable, imp importSymbol) (evidence, bool) {
	for _, item := range table.Mapping {
		if !strings.EqualFold(item.Symbol, imp.Symbol) {
			continue
		}
		if strings.EqualFold(item.DLL, imp.DLL) {
			return item, true
		}
		for _, alias := range item.DLLAliases {
			if strings.EqualFold(alias, imp.DLL) {
				return item, true
			}
		}
	}
	return evidence{}, false
}
func joinProse(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	if len(values) == 2 {
		return values[0] + " and " + values[1]
	}
	return strings.Join(values[:len(values)-1], ", ") + ", and " + values[len(values)-1]
}
func writeBlindSpots(out io.Writer, r *inspection) {
	hasLoadLibrary, hasGetProcAddress := false, false
	for _, imp := range r.Imports {
		if strings.EqualFold(imp.Symbol, "LoadLibraryA") || strings.EqualFold(imp.Symbol, "LoadLibraryW") || strings.EqualFold(imp.Symbol, "LoadLibrary") {
			hasLoadLibrary = true
		}
		if strings.EqualFold(imp.Symbol, "GetProcAddress") {
			hasGetProcAddress = true
		}
	}
	if hasLoadLibrary && hasGetProcAddress {
		fmt.Fprintln(out, "Both LoadLibrary and GetProcAddress are imported. This is evidence that DLLs and symbols may be resolved while the program runs, so this static import picture is partial.")
	} else {
		fmt.Fprintln(out, "This import table does not show both LoadLibrary and GetProcAddress together. That does not rule out runtime symbol resolution by another route.")
	}
	if len(r.HighEntropy) == 0 {
		fmt.Fprintln(out, "No section with entropy at or above 7.2 bits per byte was found. This is not evidence that the file is unpacked.")
	} else {
		parts := make([]string, 0, len(r.HighEntropy))
		for _, section := range r.HighEntropy {
			parts = append(parts, fmt.Sprintf("%q (%.2f bits per byte)", section.Name, section.Entropy))
		}
		fmt.Fprintf(out, "Section(s) %s have entropy at or above 7.2 bits per byte, which can occur with compressed or packed data and makes static inspection less complete.\n", joinProse(parts))
	}
	if len(r.Imports) < 5 {
		fmt.Fprintf(out, "The observed import table names only %d symbol(s). An implausibly small import table can occur when imports are resolved or reconstructed at runtime, but it is not proof of that.\n", len(r.Imports))
	}
	if len(r.UnusualSections) == 0 {
		fmt.Fprintln(out, "No section names outside this tool's small conventional-name set were observed; names alone cannot establish how code is stored.")
	} else {
		fmt.Fprintf(out, "Section name(s) %s are outside this tool's small conventional-name set. Names are only a cue for further examination, not a conclusion.\n", joinProse(r.UnusualSections))
	}
	if r.TLSReadErr != nil {
		fmt.Fprintf(out, "The TLS directory could not be read completely: %v. This static reading cannot account for callbacks it could not read.\n", r.TLSReadErr)
	} else if r.TLSCallbacks > 0 {
		fmt.Fprintf(out, "The TLS directory contains %d callback(s), which can run before the program's ordinary entry point.\n", r.TLSCallbacks)
	} else {
		fmt.Fprintln(out, "No TLS callbacks were found in the TLS directory; this does not rule out code running before ordinary application behavior by other mechanisms.")
	}
}
func observeSections(raw []byte, f *pe.File) ([]sectionObservation, []string) {
	conventional := map[string]bool{".text": true, ".rdata": true, ".data": true, ".rsrc": true, ".reloc": true, ".pdata": true, ".idata": true, ".edata": true, ".tls": true, ".debug": true, ".bss": true, ".crt": true, ".00cfg": true, ".gfids": true, ".giats": true, ".didat": true}
	var high []sectionObservation
	var unusual []string
	for _, section := range f.Sections {
		name := strings.TrimSpace(section.Name)
		if !conventional[strings.ToLower(name)] {
			unusual = append(unusual, fmt.Sprintf("%q", name))
		}
		start, end := uint64(section.Offset), uint64(section.Offset)+uint64(section.Size)
		if end < start || end > uint64(len(raw)) || start == end {
			continue
		}
		entropy := shannonEntropy(raw[int(start):int(end)])
		if entropy >= 7.2 {
			high = append(high, sectionObservation{Name: name, Entropy: entropy})
		}
	}
	return high, unusual
}
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var value float64
	for _, count := range counts {
		if count != 0 {
			p := float64(count) / float64(len(data))
			value -= p * math.Log2(p)
		}
	}
	return value
}

func optionalInfo(f *pe.File) ([]pe.DataDirectory, uint64, int, uint32, bool) {
	switch h := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return h.DataDirectory[:], uint64(h.ImageBase), 4, h.SizeOfHeaders, true
	case *pe.OptionalHeader64:
		return h.DataDirectory[:], h.ImageBase, 8, h.SizeOfHeaders, true
	default:
		return nil, 0, 0, 0, false
	}
}
func rvaMapper(raw []byte, f *pe.File, headerSize uint32) func(uint32) (int, error) {
	return func(rva uint32) (int, error) {
		if rva < headerSize && uint64(rva) < uint64(len(raw)) {
			return int(rva), nil
		}
		for _, section := range f.Sections {
			span := section.VirtualSize
			if section.Size > span {
				span = section.Size
			}
			if rva < section.VirtualAddress || uint64(rva-section.VirtualAddress) >= uint64(span) {
				continue
			}
			off := uint64(section.Offset) + uint64(rva-section.VirtualAddress)
			if off >= uint64(len(raw)) {
				return 0, errors.New("RVA points beyond file data")
			}
			return int(off), nil
		}
		return 0, errors.New("RVA is not mapped by a section")
	}
}
func readVersionInfo(raw []byte, f *pe.File) identity {
	dirs, _, _, headers, ok := optionalInfo(f)
	if !ok || len(dirs) <= 2 || dirs[2].VirtualAddress == 0 || dirs[2].Size == 0 {
		return identity{}
	}
	resources, err := findVersionResources(raw, dirs[2].VirtualAddress, rvaMapper(raw, f, headers))
	if err != nil {
		return identity{}
	}
	for _, resource := range resources {
		id, err := parseVersionInfo(resource)
		if err == nil && (id.ProductName != "" || id.Version != "" || id.Company != "") {
			return id
		}
	}
	return identity{}
}

type resourceEntry struct {
	id               uint16
	named, directory bool
	offset           uint32
}

func findVersionResources(raw []byte, baseRVA uint32, mapRVA func(uint32) (int, error)) ([][]byte, error) {
	add := func(relative uint32) (uint32, error) {
		if relative > ^uint32(0)-baseRVA {
			return 0, errors.New("resource offset overflow")
		}
		return baseRVA + relative, nil
	}
	readDirectory := func(relative uint32) ([]resourceEntry, error) {
		rva, err := add(relative)
		if err != nil {
			return nil, err
		}
		off, err := mapRVA(rva)
		if err != nil {
			return nil, err
		}
		if off < 0 || off > len(raw)-16 {
			return nil, errors.New("truncated resource directory")
		}
		count := int(binary.LittleEndian.Uint16(raw[off+12:])) + int(binary.LittleEndian.Uint16(raw[off+14:]))
		if count > (len(raw)-off-16)/8 {
			return nil, errors.New("truncated resource directory entries")
		}
		entries := make([]resourceEntry, count)
		for i := range entries {
			at := off + 16 + i*8
			name, target := binary.LittleEndian.Uint32(raw[at:]), binary.LittleEndian.Uint32(raw[at+4:])
			entries[i] = resourceEntry{id: uint16(name), named: name&0x80000000 != 0, offset: target & 0x7fffffff, directory: target&0x80000000 != 0}
		}
		return entries, nil
	}
	root, err := readDirectory(0)
	if err != nil {
		return nil, err
	}
	var results [][]byte
	var descend func(uint32, int) error
	descend = func(relative uint32, depth int) error {
		if depth > 8 {
			return errors.New("resource directory nesting is too deep")
		}
		entries, err := readDirectory(relative)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.directory {
				if err := descend(entry.offset, depth+1); err != nil {
					return err
				}
				continue
			}
			rva, err := add(entry.offset)
			if err != nil {
				return err
			}
			off, err := mapRVA(rva)
			if err != nil {
				return err
			}
			if off < 0 || off > len(raw)-16 {
				return errors.New("truncated resource data entry")
			}
			dataRVA, size := binary.LittleEndian.Uint32(raw[off:]), binary.LittleEndian.Uint32(raw[off+4:])
			dataOff, err := mapRVA(dataRVA)
			if err != nil {
				return err
			}
			if uint64(size) > uint64(int(^uint(0)>>1)) || uint64(dataOff)+uint64(size) > uint64(len(raw)) {
				return errors.New("truncated resource data")
			}
			results = append(results, raw[dataOff:dataOff+int(size)])
		}
		return nil
	}
	for _, entry := range root {
		if !entry.named && entry.id == 16 && entry.directory {
			if err := descend(entry.offset, 1); err != nil {
				return nil, err
			}
		}
	}
	return results, nil
}
func parseVersionInfo(data []byte) (identity, error) {
	root, err := parseVersionBlock(data, 0, len(data))
	if err != nil {
		return identity{}, err
	}
	if root.key != "VS_VERSION_INFO" {
		return identity{}, errors.New("VERSIONINFO root has an unexpected key")
	}
	var id identity
	var visit func(versionBlock)
	visit = func(block versionBlock) {
		switch block.key {
		case "ProductName":
			id.ProductName = block.stringValue
		case "ProductVersion":
			id.Version = block.stringValue
		case "CompanyName":
			id.Company = block.stringValue
		}
		for _, child := range block.children {
			visit(child)
		}
	}
	visit(root)
	return id, nil
}

type versionBlock struct {
	key, stringValue string
	children         []versionBlock
}

func parseVersionBlock(data []byte, start, limit int) (versionBlock, error) {
	if start < 0 || limit < start || start > limit-6 {
		return versionBlock{}, errors.New("truncated VERSIONINFO block header")
	}
	length := int(binary.LittleEndian.Uint16(data[start:]))
	valueLength := int(binary.LittleEndian.Uint16(data[start+2:]))
	typ := binary.LittleEndian.Uint16(data[start+4:])
	if length < 6 || length > limit-start {
		return versionBlock{}, errors.New("invalid VERSIONINFO block length")
	}
	end := start + length
	key, afterKey, err := readUTF16Z(data, start+6, end)
	if err != nil {
		return versionBlock{}, err
	}
	valueStart, ok := align4(afterKey)
	if !ok || valueStart > end {
		return versionBlock{}, errors.New("invalid VERSIONINFO value alignment")
	}
	valueBytes := valueLength
	if typ == 1 {
		if valueLength > (end-valueStart)/2 {
			return versionBlock{}, errors.New("truncated VERSIONINFO string value")
		}
		valueBytes = valueLength * 2
	}
	if valueBytes > end-valueStart {
		return versionBlock{}, errors.New("truncated VERSIONINFO value")
	}
	valueEnd := valueStart + valueBytes
	block := versionBlock{key: key}
	if typ == 1 && valueLength > 0 {
		block.stringValue = decodeUTF16(data[valueStart:valueEnd])
	}
	childAt, ok := align4(valueEnd)
	if !ok {
		return versionBlock{}, errors.New("invalid VERSIONINFO child alignment")
	}
	// A block's wLength is its exact length and need not be a multiple of four,
	// so aligning up to where a child would start can land at or past the end of
	// the block. That means this block simply has no children -- it is the normal
	// shape of the last string in a table, not malformed input. Anything with no
	// room for a header cannot be a child, so the loop ends rather than erroring.
	for childAt+6 <= end {
		child, err := parseVersionBlock(data, childAt, end)
		if err != nil {
			return versionBlock{}, err
		}
		childLength := int(binary.LittleEndian.Uint16(data[childAt:]))
		next, ok := align4(childAt + childLength)
		if !ok || next <= childAt {
			return versionBlock{}, errors.New("invalid VERSIONINFO child length")
		}
		block.children = append(block.children, child)
		childAt = next
	}
	return block, nil
}
func readUTF16Z(data []byte, start, limit int) (string, int, error) {
	if start > limit {
		return "", 0, errors.New("invalid UTF-16 start")
	}
	values := make([]uint16, 0)
	for at := start; at+1 < limit; at += 2 {
		value := binary.LittleEndian.Uint16(data[at:])
		if value == 0 {
			return string(utf16Decode(values)), at + 2, nil
		}
		values = append(values, value)
	}
	return "", 0, errors.New("unterminated VERSIONINFO UTF-16 string")
}
func decodeUTF16(data []byte) string {
	values := make([]uint16, 0, len(data)/2)
	for at := 0; at+1 < len(data); at += 2 {
		v := binary.LittleEndian.Uint16(data[at:])
		if v == 0 {
			break
		}
		values = append(values, v)
	}
	return string(utf16Decode(values))
}
func utf16Decode(values []uint16) []rune {
	result := make([]rune, 0, len(values))
	for i := 0; i < len(values); i++ {
		v := values[i]
		if v >= 0xd800 && v <= 0xdbff && i+1 < len(values) && values[i+1] >= 0xdc00 && values[i+1] <= 0xdfff {
			result = append(result, rune(0x10000+(uint32(v-0xd800)<<10)+uint32(values[i+1]-0xdc00)))
			i++
			continue
		}
		result = append(result, rune(v))
	}
	return result
}
func align4(value int) (int, bool) {
	if value < 0 || value > int(^uint(0)>>1)-3 {
		return 0, false
	}
	return (value + 3) &^ 3, true
}
func readTLSCallbacks(raw []byte, f *pe.File) (int, error) {
	dirs, imageBase, pointerSize, headers, ok := optionalInfo(f)
	if !ok || len(dirs) <= 9 || dirs[9].VirtualAddress == 0 || dirs[9].Size == 0 {
		return 0, nil
	}
	return parseTLSDirectory(raw, dirs[9].VirtualAddress, imageBase, pointerSize, rvaMapper(raw, f, headers))
}
func parseTLSDirectory(raw []byte, tlsRVA uint32, imageBase uint64, pointerSize int, mapRVA func(uint32) (int, error)) (int, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return 0, errors.New("unsupported TLS pointer size")
	}
	off, err := mapRVA(tlsRVA)
	if err != nil {
		return 0, err
	}
	callbacksField := off + pointerSize*3
	if callbacksField < off || callbacksField > len(raw)-pointerSize {
		return 0, errors.New("truncated TLS directory")
	}
	var callbacksVA uint64
	if pointerSize == 4 {
		callbacksVA = uint64(binary.LittleEndian.Uint32(raw[callbacksField:]))
	} else {
		callbacksVA = binary.LittleEndian.Uint64(raw[callbacksField:])
	}
	if callbacksVA == 0 {
		return 0, nil
	}
	if callbacksVA < imageBase || callbacksVA-imageBase > uint64(1<<32-1) {
		return 0, errors.New("TLS callback address is outside the image")
	}
	callbackOff, err := mapRVA(uint32(callbacksVA - imageBase))
	if err != nil {
		return 0, err
	}
	count := 0
	for at := callbackOff; ; at += pointerSize {
		if at < 0 || at > len(raw)-pointerSize {
			return 0, errors.New("unterminated TLS callback array")
		}
		var callback uint64
		if pointerSize == 4 {
			callback = uint64(binary.LittleEndian.Uint32(raw[at:]))
		} else {
			callback = binary.LittleEndian.Uint64(raw[at:])
		}
		if callback == 0 {
			return count, nil
		}
		count++
	}
}
