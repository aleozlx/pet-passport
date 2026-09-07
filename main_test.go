package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestParseVersionInfoFixture(t *testing.T) {
	product := versionFixtureBlock("ProductName", 1, utf16Bytes("Test Pet"), nil)
	version := versionFixtureBlock("ProductVersion", 1, utf16Bytes("1.2.3"), nil)
	company := versionFixtureBlock("CompanyName", 1, utf16Bytes("Example Co"), nil)
	table := versionFixtureBlock("040904B0", 1, nil, [][]byte{product, version, company})
	strings := versionFixtureBlock("StringFileInfo", 1, nil, [][]byte{table})
	root := versionFixtureBlock("VS_VERSION_INFO", 0, make([]byte, 52), [][]byte{strings})

	got, err := parseVersionInfo(root)
	if err != nil {
		t.Fatalf("parseVersionInfo returned %v", err)
	}
	if got.ProductName != "Test Pet" || got.Version != "1.2.3" || got.Company != "Example Co" {
		t.Fatalf("identity = %#v", got)
	}
}

func TestParseVersionInfoRejectsTruncatedAndMalformedData(t *testing.T) {
	valid := versionFixtureBlock("VS_VERSION_INFO", 0, nil, nil)
	for length := 0; length < len(valid); length++ {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseVersionInfo panicked for %d-byte input: %v", length, recovered)
				}
			}()
			if _, err := parseVersionInfo(valid[:length]); err == nil {
				t.Fatalf("parseVersionInfo accepted truncated %d-byte input", length)
			}
		}()
	}
	malformed := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(malformed, uint16(len(malformed)+1))
	if _, err := parseVersionInfo(malformed); err == nil {
		t.Fatal("parseVersionInfo accepted an oversized block length")
	}
}

func TestParseTLSDirectoryCountsCallbacks(t *testing.T) {
	raw := make([]byte, 128)
	const imageBase = 0x400000
	binary.LittleEndian.PutUint32(raw[12:], imageBase+64)
	binary.LittleEndian.PutUint32(raw[64:], imageBase+80)
	binary.LittleEndian.PutUint32(raw[68:], imageBase+84)
	count, err := parseTLSDirectory(raw, 0, imageBase, 4, directMapper(raw))
	if err != nil {
		t.Fatalf("parseTLSDirectory returned %v", err)
	}
	if count != 2 {
		t.Fatalf("callback count = %d, want 2", count)
	}
}

func TestParseTLSDirectoryRejectsTruncatedAndUnterminatedData(t *testing.T) {
	for _, raw := range [][]byte{make([]byte, 15), make([]byte, 68)} {
		if len(raw) >= 16 {
			binary.LittleEndian.PutUint32(raw[12:], 0x400000+64)
			binary.LittleEndian.PutUint32(raw[64:], 0x400000+80)
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseTLSDirectory panicked: %v", recovered)
				}
			}()
			if _, err := parseTLSDirectory(raw, 0, 0x400000, 4, directMapper(raw)); err == nil {
				t.Fatal("parseTLSDirectory accepted malformed or truncated data")
			}
		}()
	}
}

func TestReportedVersionUsesLinkedVersionWhenSet(t *testing.T) {
	original := passportVersion
	defer func() { passportVersion = original }()

	passportVersion = "v1.2.3"
	if got := reportedVersion(); got != "v1.2.3" {
		t.Fatalf("reportedVersion() = %q, want %q", got, "v1.2.3")
	}
}

func TestReportedVersionFallsBackWithoutALinkedOrModuleVersion(t *testing.T) {
	original := passportVersion
	defer func() { passportVersion = original }()

	// "development" is the unlinked default. Under `go test` there is no
	// `go install .../pet-passport@vX.Y.Z` module version either, so
	// debug.ReadBuildInfo reports the placeholder "(devel)" rather than a
	// real version. reportedVersion must recognize that placeholder as "no
	// real version available" and fall back to "development", not surface
	// "(devel)" as if it were one.
	passportVersion = "development"
	got := reportedVersion()
	if got != "development" {
		t.Fatalf("reportedVersion() = %q, want %q (no real module version available under go test)", got, "development")
	}
}

func TestInspectPENonPEDoesNotPanic(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("inspectPE panicked: %v", recovered)
		}
	}()
	if _, err := inspectPE([]byte("not a PE"), "not-a-pe.bin"); err == nil {
		t.Fatal("inspectPE accepted non-PE input")
	}
}

func TestClassifyRegularFile(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "pet.exe", []byte("MZ\x90\x00rest of a PE-shaped header"))
	writeFixtureFile(t, dir, "notes.txt", []byte("just some notes, not a binary"))
	writeFixtureFile(t, dir, "empty.bin", nil)

	tests := []struct {
		name       string
		file       string
		wantPE     bool
		wantReason string // substring expected in the skip reason; ignored when wantPE
	}{
		{name: "MZ header selects the file", file: "pet.exe", wantPE: true},
		{name: "no MZ header is skipped as not a PE image", file: "notes.txt", wantReason: "not a Windows PE image"},
		{name: "a file too short to have a header is skipped as not a PE image", file: "empty.bin", wantReason: "not a Windows PE image"},
		{name: "a name that cannot be opened is skipped with the read error", file: "does-not-exist.exe", wantReason: "could not be opened"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate, skip := classifyRegularFile(dir, tt.file)
			if tt.wantPE {
				if skip != nil {
					t.Fatalf("classifyRegularFile(%q) skipped it (%q), want it selected", tt.file, skip.Reason)
				}
				if candidate == nil || candidate.Name != tt.file {
					t.Fatalf("classifyRegularFile(%q) candidate = %#v, want a candidate named %q", tt.file, candidate, tt.file)
				}
				return
			}
			if candidate != nil {
				t.Fatalf("classifyRegularFile(%q) returned a candidate, want it skipped", tt.file)
			}
			if skip == nil || !strings.Contains(skip.Reason, tt.wantReason) {
				t.Fatalf("classifyRegularFile(%q) skip = %#v, want a reason containing %q", tt.file, skip, tt.wantReason)
			}
		})
	}
}

func TestScanDirectorySeparatesPEFromNonPEAndIgnoresSubdirectories(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "a-pet.exe", []byte("MZ\x90\x00rest of a PE-shaped header"))
	writeFixtureFile(t, dir, "z-pet.exe", []byte("MZ\x90\x00another PE-shaped header"))
	writeFixtureFile(t, dir, "readme.txt", []byte("not a binary"))
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeFixtureFile(t, filepath.Join(dir, "subdir"), "nested.exe", []byte("MZ\x90\x00should not be seen"))

	candidates, skipped, err := scanDirectory(dir)
	if err != nil {
		t.Fatalf("scanDirectory returned %v", err)
	}

	gotNames := make([]string, 0, len(candidates))
	for _, c := range candidates {
		gotNames = append(gotNames, c.Name)
	}
	sort.Strings(gotNames)
	if want := []string{"a-pet.exe", "z-pet.exe"}; !equalStrings(gotNames, want) {
		t.Fatalf("candidate names = %v, want %v (subdir contents must not appear - the scan is not recursive)", gotNames, want)
	}

	if len(skipped) != 1 || skipped[0].Name != "readme.txt" {
		t.Fatalf("skipped = %#v, want just readme.txt", skipped)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeFixtureFile(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", name, err)
	}
}

func directMapper(raw []byte) func(uint32) (int, error) {
	return func(rva uint32) (int, error) {
		return int(rva), nil
	}
}

func versionFixtureBlock(key string, typ uint16, value []byte, children [][]byte) []byte {
	data := make([]byte, 6)
	data = append(data, utf16Bytes(key)...)
	data = padFixture4(data)
	data = append(data, value...)
	data = padFixture4(data)
	for _, child := range children {
		data = append(data, child...)
	}
	data = padFixture4(data)
	binary.LittleEndian.PutUint16(data, uint16(len(data)))
	if typ == 1 {
		binary.LittleEndian.PutUint16(data[2:], uint16(len(value)/2))
	} else {
		binary.LittleEndian.PutUint16(data[2:], uint16(len(value)))
	}
	binary.LittleEndian.PutUint16(data[4:], typ)
	return data
}

func utf16Bytes(value string) []byte {
	data := make([]byte, 0, (len(value)+1)*2)
	for _, r := range value {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(r))
		data = append(data, encoded[:]...)
	}
	return append(data, 0, 0)
}

func padFixture4(data []byte) []byte {
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	return data
}

// fixtureManifest builds the observation a file carrying exactly these
// manifest keys would produce, through the real payload parser rather than
// by filling the struct in, so a test asserting on a manifest is asserting
// on something parseManifest actually accepts.
func fixtureManifest(fields map[string]any) manifestObservation {
	payload, err := json.Marshal(fields)
	if err != nil {
		panic("fixtureManifest: " + err.Error())
	}
	manifest, err := parseManifest(payload)
	if err != nil {
		panic("fixtureManifest: " + err.Error())
	}
	return manifestObservation{Found: true, Manifest: manifest}
}

func fixtureInspection(name string, raw []byte, id identity, imports []importSymbol, mapping evidenceTable) *inspection {
	sum := sha256.Sum256(raw)
	return &inspection{
		Raw:       raw,
		SHA256:    hex.EncodeToString(sum[:]),
		ImagePath: name,
		Identity:  id,
		Imports:   imports,
		Mapping:   mapping,
	}
}

func TestTocParenthetical(t *testing.T) {
	tests := []struct {
		name     string
		observed manifestObservation
		want     string
	}{
		{
			name:     "readable manifest is quoted from the manifest",
			observed: fixtureManifest(map[string]any{"schema": 1, "name": "Tapi Lila Esculenta", "version": "0.1.0"}),
			want:     `declares itself "Tapi Lila Esculenta", version 0.1.0`,
		},
		{
			name:     "a manifest missing keys says so rather than guessing",
			observed: fixtureManifest(map[string]any{"schema": 1, "name": "Tapi Lila Esculenta"}),
			want:     `declares itself "Tapi Lila Esculenta", version (not declared)`,
		},
		{
			name:     "an unreadable manifest is still listed",
			observed: manifestObservation{Found: true, ReadErr: errors.New("the payload is not a JSON object")},
			want:     "carries a pet_passport_v1 export whose contents could not be read as a v1 manifest",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureInspection("pet.exe", []byte("bytes"), identity{}, nil, evidenceTable{})
			r.Manifest = tt.observed
			if got := tocParenthetical(r); got != tt.want {
				t.Fatalf("tocParenthetical() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPartitionPetsReportsOnlyDeclaredPets(t *testing.T) {
	pet := fixtureInspection("pet.exe", []byte("a"), identity{}, nil, evidenceTable{})
	pet.Manifest = fixtureManifest(map[string]any{"schema": 1, "name": "Pet"})
	unreadable := fixtureInspection("half-pet.exe", []byte("b"), identity{}, nil, evidenceTable{})
	unreadable.Manifest = manifestObservation{Found: true, ReadErr: errors.New("the payload is not a JSON object")}
	plain := fixtureInspection("tool.exe", []byte("c"), identity{}, nil, evidenceTable{})
	broken := fixtureInspection("broken.exe", []byte("d"), identity{}, nil, evidenceTable{})
	broken.Manifest = manifestObservation{ExportErr: errors.New("export address table: the range runs past the end of the file")}

	pets, others := partitionPets([]*inspection{pet, unreadable, plain, broken})

	gotPets := make([]string, 0, len(pets))
	for _, r := range pets {
		gotPets = append(gotPets, r.ImagePath)
	}
	if want := []string{"pet.exe", "half-pet.exe"}; !equalStrings(gotPets, want) {
		t.Fatalf("reported files = %v, want %v (a file carrying an unreadable manifest still declared itself)", gotPets, want)
	}

	if len(others) != 2 {
		t.Fatalf("unreported files = %#v, want two", others)
	}
	if others[0].Name != "tool.exe" || others[0].Reason != "examined; not a pet (no pet_passport_v1 export)" {
		t.Fatalf("unreported[0] = %#v, want tool.exe named as examined and not a pet", others[0])
	}
	if others[1].Name != "broken.exe" || !strings.Contains(others[1].Reason, "could not be read completely") {
		t.Fatalf("unreported[1] = %#v, want broken.exe named with the reason its export directory could not be read", others[1])
	}
}

func TestOrderForReportPutsSelfHashMatchLast(t *testing.T) {
	a := fixtureInspection("a.exe", []byte("aaa"), identity{}, nil, evidenceTable{})
	self := fixtureInspection("self.exe", []byte("self bytes"), identity{}, nil, evidenceTable{})
	z := fixtureInspection("z.exe", []byte("zzz"), identity{}, nil, evidenceTable{})

	got := orderForReport([]*inspection{a, self, z}, self.SHA256)
	gotNames := make([]string, len(got))
	for i, r := range got {
		gotNames[i] = r.ImagePath
	}
	if want := []string{"a.exe", "z.exe", "self.exe"}; !equalStrings(gotNames, want) {
		t.Fatalf("orderForReport names = %v, want %v (self-match must move to the end, others keep their order)", gotNames, want)
	}

	// An unknown self hash must not reorder anything.
	unordered := orderForReport([]*inspection{a, self, z}, "")
	gotNames = gotNames[:0]
	for _, r := range unordered {
		gotNames = append(gotNames, r.ImagePath)
	}
	if want := []string{"a.exe", "self.exe", "z.exe"}; !equalStrings(gotNames, want) {
		t.Fatalf("orderForReport with unknown self hash reordered names to %v, want %v unchanged", gotNames, want)
	}
}

func TestWriteReportSectionOrderAndAppendixCompleteness(t *testing.T) {
	mapping := evidenceTable{Mapping: []evidence{
		{DLL: "kernel32.dll", Symbol: "CreateFileW", Wording: "Opens or creates a filesystem object (CreateFileW)."},
	}}
	imports := []importSymbol{
		{DLL: "kernel32.dll", Symbol: "CreateFileW"},
		{DLL: "ntdll.dll", Symbol: "NtSomeUnmappedThing"},
	}
	r := fixtureInspection("fixture.exe", []byte("fixture bytes"), identity{ProductName: "Fixture"}, imports, mapping)

	var buf bytes.Buffer
	writeReport(&buf, r, "" /* not the running passport */)
	out := buf.String()

	headings := []string{
		"* File: fixture.exe",
		"Described mechanisms",
		"Blind spots in this static reading",
		"What this tool cannot see",
		"Appendix: every imported symbol, by DLL",
	}
	lastIdx := -1
	for _, h := range headings {
		idx := strings.Index(out, h)
		if idx == -1 {
			t.Fatalf("report is missing heading %q; full report:\n%s", h, out)
		}
		if idx <= lastIdx {
			t.Fatalf("heading %q appeared out of order; full report:\n%s", h, out)
		}
		lastIdx = idx
	}

	describedMechanisms := out[strings.Index(out, "Described mechanisms"):strings.Index(out, "Blind spots in this static reading")]
	if !strings.Contains(describedMechanisms, "kernel32.dll imports CreateFileW. Opens or creates a filesystem object (CreateFileW).") {
		t.Fatalf("Described mechanisms section is missing the mapped import's sentence:\n%s", describedMechanisms)
	}
	if strings.Contains(describedMechanisms, "NtSomeUnmappedThing") {
		t.Fatalf("Described mechanisms section must not name unmapped imports - that is the appendix's job:\n%s", describedMechanisms)
	}

	appendix := out[strings.Index(out, "Appendix: every imported symbol, by DLL"):]
	if !strings.Contains(appendix, "CreateFileW") || !strings.Contains(appendix, "NtSomeUnmappedThing") {
		t.Fatalf("appendix must list every observed import, mapped and unmapped alike, so it is complete on its own:\n%s", appendix)
	}

	if strings.Contains(out, "This file is the copy of Pet Passport that produced this report.") {
		t.Fatalf("self-copy sentence must not appear when selfHash does not match:\n%s", out)
	}

	buf.Reset()
	writeReport(&buf, r, r.SHA256)
	if !strings.Contains(buf.String(), "This file is the copy of Pet Passport that produced this report.") {
		t.Fatalf("self-copy sentence must appear when the file's SHA-256 matches the running passport's own:\n%s", buf.String())
	}
}

func TestWriteDescribedMechanismsNoneMapped(t *testing.T) {
	r := fixtureInspection("fixture.exe", []byte("fixture bytes"), identity{}, []importSymbol{
		{DLL: "ntdll.dll", Symbol: "NtSomeUnmappedThing"},
	}, evidenceTable{})

	var buf bytes.Buffer
	writeDescribedMechanisms(&buf, r)
	got := buf.String()
	if !strings.Contains(got, "None of the observed imports match an entry in the published mapping table.") {
		t.Fatalf("writeDescribedMechanisms() = %q, want the no-match sentence", got)
	}
	if strings.Contains(got, "NtSomeUnmappedThing") {
		t.Fatalf("writeDescribedMechanisms() named an unmapped symbol %q; unmapped symbols belong only in the appendix", got)
	}
}

func TestWriteTableOfContentsOrdersAndAnnotatesDeclarations(t *testing.T) {
	declared := fixtureInspection("tapi.exe", []byte("a"), identity{}, nil, evidenceTable{})
	declared.Manifest = fixtureManifest(map[string]any{"schema": 1, "name": "tapi", "version": "0.1.0"})
	unreadable := fixtureInspection("tool.exe", []byte("b"), identity{}, nil, evidenceTable{})
	unreadable.Manifest = manifestObservation{Found: true, ReadErr: errors.New("the payload is not a JSON object")}

	var buf bytes.Buffer
	writeTableOfContents(&buf, []*inspection{declared, unreadable})
	got := buf.String()
	for _, want := range []string{
		`This directory has 2 file(s) carrying a pet_passport_v1 export`,
		`"tapi.exe" (declares itself "tapi", version 0.1.0)`,
		`"tool.exe" (carries a pet_passport_v1 export whose contents could not be read as a v1 manifest)`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("table of contents = %q, want it to contain %q", got, want)
		}
	}
}

func TestWriteClosingParagraphNamesEveryUnreportedFile(t *testing.T) {
	tests := []struct {
		name     string
		reported int
		skipped  []skippedFile
		want     []string
		notWant  []string
	}{
		{
			name:     "non-pets are named with the same reason grouped once",
			reported: 1,
			skipped: []skippedFile{
				{Name: "notepad.exe", Reason: "examined; not a pet (no pet_passport_v1 export)"},
				{Name: "pet-passport.exe", Reason: "examined; not a pet (no pet_passport_v1 export)"},
				{Name: "readme.txt", Reason: "not a Windows PE image"},
			},
			want: []string{
				`Examined; not a pet (no pet_passport_v1 export): "notepad.exe" and "pet-passport.exe".`,
				`Not a Windows PE image: "readme.txt".`,
			},
		},
		{
			name:     "a directory with no pets says so without implying anything about the files",
			reported: 0,
			skipped:  []skippedFile{{Name: "notepad.exe", Reason: "examined; not a pet (no pet_passport_v1 export)"}},
			want: []string{
				"No file in the current directory carries a pet_passport_v1 export",
				"That is not a statement about what these files do",
				`Examined; not a pet (no pet_passport_v1 export): "notepad.exe".`,
			},
		},
		{
			name:     "every file reported leaves nothing to account for",
			reported: 2,
			skipped:  nil,
			want:     []string{"Every regular file in the current directory declared itself and is reported above."},
			notWant:  []string{"not a pet"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeClosingParagraph(&buf, tt.reported, tt.skipped)
			got := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("closing paragraph = %q, want it to contain %q", got, want)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("closing paragraph = %q, want it not to contain %q", got, notWant)
				}
			}
		})
	}
}

func TestWriteIdentityBlockFromManifest(t *testing.T) {
	r := fixtureInspection("tapi-lila.exe", []byte("pet bytes"), identity{}, nil, evidenceTable{})
	r.Manifest = fixtureManifest(map[string]any{
		"schema":    1,
		"name":      "Tapi Lila Esculenta",
		"slug":      "tapi-lila",
		"version":   "0.1.0",
		"build":     "7a9663a",
		"publisher": "Alex",
		"homepage":  "https://example.invalid/tapi",
	})

	var buf bytes.Buffer
	writeIdentityBlock(&buf, r, "")
	got := buf.String()
	for _, want := range []string{
		"* Pet: Tapi Lila Esculenta (tapi-lila)\n",
		"* Version: 0.1.0\n",
		"* Publisher: Alex\n",
		"* Build ID: 7a9663a\n",
		"* File: tapi-lila.exe (9 bytes, sha256:" + r.SHA256 + ")\n",
		"Name, version, publisher and build are what the file declares about itself; nothing here verifies them.",
		`The manifest also declares a homepage of "https://example.invalid/tapi", which was not visited.`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("identity block = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "* Product:") {
		t.Fatalf("identity block used the VERSIONINFO form for a file with a manifest:\n%s", got)
	}
}

func TestWriteIdentityBlockReportsMissingAndExtraKeys(t *testing.T) {
	r := fixtureInspection("odd.exe", []byte("pet bytes"), identity{}, nil, evidenceTable{})
	r.Manifest = fixtureManifest(map[string]any{
		"schema":    1,
		"name":      "Odd",
		"slug":      "odd",
		"version":   "",
		"publisher": "Someone",
		"telemetry": "yes please",
	})

	var buf bytes.Buffer
	writeIdentityBlock(&buf, r, "")
	got := buf.String()
	for _, want := range []string{
		"* Version: (declared empty)\n",
		"* Build ID: (not declared)\n",
		`The manifest declares "telemetry", which schema v1 does not define; they were not read.`,
		`The manifest does not declare "build" and "homepage", which schema v1 does define.`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("identity block = %q, want it to contain %q", got, want)
		}
	}
}

func TestWriteIdentityBlockWithoutAManifestUsesVersionInfo(t *testing.T) {
	tests := []struct {
		name     string
		observed manifestObservation
		want     string
	}{
		{
			name:     "no export at all",
			observed: manifestObservation{},
			want:     "No pet_passport_v1 export was found in this file, so nothing in it declares it to be a pet.",
		},
		{
			name:     "an export whose payload did not parse",
			observed: manifestObservation{Found: true, ReadErr: errors.New("the payload is not a JSON object")},
			want:     "A pet_passport_v1 export exists but its contents could not be read as a v1 manifest",
		},
		{
			name:     "an export directory that could not be read",
			observed: manifestObservation{ExportErr: errors.New("export address table: the range runs past the end of the file")},
			want:     "Whether it carries one is unknown rather than settled.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := fixtureInspection("notepad.exe", make([]byte, 360448), identity{ProductName: "Some Product", Version: "10.0.1", Company: "Some Company"}, nil, evidenceTable{})
			r.Manifest = tt.observed

			var buf bytes.Buffer
			writeIdentityBlock(&buf, r, "")
			got := buf.String()
			for _, want := range []string{
				"* Product: Some Product\n",
				"* Version: 10.0.1\n",
				"* Publisher: Some Company\n",
				"* File: notepad.exe (360,448 bytes, sha256:",
				"Product, version and publisher above are what the file's VERSIONINFO resource declares about itself; nothing here verifies them.",
				tt.want,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("identity block = %q, want it to contain %q", got, want)
				}
			}
			if strings.Contains(got, "* Pet:") || strings.Contains(got, "* Build ID:") {
				t.Fatalf("identity block claimed manifest fields for a file with no readable manifest:\n%s", got)
			}
		})
	}
}

func TestWriteIdentityBlockNamesDisagreementsBetweenTheTwoDeclarations(t *testing.T) {
	r := fixtureInspection("pet.exe", []byte("pet bytes"), identity{ProductName: "Something Else", Version: "0.1.0", Company: "Another Publisher"}, nil, evidenceTable{})
	r.Manifest = fixtureManifest(map[string]any{
		"schema": 1, "name": "Tapi Lila Esculenta", "slug": "tapi-lila",
		"version": "0.1.0", "build": "7a9663a", "publisher": "Alex", "homepage": "",
	})

	var buf bytes.Buffer
	writeIdentityBlock(&buf, r, "")
	got := buf.String()
	if want := `The VERSIONINFO resource says the product name is "Something Else" while the manifest says "Tapi Lila Esculenta".`; !strings.Contains(got, want) {
		t.Fatalf("identity block = %q, want it to contain %q", got, want)
	}
	if want := `The VERSIONINFO resource says the company is "Another Publisher" while the manifest says "Alex".`; !strings.Contains(got, want) {
		t.Fatalf("identity block = %q, want it to contain %q", got, want)
	}
	if strings.Contains(got, "the product version is") {
		t.Fatalf("identity block named a field the two declarations agree on:\n%s", got)
	}
}

// A declared string is attacker-controlled input that ends up in the report,
// so it must not be able to forge the report's own shape.
func TestWriteIdentityBlockEscapesDeclaredValues(t *testing.T) {
	r := fixtureInspection("pet.exe", []byte("pet bytes"), identity{}, nil, evidenceTable{})
	r.Manifest = fixtureManifest(map[string]any{
		"schema": 1,
		"name":   "Innocent\n* Publisher: Microsoft Corporation\n",
		"slug":   strings.Repeat("x", 400),
	})

	var buf bytes.Buffer
	writeIdentityBlock(&buf, r, "")
	got := buf.String()
	if strings.Contains(got, "\n* Publisher: Microsoft Corporation") {
		t.Fatalf("a declared name forged a report line:\n%s", got)
	}
	if !strings.Contains(got, `Innocent\n* Publisher: Microsoft Corporation\n`) {
		t.Fatalf("identity block did not escape the newlines in a declared name:\n%s", got)
	}
	if !strings.Contains(got, "[truncated by Pet Passport]") {
		t.Fatalf("identity block did not truncate an over-long declared value:\n%s", got)
	}
}

func TestWithThousands(t *testing.T) {
	tests := []struct {
		value int
		want  string
	}{
		{0, "0"}, {7, "7"}, {999, "999"}, {1000, "1,000"}, {360448, "360,448"}, {6417408, "6,417,408"},
	}
	for _, tt := range tests {
		if got := withThousands(tt.value); got != tt.want {
			t.Fatalf("withThousands(%d) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
