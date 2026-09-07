package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// exportFixture lays out a synthetic export directory the way a linker does,
// in one flat buffer, so the tests below can use directMapper exactly as the
// TLS tests do. Layout, in order: the
// IMAGE_EXPORT_DIRECTORY, the name pointer table, the ordinal table, the
// address table, then the name strings and whatever each address points at.
//
// Each entry names a symbol and supplies the bytes its address points to.
// Set forwarder to place those bytes inside the export directory's own
// range, which is what makes an entry a forwarder rather than data.
type exportFixtureEntry struct {
	name      string
	payload   []byte
	forwarder bool
}

// base is the RVA the returned blob sits at, so the same builder serves both
// the flat directMapper tests below and the synthetic PE image, where the
// blob lives in a section at a non-zero RVA.
func exportFixture(base uint32, entries []exportFixtureEntry) (raw []byte, dirRVA, dirSize uint32) {
	count := len(entries)
	namesAt := imageExportDirectorySize
	ordinalsAt := namesAt + count*4
	functionsAt := ordinalsAt + count*2
	// The forwarder region is the tail of the export directory as the data
	// directory describes it, so anything placed here is inside that range.
	forwarderAt := functionsAt + count*4
	forwarderSize := 64
	stringsAt := forwarderAt + forwarderSize

	raw = make([]byte, stringsAt)
	binary.LittleEndian.PutUint32(raw[20:], uint32(count)) // NumberOfFunctions
	binary.LittleEndian.PutUint32(raw[24:], uint32(count)) // NumberOfNames
	binary.LittleEndian.PutUint32(raw[28:], base+uint32(functionsAt))
	binary.LittleEndian.PutUint32(raw[32:], base+uint32(namesAt))
	binary.LittleEndian.PutUint32(raw[36:], base+uint32(ordinalsAt))

	forwarderNext := forwarderAt
	for i, entry := range entries {
		nameRVA := base + uint32(len(raw))
		raw = append(raw, entry.name...)
		raw = append(raw, 0)
		binary.LittleEndian.PutUint32(raw[namesAt+i*4:], nameRVA)
		binary.LittleEndian.PutUint16(raw[ordinalsAt+i*2:], uint16(i))

		if entry.forwarder {
			copy(raw[forwarderNext:], entry.payload)
			binary.LittleEndian.PutUint32(raw[functionsAt+i*4:], base+uint32(forwarderNext))
			forwarderNext += len(entry.payload) + 1
			continue
		}
		payloadRVA := base + uint32(len(raw))
		raw = append(raw, entry.payload...)
		binary.LittleEndian.PutUint32(raw[functionsAt+i*4:], payloadRVA)
	}
	return raw, base, uint32(stringsAt)
}

// syntheticPEWithExports wraps an export-directory blob in the smallest PE
// image debug/pe will parse: DOS stub, PE signature, COFF header, a PE32+
// optional header with data directory entry 0 pointing at the blob, and one
// section holding it. It is not a runnable program and does not need to be -
// Pet Passport reads files, and this is a file shaped exactly like the one a
// pet author's linker produces for the part that matters here.
func syntheticPEWithExports(blob []byte, dirRVA, dirSize uint32) []byte {
	const (
		peSignatureAt    = 0x40
		optionalHeaderAt = peSignatureAt + 4 + 20
		sectionHeaderAt  = optionalHeaderAt + 240
		headersSize      = 0x200
		sectionRVA       = 0x1000
		sectionFileAt    = 0x200
	)
	rawSize := (len(blob) + 0x1ff) &^ 0x1ff
	image := make([]byte, headersSize+rawSize)

	copy(image, "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:], peSignatureAt)
	copy(image[peSignatureAt:], "PE\x00\x00")

	coff := image[peSignatureAt+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664) // Machine: amd64
	binary.LittleEndian.PutUint16(coff[2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], 240)   // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x0022)

	optional := image[optionalHeaderAt:]
	binary.LittleEndian.PutUint16(optional[0:], 0x20b)              // PE32+
	binary.LittleEndian.PutUint64(optional[24:], 0x140000000)       // ImageBase
	binary.LittleEndian.PutUint32(optional[32:], 0x1000)            // SectionAlignment
	binary.LittleEndian.PutUint32(optional[36:], 0x200)             // FileAlignment
	binary.LittleEndian.PutUint32(optional[56:], sectionRVA+0x1000) // SizeOfImage
	binary.LittleEndian.PutUint32(optional[60:], headersSize)       // SizeOfHeaders
	binary.LittleEndian.PutUint16(optional[68:], 2)                 // Subsystem: GUI
	binary.LittleEndian.PutUint32(optional[108:], 16)               // NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(optional[112:], dirRVA)           // Export table RVA
	binary.LittleEndian.PutUint32(optional[116:], dirSize)          // Export table size

	section := image[sectionHeaderAt:]
	copy(section[0:], ".rdata\x00\x00")
	binary.LittleEndian.PutUint32(section[8:], uint32(len(blob))) // VirtualSize
	binary.LittleEndian.PutUint32(section[12:], sectionRVA)       // VirtualAddress
	binary.LittleEndian.PutUint32(section[16:], uint32(rawSize))  // SizeOfRawData
	binary.LittleEndian.PutUint32(section[20:], sectionFileAt)    // PointerToRawData
	binary.LittleEndian.PutUint32(section[36:], 0x40000040)       // initialized data, read
	copy(image[sectionFileAt:], blob)
	return image
}

// manifestExport is the ordinary case: a NUL-terminated JSON payload.
func manifestExport(name, json string) exportFixtureEntry {
	return exportFixtureEntry{name: name, payload: append([]byte(json), 0)}
}

func TestParseExportDirectoryFindsNamedDataSymbols(t *testing.T) {
	raw, dirRVA, dirSize := exportFixture(0, []exportFixtureEntry{
		manifestExport("some_other_export", "irrelevant"),
		manifestExport(manifestSymbolName, `{"schema":1}`),
	})

	exports, err := parseExportDirectory(raw, dirRVA, dirSize, directMapper(raw))
	if err != nil {
		t.Fatalf("parseExportDirectory returned %v", err)
	}
	if len(exports) != 2 {
		t.Fatalf("exports = %#v, want two", exports)
	}
	if exports[1].Name != manifestSymbolName {
		t.Fatalf("exports[1].Name = %q, want %q", exports[1].Name, manifestSymbolName)
	}
	payload, err := readManifestPayload(raw, directMapper(raw), exports[1].RVA)
	if err != nil {
		t.Fatalf("readManifestPayload returned %v", err)
	}
	if string(payload) != `{"schema":1}` {
		t.Fatalf("payload = %q, want the JSON the export points at", payload)
	}
}

// A forwarder's "address" is a NUL-terminated "OTHER.DLL.Symbol" string
// inside the export directory, not data. Reading a manifest out of one would
// be reading a different thing entirely and calling it a declaration.
func TestParseExportDirectorySkipsForwarders(t *testing.T) {
	raw, dirRVA, dirSize := exportFixture(0, []exportFixtureEntry{
		{name: manifestSymbolName, payload: append([]byte("OTHER.pet_passport_v1"), 0), forwarder: true},
		manifestExport("real_data", "x"),
	})

	exports, err := parseExportDirectory(raw, dirRVA, dirSize, directMapper(raw))
	if err != nil {
		t.Fatalf("parseExportDirectory returned %v", err)
	}
	for _, export := range exports {
		if export.Name == manifestSymbolName {
			t.Fatalf("parseExportDirectory returned a forwarder as data: %#v", export)
		}
	}
	if len(exports) != 1 || exports[0].Name != "real_data" {
		t.Fatalf("exports = %#v, want only the non-forwarder entry", exports)
	}
}

func TestParseExportDirectoryRejectsTruncatedTables(t *testing.T) {
	valid, dirRVA, dirSize := exportFixture(0, []exportFixtureEntry{manifestExport(manifestSymbolName, `{"schema":1}`)})

	tests := []struct {
		name    string
		corrupt func(raw []byte) []byte
	}{
		{
			name:    "a header shorter than IMAGE_EXPORT_DIRECTORY",
			corrupt: func(raw []byte) []byte { return raw[:20] },
		},
		{
			name: "a name count larger than the file",
			corrupt: func(raw []byte) []byte {
				binary.LittleEndian.PutUint32(raw[24:], 0xffffffff)
				return raw
			},
		},
		{
			name: "a name pointer table past the end of the file",
			corrupt: func(raw []byte) []byte {
				binary.LittleEndian.PutUint32(raw[32:], uint32(len(raw)-2))
				return raw
			},
		},
		{
			name: "an ordinal table past the end of the file",
			corrupt: func(raw []byte) []byte {
				binary.LittleEndian.PutUint32(raw[36:], uint32(len(raw)-1))
				return raw
			},
		},
		{
			name: "an address table past the end of the file",
			corrupt: func(raw []byte) []byte {
				binary.LittleEndian.PutUint32(raw[28:], uint32(len(raw)))
				return raw
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseExportDirectory panicked: %v", recovered)
				}
			}()
			raw := tt.corrupt(append([]byte(nil), valid...))
			if _, err := parseExportDirectory(raw, dirRVA, dirSize, directMapper(raw)); err == nil {
				t.Fatal("parseExportDirectory accepted a truncated table")
			}
		})
	}

	// Every truncation of a valid fixture must be refused or read cleanly,
	// and none of them may panic. Hostile input is the normal case here.
	for length := 0; length < len(valid); length++ {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseExportDirectory panicked for a %d-byte file: %v", length, recovered)
				}
			}()
			raw := valid[:length]
			exports, err := parseExportDirectory(raw, dirRVA, dirSize, directMapper(raw))
			if err != nil {
				return
			}
			// Whatever survived truncation must still be readable without
			// reaching outside the file.
			for _, export := range exports {
				readManifestPayload(raw, directMapper(raw), export.RVA)
			}
		}()
	}
}

func TestReadManifestPayloadEnforcesTheSchemaV1Cap(t *testing.T) {
	// manifestMaxBytes counts the NUL, so the largest legal payload is one
	// byte shorter than the cap.
	largest := append([]byte(strings.Repeat("a", manifestMaxBytes-1)), 0)
	raw := make([]byte, 0, len(largest)+16)
	raw = append(raw, largest...)
	raw = append(raw, []byte(strings.Repeat("b", manifestMaxBytes+16))...)

	payload, err := readManifestPayload(raw, directMapper(raw), 0)
	if err != nil {
		t.Fatalf("readManifestPayload rejected a payload of exactly the cap: %v", err)
	}
	if len(payload) != manifestMaxBytes-1 {
		t.Fatalf("payload length = %d, want %d", len(payload), manifestMaxBytes-1)
	}

	// The second run of bytes has no NUL within the cap.
	if _, err := readManifestPayload(raw, directMapper(raw), uint32(len(largest))); err == nil {
		t.Fatal("readManifestPayload accepted a payload with no terminator within the cap")
	}

	if _, err := readManifestPayload(raw, directMapper(raw), uint32(len(raw)+1)); err == nil {
		t.Fatal("readManifestPayload accepted an address past the end of the file")
	}
}

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantErr     string // substring; empty means the payload must parse
		wantName    string
		wantMissing []string
		wantExtra   []string
	}{
		{
			name:     "a complete v1 manifest",
			payload:  `{"schema":1,"name":"Tapi Lila Esculenta","slug":"tapi-lila","version":"0.1.0","build":"7a9663a","publisher":"Alex","homepage":"https://example.invalid/"}`,
			wantName: "Tapi Lila Esculenta",
		},
		{
			name:        "a missing key is reported, not fatal",
			payload:     `{"schema":1,"name":"Pet","slug":"pet","version":"0.1.0","build":"unknown","homepage":""}`,
			wantName:    "Pet",
			wantMissing: []string{"publisher"},
		},
		{
			name:      "an unknown key is reported and otherwise ignored",
			payload:   `{"schema":1,"name":"Pet","slug":"pet","version":"1","build":"b","publisher":"p","homepage":"h","verdict":"safe"}`,
			wantName:  "Pet",
			wantExtra: []string{"verdict"},
		},
		{
			name:    "invalid JSON",
			payload: `{"schema":1,"name":`,
			wantErr: "not a JSON object",
		},
		{
			name:    "a JSON value that is not an object",
			payload: `["schema",1]`,
			wantErr: "not a JSON object",
		},
		{
			name:    "trailing bytes after the object",
			payload: `{"schema":1} and then some`,
			wantErr: "not a JSON object",
		},
		{
			name:    "a schema this symbol name cannot be carrying",
			payload: `{"schema":2,"name":"Pet"}`,
			wantErr: "declares schema 2",
		},
		{
			name:    "a schema that is not a number",
			payload: `{"schema":"1","name":"Pet"}`,
			wantErr: `"schema" key is not a number`,
		},
		{
			name:    "a v1 key of the wrong type",
			payload: `{"schema":1,"name":{"display":"Pet"}}`,
			wantErr: `"name" key is not a string`,
		},
		{
			name:    "an empty payload",
			payload: ``,
			wantErr: "not a JSON object",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseManifest panicked: %v", recovered)
				}
			}()
			manifest, err := parseManifest([]byte(tt.payload))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseManifest accepted %q", tt.payload)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseManifest error = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseManifest returned %v", err)
			}
			if manifest.Name != tt.wantName {
				t.Fatalf("manifest.Name = %q, want %q", manifest.Name, tt.wantName)
			}
			if !equalStrings(manifest.Missing, tt.wantMissing) {
				t.Fatalf("manifest.Missing = %v, want %v", manifest.Missing, tt.wantMissing)
			}
			if !equalStrings(manifest.Extra, tt.wantExtra) {
				t.Fatalf("manifest.Extra = %v, want %v", manifest.Extra, tt.wantExtra)
			}
		})
	}
}

// Every truncation of a valid payload must be rejected or accepted without
// panicking, and an accepted one must still report its own gaps honestly.
func TestParseManifestSurvivesEveryTruncation(t *testing.T) {
	valid := []byte(`{"schema":1,"name":"Pet","slug":"pet","version":"0.1.0","build":"7a9663a","publisher":"Alex","homepage":"https://example.invalid/"}`)
	for length := 0; length <= len(valid); length++ {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseManifest panicked for a %d-byte payload: %v", length, recovered)
				}
			}()
			manifest, err := parseManifest(valid[:length])
			if err == nil && manifest == nil {
				t.Fatalf("parseManifest returned no manifest and no error for a %d-byte payload", length)
			}
		}()
	}
}

// The manifest path has no real binary to test against yet - nothing ships
// carrying this export - so a synthetic image built to the documented format
// is the evidence that a pet's own report reads the way the format says it
// will, from the export directory all the way through to the identity block.
func TestInspectPEReadsAManifestFromASyntheticImage(t *testing.T) {
	const sectionRVA = 0x1000
	blob, dirRVA, dirSize := exportFixture(sectionRVA, []exportFixtureEntry{
		manifestExport(manifestSymbolName, `{"schema":1,"name":"Tapi Lila Esculenta","slug":"tapi-lila","version":"0.1.0","build":"7a9663a","publisher":"Alex","homepage":"https://example.invalid/tapi"}`),
	})
	image := syntheticPEWithExports(blob, dirRVA, dirSize)

	r, err := inspectPE(image, "tapi-lila.exe")
	if err != nil {
		t.Fatalf("inspectPE returned %v", err)
	}
	if r.Manifest.Manifest == nil {
		t.Fatalf("no manifest was read: %#v", r.Manifest)
	}
	if got := r.Manifest.Manifest.Name; got != "Tapi Lila Esculenta" {
		t.Fatalf("manifest name = %q, want the declared name", got)
	}

	var buf bytes.Buffer
	writeReport(&buf, r, "")
	got := buf.String()
	for _, want := range []string{
		"* Pet: Tapi Lila Esculenta (tapi-lila)\n",
		"* Version: 0.1.0\n",
		"* Publisher: Alex\n",
		"* Build ID: 7a9663a\n",
		"* File: tapi-lila.exe (",
		"Name, version, publisher and build are what the file declares about itself; nothing here verifies them.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("report = %q, want it to contain %q", got, want)
		}
	}
	// Printed so the report a manifest-bearing file produces can be read in
	// full with `go test -run SyntheticImage -v`, rather than only asserted
	// on a line at a time.
	t.Logf("report for a synthetic manifest-bearing image:\n%s", got)
}

// A file that carries the export but whose payload is not a v1 manifest is
// still a file declaring itself a pet, and must be reported as one rather
// than dropped or turned into an error exit.
func TestInspectPEReportsAnUnreadableManifestAsFound(t *testing.T) {
	const sectionRVA = 0x1000
	for _, payload := range []string{`{"schema":1,`, `{"schema":7}`, `not json at all`} {
		blob, dirRVA, dirSize := exportFixture(sectionRVA, []exportFixtureEntry{manifestExport(manifestSymbolName, payload)})
		image := syntheticPEWithExports(blob, dirRVA, dirSize)

		r, err := inspectPE(image, "half-pet.exe")
		if err != nil {
			t.Fatalf("inspectPE returned %v for payload %q", err, payload)
		}
		if !r.Manifest.Found || r.Manifest.Manifest != nil || r.Manifest.ReadErr == nil {
			t.Fatalf("observation for payload %q = %#v, want found with a read error", payload, r.Manifest)
		}
		var buf bytes.Buffer
		writeReport(&buf, r, "")
		if want := "A pet_passport_v1 export exists but its contents could not be read as a v1 manifest"; !strings.Contains(buf.String(), want) {
			t.Fatalf("report for payload %q does not say the manifest was unreadable:\n%s", payload, buf.String())
		}
	}
}

// An unterminated payload is the over-long case: the bytes at the export's
// address run to the end of the image without a NUL.
func TestInspectPEReportsAnOverLongManifestAsUnreadable(t *testing.T) {
	const sectionRVA = 0x1000
	blob, dirRVA, dirSize := exportFixture(sectionRVA, []exportFixtureEntry{
		{name: manifestSymbolName, payload: bytes.Repeat([]byte("a"), manifestMaxBytes+64)},
	})
	image := syntheticPEWithExports(blob, dirRVA, dirSize)

	r, err := inspectPE(image, "long-pet.exe")
	if err != nil {
		t.Fatalf("inspectPE returned %v", err)
	}
	if !r.Manifest.Found || r.Manifest.ReadErr == nil {
		t.Fatalf("observation = %#v, want found with a read error", r.Manifest)
	}
	if !strings.Contains(r.Manifest.ReadErr.Error(), "NUL-terminated within") {
		t.Fatalf("read error = %v, want it to name the schema v1 cap", r.Manifest.ReadErr)
	}
}
