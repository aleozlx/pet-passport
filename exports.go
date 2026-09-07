package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// manifestSymbolName is the one exported data symbol by which a pet declares
// itself. The "v1" is the schema version and is part of the symbol name on
// purpose: a future schema is a new symbol name, never a change to what this
// one means. A passport that understands v1 therefore keeps understanding v1
// forever, and a pet carrying a later schema is simply a file with an export
// this version does not read - which is what version independence requires.
//
// Nothing about this export is authentication. Any file can export any bytes
// under this name, including a copy of another author's declaration. It is a
// claim the file makes about itself, and the report says so every time.
const manifestSymbolName = "pet_passport_v1"

// manifestMaxBytes is the largest payload schema v1 permits, counting the
// terminating NUL. A cap is required rather than merely prudent: the RVA
// comes from the file being examined, so without one a crafted export makes
// this tool walk the whole image looking for a terminator.
const manifestMaxBytes = 4096

// maxExportNameBytes caps a single exported symbol name. Real names are
// short; the cap exists so an unterminated name in a hostile file costs a
// bounded scan rather than the whole image.
const maxExportNameBytes = 1024

// imageExportDirectorySize is the size of IMAGE_EXPORT_DIRECTORY.
const imageExportDirectorySize = 40

// manifestV1StringKeys are the string-valued keys of schema v1, in the order
// a report names them. "schema" is handled separately because it is a number.
var manifestV1StringKeys = []string{"name", "slug", "version", "build", "publisher", "homepage"}

// exportedSymbol is one named entry of a PE export directory: the name, and
// the RVA of whatever it names. For a data export like the manifest, that
// RVA is where the bytes are.
type exportedSymbol struct {
	Name string
	RVA  uint32
}

// petManifest is a decoded schema v1 payload. Every field is a string the
// file supplied about itself and none of them are checked against anything.
// Present records which v1 keys the payload actually had, so that a report
// can distinguish "declared as an empty string" from "not declared at all";
// Missing and Extra record the same fact from the other two directions.
type petManifest struct {
	Name      string
	Slug      string
	Version   string
	Build     string
	Publisher string
	Homepage  string
	Present   map[string]bool
	Missing   []string
	Extra     []string
}

// Has reports whether the payload contained key at all.
func (m *petManifest) Has(key string) bool { return m != nil && m.Present[key] }

// manifestObservation is what one file's export directory yielded on the
// subject of the manifest. The four states are distinct and a report has to
// tell them apart: no export directory or no such symbol (zero value); the
// symbol is there and parsed (Manifest); the symbol is there and did not
// parse (Found with ReadErr); the export directory itself could not be read,
// so the answer is unknown rather than no (ExportErr).
type manifestObservation struct {
	Found     bool
	Manifest  *petManifest
	ReadErr   error
	ExportErr error
}

// observeManifest looks for the manifest export in raw and reads it. It
// never returns an error: every failure is a state a report describes, and a
// file that cannot be read here is still a file worth reporting on.
func observeManifest(raw []byte, f *pe.File) manifestObservation {
	dirs, _, _, headers, ok := optionalInfo(f)
	if !ok || len(dirs) == 0 || dirs[0].VirtualAddress == 0 || dirs[0].Size == 0 {
		return manifestObservation{}
	}
	mapRVA := rvaMapper(raw, f, headers)
	exports, err := parseExportDirectory(raw, dirs[0].VirtualAddress, dirs[0].Size, mapRVA)
	if err != nil {
		return manifestObservation{ExportErr: err}
	}
	for _, export := range exports {
		// PE export names are case-sensitive, so this comparison is too.
		if export.Name != manifestSymbolName {
			continue
		}
		payload, err := readManifestPayload(raw, mapRVA, export.RVA)
		if err != nil {
			return manifestObservation{Found: true, ReadErr: err}
		}
		manifest, err := parseManifest(payload)
		if err != nil {
			return manifestObservation{Found: true, ReadErr: err}
		}
		return manifestObservation{Found: true, Manifest: manifest}
	}
	return manifestObservation{}
}

// parseExportDirectory walks the export directory at dirRVA and returns its
// named entries. debug/pe does not parse exports at all, so this is the
// whole implementation: the name pointer table and the ordinal table run in
// parallel, and the ordinal indexes the address table.
//
// Every offset in here comes from the file being examined, so each table is
// resolved and bounds-checked in full before any of it is indexed, and an
// entry that does not resolve is skipped rather than fatal - one corrupt
// name should not hide the rest of the directory.
func parseExportDirectory(raw []byte, dirRVA, dirSize uint32, mapRVA func(uint32) (int, error)) ([]exportedSymbol, error) {
	header, err := readAtRVA(raw, mapRVA, dirRVA, imageExportDirectorySize)
	if err != nil {
		return nil, fmt.Errorf("export directory header: %w", err)
	}
	numberOfFunctions := binary.LittleEndian.Uint32(header[20:])
	numberOfNames := binary.LittleEndian.Uint32(header[24:])
	addressOfFunctions := binary.LittleEndian.Uint32(header[28:])
	addressOfNames := binary.LittleEndian.Uint32(header[32:])
	addressOfNameOrdinals := binary.LittleEndian.Uint32(header[36:])
	if numberOfNames == 0 || numberOfFunctions == 0 {
		return nil, nil
	}
	// A count is four bytes wide and can claim more entries than the file
	// has room for. Reject that before allocating or resolving anything.
	if uint64(numberOfNames) > uint64(len(raw))/4 || uint64(numberOfFunctions) > uint64(len(raw))/4 {
		return nil, errors.New("export table entry counts exceed the size of the file")
	}
	names, err := readAtRVA(raw, mapRVA, addressOfNames, int(numberOfNames)*4)
	if err != nil {
		return nil, fmt.Errorf("export name pointer table: %w", err)
	}
	ordinals, err := readAtRVA(raw, mapRVA, addressOfNameOrdinals, int(numberOfNames)*2)
	if err != nil {
		return nil, fmt.Errorf("export ordinal table: %w", err)
	}
	functions, err := readAtRVA(raw, mapRVA, addressOfFunctions, int(numberOfFunctions)*4)
	if err != nil {
		return nil, fmt.Errorf("export address table: %w", err)
	}
	forwarderEnd := uint64(dirRVA) + uint64(dirSize)
	var exports []exportedSymbol
	for i := 0; i < int(numberOfNames); i++ {
		name, err := readCString(raw, mapRVA, binary.LittleEndian.Uint32(names[i*4:]), maxExportNameBytes)
		if err != nil {
			continue
		}
		ordinal := binary.LittleEndian.Uint16(ordinals[i*2:])
		if uint32(ordinal) >= numberOfFunctions {
			continue
		}
		rva := binary.LittleEndian.Uint32(functions[int(ordinal)*4:])
		if rva == 0 {
			continue
		}
		// An address that lands inside the export directory itself is a
		// forwarder: the "address" is really a NUL-terminated "OTHER.DLL.Symbol"
		// string naming where the export actually lives. It is not data and
		// reading a manifest out of it would be reading the wrong bytes.
		if uint64(rva) >= uint64(dirRVA) && uint64(rva) < forwarderEnd {
			continue
		}
		exports = append(exports, exportedSymbol{Name: name, RVA: rva})
	}
	return exports, nil
}

// readManifestPayload returns the bytes at rva up to, but not including, the
// terminating NUL, refusing anything that is not terminated within the v1
// cap.
func readManifestPayload(raw []byte, mapRVA func(uint32) (int, error), rva uint32) ([]byte, error) {
	off, err := mapRVA(rva)
	if err != nil {
		return nil, fmt.Errorf("the payload address does not resolve: %w", err)
	}
	if off < 0 || off >= len(raw) {
		return nil, errors.New("the payload begins past the end of the file")
	}
	end := off + manifestMaxBytes
	if end > len(raw) {
		end = len(raw)
	}
	at := bytes.IndexByte(raw[off:end], 0)
	if at < 0 {
		return nil, fmt.Errorf("the payload is not NUL-terminated within the %d bytes schema v1 allows", manifestMaxBytes)
	}
	return raw[off : off+at], nil
}

// parseManifest decodes a schema v1 payload. An error here means the bytes
// are not a v1 manifest at all; a payload that is merely incomplete - keys
// missing, keys this schema does not define - is not an error, it is
// something the report describes.
func parseManifest(payload []byte) (*petManifest, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("the payload is not a JSON object: %w", err)
	}
	manifest := &petManifest{Present: make(map[string]bool, len(fields))}
	known := map[string]bool{"schema": true}
	for _, key := range manifestV1StringKeys {
		known[key] = true
	}
	for key := range fields {
		if !known[key] {
			manifest.Extra = append(manifest.Extra, key)
		}
	}
	sort.Strings(manifest.Extra)

	if raw, ok := fields["schema"]; ok {
		// Decoded through UseNumber rather than straight into json.Number:
		// the latter also accepts the JSON string "1", and a quoted number
		// is not the number this schema says the key holds.
		var decoded any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return nil, errors.New(`the "schema" key could not be decoded`)
		}
		number, ok := decoded.(json.Number)
		if !ok {
			return nil, errors.New(`the "schema" key is not a number`)
		}
		// The symbol name already says v1. A payload under that name
		// declaring some other schema contradicts itself, and guessing which
		// half to believe would be inventing a fact.
		if value, err := number.Float64(); err != nil || value != 1 {
			return nil, fmt.Errorf("the payload declares schema %s under a %s export", number.String(), manifestSymbolName)
		}
		manifest.Present["schema"] = true
	} else {
		manifest.Missing = append(manifest.Missing, "schema")
	}

	for _, key := range manifestV1StringKeys {
		raw, ok := fields[key]
		if !ok {
			manifest.Missing = append(manifest.Missing, key)
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("the %q key is not a string", key)
		}
		manifest.Present[key] = true
		switch key {
		case "name":
			manifest.Name = value
		case "slug":
			manifest.Slug = value
		case "version":
			manifest.Version = value
		case "build":
			manifest.Build = value
		case "publisher":
			manifest.Publisher = value
		case "homepage":
			manifest.Homepage = value
		}
	}
	return manifest, nil
}

// readAtRVA resolves rva and returns exactly n bytes there, or an error. It
// exists so that every table this file walks is bounds-checked the same way
// rather than each caller doing its own arithmetic.
func readAtRVA(raw []byte, mapRVA func(uint32) (int, error), rva uint32, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative read length")
	}
	off, err := mapRVA(rva)
	if err != nil {
		return nil, err
	}
	if off < 0 || off > len(raw) || n > len(raw)-off {
		return nil, errors.New("the range runs past the end of the file")
	}
	return raw[off : off+n], nil
}

// readCString reads a NUL-terminated byte string at rva, refusing one that
// is not terminated within limit bytes.
func readCString(raw []byte, mapRVA func(uint32) (int, error), rva uint32, limit int) (string, error) {
	off, err := mapRVA(rva)
	if err != nil {
		return "", err
	}
	if off < 0 || off >= len(raw) {
		return "", errors.New("the string begins past the end of the file")
	}
	end := off + limit
	if end > len(raw) {
		end = len(raw)
	}
	at := bytes.IndexByte(raw[off:end], 0)
	if at < 0 {
		return "", fmt.Errorf("no NUL terminator within %d bytes", limit)
	}
	return string(raw[off : off+at]), nil
}
