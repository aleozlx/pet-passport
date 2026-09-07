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
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
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
	Identity        identity
	Imports         []importSymbol
	ImportReadErr   error
	TLSCallbacks    int
	TLSReadErr      error
	HighEntropy     []sectionObservation
	UnusualSections []string
	ImagePath       string
	Mapping         evidenceTable
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Please provide a path to one Windows PE binary.")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pet Passport could not read %q: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	result, err := inspectPE(raw, os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%q is not a PE file; Pet Passport examines Windows PE files only.\n", os.Args[1])
		os.Exit(1)
	}
	writeReport(os.Stdout, result)
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
	r := &inspection{File: f, Raw: raw, ImagePath: path, Mapping: table}
	r.Imports, r.ImportReadErr = readImports(f)
	r.Identity = readVersionInfo(raw, f)
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

func writeReport(out *os.File, r *inspection) {
	hash := sha256.Sum256(r.Raw)
	fmt.Fprintf(out, "Pet Passport %s read %q. This is a static reading of that one file, not a judgment about it.\n\n", reportedVersion(), filepath.Clean(r.ImagePath))
	fmt.Fprintln(out, "Self-reported identity (unverified)")
	fmt.Fprintf(out, "The file is %d bytes and its SHA-256 is %s.\n", len(r.Raw), hex.EncodeToString(hash[:]))
	writeIdentity(out, r.Identity)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Observed imports")
	writeImports(out, r)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Blind spots in this static reading")
	writeBlindSpots(out, r)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "What this tool cannot see")
	fmt.Fprintln(out, "This is a static reading of one file. It cannot see code produced after launch, decrypted or downloaded content, direct system calls, user-triggered paths, or what the program actually does on a particular machine. Dynamic and behavioral analysis tools, such as a sandbox, system-call monitor, network capture, or debugger, can observe kinds of runtime behavior that this report cannot.")
}
func writeIdentity(out *os.File, id identity) {
	if id.ProductName == "" {
		fmt.Fprintln(out, "No self-reported product name was found in a VERSIONINFO resource.")
	} else {
		fmt.Fprintf(out, "The self-reported product name is %q; it is unverified.\n", id.ProductName)
	}
	if id.Version == "" {
		fmt.Fprintln(out, "No self-reported product version was found in a VERSIONINFO resource.")
	} else {
		fmt.Fprintf(out, "The self-reported product version is %q; it is unverified.\n", id.Version)
	}
	if id.Company == "" {
		fmt.Fprintln(out, "No self-reported company was found in a VERSIONINFO resource.")
	} else {
		fmt.Fprintf(out, "The self-reported company is %q; it is unverified.\n", id.Company)
	}
}
func writeImports(out *os.File, r *inspection) {
	if r.ImportReadErr != nil {
		fmt.Fprintf(out, "The import table could not be read completely: %v. This does not make the static picture complete.\n", r.ImportReadErr)
		return
	}
	if len(r.Imports) == 0 {
		fmt.Fprintln(out, "The import table yielded no symbols for this static reading. Silence in an import table is not evidence about runtime behavior.")
		return
	}
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
		unmapped := make([]string, 0)
		for _, imp := range byDLL[dll] {
			if item, ok := evidenceFor(r.Mapping, imp); ok {
				fmt.Fprintf(out, "%s imports %s. %s\n", imp.DLL, imp.Symbol, item.Wording)
			} else {
				unmapped = append(unmapped, imp.Symbol)
			}
		}
		if len(unmapped) > 0 {
			fmt.Fprintf(out, "%s also imports symbols not in the published mapping table: %s. They are observed imports; this tool has not assigned them a more specific description.\n", dll, joinProse(unmapped))
		}
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
func writeBlindSpots(out *os.File, r *inspection) {
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
