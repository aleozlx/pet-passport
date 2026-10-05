package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// delayFixtureDLL is one descriptor's worth of a synthetic delay-load
// directory: a DLL name, the functions it imports by name, and how many it
// imports by ordinal only.
type delayFixtureDLL struct {
	name     string
	symbols  []string
	ordinals int
}

// delayFixture lays out a delay-load import directory in one flat buffer
// starting at RVA 0, so directMapper can resolve it. Layout, in order: the
// descriptor array with its all-zero terminator, each DLL's import name
// table, then the DLL names and hint/name pairs.
//
// rvaForm chooses between the two descriptor forms. Without it every address
// the directory holds is a virtual address, imageBase plus the RVA, which is
// the original form of the structure.
func delayFixture(pointerSize int, rvaForm bool, imageBase uint64, dlls []delayFixtureDLL) []byte {
	address := func(rva int) uint64 {
		if rvaForm {
			return uint64(rva)
		}
		return imageBase + uint64(rva)
	}
	putPointer := func(raw []byte, at int, value uint64) {
		if pointerSize == 4 {
			binary.LittleEndian.PutUint32(raw[at:], uint32(value))
		} else {
			binary.LittleEndian.PutUint64(raw[at:], value)
		}
	}
	tablesAt := (len(dlls) + 1) * imgDelayDescrSize
	tableAt := make([]int, len(dlls))
	size := tablesAt
	for i, dll := range dlls {
		tableAt[i] = size
		size += (len(dll.symbols) + dll.ordinals + 1) * pointerSize
	}
	raw := make([]byte, size)
	ordinalFlag := uint64(1) << (pointerSize*8 - 1)
	for i, dll := range dlls {
		// raw grows below, so the descriptor is addressed by offset each time
		// rather than through a slice that would go stale.
		descriptorAt := i * imgDelayDescrSize
		if rvaForm {
			binary.LittleEndian.PutUint32(raw[descriptorAt:], dlattrRva)
		}
		binary.LittleEndian.PutUint32(raw[descriptorAt+4:], uint32(address(len(raw))))
		binary.LittleEndian.PutUint32(raw[descriptorAt+16:], uint32(address(tableAt[i])))
		raw = append(raw, dll.name...)
		raw = append(raw, 0)
		for j, symbol := range dll.symbols {
			putPointer(raw, tableAt[i]+j*pointerSize, address(len(raw)))
			raw = append(raw, 0, 0) // hint
			raw = append(raw, symbol...)
			raw = append(raw, 0)
		}
		for j := 0; j < dll.ordinals; j++ {
			putPointer(raw, tableAt[i]+(len(dll.symbols)+j)*pointerSize, ordinalFlag|uint64(100+j))
		}
	}
	return raw
}

func TestParseDelayImportDirectoryReadsBothDescriptorForms(t *testing.T) {
	dlls := []delayFixtureDLL{
		{name: "user32.dll", symbols: []string{"GetAsyncKeyState", "MessageBeep"}, ordinals: 2},
		{name: "example.dll", symbols: []string{"DoSomething"}},
	}
	want := []importSymbol{
		{DLL: "user32.dll", Symbol: "GetAsyncKeyState", Delayed: true},
		{DLL: "user32.dll", Symbol: "MessageBeep", Delayed: true},
		{DLL: "example.dll", Symbol: "DoSomething", Delayed: true},
	}
	for _, tc := range []struct {
		name        string
		pointerSize int
		rvaForm     bool
		imageBase   uint64
	}{
		{"PE32+ with RVAs", 8, true, 0x140000000},
		{"PE32 with RVAs", 4, true, 0x400000},
		{"PE32 with virtual addresses", 4, false, 0x400000},
	} {
		raw := delayFixture(tc.pointerSize, tc.rvaForm, tc.imageBase, dlls)
		got := parseDelayImportDirectory(raw, 0, tc.imageBase, tc.pointerSize, directMapper(raw))
		if got.Err != nil {
			t.Fatalf("%s: parseDelayImportDirectory returned %v", tc.name, got.Err)
		}
		if !reflect.DeepEqual(got.Imports, want) {
			t.Fatalf("%s: imports = %#v, want %#v", tc.name, got.Imports, want)
		}
		if !reflect.DeepEqual(got.Ordinals, map[string]int{"user32.dll": 2}) {
			t.Fatalf("%s: ordinals = %#v, want two from user32.dll", tc.name, got.Ordinals)
		}
	}
}

// Every offset in the directory comes from the file, so every way of cutting
// it short has to end in an error naming the problem, never a panic, and
// never a result claiming to be complete.
func TestParseDelayImportDirectoryRejectsEveryTruncation(t *testing.T) {
	for _, rvaForm := range []bool{true, false} {
		valid := delayFixture(4, rvaForm, 0x400000, []delayFixtureDLL{
			{name: "user32.dll", symbols: []string{"GetAsyncKeyState", "MessageBeep"}, ordinals: 1},
		})
		for length := 0; length < len(valid); length++ {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("parseDelayImportDirectory panicked for %d of %d bytes: %v", length, len(valid), recovered)
					}
				}()
				raw := valid[:length]
				if got := parseDelayImportDirectory(raw, 0, 0x400000, 4, directMapper(raw)); got.Err == nil {
					t.Fatalf("parseDelayImportDirectory accepted %d of %d bytes (RVA form %v) as complete: %#v", length, len(valid), rvaForm, got)
				}
			}()
		}
	}
}

// Whatever was read before a failure is kept: a list said to be partial
// tells a reader more than no list.
func TestParseDelayImportDirectoryKeepsWhatItReadBeforeAFailure(t *testing.T) {
	raw := delayFixture(8, true, 0x140000000, []delayFixtureDLL{
		{name: "first.dll", symbols: []string{"Kept"}},
		{name: "second.dll", symbols: []string{"Lost"}},
	})
	// Point the second descriptor's import name table past the end of the file.
	binary.LittleEndian.PutUint32(raw[imgDelayDescrSize+16:], uint32(len(raw)+64))
	got := parseDelayImportDirectory(raw, 0, 0x140000000, 8, directMapper(raw))
	if got.Err == nil {
		t.Fatal("parseDelayImportDirectory accepted an import name table outside the file")
	}
	if want := []importSymbol{{DLL: "first.dll", Symbol: "Kept", Delayed: true}}; !reflect.DeepEqual(got.Imports, want) {
		t.Fatalf("imports = %#v, want the first descriptor's import kept", got.Imports)
	}
}

func TestParseDelayImportDirectoryRejectsAddressesOutsideTheImage(t *testing.T) {
	raw := delayFixture(4, false, 0x400000, []delayFixtureDLL{{name: "user32.dll", symbols: []string{"MessageBeep"}}})
	// A virtual address below the image base cannot be converted to an RVA.
	binary.LittleEndian.PutUint32(raw[4:], 0x1000)
	got := parseDelayImportDirectory(raw, 0, 0x400000, 4, directMapper(raw))
	if got.Err == nil || !strings.Contains(got.Err.Error(), "outside the image") {
		t.Fatalf("error = %v, want one saying the address is outside the image", got.Err)
	}
}

// The fixtures in testdata/delayload are real linker output: delayload.c
// built by MSVC with /DELAYLOAD:user32.dll, once for x64 and once for x86
// (see build.cmd there). debug/pe's ImportedSymbols sees only their two
// ordinary kernel32 imports; everything from user32.dll is in the delay-load
// directory, which is the gap this test holds closed.
func TestInspectPEReadsDelayLoadImportsFromLinkerOutput(t *testing.T) {
	for _, name := range []string{"delayload-x64.exe", "delayload-x86.exe"} {
		raw, err := os.ReadFile("testdata/delayload/" + name)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		r, err := inspectPE(raw, name)
		if err != nil {
			t.Fatalf("%s: inspectPE returned %v", name, err)
		}
		if r.ImportReadErr != nil || r.DelayImportReadErr != nil {
			t.Fatalf("%s: import errors %v / %v", name, r.ImportReadErr, r.DelayImportReadErr)
		}
		want := []importSymbol{
			{DLL: "KERNEL32.dll", Symbol: "GetProcAddress"},
			{DLL: "KERNEL32.dll", Symbol: "LoadLibraryA"},
			{DLL: "USER32.dll", Symbol: "GetAsyncKeyState", Delayed: true},
			{DLL: "USER32.dll", Symbol: "MessageBeep", Delayed: true},
		}
		if !reflect.DeepEqual(r.Imports, want) {
			t.Fatalf("%s: imports = %#v, want %#v", name, r.Imports, want)
		}

		var buf bytes.Buffer
		writeReport(&buf, r, "")
		out := buf.String()
		for _, want := range []string{
			// Mapped through the same published table as an ordinary import.
			"USER32.dll imports (delay-loaded) GetAsyncKeyState. Reads the current state of one virtual key (GetAsyncKeyState).\n",
			"Delay-loaded imports are resolved by a helper routine inside this file",
			"KERNEL32.dll: GetProcAddress, LoadLibraryA.\n",
			"USER32.dll (delay-loaded): GetAsyncKeyState, MessageBeep.\n",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s: report does not contain %q:\n%s", name, want, out)
			}
		}
		t.Logf("report for %s:\n%s", name, out)
	}
}

// A file whose two import directories both name the same DLL gets one
// appendix paragraph for each, so the marker never applies to a function
// that was not delay-loaded.
func TestWriteAppendixSeparatesOrdinaryAndDelayLoadedImportsOfOneDLL(t *testing.T) {
	imports := []importSymbol{
		{DLL: "user32.dll", Symbol: "MessageBeep", Delayed: true},
		{DLL: "USER32.dll", Symbol: "GetDC"},
		{DLL: "kernel32.dll", Symbol: "CreateThread"},
	}
	sortImports(imports)
	r := fixtureInspection("fixture.exe", []byte("fixture bytes"), identity{}, imports, evidenceTable{})
	var buf bytes.Buffer
	writeAppendix(&buf, r)
	got := buf.String()
	want := "kernel32.dll: CreateThread.\nUSER32.dll: GetDC.\nuser32.dll (delay-loaded): MessageBeep.\n"
	if !strings.HasSuffix(got, want) {
		t.Fatalf("appendix = %q, want it to end %q", got, want)
	}
}

// A failure reading one import directory must not hide what the other one
// yielded, and must say that the list it does print is partial.
func TestImportReadErrorsDoNotHideTheOtherDirectory(t *testing.T) {
	mapping := evidenceTable{Mapping: []evidence{
		{DLL: "user32.dll", Symbol: "GetDC", Wording: "Obtains a device context for a window or the screen (GetDC)."},
	}}
	r := fixtureInspection("fixture.exe", []byte("fixture bytes"), identity{}, []importSymbol{
		{DLL: "user32.dll", Symbol: "GetDC", Delayed: true},
	}, mapping)
	r.ImportReadErr = errors.New("synthetic ordinary failure")
	var buf bytes.Buffer
	writeDescribedMechanisms(&buf, r)
	got := buf.String()
	for _, want := range []string{
		"The import table could not be read completely: synthetic ordinary failure.",
		"user32.dll imports (delay-loaded) GetDC. Obtains a device context",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("described mechanisms = %q, want it to contain %q", got, want)
		}
	}

	r.ImportReadErr = nil
	r.DelayImportReadErr = errors.New("synthetic delay-load failure")
	buf.Reset()
	writeAppendix(&buf, r)
	got = buf.String()
	for _, want := range []string{
		"The delay-load import directory could not be read completely: synthetic delay-load failure. Any delay-loaded imports named here are only the ones read before that point.",
		"user32.dll (delay-loaded): GetDC.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("appendix = %q, want it to contain %q", got, want)
		}
	}
}

func TestWriteBlindSpotsNamesDelayLoadOrdinals(t *testing.T) {
	r := fixtureInspection("fixture.exe", []byte("fixture bytes"), identity{}, nil, evidenceTable{})
	r.DelayOrdinals = map[string]int{"user32.dll": 2, "comctl32.dll": 1}
	var buf bytes.Buffer
	writeBlindSpots(&buf, r)
	want := "The delay-load import directory names some functions by ordinal only (1 from comctl32.dll and 2 from user32.dll)."
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("blind spots = %q, want it to contain %q", buf.String(), want)
	}
}
