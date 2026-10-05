package main

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
)

// delayImportDirectoryIndex is IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, the data
// directory a linker fills when a DLL is named with /DELAYLOAD (or its
// equivalent in another toolchain).
const delayImportDirectoryIndex = 13

// imgDelayDescrSize is the size of one ImgDelayDescr: eight 32-bit fields.
const imgDelayDescrSize = 32

// dlattrRva is the ImgDelayDescr attribute bit saying the descriptor's
// addresses are RVAs. Without it they are virtual addresses, which is the
// original form of the structure and what older linkers emit for 32-bit
// images. No other attribute bit is defined; any others are ignored rather
// than refused, because a file newer than this tool must still be read.
const dlattrRva = 0x1

// delayImportObservation is what a file's delay-load import directory
// yielded. Imports are the named functions, each marked Delayed. Ordinals
// counts, per DLL, the entries that name a function by ordinal only, which
// this file cannot turn into a name. Err is set when the directory could not
// be read completely; whatever was read before that point is still kept,
// because a partial list said to be partial tells a reader more than none.
type delayImportObservation struct {
	Imports  []importSymbol
	Ordinals map[string]int
	Err      error
}

// readDelayImports reads data directory 13 of f. debug/pe's ImportedSymbols
// reads only the ordinary import directory, so without this a function a
// linker was told to delay-load is invisible here, even though it is named
// in the file just as plainly and resolved by name on its first call.
func readDelayImports(raw []byte, f *pe.File) delayImportObservation {
	dirs, imageBase, pointerSize, headers, ok := optionalInfo(f)
	if !ok || len(dirs) <= delayImportDirectoryIndex {
		return delayImportObservation{}
	}
	dir := dirs[delayImportDirectoryIndex]
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return delayImportObservation{}
	}
	return parseDelayImportDirectory(raw, dir.VirtualAddress, imageBase, pointerSize, rvaMapper(raw, f, headers))
}

// parseDelayImportDirectory walks the ImgDelayDescr array at dirRVA up to its
// all-zero terminator, as the loader does, and for each descriptor reads the
// DLL name and the import name table (INT). Each INT entry is either an
// ordinal or the address of a hint/name pair, exactly as in the ordinary
// import directory.
//
// Every address here comes from the file being examined. Each one is
// converted and bounds-checked before use, and the walks are capped by the
// file's own size, so a hostile directory costs a bounded read and an error
// rather than a crash or an unbounded loop.
func parseDelayImportDirectory(raw []byte, dirRVA uint32, imageBase uint64, pointerSize int, mapRVA func(uint32) (int, error)) delayImportObservation {
	var result delayImportObservation
	if pointerSize != 4 && pointerSize != 8 {
		result.Err = errors.New("unsupported pointer size")
		return result
	}
	ordinalFlag := uint64(1) << (pointerSize*8 - 1)
	maxEntries := len(raw)/imgDelayDescrSize + 1
	for i := 0; ; i++ {
		if i >= maxEntries {
			result.Err = errors.New("the descriptor array has no terminator within the file")
			return result
		}
		at, ok := addRVA(dirRVA, uint64(i)*imgDelayDescrSize)
		if !ok {
			result.Err = errors.New("the descriptor array runs past the end of the address space")
			return result
		}
		descriptor, err := readAtRVA(raw, mapRVA, at, imgDelayDescrSize)
		if err != nil {
			result.Err = fmt.Errorf("descriptor %d: %w", i, err)
			return result
		}
		if isAllZero(descriptor) {
			return result
		}
		attributes := binary.LittleEndian.Uint32(descriptor[0:])
		// The loader treats a descriptor with no DLL name as the end of the
		// array as well, so this does too rather than calling it malformed.
		nameField := binary.LittleEndian.Uint32(descriptor[4:])
		if nameField == 0 {
			return result
		}
		intField := binary.LittleEndian.Uint32(descriptor[16:])
		toRVA := func(value uint64) (uint32, error) {
			if attributes&dlattrRva != 0 {
				if value > 0xffffffff {
					return 0, errors.New("an RVA does not fit in 32 bits")
				}
				return uint32(value), nil
			}
			if value < imageBase || value-imageBase > 0xffffffff {
				return 0, errors.New("a virtual address is outside the image")
			}
			return uint32(value - imageBase), nil
		}
		nameRVA, err := toRVA(uint64(nameField))
		if err != nil {
			result.Err = fmt.Errorf("descriptor %d DLL name: %w", i, err)
			return result
		}
		dll, err := readCString(raw, mapRVA, nameRVA, maxExportNameBytes)
		if err != nil {
			result.Err = fmt.Errorf("descriptor %d DLL name: %w", i, err)
			return result
		}
		if intField == 0 {
			result.Err = fmt.Errorf("descriptor %d (%s) has no import name table", i, dll)
			return result
		}
		intRVA, err := toRVA(uint64(intField))
		if err != nil {
			result.Err = fmt.Errorf("descriptor %d (%s) import name table: %w", i, dll, err)
			return result
		}
		maxThunks := len(raw)/pointerSize + 1
		for j := 0; ; j++ {
			if j >= maxThunks {
				result.Err = fmt.Errorf("the import name table for %s has no terminator within the file", dll)
				return result
			}
			thunkRVA, ok := addRVA(intRVA, uint64(j)*uint64(pointerSize))
			if !ok {
				result.Err = fmt.Errorf("the import name table for %s runs past the end of the address space", dll)
				return result
			}
			thunk, err := readAtRVA(raw, mapRVA, thunkRVA, pointerSize)
			if err != nil {
				result.Err = fmt.Errorf("import name table entry %d for %s: %w", j, dll, err)
				return result
			}
			var value uint64
			if pointerSize == 4 {
				value = uint64(binary.LittleEndian.Uint32(thunk))
			} else {
				value = binary.LittleEndian.Uint64(thunk)
			}
			if value == 0 {
				break
			}
			if value&ordinalFlag != 0 {
				if result.Ordinals == nil {
					result.Ordinals = make(map[string]int)
				}
				result.Ordinals[dll]++
				continue
			}
			hintRVA, err := toRVA(value)
			if err != nil {
				result.Err = fmt.Errorf("import name table entry %d for %s: %w", j, dll, err)
				return result
			}
			// IMAGE_IMPORT_BY_NAME: a 16-bit hint, then the name.
			symbolRVA, ok := addRVA(hintRVA, 2)
			if !ok {
				result.Err = fmt.Errorf("import name table entry %d for %s runs past the end of the address space", j, dll)
				return result
			}
			symbol, err := readCString(raw, mapRVA, symbolRVA, maxExportNameBytes)
			if err != nil {
				result.Err = fmt.Errorf("import name table entry %d for %s: %w", j, dll, err)
				return result
			}
			result.Imports = append(result.Imports, importSymbol{DLL: dll, Symbol: symbol, Delayed: true})
		}
	}
}

// addRVA returns base+delta, or false if that is not a 32-bit RVA.
func addRVA(base uint32, delta uint64) (uint32, bool) {
	sum := uint64(base) + delta
	if sum > 0xffffffff {
		return 0, false
	}
	return uint32(sum), true
}

func isAllZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
