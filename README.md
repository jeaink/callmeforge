![cmf](CMF.png)
# 

# CallMeForge

CMF is a native C++20 toolkit for static analysis of PE (Portable Executable)
game binaries. It parses PE32/PE32+ images, scans for strings, recovers code
structure (functions, basic blocks, control flow), resolves string
cross-references, detects simple C++ vtables, and diffs two builds.

It is a developer/RE focused CLI plus a small reusable library (`forge::PEImage`,
`forge::StringScanner`, `forge::run*` analysis entry points).

## Status

The original six-phase plan is implemented through Phase 6, at MVP depth:

| Phase | Name                  | Command         | State |
|-------|-----------------------|-----------------|-------|
| 2     | Binary metadata       | `metadata`      | implemented (exports + relocations) |
| 3     | Code analysis         | `analyze`       | implemented (heuristic) |
| 4     | Relationship analysis | `relations`     | implemented (string -> code xrefs) |
| 5     | Type recovery         | `typerecovery`  | implemented (basic vtable detection) |
| 6     | Binary comparison     | `diff`          | implemented (function-level) |

Phase 1 (PE parsing, sections, imports) is the foundation in `PEImage`.

## Requirements

- A C++20 compiler. The build sets `CMAKE_CXX_STANDARD 20` and requires it.
- CMake 3.20 or newer (or a hand-configured MSVC project).
- Tested with MSYS2 g++ (UCRT64) and MSVC (Visual Studio 2022, x64).

Warnings are enabled aggressively: `/W4 /permissive-` on MSVC, and
`-Wall -Wextra -Wpedantic` elsewhere.

## Build

CMake with MSYS2 / MinGW Makefiles:

```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

CMake with Visual Studio 2022:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Direct g++ one-liner (handy for a quick local build):

```bash
g++ -std=c++20 -Iinclude -O2 -o forge.exe src/main.cpp src/PEImage.cpp src/PEParser.cpp src/StringScanner.cpp src/Analysis.cpp src/CLI.cpp
```

If you build inside Visual Studio directly, make sure all six sources are in the
project (in particular `src/Analysis.cpp`) and that C++ Language Standard is set
to C++20.

## Commands

General syntax: `forge <command> <file> [args]`.

| Command | Description |
|---------|-------------|
| `info <file>` | Arch, image base, entry RVA, image size, section/import counts |
| `sections <file>` | Section table (RVA, virtual/raw sizes, R/W/X flags) |
| `imports <file>` | Imported symbols grouped by module |
| `strings <file> [min-length]` | ASCII/UTF-8/UTF-16 string scan (default min length 5) |
| `all <file>` | `info` + `sections` + `imports` |
| `hexdump <file> <offset> <len>` | Hex+ASCII dump (`offset` accepts `0x` hex) |
| `peek-rva <file> <rva>` | Map RVA to file offset and show the u32 there |
| `peek-offset32 <file> <offset>` | Read a little-endian u32 at a file offset |
| `metadata <file>` | Phase 2: exports and relocation summary |
| `analyze <file> [show]` | Phase 3: discover functions (RVA, size, hash) |
| `relations <file> [show]` | Phase 4: strings and the code that references them |
| `typerecovery <file> [show]` | Phase 5: candidate vtables |
| `diff <v1> <v2> [show]` | Phase 6: compare two builds |

`help`, `--help` and `-h` print usage.

### The `[show]` argument

`analyze`, `relations`, `typerecovery` and `diff` print a summary line and then a
preview of the results. `[show]` controls how many rows are printed:

- omitted: default preview of `20` results
- `0`: print everything
- `N`: print up to `N` results

When a preview is truncated the tool prints a `... (N more; pass a count to show
more)` line.

## Analysis phases

### Phase 2 — Binary metadata (`metadata`)

Summarizes what `PEImage` parsed: architecture, image base/entry/size, section,
import, export and relocation counts, the export table (by name or `#ordinal`),
and a relocation-type histogram.

```text
Binary metadata
  File:       game.exe
  Arch:       x64
  Image base: 0x140000000
  Entry RVA:  0x00001400
  Image size: 0x0005B000
  Sections:   19
  Imports:    84
  Exports:    0
  Relocs:     50
```

### Phase 3 — Code analysis (`analyze`)

Heuristic disassembly and control-flow recovery, not a full x86 decoder:

- function entry candidates from standard prologues
  (`55 48 89 E5` on x64, `55 8B EC` on x86) plus every exported RVA
- basic blocks built by walking instructions until a return, jump or fall-through
- direct call/jump targets resolved through the section table
- each function fingerprinted with an FNV-1a 64-bit hash of its first bytes

```text
Discovered 1332 functions
  0x00001000  size=24  hash=0xA1B2C3D4E5F60718  <unnamed>
  ...
  ... (1312 more; pass a count to show more)
```

### Phase 4 — Relationship analysis (`relations`)

Scans strings, converts each string's file offset to an RVA, and finds code that
references it:

- x64: RIP-relative `LEA`/`MOV` (`REX.W + 8D/8B`, `mod=00, rm=101`) and
  `mov r64, imm64` absolute pointers
- x86: absolute `push`/`mov`/`moffs32` immediates

```text
Found 195 string references
  "kernel32.dll"
     offset=0x0004A100  refs=2
        ref @ 0x00001234
        ref @ 0x00002010
```

### Phase 5 — Type recovery (`typerecovery`)

Basic vtable detection: scans non-executable sections for runs of at least three
consecutive 4-byte RVAs that each point into an executable section, and reports
each run as a candidate vtable with its methods.

```text
Found 78 vtables
  vtable @ 0x0004C020  methods=5
        0x00001100
        0x00001140
        ...
```

### Phase 6 — Binary comparison (`diff`)

Runs Phase 3 on both files and matches functions:

- named functions (exports) matched by name; a differing hash counts as
  *changed*, a differing RVA is reported as a candidate layout change
- unnamed functions matched by content hash; unmatched ones count as
  *added* / *removed*

```text
Functions changed: 0
Functions added:   15
Functions removed: 1332

Candidate layout changes:

ExportedFunction::InitRenderer
    v1 -> 0x00002A10
    v2 -> 0x00002A40
```

## Library API

`forge::PEImage` (`include/forge/PEImage.hpp`):

- `load(path, error)` — parse a file; returns false and fills `error` on failure
- `data()`, `info()`, `sections()`, `imports()`, `exports()`, `relocations()`
- `rvaToOffset(rva, out)` — map an RVA to a file offset
- `readUInt32AtOffset(offset, out)` — little-endian u32 at a file offset
- `readBytes(offset, length, out)` — copy bytes into a vector

`PEInfo` carries `architecture`, `entryPointRva`, `imageBase`, `imageSize`,
`sectionAlignment`, `fileAlignment`. `Section` carries `name`, `virtualAddress`,
`virtualSize`, `rawAddress`, `rawSize`, `characteristics`.

`forge::StringScanner` (`include/forge/StringScanner.hpp`):

```cpp
std::vector<StringHit> scan(
    const std::vector<std::uint8_t>& data,
    std::size_t minimumLength = 5,
    bool detectUtf8 = true,
    bool detectUtf16le = true,
    bool detectUtf16be = false,
    bool unique = false) const;
```

`StringHit` reports the file `offset`, `value`, whether it is `unicode`, and the
detected `encoding` (`ASCII`, `UTF-8`, `UTF-16LE`, `UTF-16BE`).

`forge::Analysis` (`include/forge/Analysis.hpp`) exposes:

```cpp
bool runBinaryMetadata(const std::string& path, std::string& outMessage);
bool runCodeAnalysis(const std::string& path, std::vector<FunctionInfo>& outFunctions);
bool runRelationshipAnalysis(const std::string& path, std::vector<StringReference>& outStringRefs);
bool runTypeRecovery(const std::string& path, std::vector<VTable>& outVTables);
bool runBinaryComparison(const std::string& v1, const std::string& v2,
                         DiffSummary& outSummary, std::vector<LayoutChange>& outChanges);
```

Result types: `FunctionInfo{rva, size, hash, name}`,
`StringReference{value, fileOffset, referencingRvas}`,
`VTable{rva, methodRvas}`, `DiffSummary{functionsChanged, functionsAdded,
functionsRemoved}`, `LayoutChange{structureName, fieldName, v1Offset, v2Offset}`.

## Project layout

```text
include/forge/
  Analysis.hpp        analysis phase types + run* entry points
  CLI.hpp             runCLI declaration
  PEImage.hpp         PE image model and parsing API
  PEParser.hpp        architectureName / sectionCharacteristics helpers
  StringScanner.hpp   string scanning API
src/
  Analysis.cpp        phases 3-6 implementations
  CLI.cpp             command dispatch + output formatting
  PEImage.cpp         PE parsing (headers, sections, imports, exports, relocs)
  PEParser.cpp        small formatting helpers
  StringScanner.cpp   ASCII / UTF-8 / UTF-16 scanning
  main.cpp            argv -> runCLI
```

## Examples

```bash
# quick overview
forge info game.exe
forge all game.exe

# strings and where code points at them
forge strings game.exe 6
forge relations game.exe 40

# recover functions, vtables
forge analyze game.exe 50
forge typerecovery game.exe

# compare two builds
forge diff game_v1.exe game_v2.exe 30
```

## Limitations

- x86/x64 are the primary targets. ARM64 images parse, but function/vtable
  recovery assumes x86/x64 encodings and returns little for ARM64.
- Disassembly is heuristic (prologue-based), so function counts are approximate
  and can include false positives or miss uncommon prologues.
- String cross-reference detection is pattern based, not a complete instruction
  decoder: indirect and computed references are not resolved.
- Vtable detection is structural (runs of code pointers) and is not RTTI aware,
  so some candidates are not real vtables.
- `diff` reports function- and export-level differences; it does not recover real
  structure field offsets.
- This is a developer tool, not a signed product; run it only on binaries you are
  allowed to analyze.
