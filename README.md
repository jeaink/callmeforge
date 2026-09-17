# CallMeForge

![cmf](CMF.png)

**CallMeForge** is a native **C++20 game-binary analysis toolkit** designed for inspecting, understanding, and comparing compiled game software.

It provides a fast, dependency-conscious foundation for binary analysis, with support for PE executable inspection today and deeper static-analysis capabilities planned for future releases.

> Forge is intended for legitimate reverse engineering, debugging, compatibility research, game modding, security research, and analysis of software you own or are authorized to examine.

---

## Features

### Binary Inspection

Forge currently provides low-level inspection of Windows PE binaries:

* PE32 and PE32+ parsing
* x86 and x64 architecture detection
* image base detection
* entry-point inspection
* image-size information
* section-table inspection
* RVA → file-offset translation
* import-table inspection
* ASCII string extraction
* UTF-16LE string extraction

### Current Command Set

```text
forge info <file>
forge sections <file>
forge imports <file>
forge strings <file> [min-length]
forge all <file>
```

Example:

```bash
forge info game.exe
```

```text
Forge Binary Analysis
────────────────────────────────────
File:          game.exe
Format:        PE32+
Architecture:  x64
Image Base:    0x140000000
Entry Point:   0x12A430
Image Size:    0x8F3000
```

Inspect sections:

```bash
forge sections game.exe
```

Inspect imports:

```bash
forge imports game.exe
```

Scan strings:

```bash
forge strings game.exe 8
```

Run the complete current analysis pipeline:

```bash
forge all game.exe
```

---

# Why Forge?

Game binaries contain much more useful structure than a list of hexadecimal addresses.

Forge is being designed around a higher-level analysis model:

```text
Binary
  ↓
PE Metadata
  ↓
Sections
  ↓
Symbols / Exports
  ↓
Instructions
  ↓
Functions
  ↓
References
  ↓
Types / Objects
  ↓
Relationships
```

The long-term goal is to let developers investigate a binary through relationships and evidence rather than manually searching through raw memory.

For example, future versions may be able to represent an inferred structure like:

```text
Player
├── health
│   └── offset +0x20
├── stamina
│   └── offset +0x24
├── position
│   └── offset +0x30
└── velocity
    └── offset +0x3C
```

The important distinction is that Forge will treat these as **analysis results with supporting evidence**, rather than assuming that every discovered address or offset is automatically correct.

---

# Architecture

Forge is written in modern C++20 and is designed around independent analysis layers.

```text
┌───────────────────────────────────────┐
│               Forge CLI               │
├───────────────────────────────────────┤
│           Analysis Pipeline           │
├───────────────┬───────────────────────┤
│ PE Parser     │ String Scanner        │
├───────────────┼───────────────────────┤
│ Symbol Layer  │ Export Layer          │
├───────────────┼───────────────────────┤
│ Disassembler  │ Function Analyzer     │
├───────────────┼───────────────────────┤
│ XRef Engine   │ Type Recovery         │
├───────────────┴───────────────────────┤
│           Analysis Graph              │
├───────────────────────────────────────┤
│              Output API               │
│        CLI / JSON / GUI / SDK         │
└───────────────────────────────────────┘
```

The project is intentionally structured so that future analysis engines can be added without rewriting the core PE infrastructure.

---

# Project Layout

```text
forge/
├── CMakeLists.txt
├── README.md
├── LICENSE
│
├── include/
│   └── forge/
│       ├── CLI.hpp
│       ├── PEImage.hpp
│       ├── PEParser.hpp
│       └── StringScanner.hpp
│
├── src/
│   ├── main.cpp
│   ├── CLI.cpp
│   ├── PEImage.cpp
│   ├── PEParser.cpp
│   └── StringScanner.cpp
│
├── tests/
│
├── docs/
│
└── third_party/
```

As the project grows, the analysis layers will be separated further into reusable components.

---

# Requirements

## Windows

Forge is primarily developed for Windows PE analysis.

Recommended environments:

* Windows 10+
* Windows 11
* MSYS2 UCRT64
* Visual Studio 2022
* CMake 3.20+
* C++20-compatible compiler

## Toolchains

Supported development toolchains currently include:

* MSYS2 UCRT64 / MinGW
* Visual Studio 2022
* other C++20-compatible toolchains may work

---

# Build

## MSYS2 UCRT64

```bash
cd /c/path/to/forge

cmake -S . \
      -B build \
      -G "MinGW Makefiles" \
      -DCMAKE_BUILD_TYPE=Release

cmake --build build -j
```

The resulting executable will be located in:

```text
build/forge.exe
```

---

## Visual Studio 2022

From PowerShell or a Visual Studio developer terminal:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The resulting executable will normally be located at:

```text
build/Release/forge.exe
```

---

# Usage

## Binary Information

```bash
forge info game.exe
```

Displays core PE metadata including:

* PE format
* architecture
* image base
* entry point
* image size

---

## Section Inspection

```bash
forge sections game.exe
```

Example output:

```text
Name       RVA        VirtualSize   RawSize
.text      0x1000     0x5A2000      0x5A2200
.rdata     0x5A3000   0x1F4000      0x1F4200
.data      0x797000   0x063000      0x058000
```

---

## Import Inspection

```bash
forge imports game.exe
```

This can be used to inspect imported modules and imported APIs exposed through the PE import table.

Example:

```text
KERNEL32.dll
  CreateFileW
  ReadFile
  WriteFile

USER32.dll
  CreateWindowExW
  DefWindowProcW

ADVAPI32.dll
  RegOpenKeyExW
```

---

## String Analysis

```bash
forge strings game.exe
```

Specify a minimum string length:

```bash
forge strings game.exe 8
```

Forge scans for both ASCII and UTF-16LE strings.

---

## Full Analysis

```bash
forge all game.exe
```

Runs the currently available analysis modules sequentially.

---

# Address Model

Forge distinguishes several address representations.

```text
File Offset
    ↓
RVA
    ↓
Virtual Address
```

For example:

```text
File Offset:    0x00234000
RVA:            0x001F4000
Image Base:     0x140000000
Virtual Address:0x1401F4000
```

The PE parser provides the mapping required to safely translate between these representations.

This becomes important for future static-analysis features such as instruction references, exports, functions, and candidate field accesses.

---

# Planned Analysis Pipeline

Forge is being developed incrementally.

## Phase 1 — PE Foundation

* [x] PE32 parsing
* [x] PE32+ parsing
* [x] x86 detection
* [x] x64 detection
* [x] section parsing
* [x] RVA → file offset conversion
* [x] import parsing
* [x] ASCII string scanning
* [x] UTF-16LE string scanning

## Phase 2 — Binary Metadata

* [ ] PE exports
* [ ] relocation parsing
* [ ] TLS information
* [ ] exception/unwind information
* [ ] debug-directory parsing
* [ ] PDB discovery
* [ ] symbol/debug-info ingestion

## Phase 3 — Code Analysis

* [ ] executable code-section discovery
* [ ] disassembly backend
* [ ] instruction representation
* [ ] function-boundary detection
* [ ] basic-block construction
* [ ] control-flow graphs
* [ ] call graph generation

## Phase 4 — Relationship Analysis

* [ ] cross-reference engine
* [ ] string → code references
* [ ] function → function references
* [ ] data references
* [ ] import → caller relationships
* [ ] export → implementation relationships

## Phase 5 — Type Recovery

* [ ] RTTI analysis
* [ ] C++ type metadata
* [ ] vtable detection
* [ ] class hierarchy recovery
* [ ] object-layout inference
* [ ] candidate field-offset inference

Example future result:

```text
Candidate Structure: Player

Field       Offset    Type        Confidence
─────────────────────────────────────────────
health      +0x20     float       HIGH
stamina     +0x24     float       HIGH
position    +0x30     Vector3     MEDIUM
velocity    +0x3C     Vector3     MEDIUM
```

Confidence will be accompanied by the evidence used to derive the result.

## Phase 6 — Binary Comparison

Forge will eventually support comparing different builds:

```bash
forge diff game_v1.exe game_v2.exe
```

Potential output:

```text
Functions changed: 142
Functions added:   11
Functions removed: 7

Candidate layout changes:

Player::health
    v1 → +0x20
    v2 → +0x28

Player::position
    v1 → +0x30
    v2 → +0x38
```

This is particularly useful for compatibility analysis and tracking structural changes between legitimate builds.

## Phase 7 — Output and Tooling

* [ ] JSON output
* [ ] machine-readable API
* [ ] analysis database
* [ ] incremental indexing
* [ ] graph export
* [ ] terminal visualization
* [ ] desktop GUI
* [ ] scripting/plugin API
* [ ] IDE integration

---

# Design Goals

Forge is being built around several principles.

### Native

Forge is a native C++20 application rather than a scripting wrapper.

### Fast

Large binaries should be analyzed efficiently, with incremental work where practical.

### Modular

Major analysis components should be independently replaceable.

### Evidence-driven

Inferred information should expose how it was derived.

### Scriptable

Every useful analysis result should eventually be accessible through machine-readable output.

### Extensible

New binary formats, architectures, disassemblers, and analysis engines should be possible without redesigning the entire application.

---

# Roadmap

```text
v0.1
 ├── PE parser
 ├── section inspection
 ├── imports
 └── strings

v0.2
 ├── exports
 ├── relocations
 ├── debug information
 └── symbol ingestion

v0.3
 ├── disassembler
 ├── functions
 ├── basic blocks
 └── control-flow graphs

v0.4
 ├── xrefs
 ├── call graph
 ├── RTTI
 └── type recovery

v0.5
 ├── field-offset inference
 ├── binary diffing
 └── analysis database

v1.0
 ├── JSON API
 ├── GUI
 ├── plugins
 └── stable analysis SDK
```

The roadmap is intentionally non-binding and may change as the analysis architecture evolves.

---

# Contributing

Contributions are welcome.

Before opening a pull request:

1. Build Forge with C++20.
2. Make sure existing functionality still works.
3. Keep new analysis functionality isolated from unrelated components.
4. Add tests for parser and analysis changes where practical.
5. Document new CLI commands and output formats.

For larger changes, opening an issue first is recommended so the architecture can be discussed before implementation.

---

# Development

Debug build:

```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

Release build:

```bash
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

---

# Example Workflow

A typical analysis workflow may eventually look like:

```bash
forge info game.exe
forge sections game.exe
forge imports game.exe
forge strings game.exe 8
forge symbols game.exe
forge functions game.exe
forge xrefs game.exe
forge analyze game.exe
```

Then export the results:

```bash
forge analyze game.exe --json > analysis.json
```

---

# Status

**Current version:** `0.1.0`

Forge is currently in early development.

The PE analysis layer is functional, while deeper code-analysis and type-recovery systems are under development.

Expect APIs and command syntax to change before the first stable release.

---

# License

See [`LICENSE`](LICENSE) for the project's license.
