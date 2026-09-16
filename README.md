# callmeforge

callmeforge is a native C++20 game-binary analysis toolkit.

## Current MVP

- PE32 / PE32+ parsing
- x86 / x64 detection
- PE image metadata
- section table inspection
- import table inspection
- ASCII and UTF-16LE string scanning
- RVA -> file-offset mapping

## Build (MSYS2 UCRT64)

```bash
cd /c/path/to/forge
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Or with a Visual Studio generator:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Usage

```bash
forge info game.exe
forge sections game.exe
forge imports game.exe
forge strings game.exe 6
forge all game.exe
```

## Planned analysis layers

1. symbol/debug-info ingestion
2. PE exports and relocations
3. code-section discovery
4. disassembly backend
5. function boundaries
6. xref graph
7. RTTI/type recovery
8. candidate field-offset inference
9. version-to-version binary comparison
10. JSON output and a GUI frontend
