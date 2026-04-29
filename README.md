# DLLHijacking-Patcher

A Windows DLL dynamic tracer and patching tool built on [TitanEngine](https://github.com/HelloYmf/TitanEngine).
It traces every instruction executed inside a target DLL, identifies the initialization phase, discovers post-init call-site **points**, calculates the largest free blank region in `.text`, and validates each point by redirecting its `CALL` into that region — confirming the region is safely reachable and writable with shellcode.

Supports both **x86** and **x64** targets.

---

## How It Works

```
┌─────────────┐   InitDebugW    ┌──────────────────┐
│ dll_tracer  │ ─────────────►  │  Target Process  │
│  (debugger) │                 │  (EXE + DLL)     │
│             │ ◄── MemBPX ───  │                  │
│  ┌────────┐ │   (on 1st DLL   │                  │
│  │ Tracer │ │    execution)   │                  │
│  └────────┘ │                 │                  │
│  ┌────────┐ │ ── StepInto ──► │                  │
│  │  DB    │ │ ◄─ callback ──  │  (every instr)   │
│  └────────┘ │                 └──────────────────┘
└─────────────┘
       │
       ▼
  SQLite .db  ──►  Validation  ──►  outputs/<callerRva>_<foa>_<size>/
```

### Key Algorithms

| Phase                       | Description                                                                                                                                                                                                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Init detection**    | Traces from DLL load until the first exported function is called. All instructions before that point belong to the "init region" and are marked non-overwritable.                                                                                            |
| **Point discovery**   | In POST_INIT phase, every `CALL` whose callee lands outside the init region is recorded as a *point* (`caller_rva` → `rva`).                                                                                                                        |
| **Space calculation** | Merges all executed RVA intervals across the full trace to find the largest contiguous unexecuted range in `.text`. The start address is **16-byte aligned** (satisfies x64 ABI + SSE/AVX requirements).                                             |
| **Validation**        | For each point with an `E8 rel32` CALL: redirects the CALL target to the blank region, zero-fills the blank, launches a patched debug session, and places two BPs — at `caller_rva` and at the blank region start. Both must fire in order for `YES`. |
| **Output saving**     | On `YES`: saves EXE + patched DLL (CALL redirected, blank region with **original bytes**) to `outputs/<callerRva>_<foa>_<size>/`. Optionally writes `--shellcode` into the blank region.                                                         |

---

## Requirements

| Dependency      | Version              | Notes                                             |
| --------------- | -------------------- | ------------------------------------------------- |
| Windows         | 10 / 11 (x64 host)   | Required for Win32 Debug API                      |
| Visual Studio   | 2019 + (MSVC)        | With "Desktop development with C++" workload      |
| CMake           | ≥ 3.15              | Bundled with VS or from cmake.org                 |
| Internet access | First configure only | FetchContent downloads SQLite 3.45.3 amalgamation |

> **TitanEngine** prebuilt binaries for both x86 and x64 are bundled in `deps/` — no external build required.

---

## Building

### Quick build (recommended)

```bat
build.bat              :: all archs (x86 + x64), Debug
build.bat x64 Release  :: x64 Release only
build.bat x86          :: x86 Debug only
build.bat all Release  :: x86 + x64, Release
build.bat all all      :: every combination
```

Output lands in `build_x86\<Config>\` and `build_x64\<Config>\`.

### Manual CMake

```bat
:: x64
cmake -B build_x64 -A x64
cmake --build build_x64 --config Debug

:: x86
cmake -B build_x86 -A Win32
cmake --build build_x86 --config Debug
```

`TitanEngine.dll` is automatically copied next to the built executable.

---

## Usage

```
dll_tracer.exe --sam <sample_dir> [options]
```

| Option                       | Required | Description                                                                                                                                 |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `--sam <dir>`              | Yes      | Sample directory — must contain exactly 1 `.exe` and the target `.dll`                                                                 |
| `--dll <name>`             | No       | Specify DLL filename when the directory contains multiple DLLs                                                                              |
| `--max-points <N>`         | No       | Stop after recording N points (0 = unlimited, default)                                                                                      |
| `--validate-timeout <sec>` | No       | Per-point validation timeout in seconds (default: 5)                                                                                        |
| `--shellcode <hex\|file>`   | No       | Shellcode as a hex string (`9090CC`) or path to a binary file. Written into the blank region of the output DLL if `size ≤ blank_size`. |

### Examples

```bat
:: Trace all points, x64 target
dll_tracer.exe --sam D:\samples\defender --dll MpClient.dll

:: Quick test: first point only, x86 target
dll_tracer.exe --sam D:\samples\edge --dll msedgeupdate.dll --max-points 1

:: Validate with shellcode injection
dll_tracer.exe --sam D:\samples\edge --max-points 1 --shellcode 909090C3

:: Shellcode from a binary file
dll_tracer.exe --sam D:\samples\target --shellcode D:\payloads\calc.bin
```

---

## Output Database

Filename: `{exe_stem}_{dll_stem}_{YYYYMMDD_HHMMSS}.db`
Format: SQLite 3

| Table                | Description                                                                                                                                                     |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dll_instructions` | Every instruction executed inside the DLL:`rva`, `execution_order`, `instr_size`, `is_init_end`, `in_init_region`                                     |
| `points`           | Discovered call-site points:`rva`, `caller_rva`, `execution_order`, `blank_foa`, `blank_rva`, `blank_size`, `validated` (1=YES, 0=TIMEOUT, -1=NO) |
| `exports`          | DLL export table snapshot at trace time                                                                                                                         |
| `analysis_meta`    | Key-value metadata: exe/dll names, timestamp, OS info, instruction counts                                                                                       |

---

## Validation Detail

### Preconditions (per point)

- The `CALL` at `caller_rva` must be an **`E8 rel32`** (5-byte, opcode `0xE8`).
- Any other form (`FF 15`, `FF D0`, etc.) is skipped with `validated=-1 (NO)`.

### Process

For each eligible point, the validator:

1. Creates `<sam_dir>/tmp/{HHmmss}_{callerRva}/` with copies of EXE + DLL
2. **Redirects** the `E8 rel32` CALL to `blank_rva` (only changes the 4-byte rel32 field, keeps `0xE8`)
3. **Zero-fills** the blank region in the DLL copy (strict test: no code to execute)
4. Launches a new debug session of the patched copy
5. Places **two one-shot BPs**: one at `caller_rva`, one at `blank_rva`
6. Starts a watchdog thread for the configured timeout

| Result      | Meaning                                                                    | `validated` value |
| ----------- | -------------------------------------------------------------------------- | ------------------- |
| `YES`     | **Both** BPs fired in order — call-site reached and redirect worked | `1`               |
| `TIMEOUT` | Process ran past the timeout without both BPs firing                       | `0`               |
| `NO`      | Process crashed before reaching the call-site (or non-E8 CALL skipped)     | `-1`              |

### Output on `YES`

Saves to `<sam_dir>/outputs/<callerRva8>_<blankFoa8>_<blankSize8>/`:

| File      | Contents                                                                                       |
| --------- | ---------------------------------------------------------------------------------------------- |
| `*.dll` | Original DLL with only the CALL redirect patched —**blank region keeps original bytes** |
| `*.exe` | Unchanged copy of the host EXE (for easy re-testing)                                           |

If `--shellcode` was provided and its size fits within `blank_size`, the shellcode is also written into the blank region of the output DLL.

> The shellcode is called as a normal function (`E8 CALL`), so the stack is in standard function-entry state. A simple `RET` at the end of the shellcode returns control to the original call flow.

### Address Alignment

The blank region start (both `blank_rva` and `blank_foa`) is always **16-byte aligned**:

- Guarantees VA alignment regardless of ASLR (Windows ImageBase is always ≥ page-aligned = multiple of 16).
- Satisfies x64 ABI function-entry requirements and SSE/AVX data alignment.

On `YES`, the temp directory is deleted. On `TIMEOUT`/`NO`, it is retained for inspection.

---

## License

This project is released under the MIT License.
