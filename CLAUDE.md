# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with SymCC and its SymAFL runtime integration.

## Scope and Ownership Boundary

This subtree contains upstream-style SymCC compiler and runtime sources. **The compiler pass used by SymAFL-built targets is not the standalone pass here**: it is integrated into the RSan LLVM CodeGen tree at `../RSan/llvm-project-16/llvm/lib/CodeGen/SymCC/`. Make target-instrumentation or pass-pipeline changes there; see [`../RSan/CLAUDE.md`](../RSan/CLAUDE.md).

This subtree owns runtime ABI/shared state, libc wrappers, shadow memory, and the QSYM/Simple backends. AFL++ PCBT pre-screening and its trace-consumption rules are documented in [`../AFLplusplus/CLAUDE.md`](../AFLplusplus/CLAUDE.md).

## Runtime Architecture

| Responsibility | Files |
|---|---|
| Upstream-style compiler pass and wrapper | `compiler/Pass.cpp`, `Symbolizer.cpp`, `Runtime.cpp`, `symcc.in` |
| Compiler/runtime ABI declaration | `compiler/Runtime.cpp`, `runtime/include/RuntimeCommon.h` |
| Shared runtime expression, memory, and initialization support | `runtime/src/RuntimeCommon.cpp`, `Shadow.cpp`, `Config.cpp`, `LibcWrappers.cpp` |
| QSYM backend: solver, forkserver, AFL SHM, `.pct` persistence | `runtime/src/backends/qsym/Runtime.cpp` |
| Simple backend: smaller direct-Z3 implementation | `runtime/src/backends/simple/Runtime.cpp` |
| Backend selection and library build | `runtime/CMakeLists.txt`, backend `CMakeLists.txt` files |
| Upstream pass/runtime tests | `test/CMakeLists.txt`, `test/lit.cfg`, `test/regression/` |

The SymAFL compiler path is:

```
RSan SafeStack CodeGen pass → RSan-integrated SymCC CodeGen pass → SymCC runtime library
```

The integrated pass is enabled only during CodeGen, normally at Full LTO link time with `-flto=full -Wl,-plugin-opt=-enable-symcc`. Building the standalone `compiler/` pass or invoking the upstream `symcc` wrapper does not exercise this path.

## Backends and SymAFL Contract

### QSYM backend

QSYM is the intended SymAFL backend. In addition to symbolic expression construction and solving, its modified runtime implements an AFL-compatible forkserver and attaches the following SysV shared-memory channels:

| Environment variable | Runtime state | Purpose |
|---|---|---|
| `__AFL_SHM_ID` | `__afl_area_ptr` | Coverage bitmap |
| `__AFL_SHM_OUTDIR_ENV_ID` | `__out_dir` | Output directory |
| `__AFL_SHM_SYMBOLIC_ENV_ID` | `__symbolic` | Concrete/symbolic mode |
| `__AFL_SHM_QUEUE_ENTRY_ID` | `__queue_entry_id` | Current queue entry |
| `__AFL_SHM_INSERT_DEPTH__ID` | `__insert_depth` | First new constraint to persist; spelling is intentional |

Before every fork, `reset_gconfig()` reads `*__symbolic`:

- `0` sets `g_config.input = NoInput{}` **and** `inputFileDescriptor = -1`, enabling true concrete execution without symbolic-input creation.
- `1` sets `g_config.input = StdinInput{}` **and** `inputFileDescriptor = 0`, symbolizing stdin reads.

Changing only `g_config.input` is insufficient because `LibcWrappers.cpp` uses `inputFileDescriptor` to decide whether `read_symbolized()` creates symbolic values.

On relevant exits/signals, QSYM persists solver assertions beginning at `*__insert_depth` as `queue/.pct-<queue-entry-id>`. Keep that format and naming synchronized with the PCBT insertion code in AFL++.

### Simple backend

The Simple backend is useful for direct/basic Z3 behavior and debugging without QSYM's LLVM support dependency. It does not provide QSYM-equivalent path pruning, call-stack features, or SymAFL `.pct` persistence; do not use it as evidence that the complete AFL++ `-K` integration works.

## Build and Test

Use build directories outside source directories. `/home/hahafish/SymAFL` is a symbolic link to the current checkout at `/media/hahafish/Data/ForUbuntu/SymAFL`, so either spelling used by root helper scripts resolves to the same repository.

### SymAFL runtime builds

```bash
export SYMAFL_ROOT=/media/hahafish/Data/ForUbuntu/SymAFL
# After ensuring the script exports paths for this checkout:
source "$SYMAFL_ROOT/symafl-env.sh"

# QSYM: requires LLVM 16 configuration and Z3
cmake -G Ninja \
  -DCMAKE_C_COMPILER="$RSAN_C" -DCMAKE_CXX_COMPILER="$RSAN_CXX" \
  -DCMAKE_BUILD_TYPE=Release -DSYMCC_RT_BACKEND=qsym \
  -DLLVM_VERSION=16 -DLLVM_DIR="$RSAN_LLVM_BUILD/lib/cmake/llvm" \
  -DZ3_TRUST_SYSTEM_VERSION=ON \
  -S "$SYMAFL_ROOT/symcc/runtime" -B /tmp/symcc-rt-qsym
ninja -C /tmp/symcc-rt-qsym

# Simple: no LLVM CMake configuration required
cmake -G Ninja \
  -DCMAKE_C_COMPILER="$RSAN_C" -DCMAKE_CXX_COMPILER="$RSAN_CXX" \
  -DCMAKE_BUILD_TYPE=Release -DSYMCC_RT_BACKEND=simple \
  -DZ3_TRUST_SYSTEM_VERSION=ON \
  -S "$SYMAFL_ROOT/symcc/runtime" -B /tmp/symcc-rt-simple
ninja -C /tmp/symcc-rt-simple
```

For upstream-style compiler/runtime tests, configure the top-level `symcc/` build with the selected backend and run:

```bash
ninja check
```

Run this independently for QSYM and Simple when changing shared runtime APIs. The test configuration uses backend-aware lit prefixes; a successful test suite does not replace a SymAFL integration run.

### End-to-end integration smoke test

```bash
export SYMAFL_ROOT=/media/hahafish/Data/ForUbuntu/SymAFL
source "$SYMAFL_ROOT/symafl-env.sh"  # Audit legacy paths first.
symafl-build --symcc target.c -o target
symafl-fuzz ./target seeds /tmp/symafl-output
```

A complete QSYM/AFL++ run must attach all SHM segments, execute `-K` PCBT screening, and emit queue `.pct-*` artifacts. A standalone binary lacks AFL-created SHM unless a compatible runner creates those segments first.

## Pitfalls

- Do not modify `symcc/compiler/` expecting SymAFL target builds to change; use the integrated RSan CodeGen pass instead.
- Do not build the QSYM submodule independently in normal workflows; the CMake build selects and incorporates the needed sources.
- All symbolic input must be available at startup for QSYM's input model.
- Keep the QSYM forkserver protocol, SHM names, and `.pct` artifacts synchronized with AFL++ changes.
- Test runtime changes in both backend-level tests and an AFL++ `-K` integration run; they exercise different behavior.
- Runtime stubs that must remain outside symbolic instrumentation should be compiled with GCC rather than the integrated RSan compiler.
