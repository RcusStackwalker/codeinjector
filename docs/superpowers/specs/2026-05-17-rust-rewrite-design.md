# Rust Rewrite Design

**Date:** 2026-05-17  
**Branch:** `stackwalker/rust`  
**Goal:** Rewrite `codeinjector` in Rust, replacing the C/CMake build and the `libbfd` dependency, and package the resulting binary in a Python wheel via maturin.

---

## Context

`codeinjector` is a CLI tool that reads a big-endian ELF injection file and applies binary patches to a ROM image, emitting EcuFlash-compatible XML fragments to stdout. The current C implementation depends on `libbfd` (GNU binutils), which requires Homebrew on macOS and a from-source `libiberty` build, making distribution painful.

The Rust rewrite eliminates all system C library dependencies by using the pure-Rust `object` crate for ELF parsing. The CLI interface, argument order, stdout XML format, and exit codes are preserved exactly so the existing Python integration tests pass unchanged.

---

## Architecture

The repo root replaces `CMakeLists.txt` with `Cargo.toml` + `pyproject.toml`. Source is organised as a single binary crate:

```
codeinjector/
├── Cargo.toml
├── pyproject.toml
├── src/
│   ├── main.rs        # arg parsing, ROM I/O, top-level orchestration
│   ├── ecu.rs         # EcuDescription table (replaces supported_ecus.c/.h)
│   ├── patch.rs       # PatchMethod enum + inject_section logic
│   └── datadesc.rs    # data_desc_generator + emit_* XML functions
└── tests/             # existing Python tests — unchanged
```

No globals. The C's global mutable state (`ori_buffer`, `obuffer`, `symbol_table`, `current_ecu`) becomes owned values threaded through function arguments.

---

## ELF Parsing — `object` Crate Mapping

Every `libbfd` call maps directly to the `object` crate (v0.39):

| C (libbfd) | Rust (`object` crate) |
|---|---|
| `bfd_init()` + `bfd_fdopenr()` | `object::File::parse(&bytes)` |
| `bfd_map_over_sections(cb)` | `file.sections()` iterator |
| `bfd_get_section_contents()` | `section.data()` |
| `bfd_canonicalize_symtab()` | `file.symbols()` → `Vec` |
| `bfd_asymbol_name()` | `symbol.name()` |
| `bfd_asymbol_value()` | `symbol.address()` |
| `bfd_asymbol_section()` | `symbol.section()` |
| `sect->vma` | `section.address()` |
| `sect->size` | `section.size()` |
| `sect->flags & SEC_LOAD` | check `section.flags()` for `SHF_ALLOC` via `object::elf` raw flags, or use `section.kind() != SectionKind::Unknown` — skip debug/metadata sections that carry no load data |

The injection file is read into `Vec<u8>` and parsed with `object::File::parse`. The symbol table is collected once into a `Vec`, sorted by name (preserving the C `qsort` order), and used for the lifetime of the run. Symbol lookup by name remains a linear scan.

---

## ROM Buffers

The original ROM is read into two `Vec<u8>` buffers:
- `ori_buf` — immutable copy, used only for the `Original` hex output in XML
- `out_buf` — mutable copy, patched in-place section by section

After all sections are processed, `out_buf` is written to the output file.

---

## ECU Table (`ecu.rs`)

```rust
pub struct EcuDescription {
    pub name: &'static str,
    pub patch_method_prefix: &'static str,
    pub short_pointer_size: usize,
}
```

Two entries: `mmc-sh2` (prefix `"[sh-"`, pointer size 4) and `mmc-m32r` (prefix `"[m32r-"`, pointer size 2). Lookup is a linear scan by name; unknown ECU prints the same error message as the C version and exits 1.

---

## Patch Dispatch (`patch.rs`)

```rust
enum PatchMethod {
    M32rBl, M32rLd24R0, M32rLd24R4, M32rLduhR1,
    M32rSpliceIntoFunction, M32rRelocateSection,
    ShJumpToBody, ShSpliceIntoFunction, ShRelocateSection,
    Generic,
}
```

`get_patch_method(name: &str) -> PatchMethod` scans the same nine marker substrings (`"[m32r-bl]"` etc.) in order.

Each variant's encoding arithmetic is translated literally:
- `be32toh`/`htobe32` → `u32::from_be_bytes` / `u32::to_be_bytes`
- `memcpy(&obuffer[addr], ...)` → `out_buf[addr..addr+n].copy_from_slice(...)`
- Fixed patch-body byte arrays are identical to the C version

Arch-compatibility check and per-variant size validation are preserved. On error, `eprintln!` the same message and `std::process::exit(1)`.

---

## Data Descriptor XML (`datadesc.rs`)

The `data_desc` section name triggers the descriptor path (same check as C). Descriptor strings are read from section data at the symbol's offset up to a null terminator, then split on `';'` with `.splitn`. The nine `DataDescType` variants and the `emit_*` functions produce byte-for-byte identical XML output to the C version.

---

## Error Handling & Exit Codes

The C `usage()` function prints to stdout and calls `exit(1)`. The Rust version uses `eprintln!` for error messages (same text) and `std::process::exit(1)`. Argument validation order is preserved to keep exit behaviour identical for the test suite.

---

## maturin Packaging

`pyproject.toml`:
```toml
[build-system]
requires = ["maturin>=1,<2"]
build-backend = "maturin"

[project]
name = "codeinjector"
version = "0.1.0"

[tool.maturin]
binaries = ["codeinjector"]
```

`pip install .` builds the Rust binary and installs `codeinjector` into the environment's `bin/`. No system library dependencies. The existing Python tests pass `--binary` pointing to the installed binary path.

---

## Out of Scope

- Cleanup, refactoring, or interface changes (deferred to a later branch)
- PyO3 Python extension module
- Cross-compilation targets (follow-up work)
- Changes to the Python test suite
