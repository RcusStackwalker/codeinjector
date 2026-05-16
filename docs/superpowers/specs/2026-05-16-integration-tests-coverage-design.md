# Integration Tests & Coverage Design

**Date:** 2026-05-16
**Goal:** Establish a behavioral test baseline and coverage tracking in CI to support a future rewrite in a different language.

---

## Context

`codeinjector` is a C binary (~700 lines in `main.c`) that reads a big-endian ELF object file and patches a ROM image. All logic is tightly coupled to libbfd types (`bfd*`, `asection*`, `asymbol*`). There are no existing tests.

The rewrite goal means the test suite must be:
- **Language-agnostic**: tests invoke the binary as a subprocess, not the C internals
- **Transparent**: fixtures are generated from readable source, not opaque blobs
- **Behavioral**: outputs (stdout XML-like tags + patched ROM bytes) are the contract

---

## Approach

**pytest** drives all tests as subprocess invocations. A **Python ELF generator** (`generate_fixtures.py`) builds minimal big-endian 32-bit ELF object files using Python's `struct` module — no cross-compiler required. **gcovr** reports coverage to the GitHub Actions job summary (`$GITHUB_STEP_SUMMARY`). Coverage runs **Linux only** (GCC gcov + gcovr, clean integration; macOS/LLVM coverage is a different toolchain with no additional benefit for this baseline).

---

## Directory Layout

```
tests/
  conftest.py            # pytest fixtures: binary path (--binary CLI flag), ROM buffer factory
  generate_fixtures.py   # standalone script: builds ELF files; called before pytest
  fixtures/              # generated at test time; gitignored
  test_errors.py         # early-exit / error paths
  test_patch_methods.py  # one test per patch method × relevant ECU
  test_data_descs.py     # one test per data descriptor type
```

---

## ELF Fixture Generation (`generate_fixtures.py`)

Invoked as `python tests/generate_fixtures.py tests/fixtures/` before the test run.

Each fixture is a function that returns bytes, assembled with Python `struct`:

- **ELF header**: class=32-bit, data=big-endian, type=ET_REL, machine=EM_SH or EM_M32R
- **Sections**: named after patch markers (e.g. `[sh-jump-to-body]`, `[m32r-bl]`), with VMAs and big-endian content encoding target addresses
- **Symbol table + string table**: required for `data_desc` tests; symbols point into a `data_desc` section whose content is a semicolon-delimited descriptor string (e.g. `value;Category;MyTable;scaling_name`)
- **Section header string table**: required for BFD to resolve section names

One generator function per fixture type:
- `make_sh_jump_to_body_elf(vma, target)`
- `make_sh_splice_into_function_elf(vma, target_fn, target_ret)`
- `make_sh_relocate_section_elf(vma, target, data)`
- `make_m32r_bl_elf(vma, target)`
- `make_m32r_ld24_elf(vma, target, register)` (R0 and R4 variants)
- `make_m32r_lduh_r1_elf(vma, target)`
- `make_m32r_splice_into_function_elf(vma, target_fn, target_ret)`
- `make_m32r_relocate_section_elf(vma, target, data)`
- `make_generic_patch_elf(vma, data)`
- `make_data_desc_elf(descriptors)` — list of `(desc_string, data_address)` tuples

---

## Test Cases

### `test_errors.py`

Exercises early-exit paths in `main()`:

| Test | Input | Expected |
|------|-------|----------|
| Too few arguments | `codeinjector` with 0–2 args | Non-zero exit, usage message |
| Unknown ECU name | `codeinjector bad-ecu rom.bin inj.elf` | "ecu not supported" |
| Original file missing | Non-existent ROM path | "No original_file" |
| Injection file missing | Non-existent ELF path | "No injection_file" |
| Output file unwritable | Output path in `/dev/null/x` | "Can't create output_file" |
| Non-ELF injection file | Random bytes as injection | "injection_file isn't BFD object" |

### `test_patch_methods.py`

One test per patch method. Each test: asserts stdout contains `<scaling>` and `<table>` tags with correct hex bytes; asserts output ROM has expected patch bytes at expected address.

| Test | ECU | Section name | Key assertion |
|------|-----|-------------|---------------|
| `M32R_BL` | mmc-m32r | `[m32r-bl]` | BL opcode `0xfe000000` + relative offset |
| `M32R_LD24_R0` | mmc-m32r | `[m32r-ld24-r0]` | `0xe0000000` + target |
| `M32R_LD24_R4` | mmc-m32r | `[m32r-ld24-r4]` | `0xe4000000` + target |
| `M32R_LDUH_R1` | mmc-m32r | `[m32r-lduh-r1]` | `0xa1bd0000` + disp16 |
| `M32R_SPLICE_INTO_FUNCTION` | mmc-m32r | `[m32r-splice-into-function]` | Two BL/BCL encodings |
| `M32R_RELOCATE_SECTION` | mmc-m32r | `[m32r-relocate-section]` | Data at target address |
| `SH_JUMP_TO_BODY` aligned | mmc-sh2 | `[sh-jump-to-body]` | 12-byte patch at vma % 4 == 0 |
| `SH_JUMP_TO_BODY` misaligned | mmc-sh2 | `[sh-jump-to-body]` | NOP prefix + 12-byte patch at vma % 4 == 2 |
| `SH_SPLICE_INTO_FUNCTION` aligned | mmc-sh2 | `[sh-splice-into-function]` | 24-byte patch |
| `SH_SPLICE_INTO_FUNCTION` misaligned | mmc-sh2 | `[sh-splice-into-function]` | NOP prefix + 24-byte patch |
| `SH_RELOCATE_SECTION` | mmc-sh2 | `[sh-relocate-section]` | Data at target address |
| `PATCH_GENERIC` | mmc-m32r | `generic_section` | Raw copy of section data |

Also tests that a patch method name incompatible with the ECU (e.g. `[sh-jump-to-body]` with `mmc-m32r`) prints "patch_method incompatible" and exits.

### `test_data_descs.py`

One test per descriptor type against an ELF with a `data_desc` section and matching symbol table:

| Descriptor type | Expected stdout |
|----------------|-----------------|
| `value` | `<table ... type="1D" .../>` |
| `array` | `<table ... type="2D" .../>` with inline axis |
| `3darray` | `<table ... type="3D" .../>` with two inline axes |
| `2dmap8` | `<table ... type="2D" .../>` with Y axis |
| `3dmap8` | `<table ... type="3D" .../>` with X and Y axes |
| `2dmap16` | `<table ... type="2D" .../>` with Y axis |
| `3dmap16` | `<table ... type="3D" .../>` with X and Y axes |
| `axis` | No output (axes skipped explicitly) |
| `axisex` | No output (axes skipped explicitly) |
| Unknown type | `<comment name="...">...</comment>` |
| Missing data symbol | `<comment>unable to find data symbol...</comment>` |
| Missing desc symbol | `<comment>unable to find desc string...</comment>` |

---

## Coverage Build

New `Coverage` build type in `CMakeLists.txt`:

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    target_compile_options(${PROJECT_NAME} PRIVATE --coverage -O0 -g)
    target_link_options(${PROJECT_NAME} PRIVATE --coverage)
endif()
```

The `--coverage` flag is portable across GCC and Clang. Coverage data (`.gcno`/`.gcda`) lands in the build directory as the binary runs.

---

## CI Integration

New `test-coverage` job in `pr.yml` (ubuntu-latest only). The existing `build` matrix job is unchanged.

```yaml
test-coverage:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v6
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y binutils-dev python3-pip
        pip install gcovr pytest
    - name: Build with coverage
      run: |
        cmake -B build -S . -DCMAKE_BUILD_TYPE=Coverage
        cmake --build build --parallel
    - name: Generate fixtures
      run: python tests/generate_fixtures.py tests/fixtures/
    - name: Run tests
      run: pytest tests/ --binary=build/codeinjector -v
    - name: Report coverage
      run: |
        gcovr --root . --exclude tests/ --output-format markdown >> $GITHUB_STEP_SUMMARY
```

---

## Coverage Target

The goal is 100% line coverage. Paths that are structurally unreachable at the integration level (e.g. `bfd_canonicalize_symtab` returning negative storage) may be excluded with `// LCOV_EXCL_LINE` annotations if they prove impossible to trigger through a valid ELF input, but this should be a last resort.
