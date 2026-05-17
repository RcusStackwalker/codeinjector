# Rust Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `codeinjector` in Rust on branch `stackwalker/rust`, replacing `libbfd` with the pure-Rust `object` crate, preserving full CLI/output compatibility so the existing Python integration tests pass unchanged, and packaging the binary as a Python wheel via maturin.

**Architecture:** Single Rust binary crate (`src/main.rs` + three focused modules). `main.rs` owns ELF parsing via the `object` crate and extracts raw bytes/metadata before delegating to `patch.rs` (encoding logic) and `datadesc.rs` (XML generation). Neither module imports `object` — they receive plain slices and primitive values, making them unit-testable without ELF fixtures. All output (including errors) goes to stdout via `println!`/`print!` to match the C `printf` behaviour the test suite checks against `r.stdout`.

**Tech Stack:** Rust 1.95 (installed), `object` crate v0.39 (ELF parsing, no system deps), maturin ≥ 1.0 (Python wheel packaging), existing Python/pytest integration tests.

---

## File Map

**Create:**
- `Cargo.toml` — Rust package manifest with `object` dependency
- `pyproject.toml` — maturin build config
- `src/main.rs` — entry point: arg parsing, ROM I/O, ELF parsing, section dispatch
- `src/ecu.rs` — `EcuDescription` table and `find_ecu` lookup
- `src/patch.rs` — `PatchMethod` enum, detection, pure encoding fns, section dispatcher
- `src/datadesc.rs` — `SymInfo` struct, symbol helpers, `emit_*` XML fns, `process_section`

**Delete (on `stackwalker/rust` branch — Task 12):**
- `CMakeLists.txt`, `codeinjector-config.cmake`, `main.c`, `supported_ecus.c`, `supported_ecus.h`

**Keep unchanged:**
- `tests/` — all Python integration tests

---

### Task 1: Create branch and project scaffold

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`, `src/ecu.rs`, `src/patch.rs`, `src/datadesc.rs`

- [ ] **Step 1: Create the `stackwalker/rust` branch**

```bash
git checkout -b stackwalker/rust
```

Expected: `Switched to a new branch 'stackwalker/rust'`

- [ ] **Step 2: Create `Cargo.toml`**

```toml
[package]
name = "codeinjector"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "codeinjector"
path = "src/main.rs"

[dependencies]
object = "0.39"
```

- [ ] **Step 3: Create `src/main.rs`**

```rust
mod datadesc;
mod ecu;
mod patch;

fn main() {}
```

- [ ] **Step 4: Create `src/ecu.rs`**

```rust
pub struct EcuDescription {
    pub name: &'static str,
    pub patch_method_prefix: &'static str,
    pub short_pointer_size: usize,
}
```

- [ ] **Step 5: Create `src/patch.rs`**

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchMethod {
    Generic,
}
```

- [ ] **Step 6: Create `src/datadesc.rs`**

```rust
// placeholder
```

- [ ] **Step 7: Build**

```bash
cargo build
```

Expected: `Finished dev [unoptimized + debuginfo] target(s)`

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml src/
git commit -m "chore: scaffold Rust crate"
```

---

### Task 2: ECU module

**Files:**
- Modify: `src/ecu.rs`

- [ ] **Step 1: Write failing tests — replace `src/ecu.rs` with**

```rust
pub struct EcuDescription {
    pub name: &'static str,
    pub patch_method_prefix: &'static str,
    pub short_pointer_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ecu_sh2() {
        let e = find_ecu("mmc-sh2").unwrap();
        assert_eq!(e.name, "mmc-sh2");
        assert_eq!(e.patch_method_prefix, "[sh-");
        assert_eq!(e.short_pointer_size, 4);
    }

    #[test]
    fn test_find_ecu_m32r() {
        let e = find_ecu("mmc-m32r").unwrap();
        assert_eq!(e.name, "mmc-m32r");
        assert_eq!(e.patch_method_prefix, "[m32r-");
        assert_eq!(e.short_pointer_size, 2);
    }

    #[test]
    fn test_find_ecu_unknown() {
        assert!(find_ecu("unknown").is_none());
    }
}
```

- [ ] **Step 2: Run — confirm they fail**

```bash
cargo test ecu
```

Expected: `error[E0425]: cannot find function 'find_ecu'`

- [ ] **Step 3: Add implementation — append to `src/ecu.rs`**

```rust
static SUPPORTED_ECUS: &[EcuDescription] = &[
    EcuDescription {
        name: "mmc-sh2",
        patch_method_prefix: "[sh-",
        short_pointer_size: 4,
    },
    EcuDescription {
        name: "mmc-m32r",
        patch_method_prefix: "[m32r-",
        short_pointer_size: 2,
    },
];

pub fn find_ecu(name: &str) -> Option<&'static EcuDescription> {
    SUPPORTED_ECUS.iter().find(|e| e.name == name)
}
```

- [ ] **Step 4: Run — confirm they pass**

```bash
cargo test ecu
```

Expected: `test ecu::tests::test_find_ecu_m32r ... ok` (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/ecu.rs
git commit -m "feat: add ECU description table"
```

---

### Task 3: Patch method detection

**Files:**
- Modify: `src/patch.rs`

- [ ] **Step 1: Replace `src/patch.rs` with enum + failing tests**

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatchMethod {
    M32rBl,
    M32rLd24R0,
    M32rLd24R4,
    M32rLduhR1,
    M32rSpliceIntoFunction,
    M32rRelocateSection,
    ShJumpToBody,
    ShSpliceIntoFunction,
    ShRelocateSection,
    Generic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_patch_method_all_markers() {
        assert_eq!(get_patch_method("[m32r-bl].text"),                    PatchMethod::M32rBl);
        assert_eq!(get_patch_method("[m32r-ld24-r0].text"),               PatchMethod::M32rLd24R0);
        assert_eq!(get_patch_method("[m32r-ld24-r4].text"),               PatchMethod::M32rLd24R4);
        assert_eq!(get_patch_method("[m32r-lduh-r1].text"),               PatchMethod::M32rLduhR1);
        assert_eq!(get_patch_method("[m32r-splice-into-function].text"),  PatchMethod::M32rSpliceIntoFunction);
        assert_eq!(get_patch_method("[m32r-relocate-section].text"),      PatchMethod::M32rRelocateSection);
        assert_eq!(get_patch_method("[sh-jump-to-body].text"),            PatchMethod::ShJumpToBody);
        assert_eq!(get_patch_method("[sh-splice-into-function].text"),    PatchMethod::ShSpliceIntoFunction);
        assert_eq!(get_patch_method("[sh-relocate-section].text"),        PatchMethod::ShRelocateSection);
        assert_eq!(get_patch_method("generic_section"),                   PatchMethod::Generic);
        assert_eq!(get_patch_method("data_desc"),                        PatchMethod::Generic);
    }
}
```

- [ ] **Step 2: Confirm fail**

```bash
cargo test patch::tests
```

Expected: `error[E0425]: cannot find function 'get_patch_method'`

- [ ] **Step 3: Add implementation — append to `src/patch.rs`**

```rust
static PATCH_MARKERS: &[(&str, PatchMethod)] = &[
    ("[m32r-bl]",                     PatchMethod::M32rBl),
    ("[m32r-ld24-r0]",                PatchMethod::M32rLd24R0),
    ("[m32r-ld24-r4]",                PatchMethod::M32rLd24R4),
    ("[m32r-lduh-r1]",                PatchMethod::M32rLduhR1),
    ("[m32r-splice-into-function]",   PatchMethod::M32rSpliceIntoFunction),
    ("[m32r-relocate-section]",       PatchMethod::M32rRelocateSection),
    ("[sh-jump-to-body]",             PatchMethod::ShJumpToBody),
    ("[sh-splice-into-function]",     PatchMethod::ShSpliceIntoFunction),
    ("[sh-relocate-section]",         PatchMethod::ShRelocateSection),
];

pub fn get_patch_method(name: &str) -> PatchMethod {
    for (marker, method) in PATCH_MARKERS {
        if name.contains(marker) {
            return *method;
        }
    }
    PatchMethod::Generic
}
```

- [ ] **Step 4: Confirm pass**

```bash
cargo test patch::tests
```

Expected: `test patch::tests::test_get_patch_method_all_markers ... ok`

- [ ] **Step 5: Commit**

```bash
git add src/patch.rs
git commit -m "feat: add PatchMethod enum and detection"
```

---

### Task 4: Main entry point — arg parsing, ROM I/O, ELF dispatch skeleton

**Files:**
- Modify: `src/main.rs`, `src/patch.rs`, `src/datadesc.rs`

- [ ] **Step 1: Replace `src/main.rs` with full skeleton**

```rust
mod datadesc;
mod ecu;
mod patch;

use std::fs;
use object::{Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind};

pub(crate) fn usage_and_exit() -> ! {
    println!("Usage: codeinjector ecu_name original_file injection_file [output_file]");
    println!("\tecu_name - one of supported ecu names: mmc-sh2, mmc-m32r");
    println!("\toriginal_file - binary file of stock ROM");
    println!("\tinjection_file - ELF container with override code");
    std::process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage_and_exit();
    }

    let ecu = ecu::find_ecu(&args[1]).unwrap_or_else(|| {
        println!("{} ecu not supported", args[1]);
        usage_and_exit();
    });

    let ori_buf = fs::read(&args[2]).unwrap_or_else(|_| {
        println!("No original_file");
        usage_and_exit();
    });
    let mut out_buf = ori_buf.clone();

    let injection_data = fs::read(&args[3]).unwrap_or_else(|_| {
        println!("No injection_file");
        usage_and_exit();
    });

    let injection_file = object::File::parse(injection_data.as_slice()).unwrap_or_else(|_| {
        println!("injection_file isn't BFD object");
        usage_and_exit();
    });

    // Build sorted symbol table (mirrors bfd_canonicalize_symtab + qsort)
    let mut symbols: Vec<datadesc::SymInfo> = injection_file
        .symbols()
        .map(|s| datadesc::SymInfo {
            name: s.name().unwrap_or("").to_string(),
            address: s.address(),
            section_index: s.section_index(),
            is_section_sym: s.kind() == SymbolKind::Section,
        })
        .collect();
    symbols.sort_by(|a, b| a.name.cmp(&b.name));

    // Process sections (mirrors bfd_map_over_sections)
    for section in injection_file.sections() {
        let name = match section.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        let section_data = section.data().unwrap_or(&[]);

        if name == "data_desc" {
            datadesc::process_section(section_data, section.index(), &symbols, ecu, &ori_buf);
            continue;
        }

        // Skip sections without SHF_ALLOC (mirrors SEC_LOAD check)
        let loadable = match section.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & 2 != 0,
            _ => false,
        };
        if !loadable {
            continue;
        }

        patch::inject_section(
            &name,
            section.address() as usize,
            section_data,
            ecu,
            &ori_buf,
            &mut out_buf,
        );
    }

    if args.len() > 4 {
        fs::write(&args[4], &out_buf).unwrap_or_else(|_| {
            println!("Can't create output_file");
            usage_and_exit();
        });
    } else {
        use std::io::Write;
        std::io::stdout().write_all(&out_buf).unwrap_or_else(|e| {
            println!("Unable to write contents to output\n: {e}");
        });
    }
}
```

- [ ] **Step 2: Add stub `inject_section` to `src/patch.rs`**

Append to `src/patch.rs`:

```rust
use crate::ecu::EcuDescription;

pub fn inject_section(
    name: &str,
    vma: usize,
    section_data: &[u8],
    ecu: &EcuDescription,
    ori_buf: &[u8],
    out_buf: &mut Vec<u8>,
) {
    // TODO: implement in Tasks 5-8
    let _ = (name, vma, section_data, ecu, ori_buf, out_buf);
}
```

- [ ] **Step 3: Add `SymInfo` and stub `process_section` to `src/datadesc.rs`**

```rust
use object::SectionIndex;
use crate::ecu::EcuDescription;

pub struct SymInfo {
    pub name: String,
    pub address: u64,
    pub section_index: Option<SectionIndex>,
    pub is_section_sym: bool,
}

pub fn process_section(
    _section_data: &[u8],
    _section_index: SectionIndex,
    _symbols: &[SymInfo],
    _ecu: &EcuDescription,
    _ori_buf: &[u8],
) {
    // TODO: implement in Task 9
}
```

- [ ] **Step 4: Build**

```bash
cargo build
```

Expected: `Finished dev [unoptimized + debuginfo] target(s)`

- [ ] **Step 5: Verify usage output**

```bash
./target/debug/codeinjector
```

Expected (exit code 1, to stdout):
```
Usage: codeinjector ecu_name original_file injection_file [output_file]
	ecu_name - one of supported ecu names: mmc-sh2, mmc-m32r
	original_file - binary file of stock ROM
	injection_file - ELF container with override code
```

- [ ] **Step 6: Commit**

```bash
git add src/
git commit -m "feat: add arg parsing, ROM I/O, and ELF section dispatch skeleton"
```

---

### Task 5: PATCH_GENERIC and XML output helpers

**Files:**
- Modify: `src/patch.rs`

- [ ] **Step 1: Replace the `inject_section` stub in `src/patch.rs` with the following** (keep the `PatchMethod` enum, `PATCH_MARKERS`, and `get_patch_method` from Task 3 — only replace the `inject_section` function and add the helpers before it)

```rust
use crate::ecu::EcuDescription;

fn hex_print(data: &[u8]) {
    for b in data {
        print!("{:02x}", b);
    }
}

fn print_patch_xml(
    section_name: &str,
    patch_address: usize,
    patch_size: usize,
    ori_buf: &[u8],
    out_buf: &[u8],
) {
    let scaling_name = format!("{} _scaling", section_name).replace('.', "_");
    println!("<scaling name=\"{}\" storagetype=\"bloblist\">", scaling_name);
    print!("\t<data name=\"Original\" value=\"");
    hex_print(&ori_buf[patch_address..patch_address + patch_size]);
    println!("\" />");
    print!("\t<data name=\"Patched\" value=\"");
    hex_print(&out_buf[patch_address..patch_address + patch_size]);
    println!("\" />\n</scaling>\n");
    println!(
        "<table name=\"{}\" address=\"{:x}\" category=\"Patches\" type=\"1D\" scaling=\"{}\" />\n",
        section_name, patch_address, scaling_name
    );
}

pub fn inject_section(
    name: &str,
    vma: usize,
    section_data: &[u8],
    ecu: &EcuDescription,
    ori_buf: &[u8],
    out_buf: &mut Vec<u8>,
) {
    let method = get_patch_method(name);

    if method != PatchMethod::Generic {
        if !name.contains(ecu.patch_method_prefix) {
            println!("patch_method incompatible with arch at {}", name);
            crate::usage_and_exit();
        }
    }

    let sec_size = section_data.len();
    let (patch_address, patch_size): (usize, usize) = match method {
        PatchMethod::Generic => {
            out_buf[vma..vma + sec_size].copy_from_slice(section_data);
            (vma, sec_size)
        }
        _ => return, // TODO: Tasks 6-8
    };

    print_patch_xml(name, patch_address, patch_size, ori_buf, out_buf);
}
```

- [ ] **Step 2: Build**

```bash
cargo build
```

Expected: `Finished`

- [ ] **Step 3: Smoke-test with a generic patch**

```bash
cd tests
python3 -c "
from fixtures_patch import make_generic_patch_elf
import tempfile, pathlib
p = pathlib.Path(tempfile.mkdtemp())
(p/'rom.bin').write_bytes(b'\x00'*0x10000)
(p/'inj.elf').write_bytes(make_generic_patch_elf(vma=0x1000, payload=b'\xde\xad\xbe\xef'))
import subprocess
r = subprocess.run(['../target/debug/codeinjector','mmc-m32r',str(p/'rom.bin'),str(p/'inj.elf'),str(p/'out.bin')],capture_output=True,text=True)
print('rc:', r.returncode)
print('stdout:', r.stdout[:200])
data = (p/'out.bin').read_bytes()
print('patch:', data[0x1000:0x1004].hex())
"
cd ..
```

Expected: `rc: 0`, patch `deadbeef`, stdout contains `<scaling name="generic_section _scaling"`.

- [ ] **Step 4: Commit**

```bash
git add src/patch.rs
git commit -m "feat: add PATCH_GENERIC, XML output helpers"
```

---

### Task 6: M32R instruction patches (BL, LD24_R0, LD24_R4, LDUH_R1)

**Files:**
- Modify: `src/patch.rs`

- [ ] **Step 1: Add unit tests to `src/patch.rs` — append to the `tests` module**

```rust
    #[test]
    fn test_encode_m32r_bl() {
        // target=0x2000, vma=0x1000 → offset=(0x1000/4)=0x400 → 0xfe000400
        let result = encode_m32r_bl(&[0x00, 0x00, 0x20, 0x00], 0x1000);
        assert_eq!(result.unwrap(), [0xfe, 0x00, 0x04, 0x00]);
        // Wrong size
        assert!(encode_m32r_bl(&[0x00; 8], 0x1000).is_err());
    }

    #[test]
    fn test_encode_m32r_ld24() {
        // target=0x1234 → r0: 0xe0001234, r4: 0xe4001234
        assert_eq!(encode_m32r_ld24(&[0x00, 0x00, 0x12, 0x34], false).unwrap(), [0xe0, 0x00, 0x12, 0x34]);
        assert_eq!(encode_m32r_ld24(&[0x00, 0x00, 0x12, 0x34], true).unwrap(),  [0xe4, 0x00, 0x12, 0x34]);
        assert!(encode_m32r_ld24(&[0x00; 8], false).is_err());
    }

    #[test]
    fn test_encode_m32r_lduh_r1() {
        // target=0x80009000 → disp16=0x1000 → 0xa1bd1000
        assert_eq!(
            encode_m32r_lduh_r1(&[0x80, 0x00, 0x90, 0x00]).unwrap(),
            [0xa1, 0xbd, 0x10, 0x00]
        );
        assert!(encode_m32r_lduh_r1(&[0x00; 8]).is_err());
    }
```

- [ ] **Step 2: Confirm tests fail**

```bash
cargo test patch::tests::test_encode_m32r
```

Expected: `error[E0425]: cannot find function 'encode_m32r_bl'`

- [ ] **Step 3: Add encoding functions to `src/patch.rs`** (before `inject_section`)

```rust
fn encode_m32r_bl(data: &[u8], vma: usize) -> Result<[u8; 4], &'static str> {
    if data.len() != 4 {
        return Err("Invalid bl injection instruction section size");
    }
    let target = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let pc = vma as u32;
    let patch = 0xfe000000u32.wrapping_add(
        target.wrapping_sub(pc).wrapping_div(4) & 0x00ff_ffff,
    );
    Ok(patch.to_be_bytes())
}

fn encode_m32r_ld24(data: &[u8], r4: bool) -> Result<[u8; 4], &'static str> {
    if data.len() != 4 {
        return Err("Invalid ld24 injection instruction section size");
    }
    let target = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let mut patch = 0xe000_0000u32.wrapping_add(target);
    if r4 {
        patch = patch.wrapping_add(4u32 << 24);
    }
    Ok(patch.to_be_bytes())
}

fn encode_m32r_lduh_r1(data: &[u8]) -> Result<[u8; 4], &'static str> {
    if data.len() != 4 {
        return Err("Invalid lduh injection instruction section size");
    }
    let target = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let disp16 = target.wrapping_sub(0x8000_8000) as u16;
    let dst_register: u32 = 1;
    let patch = 0xa0bd_0000u32
        .wrapping_add(dst_register << 24)
        .wrapping_add(disp16 as u32);
    Ok(patch.to_be_bytes())
}
```

- [ ] **Step 4: Confirm encoding tests pass**

```bash
cargo test patch::tests::test_encode_m32r
```

Expected: all 3 tests pass.

- [ ] **Step 5: Wire M32R instruction cases into `inject_section`** — replace the `_ => return` arm with:

```rust
        PatchMethod::M32rBl => {
            let patch = encode_m32r_bl(section_data, vma).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLd24R0 => {
            let patch = encode_m32r_ld24(section_data, false).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLd24R4 => {
            let patch = encode_m32r_ld24(section_data, true).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        PatchMethod::M32rLduhR1 => {
            let patch = encode_m32r_lduh_r1(section_data).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 4].copy_from_slice(&patch);
            (vma, 4)
        }
        _ => return, // TODO: Tasks 7-8
```

- [ ] **Step 6: Build**

```bash
cargo build
```

Expected: `Finished`

- [ ] **Step 7: Commit**

```bash
git add src/patch.rs
git commit -m "feat: implement M32R instruction patches (BL, LD24, LDUH)"
```

---

### Task 7: M32R function patches (SPLICE_INTO_FUNCTION, RELOCATE_SECTION)

**Files:**
- Modify: `src/patch.rs`

- [ ] **Step 1: Add unit tests to the `tests` module in `src/patch.rs`**

```rust
    #[test]
    fn test_encode_m32r_splice() {
        // target_fn=0x2000, target_ret=0x3000, vma=0x1000
        // BL to 0x2000: offset=(0x1000/4)=0x400 → 0xfe000400
        // BCL to 0x3000: offset=(0x3000-0x1004)/4=0x7ff → 0xff0007ff
        let data = [0x00u8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x30, 0x00];
        let result = encode_m32r_splice(&data, 0x1000).unwrap();
        assert_eq!(&result[0..4], &[0xfe, 0x00, 0x04, 0x00]);
        assert_eq!(&result[4..8], &[0xff, 0x00, 0x07, 0xff]);
        assert!(encode_m32r_splice(&[0u8; 4], 0x1000).is_err());
    }
```

- [ ] **Step 2: Confirm tests fail**

```bash
cargo test patch::tests::test_encode_m32r_splice
```

Expected: `error[E0425]: cannot find function 'encode_m32r_splice'`

- [ ] **Step 3: Add encoding function to `src/patch.rs`** (before `inject_section`)

```rust
fn encode_m32r_splice(data: &[u8], vma: usize) -> Result<[u8; 8], &'static str> {
    if data.len() < 8 {
        return Err("Invalid splice injection section size");
    }
    let target1 = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let target2 = u32::from_be_bytes(data[4..8].try_into().unwrap());
    let pc1 = vma as u32;
    let pc2 = vma as u32 + 4;
    let p1 = 0xfe00_0000u32.wrapping_add(
        target1.wrapping_sub(pc1).wrapping_div(4) & 0x00ff_ffff,
    );
    let p2 = 0xff00_0000u32.wrapping_add(
        target2.wrapping_sub(pc2).wrapping_div(4) & 0x00ff_ffff,
    );
    let mut result = [0u8; 8];
    result[0..4].copy_from_slice(&p1.to_be_bytes());
    result[4..8].copy_from_slice(&p2.to_be_bytes());
    Ok(result)
}
```

- [ ] **Step 4: Confirm tests pass**

```bash
cargo test patch::tests::test_encode_m32r_splice
```

Expected: `ok`

- [ ] **Step 5: Wire M32R function cases into `inject_section`** — replace `_ => return` with:

```rust
        PatchMethod::M32rSpliceIntoFunction => {
            let patch = encode_m32r_splice(section_data, vma).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + 8].copy_from_slice(&patch);
            (vma, 8)
        }
        PatchMethod::M32rRelocateSection | PatchMethod::ShRelocateSection => {
            if section_data.len() < 4 {
                return;
            }
            let target = u32::from_be_bytes(section_data[0..4].try_into().unwrap()) as usize;
            out_buf[target..target + section_data.len()].copy_from_slice(section_data);
            (target, section_data.len())
        }
        _ => return, // TODO: Task 8
```

- [ ] **Step 6: Build**

```bash
cargo build
```

Expected: `Finished`

- [ ] **Step 7: Commit**

```bash
git add src/patch.rs
git commit -m "feat: implement M32R splice and relocate patches"
```

---

### Task 8: SH patches (JUMP_TO_BODY, SPLICE_INTO_FUNCTION)

**Files:**
- Modify: `src/patch.rs`

- [ ] **Step 1: Add unit tests to the `tests` module in `src/patch.rs`**

```rust
    #[test]
    fn test_sh_jump_to_body() {
        let target = [0x00u8, 0x00, 0x80, 0x00]; // 0x8000
        let (body, size) = encode_sh_jump_to_body(&target, 0x1000).unwrap(); // aligned
        assert_eq!(size, 12);
        assert_eq!(&body[0..8], &[0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09]);
        assert_eq!(&body[8..12], &[0x00, 0x00, 0x80, 0x00]);

        let (body2, size2) = encode_sh_jump_to_body(&target, 0x1002).unwrap(); // misaligned
        assert_eq!(size2, 14);
        assert_eq!(&body2[0..2], &[0x00, 0x09]); // NOP prefix

        assert!(encode_sh_jump_to_body(&target, 0x1001).is_err()); // bad VMA
    }

    #[test]
    fn test_sh_splice() {
        let data = [0x00u8, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x00]; // 0x5000, 0x6000
        let (body, size) = encode_sh_splice(&data, 0x1000).unwrap();
        assert_eq!(size, 24);
        let expected = [
            0xda_u8, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
            0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
            0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x60, 0x00,
        ];
        assert_eq!(&body[0..24], &expected);
    }
```

- [ ] **Step 2: Confirm tests fail**

```bash
cargo test patch::tests::test_sh
```

Expected: `error[E0425]: cannot find function 'encode_sh_jump_to_body'`

- [ ] **Step 3: Add encoding functions to `src/patch.rs`** (before `inject_section`)

```rust
// Returns (buf, total_patch_size). buf is 14 bytes max; only buf[..size] is valid.
fn encode_sh_jump_to_body(data: &[u8], vma: usize) -> Result<([u8; 14], usize), &'static str> {
    let nop_prefix = match vma % 4 {
        2 => true,
        0 => false,
        _ => return Err("Invalid vma in [sh-jump-to-body]"),
    };
    let mut buf = [0u8; 14];
    let static_body: [u8; 8] = [0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09];
    if nop_prefix {
        buf[0..2].copy_from_slice(&[0x00, 0x09]);
        buf[2..10].copy_from_slice(&static_body);
        buf[10..14].copy_from_slice(&data[0..4]);
        Ok((buf, 14))
    } else {
        buf[0..8].copy_from_slice(&static_body);
        buf[8..12].copy_from_slice(&data[0..4]);
        Ok((buf, 12))
    }
}

// Returns (buf, total_patch_size). buf is 26 bytes max; only buf[..size] is valid.
fn encode_sh_splice(data: &[u8], vma: usize) -> Result<([u8; 26], usize), &'static str> {
    let nop_prefix = match vma % 4 {
        2 => true,
        0 => false,
        _ => return Err("Invalid vma in [sh-jump-to-body]"),
    };
    let static_body: [u8; 16] = [
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
    ];
    let mut buf = [0u8; 26];
    if nop_prefix {
        buf[0..2].copy_from_slice(&[0x00, 0x09]);
        buf[2..18].copy_from_slice(&static_body);
        buf[18..26].copy_from_slice(&data[0..8]);
        Ok((buf, 26))
    } else {
        buf[0..16].copy_from_slice(&static_body);
        buf[16..24].copy_from_slice(&data[0..8]);
        Ok((buf, 24))
    }
}
```

- [ ] **Step 4: Confirm tests pass**

```bash
cargo test patch::tests::test_sh
```

Expected: `test patch::tests::test_sh_jump_to_body ... ok` and `test_sh_splice ... ok`

- [ ] **Step 5: Wire SH cases into `inject_section`** — replace `_ => return` with:

```rust
        PatchMethod::ShJumpToBody => {
            let (buf, size) = encode_sh_jump_to_body(section_data, vma).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + size].copy_from_slice(&buf[0..size]);
            (vma, size)
        }
        PatchMethod::ShSpliceIntoFunction => {
            let (buf, size) = encode_sh_splice(section_data, vma).unwrap_or_else(|e| {
                println!("{}", e);
                crate::usage_and_exit();
            });
            out_buf[vma..vma + size].copy_from_slice(&buf[0..size]);
            (vma, size)
        }
        // ShRelocateSection is handled together with M32rRelocateSection above
        PatchMethod::ShRelocateSection => unreachable!(),
```

Wait — `ShRelocateSection` is already handled in the `M32rRelocateSection | ShRelocateSection` arm from Task 7. The Rust compiler will flag the unreachable arm. Instead, make sure the arm from Task 7 covers both cases, and don't add a separate arm here. The match arms from Task 7 already include `PatchMethod::ShRelocateSection`.

Replace the last `_ => return` (if it's still there) with this to ensure exhaustiveness:

```rust
        PatchMethod::ShRelocateSection => unreachable!(), // covered by M32rRelocateSection arm above
```

Actually, the combined arm from Task 7 is `PatchMethod::M32rRelocateSection | PatchMethod::ShRelocateSection =>`. If both are already there, add only `ShJumpToBody` and `ShSpliceIntoFunction` here, with no remaining `_ => return`. All 10 variants must be covered.

- [ ] **Step 6: Verify all match arms are covered — build must succeed with no warnings about non-exhaustive patterns**

```bash
cargo build 2>&1 | grep -E "error|non-exhaustive"
```

Expected: no output (clean build)

- [ ] **Step 7: Commit**

```bash
git add src/patch.rs
git commit -m "feat: implement SH jump-to-body and splice patches"
```

---

### Task 9: Data descriptor XML

**Files:**
- Modify: `src/datadesc.rs`

- [ ] **Step 1: Replace `src/datadesc.rs` with the full implementation**

```rust
use object::SectionIndex;
use crate::ecu::EcuDescription;

pub struct SymInfo {
    pub name: String,
    pub address: u64,
    pub section_index: Option<SectionIndex>,
    pub is_section_sym: bool,
}

fn get_symbol<'a>(name: &str, symbols: &'a [SymInfo]) -> Option<&'a SymInfo> {
    symbols.iter().find(|s| s.name == name)
}

fn get_data_symbol<'a>(desc_sym_name: &str, symbols: &'a [SymInfo]) -> Option<&'a SymInfo> {
    if desc_sym_name.len() < 3 {
        return None;
    }
    get_symbol(&desc_sym_name[2..], symbols)
}

fn get_data_desc_string(sym_address: u64, section_data: &[u8]) -> Option<String> {
    let offset = sym_address as usize;
    let data = section_data.get(offset..)?;
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).into_owned())
}

#[derive(PartialEq)]
enum DataDescType {
    Unknown,
    Value,
    Array,
    Array3D,
    Map2D8,
    Map3D8,
    Map2D16,
    Map3D16,
    Axis,
    AxisEx,
}

fn get_data_desc_type(s: &str) -> DataDescType {
    match s.splitn(2, ';').next().unwrap_or("") {
        "value"   => DataDescType::Value,
        "array"   => DataDescType::Array,
        "3darray" => DataDescType::Array3D,
        "2dmap8"  => DataDescType::Map2D8,
        "3dmap8"  => DataDescType::Map3D8,
        "2dmap16" => DataDescType::Map2D16,
        "3dmap16" => DataDescType::Map3D16,
        "axis"    => DataDescType::Axis,
        "axisex"  => DataDescType::AxisEx,
        _         => DataDescType::Unknown,
    }
}

fn get_axis_size(rom_addr: usize, ori_buf: &[u8], short_pointer_size: usize) -> u16 {
    let offset = rom_addr + 2 * short_pointer_size;
    if offset + 2 > ori_buf.len() {
        return 0;
    }
    u16::from_be_bytes(ori_buf[offset..offset + 2].try_into().unwrap_or([0, 0]))
}

fn emit_value_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(5, ';');
    let _ty  = p.next().unwrap_or("");
    let cat  = p.next().unwrap_or("");
    let name = p.next().unwrap_or("");
    let scl  = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"1D\" scaling=\"{}\"/>",
        name, cat, data_addr as u32, scl);
}

fn emit_array_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(6, ';');
    let _ty   = p.next().unwrap_or("");
    let cat   = p.next().unwrap_or("");
    let name  = p.next().unwrap_or("");
    let scl   = p.next().unwrap_or("");
    let axdsc = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"2D\" scaling=\"{}\">\n\t{}\n</table>\n",
        name, cat, data_addr as u32, scl, axdsc);
}

fn emit_3darray_data_desc(s: &str, data_addr: u64) {
    let mut p = s.splitn(7, ';');
    let _ty  = p.next().unwrap_or("");
    let cat  = p.next().unwrap_or("");
    let name = p.next().unwrap_or("");
    let scl  = p.next().unwrap_or("");
    let xdsc = p.next().unwrap_or("");
    let ydsc = p.next().unwrap_or("");
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"3D\" scaling=\"{}\">\n\t{}\n\t{}\n</table>\n",
        name, cat, data_addr as u32, scl, xdsc, ydsc);
}

fn emit_axis_ex_desc(
    axis_sym_name: &str,
    axis_type: &str,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let desc_sym = get_symbol(axis_sym_name, symbols);
    let data_sym = desc_sym.and_then(|s| get_data_symbol(&s.name, symbols));

    match (desc_sym, data_sym) {
        (Some(ds), Some(da)) => {
            if let Some(str_val) = get_data_desc_string(ds.address, section_data) {
                let mut p = str_val.splitn(4, ';');
                let _ty  = p.next().unwrap_or("");
                let name = p.next().unwrap_or("");
                let scl  = p.next().unwrap_or("");
                let axis_size = get_axis_size(da.address as usize, ori_buf, short_pointer_size);
                let axis_header = 2 * short_pointer_size + 2;
                println!(
                    "\t<table name=\"{}\" type=\"{} Axis\" address=\"{:x}\" elements=\"{}\" scaling=\"{}\"/>",
                    name, axis_type, da.address as usize + axis_header, axis_size, scl
                );
            }
        }
        _ => {
            println!("\t<table name=\"{}\" type=\"{} Axis\"/>", axis_sym_name, axis_type);
        }
    }
}

fn emit_axis_desc(
    axis_sym_name: &str,
    axis_type: &str,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    if axis_sym_name.as_bytes().get(1) == Some(&b'X') {
        emit_axis_ex_desc(axis_sym_name, axis_type, symbols, section_data, ori_buf, short_pointer_size);
        return;
    }

    let desc_sym = get_symbol(axis_sym_name, symbols);
    let data_sym = desc_sym.and_then(|s| get_data_symbol(&s.name, symbols));

    match (desc_sym, data_sym) {
        (Some(ds), Some(da)) => {
            if let Some(str_val) = get_data_desc_string(ds.address, section_data) {
                let mut p = str_val.splitn(5, ';');
                let _ty   = p.next().unwrap_or("");
                let name  = p.next().unwrap_or("");
                let scl   = p.next().unwrap_or("");
                let size  = p.next().unwrap_or("");
                let axis_header = 2 * short_pointer_size + 2;
                println!(
                    "\t<table name=\"{}\" type=\"{} Axis\" address=\"{:x}\" elements=\"{}\" scaling=\"{}\"/>",
                    name, axis_type, da.address as usize + axis_header, size, scl
                );
            }
        }
        _ => {
            println!("\t<table name=\"{}\" type=\"{} Axis\"/>", axis_sym_name, axis_type);
        }
    }
}

fn emit_2dmap_data_desc(
    s: &str,
    data_addr: u64,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let mut p = s.splitn(6, ';');
    let _ty      = p.next().unwrap_or("");
    let cat      = p.next().unwrap_or("");
    let name     = p.next().unwrap_or("");
    let scl      = p.next().unwrap_or("");
    let axisname = p.next().unwrap_or("").to_string();
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"2D\" scaling=\"{}\">",
        name, cat, data_addr as u32, scl);
    emit_axis_desc(&axisname, "Y", symbols, section_data, ori_buf, short_pointer_size);
    println!("</table>\n");
}

fn emit_3dmap_data_desc(
    s: &str,
    data_addr: u64,
    symbols: &[SymInfo],
    section_data: &[u8],
    ori_buf: &[u8],
    short_pointer_size: usize,
) {
    let mut p = s.splitn(7, ';');
    let _ty       = p.next().unwrap_or("");
    let cat       = p.next().unwrap_or("");
    let name      = p.next().unwrap_or("");
    let scl       = p.next().unwrap_or("");
    let xaxisname = p.next().unwrap_or("").to_string();
    let yaxisname = p.next().unwrap_or("").to_string();
    println!("<table name=\"{}\" category=\"{}\" address=\"{:x}\" type=\"3D\" scaling=\"{}\" swapxy=\"true\">",
        name, cat, data_addr as u32, scl);
    emit_axis_desc(&xaxisname, "X", symbols, section_data, ori_buf, short_pointer_size);
    emit_axis_desc(&yaxisname, "Y", symbols, section_data, ori_buf, short_pointer_size);
    println!("</table>\n");
}

pub fn process_section(
    section_data: &[u8],
    section_index: SectionIndex,
    symbols: &[SymInfo],
    ecu: &EcuDescription,
    ori_buf: &[u8],
) {
    let ptr = ecu.short_pointer_size;

    for sym in symbols.iter().filter(|s| {
        s.section_index == Some(section_index) && !s.is_section_sym
    }) {
        let desc_str = match get_data_desc_string(sym.address, section_data) {
            Some(s) if !s.is_empty() => s,
            _ => {
                println!("<comment>That's strange: unable to find desc string for {}</comment>", sym.name);
                continue;
            }
        };
        let data_sym = match get_data_symbol(&sym.name, symbols) {
            Some(s) => s,
            None => {
                println!("<comment>That's strange: unable to find data symbol for {}</comment>", sym.name);
                continue;
            }
        };
        let da = data_sym.address;

        match get_data_desc_type(&desc_str) {
            DataDescType::Value   => emit_value_data_desc(&desc_str, da),
            DataDescType::Array   => emit_array_data_desc(&desc_str, da),
            DataDescType::Array3D => emit_3darray_data_desc(&desc_str, da),
            DataDescType::Map3D8  => emit_3dmap_data_desc(&desc_str, da + (3 + 2*ptr) as u64, symbols, section_data, ori_buf, ptr),
            DataDescType::Map3D16 => emit_3dmap_data_desc(&desc_str, da + (6 + 2*ptr) as u64, symbols, section_data, ori_buf, ptr),
            DataDescType::Map2D8  => emit_2dmap_data_desc(&desc_str, da + (2 + ptr) as u64,   symbols, section_data, ori_buf, ptr),
            DataDescType::Map2D16 => emit_2dmap_data_desc(&desc_str, da + (4 + ptr) as u64,   symbols, section_data, ori_buf, ptr),
            DataDescType::Axis | DataDescType::AxisEx => { /* skipped explicitly */ }
            DataDescType::Unknown => println!("<comment name=\"{}\">{}</comment>", sym.name, desc_str),
        }
    }
}
```

- [ ] **Step 2: Build**

```bash
cargo build
```

Expected: `Finished`

- [ ] **Step 3: Commit**

```bash
git add src/datadesc.rs
git commit -m "feat: implement data descriptor XML generation"
```

---

### Task 10: Full integration test run

**Files:** none (tests only)

- [ ] **Step 1: Install test dependencies**

```bash
pip3 install pytest
```

- [ ] **Step 2: Run all integration tests against the debug binary**

```bash
cd tests && pytest . --binary ../target/debug/codeinjector -v
```

Expected: all tests pass. If failures occur, investigate each and fix before proceeding.

Common failure modes to check:
- Output format mismatch (extra/missing newlines, hex case) → compare `r.stdout` with C binary output side-by-side
- Off-by-one in address offset formulas in `datadesc.rs` → re-verify against the C `sizeof` expressions
- `SHF_ALLOC` check too broad/narrow → check that non-loadable sections are being skipped

- [ ] **Step 3: Once all tests pass, commit**

```bash
cd ..
git add src/
git commit -m "fix: ensure all integration tests pass against Rust binary"
```

(If no source changes were needed, skip this commit.)

---

### Task 11: maturin packaging

**Files:**
- Create: `pyproject.toml`

- [ ] **Step 1: Install maturin**

```bash
pip3 install "maturin>=1,<2"
maturin --version
```

Expected: `maturin 1.x.y`

- [ ] **Step 2: Create `pyproject.toml`**

```toml
[build-system]
requires = ["maturin>=1,<2"]
build-backend = "maturin"

[project]
name = "codeinjector"
version = "0.1.0"
description = "Code injection tool generating EcuFlash XML fragments to patch ROM files"
requires-python = ">=3.8"

[tool.maturin]
# Binary-only crate: maturin detects [[bin]] in Cargo.toml and includes the binary
```

- [ ] **Step 3: Build the wheel**

```bash
maturin build --release
```

Expected: `📦 Built wheel ... codeinjector-0.1.0-...whl`

- [ ] **Step 4: Install the wheel**

```bash
pip3 install --force-reinstall dist/*.whl
```

- [ ] **Step 5: Verify the installed binary works**

```bash
codeinjector
```

Expected: usage message (exit code 1)

```bash
which codeinjector
```

Expected: path inside your Python environment's `bin/`

- [ ] **Step 6: Run integration tests against the installed binary**

```bash
cd tests && pytest . --binary "$(which codeinjector)" -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
cd ..
git add pyproject.toml
git commit -m "feat: add maturin pyproject.toml for Python wheel packaging"
```

---

### Task 12: Remove C build files

**Files:**
- Delete: `CMakeLists.txt`, `codeinjector-config.cmake`, `main.c`, `supported_ecus.c`, `supported_ecus.h`

- [ ] **Step 1: Remove C source and build files**

```bash
git rm CMakeLists.txt codeinjector-config.cmake main.c supported_ecus.c supported_ecus.h
```

- [ ] **Step 2: Build (sanity check — Rust build must still work)**

```bash
cargo build --release
```

Expected: `Finished release [optimized] target(s)`

- [ ] **Step 3: Final integration test run**

```bash
cd tests && pytest . --binary ../target/release/codeinjector -v
cd ..
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: remove C source files and CMake build system"
```

---

## Self-Review

**Spec coverage:**
- ✅ Rust binary with `object` crate (no libbfd) — Tasks 1–9
- ✅ Full CLI/output compatibility — Task 10 (integration tests)
- ✅ maturin Python wheel packaging — Task 11
- ✅ Remove C files — Task 12
- ✅ All 9 patch methods — Tasks 6–8
- ✅ Data descriptor XML — Task 9

**Placeholder scan:** None found. All code is complete.

**Type consistency:**
- `encode_m32r_bl` defined in Task 6, called in Task 6 inject_section arm ✓
- `encode_m32r_splice` defined in Task 7, called in Task 7 inject_section arm ✓
- `encode_sh_jump_to_body` / `encode_sh_splice` defined in Task 8, called in Task 8 ✓
- `datadesc::SymInfo` defined in Task 4 stub (updated in Task 9), used in `main.rs` Task 4 ✓
- `usage_and_exit` defined in `main.rs` Task 4, called as `crate::usage_and_exit()` in `patch.rs` ✓
- `ShRelocateSection` matched together with `M32rRelocateSection` in Task 7 — the `ShRelocateSection` arm added in Task 8 must be removed (compiler will catch duplicate arm) ✓
