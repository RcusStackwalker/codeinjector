# Integration Tests & Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pytest integration tests driven by a Python ELF fixture generator, and gcov coverage reporting in CI, establishing a behavioral baseline for a future rewrite.

**Architecture:** pytest invokes `codeinjector` as a subprocess. A Python `ELFBuilder` class constructs minimal big-endian 32-bit ELF object files using Python's `struct` module — no cross-compiler needed. Coverage is measured on Linux via GCC `--coverage` flag + `gcovr`, written to the GitHub Actions job summary via `$GITHUB_STEP_SUMMARY`.

**Tech Stack:** Python 3 (`struct`, `subprocess`, `pytest`), GCC `--coverage`, `gcovr`, CMake `Coverage` build type.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `tests/elf_builder.py` | Create | ELF binary format constants, pack helpers, `ELFBuilder` class |
| `tests/fixtures_patch.py` | Create | Generator functions for each patch-method ELF fixture |
| `tests/fixtures_datadesc.py` | Create | Generator functions for data-descriptor ELF fixtures |
| `tests/conftest.py` | Create | `--binary` CLI option, pytest fixtures, `run()` helper |
| `tests/test_errors.py` | Create | Error path tests (wrong args, bad ECU, missing files, etc.) |
| `tests/test_patch_methods.py` | Create | One test per patch method × ECU |
| `tests/test_data_descs.py` | Create | One test per descriptor type + axis coverage |
| `tests/.gitignore` | Create | Ignore `fixtures/` directory |
| `CMakeLists.txt` | Modify | Add `Coverage` build type |
| `.github/workflows/pr.yml` | Modify | Add `test-coverage` job |
| `main.c` | Modify | Annotate truly unreachable paths with `LCOV_EXCL` |

---

## ELF Fixture Reference

All fixtures produce big-endian 32-bit ET_REL ELF files (`e_ident[5]=2, e_class=1, e_type=1`).

**Patch-section ELF layout:**
- 1 section with the patch-marker name (e.g. `[m32r-bl]`)
- `sh_flags = SHF_ALLOC` → BFD sets `SEC_LOAD`
- `sh_addr = vma` → `sect->vma` used as ROM address
- `.shstrtab` added automatically by `ELFBuilder.build()`

**Data-desc ELF layout:**
- `data_desc` section — concatenated null-terminated descriptor strings
- `.strtab` — symbol name strings
- `.symtab` — descriptor symbols (`st_shndx = data_desc`) and data symbols (`st_shndx = SHN_ABS`)
- `.shstrtab` automatic

**Patch byte expected values** (all big-endian, ROM initialized to `b'\x00' * 0x10000`):

| Method | vma | input bytes | ROM[vma:vma+N] |
|--------|-----|-------------|-----------------|
| M32R_BL | 0x1000 | htobe32(0x2000) | `fe 00 04 00` ← `0xfe000000 + ((0x2000-0x1000)/4)` |
| M32R_LD24_R0 | 0x1000 | htobe32(0x1234) | `e0 00 12 34` |
| M32R_LD24_R4 | 0x1000 | htobe32(0x1234) | `e4 00 12 34` |
| M32R_LDUH_R1 | 0x1000 | htobe32(0x80009000) | `a1 bd 10 00` ← `0xa0bd0000+(1<<24)+(0x80009000-0x80008000)` |
| M32R_SPLICE | 0x1000 | htobe32(0x2000)+htobe32(0x3000) | `fe 00 04 00 ff 00 07 ff` |
| M32R_RELOCATE | 0x1000 | htobe32(0x2000)+`de ad be ef` | ROM[0x2000:0x2008]=`00 00 20 00 de ad be ef` |
| SH_JUMP aligned | 0x1000 | htobe32(0x8000) | `d0 01 40 2b 00 09 00 09 00 00 80 00` |
| SH_JUMP misalign | 0x1002 | htobe32(0x8000) | ROM[0x1002]=`00 09`, ROM[0x1004:0x1010]=`d0 01 40 2b 00 09 00 09 00 00 80 00` |
| SH_SPLICE aligned | 0x1000 | htobe32(0x5000)+htobe32(0x6000) | `da 03 4a 0b 00 09 00 09 d0 02 40 2b 00 09 00 09 00 00 50 00 00 00 60 00` |
| SH_SPLICE misalign | 0x1002 | htobe32(0x5000)+htobe32(0x6000) | ROM[0x1002]=`00 09`, ROM[0x1004:0x101c]=same 24 bytes |
| SH_RELOCATE | 0x1000 | htobe32(0x2000)+`de ad be ef` | ROM[0x2000:0x2008]=`00 00 20 00 de ad be ef` |
| PATCH_GENERIC | 0x1000 | `de ad be ef` | ROM[0x1000:0x1004]=`de ad be ef` |

---

## Task 1: Scaffold

**Files:**
- Create: `tests/.gitignore`
- Create: `tests/` (directory structure)

- [ ] **Step 1: Create `tests/.gitignore`**

```
fixtures/
__pycache__/
*.pyc
.pytest_cache/
```

- [ ] **Step 2: Commit**

```bash
git add tests/.gitignore
git commit -m "test: scaffold tests directory"
```

---

## Task 2: ELF Builder (`tests/elf_builder.py`)

**Files:**
- Create: `tests/elf_builder.py`

- [ ] **Step 1: Write `tests/elf_builder.py`**

```python
"""Minimal big-endian 32-bit ELF object file builder."""
import struct

# ELF identity
ELFMAG       = b'\x7fELF'
ELFCLASS32   = 1
ELFDATA2MSB  = 2
EV_CURRENT   = 1

# e_type
ET_REL = 1

# e_machine
EM_SH   = 0x0002
EM_M32R = 0x0058

# sh_type
SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3

# sh_flags
SHF_ALLOC = 0x2

# st_info binding / type
STB_LOCAL  = 0
STB_GLOBAL = 1
STT_OBJECT = 1

# st_shndx special values
SHN_UNDEF = 0
SHN_ABS   = 0xfff1

EHDR_SIZE = 52   # ELF32 header
SHDR_SIZE = 40   # ELF32 section header
SYM_SIZE  = 16   # ELF32 symbol table entry


def _pack_ehdr(machine, shoff, shnum, shstrndx):
    e_ident = (ELFMAG +
               bytes([ELFCLASS32, ELFDATA2MSB, EV_CURRENT]) +
               b'\x00' * 9)
    return struct.pack('>16sHHIIIIIHHHHHH',
        e_ident,
        ET_REL, machine,
        EV_CURRENT,
        0,          # e_entry
        0,          # e_phoff
        shoff,
        0,          # e_flags
        EHDR_SIZE,
        0, 0,       # e_phentsize, e_phnum
        SHDR_SIZE,
        shnum,
        shstrndx,
    )


def _pack_shdr(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
               sh_link=0, sh_info=0, sh_addralign=4, sh_entsize=0):
    return struct.pack('>IIIIIIIIII',
        sh_name, sh_type, sh_flags, sh_addr,
        sh_offset, sh_size, sh_link, sh_info,
        sh_addralign, sh_entsize,
    )


def pack_sym(st_name, st_value, st_size, st_info, st_other, st_shndx):
    return struct.pack('>IIIBBH',
        st_name, st_value, st_size, st_info, st_other, st_shndx,
    )


class ELFBuilder:
    """Builds a minimal big-endian 32-bit ET_REL ELF."""

    def __init__(self, machine):
        self.machine = machine
        self._sections = []

    def add_section(self, name, data, sh_type=SHT_PROGBITS, sh_flags=SHF_ALLOC,
                    sh_addr=0, sh_link=0, sh_info=0, sh_entsize=0, sh_addralign=4):
        """Add a section and return its 1-based section index."""
        idx = 1 + len(self._sections)
        self._sections.append(dict(
            name=name, data=data, sh_type=sh_type, sh_flags=sh_flags,
            sh_addr=sh_addr, sh_link=sh_link, sh_info=sh_info,
            sh_entsize=sh_entsize, sh_addralign=sh_addralign,
        ))
        return idx

    def build(self):
        # Build .shstrtab — contains names of all sections + itself
        shstrtab = b'\x00'
        name_offsets = {}

        def _strtab_add(name):
            nonlocal shstrtab
            if name not in name_offsets:
                name_offsets[name] = len(shstrtab)
                shstrtab += name.encode() + b'\x00'

        for s in self._sections:
            _strtab_add(s['name'])
        _strtab_add('.shstrtab')

        shstrndx = 1 + len(self._sections)   # null + user sections + shstrtab
        total_shnum = shstrndx + 1

        # Lay out: ELF header | section data... | shstrtab | section headers
        buf = bytearray(EHDR_SIZE)
        section_offsets = []

        for s in self._sections:
            align = s['sh_addralign']
            if align > 1 and len(buf) % align:
                buf += b'\x00' * (align - len(buf) % align)
            section_offsets.append(len(buf))
            buf += s['data']

        # shstrtab
        if len(buf) % 4:
            buf += b'\x00' * (4 - len(buf) % 4)
        shstrtab_offset = len(buf)
        buf += shstrtab

        # section headers
        if len(buf) % 4:
            buf += b'\x00' * (4 - len(buf) % 4)
        shoff = len(buf)

        # null section header
        buf += _pack_shdr(0, SHT_NULL, 0, 0, 0, 0)

        for i, s in enumerate(self._sections):
            buf += _pack_shdr(
                name_offsets[s['name']], s['sh_type'], s['sh_flags'], s['sh_addr'],
                section_offsets[i], len(s['data']),
                s['sh_link'], s['sh_info'], s['sh_addralign'], s['sh_entsize'],
            )

        # .shstrtab header
        buf += _pack_shdr(
            name_offsets['.shstrtab'], SHT_STRTAB, 0, 0,
            shstrtab_offset, len(shstrtab),
            0, 0, 1, 0,
        )

        # Patch ELF header at offset 0
        buf[:EHDR_SIZE] = _pack_ehdr(self.machine, shoff, total_shnum, shstrndx)
        return bytes(buf)
```

- [ ] **Step 2: Verify builder produces a parseable ELF**

```bash
cd /path/to/codeinjector
python3 - <<'EOF'
import struct, sys
sys.path.insert(0, 'tests')
from elf_builder import ELFBuilder, EM_M32R, SHF_ALLOC
b = ELFBuilder(EM_M32R)
b.add_section('[m32r-bl]', b'\x00\x00\x20\x00', sh_flags=SHF_ALLOC, sh_addr=0x1000)
data = b.build()
assert data[:4] == b'\x7fELF', "bad magic"
assert data[5] == 2, "not big-endian"
assert len(data) > 52, "too short"
print("OK, %d bytes" % len(data))
EOF
```
Expected: `OK, N bytes` (N > 52).

- [ ] **Step 3: Commit**

```bash
git add tests/elf_builder.py
git commit -m "test: add ELF builder"
```

---

## Task 3: Patch ELF Fixtures (`tests/fixtures_patch.py`)

**Files:**
- Create: `tests/fixtures_patch.py`

- [ ] **Step 1: Write `tests/fixtures_patch.py`**

```python
"""Generator functions for patch-method ELF fixtures."""
import struct
from elf_builder import ELFBuilder, EM_M32R, EM_SH, SHF_ALLOC


def _be32(v):
    return struct.pack('>I', v)


def make_m32r_bl_elf(vma=0x1000, target=0x2000):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-bl]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_ld24_r0_elf(vma=0x1000, target=0x1234):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-ld24-r0]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_ld24_r4_elf(vma=0x1000, target=0x1234):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-ld24-r4]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_lduh_r1_elf(vma=0x1000, target=0x80009000):
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-lduh-r1]', _be32(target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_splice_elf(vma=0x1000, target_fn=0x2000, target_ret=0x3000):
    b = ELFBuilder(EM_M32R)
    data = _be32(target_fn) + _be32(target_ret)
    b.add_section('[m32r-splice-into-function]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_m32r_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_M32R)
    data = _be32(target) + payload
    b.add_section('[m32r-relocate-section]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_jump_to_body_elf(vma=0x1000, jump_target=0x8000):
    b = ELFBuilder(EM_SH)
    b.add_section('[sh-jump-to-body]', _be32(jump_target), sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_splice_elf(vma=0x1000, target_fn=0x5000, target_ret=0x6000):
    b = ELFBuilder(EM_SH)
    data = _be32(target_fn) + _be32(target_ret)
    b.add_section('[sh-splice-into-function]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_sh_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_SH)
    data = _be32(target) + payload
    b.add_section('[sh-relocate-section]', data, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_generic_patch_elf(vma=0x1000, payload=b'\xde\xad\xbe\xef'):
    b = ELFBuilder(EM_M32R)
    b.add_section('generic_section', payload, sh_flags=SHF_ALLOC, sh_addr=vma)
    return b.build()


def make_invalid_size_elf():
    """[m32r-bl] with 8 bytes instead of required 4 — triggers size error."""
    b = ELFBuilder(EM_M32R)
    b.add_section('[m32r-bl]', b'\x00' * 8, sh_flags=SHF_ALLOC, sh_addr=0x1000)
    return b.build()


def make_incompatible_method_elf():
    """[sh-jump-to-body] section used with mmc-m32r ECU — triggers incompatible error."""
    b = ELFBuilder(EM_M32R)
    b.add_section('[sh-jump-to-body]', b'\x00' * 4, sh_flags=SHF_ALLOC, sh_addr=0x1000)
    return b.build()


def make_bad_sh_vma_elf():
    """[sh-jump-to-body] with vma % 4 == 1 — triggers invalid VMA error."""
    b = ELFBuilder(EM_SH)
    b.add_section('[sh-jump-to-body]', b'\x00' * 4, sh_flags=SHF_ALLOC, sh_addr=0x1001)
    return b.build()
```

- [ ] **Step 2: Verify each generator returns bytes**

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, 'tests')
from fixtures_patch import *
for fn in [make_m32r_bl_elf, make_m32r_ld24_r0_elf, make_m32r_ld24_r4_elf,
           make_m32r_lduh_r1_elf, make_m32r_splice_elf, make_m32r_relocate_elf,
           make_sh_jump_to_body_elf, make_sh_splice_elf, make_sh_relocate_elf,
           make_generic_patch_elf, make_invalid_size_elf,
           make_incompatible_method_elf, make_bad_sh_vma_elf]:
    data = fn()
    assert data[:4] == b'\x7fELF', fn.__name__
    print(fn.__name__, len(data), 'bytes OK')
EOF
```
Expected: each line prints `<name> N bytes OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures_patch.py
git commit -m "test: add patch-method ELF fixture generators"
```

---

## Task 4: Data Descriptor ELF Fixtures (`tests/fixtures_datadesc.py`)

**Files:**
- Create: `tests/fixtures_datadesc.py`

Background: the `data_desc` section holds null-terminated descriptor strings. Each descriptor symbol's `st_value` is the byte offset of its string within the section. Each descriptor symbol's name minus its first two chars is the corresponding data symbol name. Data symbols use `SHN_ABS` with an arbitrary ROM address.

- [ ] **Step 1: Write `tests/fixtures_datadesc.py`**

```python
"""Generator functions for data-descriptor ELF fixtures."""
from elf_builder import (ELFBuilder, EM_M32R, SHT_SYMTAB, SHT_STRTAB,
                          SHF_ALLOC, STB_GLOBAL, STT_OBJECT, SHN_UNDEF,
                          SHN_ABS, SYM_SIZE, pack_sym)


def _build_strtab(names):
    """Return (bytes, dict[name -> offset]) for an ELF string table."""
    strtab = b'\x00'
    offsets = {}
    for n in names:
        if n not in offsets:
            offsets[n] = len(strtab)
            strtab += n.encode() + b'\x00'
    return strtab, offsets


def make_data_desc_elf(descriptors, machine=EM_M32R):
    """
    Build a data_desc ELF.

    descriptors: list of dicts, each with:
      'desc_sym'   : descriptor symbol name, e.g. 'd_val'
      'desc_str'   : semicolon-delimited descriptor, e.g. 'value;Cat;Name;scl'
      'data_addr'  : absolute ROM address for the data symbol
                     (data sym name = desc_sym[2:])
    Extra symbols (for axes referenced by map descriptors) can be injected via
    the same descriptor list — just include an entry for each axis symbol too.
    """
    b = ELFBuilder(machine)

    # Build data_desc section content
    desc_section = b''
    str_offsets = []
    for d in descriptors:
        str_offsets.append(len(desc_section))
        desc_section += d['desc_str'].encode() + b'\x00'

    data_desc_idx = b.add_section(
        'data_desc', desc_section,
        sh_type=1,  # SHT_PROGBITS
        sh_flags=0, sh_addr=0,
    )

    # Build symbol string table
    all_names = []
    for d in descriptors:
        all_names.append(d['desc_sym'])
        all_names.append(d['desc_sym'][2:])  # data symbol
    strtab, strtab_offsets = _build_strtab(all_names)

    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                                sh_flags=0, sh_addralign=1)

    # Build symbol table: index 0 = undefined, then pairs (desc_sym, data_sym)
    symtab = pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)  # STN_UNDEF
    for i, d in enumerate(descriptors):
        desc_sym_name = d['desc_sym']
        data_sym_name = desc_sym_name[2:]
        info = (STB_GLOBAL << 4) | STT_OBJECT

        # Descriptor symbol: in data_desc section at str_offsets[i]
        symtab += pack_sym(
            strtab_offsets[desc_sym_name],
            str_offsets[i],   # st_value = offset into data_desc section
            0, info, 0,
            data_desc_idx,
        )
        # Data symbol: absolute
        symtab += pack_sym(
            strtab_offsets[data_sym_name],
            d['data_addr'],
            0, info, 0,
            SHN_ABS,
        )

    # sh_info = 1 (all symbols are global; first global at index 1)
    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)

    return b.build()


def make_no_symtab_datadesc_elf():
    """data_desc section with no .symtab — exercises storage_needed==0 branch."""
    b = ELFBuilder(EM_M32R)
    b.add_section('data_desc', b'value;Cat;Name;scl\x00',
                  sh_type=1, sh_flags=0)
    return b.build()


def make_missing_data_sym_elf():
    """Descriptor whose data symbol (desc_sym[2:]) is absent from the table."""
    b = ELFBuilder(EM_M32R)
    desc_section = b'value;Cat;Name;scl\x00'
    data_desc_idx = b.add_section('data_desc', desc_section, sh_type=1, sh_flags=0)

    strtab = b'\x00d_orphan\x00'
    strtab_offsets = {'d_orphan': 1}
    strtab_idx = b.add_section('.strtab', strtab, sh_type=SHT_STRTAB,
                                sh_flags=0, sh_addralign=1)

    info = (STB_GLOBAL << 4) | STT_OBJECT
    symtab = pack_sym(0, 0, 0, 0, 0, SHN_UNDEF)
    symtab += pack_sym(strtab_offsets['d_orphan'], 0, 0, info, 0, data_desc_idx)

    b.add_section('.symtab', symtab, sh_type=SHT_SYMTAB, sh_flags=0,
                  sh_link=strtab_idx, sh_info=1, sh_entsize=SYM_SIZE)
    return b.build()
```

- [ ] **Step 2: Verify generator**

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, 'tests')
from fixtures_datadesc import make_data_desc_elf, make_no_symtab_datadesc_elf

elf = make_data_desc_elf([
    {'desc_sym': 'd_val', 'desc_str': 'value;Cat;Name;scl', 'data_addr': 0x1234},
])
assert elf[:4] == b'\x7fELF'
print('make_data_desc_elf OK', len(elf), 'bytes')

elf2 = make_no_symtab_datadesc_elf()
assert elf2[:4] == b'\x7fELF'
print('make_no_symtab_datadesc_elf OK', len(elf2), 'bytes')
EOF
```
Expected: two OK lines.

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures_datadesc.py
git commit -m "test: add data-descriptor ELF fixture generators"
```

---

## Task 5: pytest Infrastructure (`tests/conftest.py`)

**Files:**
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `tests/conftest.py`**

```python
import os
import subprocess
import pytest


ROM_SIZE = 0x10000  # 64 KB, all zeros


def pytest_addoption(parser):
    parser.addoption('--binary', required=True,
                     help='Path to the codeinjector binary under test')


@pytest.fixture(scope='session')
def binary(request):
    path = request.config.getoption('--binary')
    assert os.path.isfile(path), f'Binary not found: {path}'
    return os.path.abspath(path)


@pytest.fixture
def rom(tmp_path):
    """64 KB ROM file, all zeros."""
    p = tmp_path / 'rom.bin'
    p.write_bytes(b'\x00' * ROM_SIZE)
    return p


@pytest.fixture
def out(tmp_path):
    """Path for the output ROM."""
    return tmp_path / 'out.bin'


def run(binary, ecu, rom_path, injection_bytes, out_path, tmp_path):
    """
    Write injection_bytes to a temp file, run codeinjector, return
    (CompletedProcess, output_rom_bytes_or_None).
    """
    inj = tmp_path / 'injection.elf'
    inj.write_bytes(injection_bytes)
    result = subprocess.run(
        [binary, ecu, str(rom_path), str(inj), str(out_path)],
        capture_output=True, text=True,
    )
    rom_out = out_path.read_bytes() if out_path.exists() else None
    return result, rom_out


@pytest.fixture
def run_ci(binary, rom, out, tmp_path):
    """Convenience fixture: partial application of run() bound to session binary."""
    def _run(ecu, injection_bytes):
        return run(binary, ecu, rom, injection_bytes, out, tmp_path)
    return _run
```

- [ ] **Step 2: Smoke-test conftest import**

```bash
cd /path/to/codeinjector
python3 -c "import sys; sys.path.insert(0,'tests'); import conftest; print('OK')"
```
Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py
git commit -m "test: add pytest conftest with binary fixture and run helper"
```

---

## Task 6: Error Tests (`tests/test_errors.py`)

**Files:**
- Create: `tests/test_errors.py`

- [ ] **Step 1: Write `tests/test_errors.py`**

```python
import subprocess
import pytest


def test_too_few_args(binary, tmp_path):
    """Fewer than 4 argv entries triggers usage()."""
    r = subprocess.run([binary], capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Usage:' in r.stdout


def test_unknown_ecu(binary, rom, out, tmp_path):
    """Unrecognised ECU name prints 'ecu not supported'."""
    from conftest import run
    inj = tmp_path / 'dummy.elf'
    inj.write_bytes(b'\x00' * 4)
    r = subprocess.run(
        [binary, 'bad-ecu', str(rom), str(inj), str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert 'ecu not supported' in r.stdout


def test_original_file_missing(binary, out, tmp_path):
    """Non-existent ROM path prints 'No original_file'."""
    inj = tmp_path / 'dummy.elf'
    inj.write_bytes(b'\x00' * 4)
    r = subprocess.run(
        [binary, 'mmc-m32r', str(tmp_path / 'no_such_rom.bin'),
         str(inj), str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert 'No original_file' in r.stdout


def test_injection_file_missing(binary, rom, out, tmp_path):
    """Non-existent injection path prints 'No injection_file'."""
    r = subprocess.run(
        [binary, 'mmc-m32r', str(rom),
         str(tmp_path / 'no_such.elf'), str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert 'No injection_file' in r.stdout


def test_output_file_unwritable(binary, rom, tmp_path):
    """Unwritable output path prints 'Can't create output_file'."""
    import sys; sys.path.insert(0, 'tests')
    from fixtures_patch import make_generic_patch_elf
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_generic_patch_elf())
    r = subprocess.run(
        [binary, 'mmc-m32r', str(rom), str(inj),
         '/dev/null/cannot_create'],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "Can't create output_file" in r.stdout


def test_non_elf_injection(binary, rom, out, tmp_path):
    """Random bytes as injection file → 'injection_file isn't BFD object'."""
    inj = tmp_path / 'not_elf.bin'
    inj.write_bytes(b'\xde\xad\xbe\xef' * 16)
    r = subprocess.run(
        [binary, 'mmc-m32r', str(rom), str(inj), str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode != 0
    assert "isn't BFD object" in r.stdout
```

- [ ] **Step 2: Run error tests (binary must exist — use a coverage build)**

```bash
# Build first (plain build; coverage build done in Task 9)
cmake -B build -S . && cmake --build build --parallel
pytest tests/test_errors.py --binary=build/codeinjector -v
```
Expected: all 6 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_errors.py
git commit -m "test: add error-path integration tests"
```

---

## Task 7: Patch Method Tests (`tests/test_patch_methods.py`)

**Files:**
- Create: `tests/test_patch_methods.py`

- [ ] **Step 1: Write `tests/test_patch_methods.py`**

```python
import sys, struct
sys.path.insert(0, 'tests')
import pytest
from fixtures_patch import (
    make_m32r_bl_elf, make_m32r_ld24_r0_elf, make_m32r_ld24_r4_elf,
    make_m32r_lduh_r1_elf, make_m32r_splice_elf, make_m32r_relocate_elf,
    make_sh_jump_to_body_elf, make_sh_splice_elf, make_sh_relocate_elf,
    make_generic_patch_elf, make_invalid_size_elf,
    make_incompatible_method_elf, make_bad_sh_vma_elf,
)


def _be32(v):
    return struct.pack('>I', v)


# ---------- M32R ----------

def test_m32r_bl(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_bl_elf(vma=0x1000, target=0x2000))
    assert r.returncode == 0
    # BL: 0xfe000000 + ((0x2000 - 0x1000) / 4) = 0xfe000400
    assert rom[0x1000:0x1004] == bytes([0xfe, 0x00, 0x04, 0x00])
    assert '<scaling name="[m32r-bl] _scaling"' in r.stdout
    assert '<table name="[m32r-bl]"' in r.stdout


def test_m32r_ld24_r0(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_ld24_r0_elf(vma=0x1000, target=0x1234))
    assert r.returncode == 0
    # 0xe0000000 + 0x1234
    assert rom[0x1000:0x1004] == bytes([0xe0, 0x00, 0x12, 0x34])


def test_m32r_ld24_r4(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_ld24_r4_elf(vma=0x1000, target=0x1234))
    assert r.returncode == 0
    # 0xe0000000 + 0x1234 + (4 << 24) = 0xe4001234
    assert rom[0x1000:0x1004] == bytes([0xe4, 0x00, 0x12, 0x34])


def test_m32r_lduh_r1(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_lduh_r1_elf(vma=0x1000, target=0x80009000))
    assert r.returncode == 0
    # disp16 = 0x80009000 - 0x80008000 = 0x1000
    # patch = 0xa0bd0000 + (1<<24) + 0x1000 = 0xa1bd1000
    assert rom[0x1000:0x1004] == bytes([0xa1, 0xbd, 0x10, 0x00])


def test_m32r_splice(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_splice_elf(vma=0x1000, target_fn=0x2000, target_ret=0x3000))
    assert r.returncode == 0
    # BL to 0x2000: 0xfe000000 + ((0x2000-0x1000)/4) = 0xfe000400
    # BCL to 0x3000: 0xff000000 + ((0x3000-0x1004)/4) = 0xff000000 + 0x7ff = 0xff0007ff
    assert rom[0x1000:0x1008] == bytes([0xfe, 0x00, 0x04, 0x00, 0xff, 0x00, 0x07, 0xff])


def test_m32r_relocate(run_ci):
    r, rom = run_ci('mmc-m32r', make_m32r_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    # Data copied to ROM[0x2000]; first 4 bytes are the target address itself
    assert rom[0x2000:0x2008] == b'\x00\x00\x20\x00\xde\xad\xbe\xef'


# ---------- SH ----------

def test_sh_jump_to_body_aligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_jump_to_body_elf(vma=0x1000, jump_target=0x8000))
    assert r.returncode == 0
    expected = bytes([0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
                      0x00, 0x00, 0x80, 0x00])
    assert rom[0x1000:0x100c] == expected


def test_sh_jump_to_body_misaligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_jump_to_body_elf(vma=0x1002, jump_target=0x8000))
    assert r.returncode == 0
    # NOP prefix at 0x1002, then 12-byte body at 0x1004
    assert rom[0x1002:0x1004] == bytes([0x00, 0x09])
    assert rom[0x1004:0x1010] == bytes([0xd0, 0x01, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
                                         0x00, 0x00, 0x80, 0x00])


def test_sh_splice_aligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_splice_elf(vma=0x1000, target_fn=0x5000, target_ret=0x6000))
    assert r.returncode == 0
    expected = bytes([
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
        0x00, 0x00, 0x50, 0x00,
        0x00, 0x00, 0x60, 0x00,
    ])
    assert rom[0x1000:0x1018] == expected


def test_sh_splice_misaligned(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_splice_elf(vma=0x1002, target_fn=0x5000, target_ret=0x6000))
    assert r.returncode == 0
    assert rom[0x1002:0x1004] == bytes([0x00, 0x09])
    expected_body = bytes([
        0xda, 0x03, 0x4a, 0x0b, 0x00, 0x09, 0x00, 0x09,
        0xd0, 0x02, 0x40, 0x2b, 0x00, 0x09, 0x00, 0x09,
        0x00, 0x00, 0x50, 0x00,
        0x00, 0x00, 0x60, 0x00,
    ])
    assert rom[0x1004:0x101c] == expected_body


def test_sh_relocate(run_ci):
    r, rom = run_ci('mmc-sh2', make_sh_relocate_elf(vma=0x1000, target=0x2000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    assert rom[0x2000:0x2008] == b'\x00\x00\x20\x00\xde\xad\xbe\xef'


def test_generic_patch(run_ci):
    r, rom = run_ci('mmc-m32r', make_generic_patch_elf(vma=0x1000, payload=b'\xde\xad\xbe\xef'))
    assert r.returncode == 0
    assert rom[0x1000:0x1004] == b'\xde\xad\xbe\xef'


# ---------- Error branches in inject_section ----------

def test_invalid_bl_size(binary, rom, out, tmp_path):
    """[m32r-bl] with 8 bytes → 'Invalid bl injection instruction section size'."""
    import subprocess
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_invalid_size_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Invalid bl injection instruction section size' in r.stdout


def test_incompatible_method(binary, rom, out, tmp_path):
    """[sh-jump-to-body] with mmc-m32r → 'patch_method incompatible'."""
    import subprocess
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_incompatible_method_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'patch_method incompatible' in r.stdout


def test_bad_sh_vma(binary, rom, out, tmp_path):
    """[sh-jump-to-body] with vma%4==1 → 'Invalid vma'."""
    import subprocess
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_bad_sh_vma_elf())
    r = subprocess.run([binary, 'mmc-sh2', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Invalid vma' in r.stdout
```

- [ ] **Step 2: Run patch method tests**

```bash
pytest tests/test_patch_methods.py --binary=build/codeinjector -v
```
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_patch_methods.py
git commit -m "test: add patch method integration tests"
```

---

## Task 8: Data Descriptor Tests (`tests/test_data_descs.py`)

**Files:**
- Create: `tests/test_data_descs.py`

- [ ] **Step 1: Write `tests/test_data_descs.py`**

```python
import sys, subprocess
sys.path.insert(0, 'tests')
import pytest
from fixtures_datadesc import (
    make_data_desc_elf, make_no_symtab_datadesc_elf, make_missing_data_sym_elf,
)


def _run_datadesc(binary, rom, out, tmp_path, descriptors, ecu='mmc-m32r', **kw):
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_data_desc_elf(descriptors, **kw))
    r = subprocess.run([binary, ecu, str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    return r


def test_value(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_val', 'desc_str': 'value;Cat;ValName;scl', 'data_addr': 0x1234},
    ])
    assert r.returncode == 0
    assert 'type="1D"' in r.stdout
    assert 'ValName' in r.stdout
    assert '1234' in r.stdout


def test_array(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_arr', 'desc_str': 'array;Cat;ArrName;scl;<table inline/>', 'data_addr': 0x2000},
    ])
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout
    assert 'ArrName' in r.stdout
    assert '<table inline/>' in r.stdout


def test_3darray(binary, rom, out, tmp_path):
    r = _run_datadesc(binary, rom, out, tmp_path, [
        {'desc_sym': 'd_3a', 'desc_str': '3darray;Cat;3DArr;scl;<xaxis/>;< yaxis/>', 'data_addr': 0x3000},
    ])
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout
    assert '3DArr' in r.stdout


def test_2dmap8(binary, rom, out, tmp_path):
    # Map descriptor references axis symbol 'd_ax8'
    # Axis descriptor: axis;AxName;ax_scl;8
    descriptors = [
        {'desc_sym': 'd_m8',  'desc_str': '2dmap8;Cat;Map8;map_scl;d_ax8', 'data_addr': 0x2000},
        {'desc_sym': 'd_ax8', 'desc_str': 'axis;AxName;ax_scl;8',           'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout
    assert 'Map8' in r.stdout
    assert 'AxName' in r.stdout


def test_3dmap8(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m38',  'desc_str': '3dmap8;Cat;Map38;scl;d_xax;d_yax', 'data_addr': 0x2000},
        {'desc_sym': 'd_xax',  'desc_str': 'axis;XAx;x_scl;4',                  'data_addr': 0x3000},
        {'desc_sym': 'd_yax',  'desc_str': 'axis;YAx;y_scl;8',                  'data_addr': 0x4000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout
    assert 'Map38' in r.stdout


def test_2dmap16(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m16',  'desc_str': '2dmap16;Cat;Map16;scl;d_a16', 'data_addr': 0x2000},
        {'desc_sym': 'd_a16',  'desc_str': 'axis;A16;a16_scl;4',           'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="2D"' in r.stdout


def test_3dmap16(binary, rom, out, tmp_path):
    descriptors = [
        {'desc_sym': 'd_m316', 'desc_str': '3dmap16;Cat;Map316;scl;d_x16;d_y16', 'data_addr': 0x2000},
        {'desc_sym': 'd_x16',  'desc_str': 'axis;X16;x16_scl;4',                   'data_addr': 0x3000},
        {'desc_sym': 'd_y16',  'desc_str': 'axis;Y16;y16_scl;8',                   'data_addr': 0x4000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'type="3D"' in r.stdout


def test_axis_skipped(binary, rom, out, tmp_path):
    """Standalone axis descriptor produces no output (skipped explicitly)."""
    descriptors = [
        {'desc_sym': 'd_ax', 'desc_str': 'axis;AxName;scl;8', 'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'AxName' not in r.stdout


def test_axisex_skipped(binary, rom, out, tmp_path):
    """Standalone axisex descriptor produces no output (skipped explicitly)."""
    descriptors = [
        {'desc_sym': 'd_axex', 'desc_str': 'axisex;AxExName;scl', 'data_addr': 0x3000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert 'AxExName' not in r.stdout


def test_axisex_in_map(binary, rom, out, tmp_path):
    """Axis with name[1]=='X' triggers emit_axis_ex_desc; reads axis size from ROM."""
    # d_Xax: 'X' at index 1 → axisex path; data sym = 'ax'
    # ROM[0x3000+4] = uint16 big-endian axis size = 5
    import struct
    # Build a rom with the axis size embedded
    rom_data = bytearray(0x10000)
    struct.pack_into('>H', rom_data, 0x3004, 5)   # short_pointer_size=2 for M32R → offset+4

    rom_path = tmp_path / 'rom.bin'
    rom_path.write_bytes(bytes(rom_data))

    descriptors = [
        {'desc_sym': 'd_m8x',  'desc_str': '2dmap8;Cat;MapX;scl;d_Xax', 'data_addr': 0x2000},
        {'desc_sym': 'd_Xax',  'desc_str': 'axisex;XAxName;ax_scl',       'data_addr': 0x3000},
    ]
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_data_desc_elf(descriptors))
    r = subprocess.run(
        [binary, 'mmc-m32r', str(rom_path), str(inj), str(tmp_path / 'out.bin')],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert 'XAxName' in r.stdout
    assert 'elements="5"' in r.stdout


def test_unknown_desc_type(binary, rom, out, tmp_path):
    """Unknown type → <comment> output."""
    descriptors = [
        {'desc_sym': 'd_unk', 'desc_str': 'unknown_type;Cat;Name;scl', 'data_addr': 0x1000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    assert '<comment' in r.stdout


def test_no_symtab(binary, rom, out, tmp_path):
    """data_desc ELF with no .symtab → storage_needed==0 branch, no output."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_no_symtab_datadesc_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0


def test_missing_data_sym(binary, rom, out, tmp_path):
    """Desc symbol whose data symbol is absent → <comment> for 'unable to find data symbol'."""
    inj = tmp_path / 'inj.elf'
    inj.write_bytes(make_missing_data_sym_elf())
    r = subprocess.run([binary, 'mmc-m32r', str(rom), str(inj), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert 'unable to find data symbol' in r.stdout


def test_axis_missing_symbols(binary, rom, out, tmp_path):
    """Map descriptor references axis symbol that doesn't exist → fallback <table> tag."""
    descriptors = [
        {'desc_sym': 'd_m8m', 'desc_str': '2dmap8;Cat;MapMiss;scl;d_Zmissing', 'data_addr': 0x2000},
    ]
    r = _run_datadesc(binary, rom, out, tmp_path, descriptors)
    assert r.returncode == 0
    # emit_axis_desc falls back to: <table name="d_Zmissing" type="Y Axis"/>
    assert 'd_Zmissing' in r.stdout
```

- [ ] **Step 2: Run data descriptor tests**

```bash
pytest tests/test_data_descs.py --binary=build/codeinjector -v
```
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_data_descs.py
git commit -m "test: add data descriptor integration tests"
```

---

## Task 9: LCOV Exclusions in `main.c`

**Files:**
- Modify: `main.c`

Two blocks in `main.c` are structurally unreachable at integration level:
1. `print_table()` — defined but never called from `main()`.
2. `storage_needed < 0` and `number_of_symbols < 0` in `data_desc_generator` — BFD never returns negative from a well-formed ELF.

- [ ] **Step 1: Annotate `main.c`**

Find `print_table` and wrap it (lines ~48–80 in current file):

```c
/* LCOV_EXCL_START */
void print_table()
{
    ...
}
/* LCOV_EXCL_STOP */
```

Find the two negative-return guards in `data_desc_generator` (~lines 388–400):

```c
	if (storage_needed < 0)
		return; /* LCOV_EXCL_LINE */
	...
	if (number_of_symbols < 0)
		return; /* LCOV_EXCL_LINE */
```

- [ ] **Step 2: Confirm annotations are in place**

```bash
grep -n 'LCOV_EXCL' main.c
```
Expected: 4+ lines showing the exclusion markers.

- [ ] **Step 3: Commit**

```bash
git add main.c
git commit -m "chore: annotate unreachable paths with LCOV_EXCL"
```

---

## Task 10: CMake Coverage Build Type

**Files:**
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Add Coverage build type after `project(codeinjector)`**

Open `CMakeLists.txt`. After the line `project(codeinjector)` add:

```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    set(COVERAGE_FLAGS --coverage -O0 -g)
    add_compile_options(${COVERAGE_FLAGS})
    add_link_options(--coverage)
endif()
```

- [ ] **Step 2: Verify coverage build compiles locally**

```bash
cmake -B build-cov -S . -DCMAKE_BUILD_TYPE=Coverage
cmake --build build-cov --parallel
ls build-cov/codeinjector
```
Expected: binary exists.

- [ ] **Step 3: Commit**

```bash
git add CMakeLists.txt
git commit -m "build: add Coverage cmake build type"
```

---

## Task 11: CI Workflow Update (`.github/workflows/pr.yml`)

**Files:**
- Modify: `.github/workflows/pr.yml`

- [ ] **Step 1: Add `test-coverage` job to `pr.yml`**

Append to the `jobs:` section (keep existing `build` matrix job unchanged):

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

      - name: Run tests
        run: pytest tests/ --binary=build/codeinjector -v

      - name: Report coverage
        run: |
          gcovr \
            --root . \
            --exclude 'build/.*' \
            --exclude 'tests/.*' \
            --output-format markdown \
            >> $GITHUB_STEP_SUMMARY
```

- [ ] **Step 2: Verify YAML syntax**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/pr.yml'))" && echo "YAML OK"
```
Expected: `YAML OK`.

- [ ] **Step 3: Commit and push**

```bash
git add .github/workflows/pr.yml
git commit -m "ci: add test-coverage job with gcovr reporting"
git push origin stackwalker/macos
```

---

## Task 12: Verify End-to-End

- [ ] **Step 1: Run full test suite locally against the coverage build**

```bash
pytest tests/ --binary=build-cov/codeinjector -v
```
Expected: all tests PASS, no failures.

- [ ] **Step 2: Run gcovr locally to preview coverage**

```bash
gcovr --root . --exclude 'build.*' --exclude 'tests/.*' --output-format markdown
```
Expected: markdown table showing coverage per file. Aim for ≥95% line coverage on `main.c` and `supported_ecus.c`; gaps indicate missing test cases.

- [ ] **Step 3: Check CI run passes**

After pushing in Task 11, open the PR and verify the `test-coverage` job passes and the GitHub Actions job summary shows a coverage table.
