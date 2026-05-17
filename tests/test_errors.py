import subprocess
import pytest
from fixtures_patch import make_generic_patch_elf


def test_too_few_args(binary, tmp_path):
    """Fewer than 4 argv entries triggers usage()."""
    r = subprocess.run([binary], capture_output=True, text=True)
    assert r.returncode != 0
    assert 'Usage:' in r.stdout


def test_unknown_ecu(binary, rom, out, tmp_path):
    """Unrecognised ECU name prints 'ecu not supported'."""
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
