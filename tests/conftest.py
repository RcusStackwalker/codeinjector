# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Aleksei Markelov

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
