#!/usr/bin/env bash
set -euo pipefail

# cargo-llvm-cov locates llvm-cov/llvm-profdata via the active rustc sysroot.
# When the active rustc comes from Homebrew (which lacks these tools) but a
# rustup toolchain with llvm-tools is available, point cargo-llvm-cov at the
# rustup toolchain's copies explicitly.
if ! cargo llvm-cov show-env --sh >/dev/null 2>&1; then
    if command -v rustup >/dev/null 2>&1; then
        sysroot=$(rustup run stable rustc --print sysroot 2>/dev/null)
        target=$(rustup run stable rustc -vV 2>/dev/null | sed -n 's/^host: //p')
        export LLVM_COV="$sysroot/lib/rustlib/$target/bin/llvm-cov"
        export LLVM_PROFDATA="$sysroot/lib/rustlib/$target/bin/llvm-profdata"
    fi
fi

source <(cargo llvm-cov show-env --sh 2>/dev/null)
cargo build
pytest tests/ --binary ./target/debug/codeinjector -v
cargo llvm-cov report --summary-only
