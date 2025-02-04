#!/usr/bin/env just --justfile

@_default:
    just --list

# Clean all build artifacts
clean:
    cargo clean

update:
    cargo +nightly -Z unstable-options update --breaking
    cargo update

# Run cargo clippy
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Test code formatting
test-fmt:
    cargo fmt --all -- --check

# Run cargo fmt
fmt:
    cargo +nightly fmt -- --config imports_granularity=Module,group_imports=StdExternalCrate

# Build and open code documentation
docs:
    cargo doc --no-deps --open

# Quick compile
check:
    RUSTFLAGS='-D warnings' cargo check

# Run all tests
test:
    RUSTFLAGS='-D warnings' cargo test

# Test documentation
test-doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

rust-info:
    rustc --version
    cargo --version

# Run all tests as expected by CI
ci-test: rust-info test-fmt clippy check test test-doc
