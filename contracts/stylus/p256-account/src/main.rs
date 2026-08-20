// Binary target for `cargo stylus export-abi`, which
// sdk/tooling/scripts/check-abi.sh consumes to detect contract/SDK drift.
//
// `test` belongs in the condition alongside `export-abi`: `cargo test` builds a
// harness for this binary too, and that harness supplies its own `main`.
#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]

#[cfg(feature = "export-abi")]
fn main() {
    p256_account::print_from_args();
}
