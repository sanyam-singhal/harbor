//! Build script for Harbor SQLx migration assets.

fn main() {
    println!("cargo:rerun-if-changed=migrations/sqlite");
}
