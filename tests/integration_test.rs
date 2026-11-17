// Integration test for SigmaOS-adler32
// Verifies the crate builds and links as a dependency.
#![allow(unused_imports)]

use adler32 as _;

#[test]
fn crate_links_and_runs() {
    assert_eq!(2 + 2, 4);
}
