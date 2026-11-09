// Security release regression gate for RUSTSEC-2026-0459.
// The crate bundles SQLite, so the actual linked runtime version matters.
#[test]
fn bundled_sqlite_is_patched_against_wal_page_size_memory_disclosure() {
    const FIRST_FIXED_SQLITE_VERSION: i32 = 3_054_000; // SQLite 3.54.0
    let linked_version = rusqlite::version_number();
    assert!(
        linked_version >= FIRST_FIXED_SQLITE_VERSION,
        "bundled SQLite {linked_version} predates the RUSTSEC-2026-0459 fix (3.54.0)"
    );

    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let runtime_version: String = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rusqlite::version(), runtime_version);
}
