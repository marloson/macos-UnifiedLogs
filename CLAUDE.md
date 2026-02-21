# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`macos-unifiedlogs` is a cross-platform Rust library for parsing Apple's macOS Unified Log format (tracev3 files). No Apple APIs are used, so it runs on any platform. Used in digital forensics to extract log data from macOS/iOS systems.

## Build & Test Commands

```bash
cargo build --release                    # Release build
cargo fmt -- --check                     # Format check (CI enforced)
cargo clippy                             # Lint check (CI enforced)
cargo test --release                     # Run tests (requires test data)
cargo test --release <test_name>         # Run a single test
cargo bench                              # Run benchmarks (criterion)
cargo deny check                         # License/advisory/ban checks
```

**Test data is required** before running tests or benchmarks:
```bash
cd tests && wget -O ./test_data.zip https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip && unzip test_data.zip
```

Tests reference logarchive fixtures under `tests/test_data/` (e.g., `system_logs_big_sur.logarchive`). Test files are organized by macOS version: `high_sierra_tests.rs`, `big_sur_tests.rs`, `monterey_tests.rs`.

**Example binary** (separate Cargo workspace in `examples/`):
```bash
cd examples && cargo build --release
# Parse logarchive:  ./target/release/unifiedlog_iterator -m log-archive -i <path.logarchive>
# Parse live system: ./target/release/unifiedlog_iterator -m live
# Parse single file: ./target/release/unifiedlog_iterator -m single-file -i <path.tracev3>
# Output formats: --format csv or --format jsonl (default)
```

## Code Conventions

- **Rust edition 2024**, `#![forbid(unsafe_code)]`
- Strict clippy lints enforced: `cast_lossless`, `cast_possible_wrap`, `checked_conversions`, `unnecessary_cast` are all `#[deny]`
- rustfmt config: Unix newlines, 4-space tabs, 100 char max width, 60 char chain width
- CI runs on macOS (x86_64 + aarch64): `cargo fmt --check`, `cargo clippy`, `cargo test --release`
- Allowed licenses: MIT, Apache-2.0, Unlicense, Unicode-3.0 (enforced via `cargo-deny`)

## Architecture

### Parsing Pipeline

The library parses Apple's binary Unified Log format in stages:

1. **File Discovery** — `FileProvider` trait (`src/traits.rs`) abstracts file access. Two implementations in `src/filesystem.rs`: `LiveSystemProvider` (reads from `/var/db/diagnostics` on live macOS) and `LogarchiveProvider` (reads from a `.logarchive` directory). Custom providers can be implemented for arbitrary storage backends.

2. **Timesync Collection** — `collect_timesync()` in `src/parser.rs` reads `.timesync` files (`src/timesync.rs`) to build a `HashMap<String, TimesyncBoot>` mapping boot UUIDs to timing data needed for timestamp reconstruction.

3. **TraceV3 Parsing** — `parse_log()` in `src/parser.rs` reads raw tracev3 bytes, then `LogData::parse_unified_log()` in `src/unified_log.rs` deconstructs them into `UnifiedLogData`:
   - `src/header.rs` — File header (chunk type `0x1000`)
   - `src/preamble.rs` — Chunk preamble detection (16-byte prefix on every chunk)
   - `src/catalog.rs` — Catalog chunks (`0x600b`) containing process info and subsystem metadata
   - `src/chunkset.rs` — Chunkset chunks (`0x600d`) wrapping LZ4-compressed firehose data

4. **Chunk Iteration** — `UnifiedLogIterator` (`src/iterator.rs`) implements `Iterator<Item = UnifiedLogData>`, yielding one catalog's worth of data per iteration. Consumers loop through chunks per tracev3 file.

5. **Log Reconstruction** — `build_log()` in `src/parser.rs` takes `UnifiedLogData` + provider + timesync data and produces `Vec<LogData>` (the final output structs). This is where UUIDs are resolved to strings and messages are assembled.

### Chunk Types (`src/chunks/`)

- **`firehose/`** — The primary log entry format, with subtypes:
  - `nonactivity.rs` — Standard log entries (Default, Info, Debug, Error, Fault)
  - `activity.rs` — Activity create/transition entries
  - `signpost.rs` — Performance signpost entries (begin/end/event at process/system/thread scope)
  - `trace.rs` — Trace entries
  - `loss.rs` — Lost log entry markers
  - `firehose_log.rs` — `Firehose` struct and `FirehosePreamble` parsing
  - `flags.rs` — Firehose flag constants
  - `message.rs` — Firehose-level message item extraction
- **`oversize.rs`** — Oversize entries (large strings that don't fit in normal firehose entries). These can span across tracev3 files, requiring cross-file accumulation.
- **`simpledump.rs`** / **`statedump.rs`** — Diagnostic dump entries

### Message Assembly (`src/message.rs`)

Reconstructs human-readable log messages from printf-style format strings (from UUID/DSC files) combined with binary data items from firehose entries. Handles format specifiers: `%d/%i/%u` (int), `%f/%e/%g` (float), `%x/%p` (hex), `%s/%@` (string), `%m` (error code — output as numeric, not resolved to text).

### String Resolution

Log messages are stored as format strings in two external file types:
- **UUID text files** (`src/uuidtext.rs`) — Per-binary string tables in `/var/db/uuidtext/XX/`
- **DSC (Shared Cache Strings)** (`src/dsc.rs`) — Shared library string tables in `/var/db/uuidtext/dsc/`

Both are cached by `FileProvider` implementations and resolved at runtime via UUID lookups during `build_log()`.

### Decoders (`src/decoders/`)

Type-specific decoders invoked by the message formatter for custom Apple log objects. Each handles a specific `%{...}` custom format specifier:
- `bool.rs`, `uuid.rs`, `time.rs` — Basic type formatting
- `darwin.rs` — Darwin/XNU kernel types (errno, signal names, etc.)
- `dns.rs` — DNS record formatting
- `network.rs` — IP addresses, sockaddr structures
- `location.rs` — CoreLocation data
- `opendirectory.rs` — OpenDirectory types
- `config.rs` — Maps custom decoder names to implementations

### Key Types

- `UnifiedLogData` — Raw parsed tracev3 data (headers, catalog data, oversize entries)
- `LogData` — Final reconstructed log entry (timestamp, PID, message, subsystem, category, etc.) — serializable via serde
- `LogType` — Enum: Debug, Info, Default, Error, Fault, plus signpost/dump/loss variants
- `FileProvider` / `SourceFile` — Traits for abstracting file access (implement these for custom storage)

### Oversize String Handling

A key complexity: some log entries reference oversize strings stored in different tracev3 files. The example binary demonstrates the pattern — accumulate oversize entries across files, then re-process any entries that had missing data in a second pass.

---

## Working with Claude

### Claude Code Integration
This repository is configured to work with [Claude Code](https://claude.ai/code). The instructions in this file help Claude understand the project structure, conventions, and how to work effectively within this codebase.

### Key Principles for AI Assistance
- Always run `cargo clippy` and `cargo fmt` after making changes
- Never skip or delete tests to make the suite pass
- Prefer fixing root causes over patching symptoms
- Keep changes minimal and focused — avoid unrelated refactors
- When in doubt about behavior, check existing tests for examples

### Common Tasks

**Adding a new decoder:**
1. Create `src/decoders/<name>.rs`
2. Implement the decode function
3. Register it in `src/decoders/config.rs`
4. Add tests

**Adding support for a new log chunk type:**
1. Add a new file in `src/chunks/`
2. Implement parsing logic
3. Wire it into `src/unified_log.rs`
4. Add test fixtures and tests

**Debugging a test failure:**
1. Run the specific test: `cargo test --release <test_name> -- --nocapture`
2. Check the test fixture under `tests/test_data/`
3. Trace the parsing pipeline from the relevant chunk type

### Environment Setup
- Rust stable toolchain required
- Test data must be downloaded before running tests (see Build & Test Commands above)
- `cargo-deny` required for license checks: `cargo install cargo-deny`
