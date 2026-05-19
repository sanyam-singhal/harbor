# Rust Codebase Advice

This document is a project-agnostic operating manual for building consistently
high-quality Rust codebases. It is meant to be copied into new Rust workspaces
or used as standing instructions for coding agents. It combines strict Rust
workspace hygiene, adversarial testing, API design discipline, and systems
engineering common sense.

The goal is not merely "clean code". The goal is code that is correct under
pressure, easy to review, hard to misuse, cheap to operate, and still pleasant
to extend after the original author has forgotten the implementation details.

## Prime Directive

Optimize in this order:

```text
correctness
  -> durability and security
  -> predictable performance
  -> maintainability
  -> developer experience
```

Developer experience matters deeply, but it must serve correctness rather than
hide it. Performance matters early, but not as cleverness. The strongest Rust
codebases are explicit about ownership, failure, resource bounds, and public
contracts.

The working standard is:

```text
understand the domain
  -> model invariants with types
  -> implement a narrow source slice
  -> run fast checks
  -> add adversarial tests
  -> inspect coverage and missing cases
  -> run strict lint/doc gates
  -> stress critical behavior
  -> document the intent
  -> merge only when the repo is better than before
```

## Non-Negotiables

- Safe Rust by default. Use `unsafe_code = "forbid"` unless the project has a
  documented, reviewed, isolated unsafe policy.
- No warning debt. `cargo fmt`, `cargo clippy -- -D warnings`, and rustdoc with
  denied warnings must be clean.
- Public APIs must be documented. Fallible public APIs must document `# Errors`.
  Public panics must document `# Panics`. Unsafe APIs, if any, must document
  `# Safety`.
- Dependencies must earn their place. Prefer the standard library and existing
  workspace crates. Add dependencies only when they remove real complexity or
  risk.
- Tests are adversarial. They should try to break invariants from multiple
  angles, not merely prove that happy paths work.
- Every persistent format, wire format, schema, or public API is a compatibility
  contract. Treat it as such from the first commit.
- Every queue, cache, file, request, batch, retry loop, and background worker
  needs a bound or an explicit reason it cannot be bounded.
- Every phase of work should leave the repository shippable.

## Change Ordering And Test Placement

When replacing, moving, or modularizing code, always land the new writes before
deleting the old ones. Create the new module/file/test target, wire it into the
build, run the narrow check that proves the new path works, and only then remove
the old file or old entry point. Delete-first refactors make interruption,
review, and recovery harder than they need to be.

Tests belong in exactly two places:

- Directly beside the source they test, only when they exercise private
  same-file logic. Keep these tests in the same module scope with `#[cfg(test)]`
  on the test helpers/functions; do not create nested `mod tests`, `use super`,
  or `super::` indirection.
- In the crate-level `tests/` directory when they exercise public APIs,
  cross-module behavior, integration contracts, or behavior spread across
  multiple source files.

Do not add `src/tests.rs`, `src/*/tests.rs`, or test-only module trees inside
production source directories. If a test needs imports from multiple production
modules, it is an integration test and should go through the crate boundary.

## Workspace Foundation

Start with a disciplined workspace layout:

```text
Cargo.toml
Cargo.lock
crates/
  domain-core/
  protocol/
  storage/
  cli/
  test-support/
docs/
scripts/
```

Use workspace-level configuration for shared truth:

- `[workspace.package]` for edition, license, repository, authors, and rust
  version when consistent.
- `[workspace.dependencies]` for dependency versions and feature policy.
- `[workspace.lints]` for Rust, Clippy, and rustdoc lint posture.
- Root `[profile.*]` settings for build behavior. Cargo reads profile settings
  from the workspace root, so do not scatter profile assumptions in crates.
- A single `Cargo.lock` for applications and workspaces that are tested as a
  whole. Libraries may choose whether to commit it, but product workspaces
  should commit it.

Prefer a virtual workspace when there is no single root package. Keep crate
boundaries aligned with architecture, not convenience. A crate is a dependency
boundary and a compilation boundary; a module is a local responsibility boundary.

## Rust Edition And MSRV

- Pick the newest stable edition that the project can reasonably require.
- Declare an MSRV intentionally through `rust-version`.
- Do not casually bump MSRV. Treat it as a compatibility decision.
- If MSRV matters to users, test it explicitly in CI or with a local script.
- Use edition changes to simplify code only after reviewing the migration notes.

## Lint Posture

Use lints as a guardrail, not theater.

Baseline:

```toml
[workspace.lints.rust]
missing_docs = "warn"
unsafe_code = "forbid"
unused_must_use = "deny"

[workspace.lints.rustdoc]
broken_intra_doc_links = "deny"
bare_urls = "deny"

[workspace.lints.clippy]
dbg_macro = "deny"
todo = "deny"
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
```

Guidance:

- Always run Clippy on all targets and all features before merging.
- Do not enable all of `clippy::restriction`, `clippy::nursery`, or
  `clippy::pedantic` blindly. Cherry-pick high-value lints.
- Prefer narrow `#[expect(..., reason = "...")]` over broad `#[allow]`.
- If a lint harms clarity in a specific case, document why the exception is
  better than mechanical compliance.
- Never suppress correctness lints casually.

## Cargo Profiles And Build Bloat

Choose profile settings intentionally:

- `debug = 0` if local disk bloat matters more than debugger convenience.
- `split-debuginfo`, `strip`, and `incremental` should be explicit choices, not
  accidental defaults.
- Keep release and benchmark profiles representative of production behavior.
- Avoid scripts that create large persistent artifacts without documenting where
  they go and how to clean them.
- Use package-scoped checks during drafting to keep feedback fast.
- Use workspace-wide checks at closure to catch dependency and feature issues.

## Dependency Policy

Dependencies are design decisions.

Before adding a dependency, answer:

- What concrete complexity or risk does this remove?
- Is the crate actively maintained?
- Does it pull default features that are irrelevant?
- Does it introduce a runtime, TLS stack, proc macro, C dependency, or build
  script?
- Does it widen the public API if re-exported?
- Is it needed in production, tests, benches, or examples only?
- Can the dependency be kept behind a feature?

Rules:

- Use `default-features = false` unless defaults are wanted.
- Keep dependency declarations centralized in the workspace.
- Keep public APIs insulated from dependency types unless the dependency is part
  of the deliberate public contract.
- Use `cargo tree` to inspect what a dependency really costs.
- For serious products, add supply-chain checks such as `cargo deny` or
  `cargo vet`.

## API Design

APIs should be unsurprising, typed, and hard to misuse.

- Follow the Rust API Guidelines for naming, conversions, traits, docs,
  flexibility, type safety, dependability, debuggability, and future proofing.
- Prefer small public APIs over exposing internal module structure.
- Re-export intentionally from crate roots.
- Keep constructors explicit:
  - `new` for obvious minimal construction;
  - `with_*` for named variants;
  - builders for multi-field configuration;
  - `try_new` or `TryFrom` when validation can fail.
- Use conversion names precisely:
  - `as_` for cheap borrowed views;
  - `to_` for conversion that clones or allocates;
  - `into_` for consuming conversion.
- Implement standard conversion traits when they simplify callers:
  `From`, `TryFrom`, `AsRef`, `Borrow`, `IntoIterator`.
- Derive common traits only when semantically honest:
  `Debug`, `Clone`, `Copy`, `Eq`, `Ord`, `Hash`, `Default`, `Display`.
- Use `#[must_use]` for builders, plans, guards, validation results, and values
  representing deferred work.
- Avoid boolean parameters. Use enums that name the mode.
- Avoid stringly APIs for domain concepts.

Public data structures:

- Keep fields private unless the type is intentionally passive data.
- Use accessors to preserve invariants.
- Use `#[non_exhaustive]` for public enums and structs that may grow.
- Seal traits that are not intended as external implementation points.
- Document sealed traits so users understand the boundary.

## Domain Types

Model the domain before writing algorithms.

Prefer:

```text
UserId over String
ByteCount over u64
SchemaVersion over u32
UnixTimestampMicros over i64
RetryBudget over usize
```

Use newtypes for:

- IDs
- hashes
- versions
- timestamps
- byte counts
- indexes
- limits
- sequence numbers
- offsets
- durations where units matter

Newtypes should usually provide:

- validation at construction;
- explicit unit naming;
- `Display` for stable user-facing formatting;
- `Debug` for developer-facing formatting;
- `From` only for infallible conversions;
- `TryFrom` for validation;
- no implicit lossy conversions.

Avoid primitive confusion:

- An index is not a count.
- A count is not a byte size.
- A capacity is not a current length.
- A timestamp is not a duration.
- A logical ID is not a storage offset.

## Ownership And Borrowing

Take exactly what the function needs:

- `&T` to inspect.
- `&mut T` to mutate in place.
- `T` to store, consume, or cross a boundary.
- `&[T]` instead of `&Vec<T>`.
- `&str` instead of `&String`.
- `impl IntoIterator<Item = T>` when consuming flexible inputs improves callers.

Do not clone to hide a bad API shape. If cloning is necessary, make it visible
at the boundary or explain why the copy is cheap and intentional.

Keep lifetimes boring:

- Let owned values cross persistence, async, thread, and FFI boundaries.
- Use borrowed views inside tight local computations.
- Avoid self-referential structures unless the project truly needs them.
- Do not force callers into lifetime puzzles for ordinary data flow.

Scope variables tightly. Compute values near use. This reduces stale checks,
wrong-variable mistakes, and time-of-check/time-of-use bugs.

## Error Handling

Rust distinguishes recoverable errors from unrecoverable bugs. Respect that
distinction.

Library crates:

- Expose typed errors.
- Prefer `thiserror` for domain errors.
- Avoid `String` or `Box<dyn Error>` as the primary public error type unless the
  crate is explicitly an application edge.
- Error variants should carry recovery-relevant context.
- Preserve source errors with `#[source]` where useful.
- Avoid losing context in `map_err` chains.

Applications, examples, tests, and scripts:

- `anyhow` is fine at aggregation edges.
- Convert typed library errors into user-facing diagnostics near the boundary.
- Return `ExitCode` or a structured CLI error rather than panicking for normal
  user mistakes.

Panic policy:

- Panic for impossible invariant violations and programming bugs.
- Return `Result` for invalid input, I/O failure, bad configuration, unavailable
  services, corrupt external data, and anything a caller can reasonably handle.
- Avoid `unwrap` and `expect` in production code.
- In tests, prefer assertions with clear messages over `unwrap`; if unwrapping
  improves readability, keep it inside test helper functions.

## Assertions And Invariants

Assertions are executable design notes. They should protect assumptions that
must hold for the code to remain correct.

Use:

- `assert!` for invariants that must hold in all builds.
- `debug_assert!` for expensive internal checks that are useful during testing
  but not required for release safety.
- `checked_*`, `saturating_*`, or `wrapping_*` arithmetic deliberately. Do not
  let overflow behavior be accidental.
- Compile-time assertions through `const` checks where stable and clear.

Assert positive and negative space:

- The state you expect.
- The invalid state you reject.
- The transition before and after mutation.
- The invariant before writing and after reading persisted data.

Avoid compound assertions when separate checks would provide clearer failure
signals.

## Unsafe Rust Policy

The default policy is no unsafe code.

If a project allows unsafe, require all of this:

- Unsafe is isolated in the smallest possible module.
- Safe wrappers enforce the contract for all safe callers.
- Every unsafe block has a `SAFETY:` comment explaining the proof.
- Every unsafe function or trait has a `# Safety` rustdoc section.
- `unsafe_op_in_unsafe_fn` is denied so unsafe operations still require explicit
  unsafe blocks inside unsafe functions.
- Miri runs on relevant tests.
- Fuzzing or property tests attack the safe wrapper boundary.
- Code review includes a specific soundness review.

Never use unsafe for ordinary performance speculation. First prove the safe code
is the bottleneck, then benchmark the unsafe alternative, then document why the
safe design cannot meet the requirement.

## Modules And Crates

Split by responsibility:

```text
config
schema
codec
storage
catalog
query
transport
runtime
cli
```

Avoid catch-all modules:

```text
types
utils
common
helpers
misc
```

A good module has one reason to change. A good crate has one architectural role.

Rules:

- Lower-level crates must not depend on higher-level product surfaces.
- Protocol crates should not know about UI or CLI.
- Storage crates should not know about application-specific business behavior.
- Test-support crates may depend upward only if they are clearly test-only.
- Keep serialization mappings close to the types they protect.
- Keep compatibility code explicit and tested.

File order should aid top-down reading:

```text
module docs
imports
constants
public types
public impls
private types
private helpers
tests
```

## Naming

Names are part of the design.

- Use Rust casing:
  - `snake_case` for modules, functions, methods, variables;
  - `UpperCamelCase` for types, traits, enum variants;
  - `SCREAMING_SNAKE_CASE` for constants and statics.
- Use Rust acronym style in type names: `HttpClient`, `Uuid`, `TlsConfig`.
- Do not abbreviate unless the abbreviation is more common than the full word.
- Include units in names: `timeout_ms`, `size_bytes`,
  `created_at_unix_micros`.
- Prefer domain nouns and verbs over generic names.
- Prefer names that make invalid combinations awkward.
- Keep related names in the same word order:
  `latency_ms_min`, `latency_ms_max`, `latency_ms_p99`.
- Avoid overloading one word with multiple domain meanings.

Function names should say what changes:

```text
validate_config
compile_schema
append_frame
flush_segment
replay_log
```

If a helper exists only for one parent function, prefixing it with the parent
name can make the call history easier to inspect.

## Control Flow

Keep control flow explicit and shallow.

- Prefer `match` when all enum states matter.
- Prefer early returns for invalid input and guard conditions.
- Avoid deep nesting.
- Avoid long `else if` chains when a `match` or state enum is clearer.
- Keep functions short enough to fit in working memory. Around 70 lines is a
  useful warning threshold, not a reason to split thoughtlessly.
- Push branching decisions upward and keep leaf helpers focused.
- Keep state mutation centralized when possible; let helpers compute facts.
- Avoid hidden I/O in helpers that look pure.

Use iterators where they clarify intent. Use loops where control flow, early
exit, error handling, or mutation is easier to read.

## State Machines

Use explicit state machines for lifecycle-heavy code:

- parsers;
- WAL and recovery;
- network protocols;
- background workers;
- resource cleanup;
- retries;
- migrations;
- transactions.

Prefer enums over loose booleans:

```rust
enum SegmentState {
    Open,
    Sealed,
    Archived,
}
```

State transition functions should validate:

- current state;
- requested transition;
- side effects required before and after the transition;
- idempotency behavior;
- recovery behavior after interruption.

## Resource Bounds

Bound everything that can grow:

- input length;
- decoded message size;
- queue depth;
- batch size;
- retry count;
- open files;
- concurrent tasks;
- cache capacity;
- log segment size;
- memory used by pending work.

Resource limits should be:

- named;
- documented;
- configurable where appropriate;
- validated at startup;
- enforced at runtime;
- tested at boundaries.

Use hardware sympathy when choosing defaults:

- align batch and buffer sizes with common page, cache, disk, and network
  behavior when it is relevant;
- prefer simple powers of two only when they map to real constraints;
- avoid huge defaults that hide bad backpressure;
- avoid tiny defaults that produce artificial overhead.

## Performance

Performance work starts with a resource sketch.

Estimate:

```text
network: requests/sec, bytes/sec, latency budget
disk: fsync count, sequential vs random I/O, write amplification
memory: live bytes, allocation rate, cache pressure
CPU: parse cost, hashing cost, compression cost, branch behavior
```

Rules:

- Separate control plane from data plane.
- Batch at I/O boundaries.
- Avoid allocation in hot loops.
- Preallocate when final size is known or bounded.
- Keep hot loops simple and local.
- Avoid dynamic dispatch in hot paths unless it buys real architecture.
- Benchmark before and after performance-sensitive changes.
- Benchmark representative workloads, not only microbenchmarks.
- Track throughput and tail latency where latency matters.

Do not contort ordinary code for speculative speed. Mechanical sympathy is not
permission for unreadable code. The best performance changes often come from
better data layout, less work, fewer allocations, and better batching.

## Async And Concurrency

Make async boundaries obvious.

- Do not hide network, filesystem, sleep, or lock acquisition behind innocent
  helper names.
- Avoid holding locks across `.await`.
- Prefer bounded channels.
- Define backpressure behavior.
- Define cancellation behavior.
- Define shutdown behavior.
- Define whether tasks are best-effort or durability-critical.
- Document ordering guarantees.
- Test replay, retries, duplicate messages, and task interruption.

Use `Send` and `Sync` intentionally:

- Let auto traits derive naturally when possible.
- Be suspicious of types that contain interior mutability.
- Do not manually implement `Send` or `Sync` without an unsafe policy.
- Use Loom only for concurrency-critical state machines where schedule
  exploration can find real bugs.

Prefer simple concurrency:

- One owner for mutable state.
- Message passing for boundaries.
- Locks for small, well-scoped critical sections.
- Atomic types only when the invariant is simple enough to explain.

## Persistence And Protocols

Persistent and wire formats require extra discipline.

For every format, document:

- magic bytes or version markers;
- endianness;
- checksums;
- length prefixes and max lengths;
- forward and backward compatibility rules;
- unknown field behavior;
- corruption behavior;
- replay and idempotency behavior;
- atomicity guarantees;
- migration path.

Tests should include:

- golden encodings;
- round trips;
- older fixture compatibility;
- truncated data;
- bad checksums;
- invalid lengths;
- unknown versions;
- duplicate replay;
- partial writes;
- cross-platform assumptions.

Never rely on "the current struct layout" as a persistence format.

## Security And Privacy

Security is not a feature pass at the end.

- Validate all external input at the boundary.
- Parse into typed, validated structures before business logic.
- Avoid logging secrets, tokens, credentials, private keys, and raw PII.
- Make redaction explicit in type names and APIs.
- Treat debug output as potentially user-visible.
- Keep error messages useful without leaking sensitive data.
- Review dependencies for advisories, licenses, maintenance, and build scripts.
- Avoid deserialization formats or options that can allocate unboundedly.
- Use constant-time operations only where the threat model requires them, and
  document that requirement.

## Testing Philosophy

Tests are architecture pressure.

Layer tests by failure mode:

- Happy path: intended workflow works.
- Invalid input: malformed config, bad IDs, impossible state, invalid encoding.
- Boundary input: empty, one, max, near-overflow, timestamp edges.
- Corruption and recovery: truncation, checksum mismatch, missing file, partial
  commit.
- Idempotency and replay: duplicate operations do not corrupt state.
- Compatibility: old fixtures and stable public behavior remain valid.
- Golden tests: generated text, encoded bytes, CLI output, schema summaries.
- Property tests: broad input spaces and shrinking.
- Concurrency tests: ordering, backpressure, cancellation, shutdown.
- Mutation tests: final pressure on test quality.

Unit tests defend local invariants. Integration tests attack crate boundaries.
Doctests keep examples honest. Property tests search spaces humans will not
enumerate. Golden tests protect compatibility.

Coverage is a floor, not the goal. A project can have high coverage and weak
tests. Inspect uncovered regions, but also inspect untested behaviors.

## Test Tooling

Baseline tools:

- `cargo test --workspace --all-features`
- `cargo llvm-cov` for line and region coverage
- `proptest` for large input spaces
- `cargo nextest` for fast isolated test execution when useful
- `cargo mutants` for mutation testing before release or phase closure
- Loom for concurrency-critical code
- Miri for unsafe code and undefined-behavior-sensitive logic
- Fuzzing for parsers, codecs, and protocol boundaries

Use ordinary tests first. Add heavier tools where the risk justifies the cost.
Do not hide slow stress tools in the fast development loop.

## Documentation

Documentation explains intent, invariants, and failure behavior.

Rustdoc should cover:

- what the type or function is for;
- invariants callers can rely on;
- validation rules;
- error behavior;
- panic behavior;
- safety requirements;
- compatibility and persistence implications;
- examples for important public APIs.

Internal comments should explain why, not restate what:

```rust
// Keep the checksum outside the encoded payload so a torn write cannot
// accidentally validate as a shorter frame.
```

Avoid comments like:

```rust
// Increment i.
```

Comments should age well. When code changes, update or remove stale comments.

## Review Discipline

Review in this order:

1. Is the design right?
2. Are the invariants explicit?
3. Are resource bounds enforced?
4. Are errors recoverable where they should be?
5. Are panics limited to bugs?
6. Is the public API hard to misuse?
7. Are compatibility contracts protected?
8. Are dependencies justified?
9. Are tests adversarial enough?
10. Is the code simpler than the problem?

A review that only comments on style has arrived too late or too shallowly.

## Commit And Branch Discipline

- Work on branches, not directly on the protected main branch.
- Keep commits coherent. A commit should have one logical purpose.
- Commit messages should explain what changed and, when useful, why.
- Do not mix refactors with behavior changes unless the refactor is required to
  make the behavior change safe.
- Preserve intermediate commits when they tell a useful implementation story.
- Before merging, run the full gate locally or in CI.

## Local Check Ladder

A serious Rust workspace should standardize a small `scripts/` harness and use
it everywhere. The exact script bodies can evolve by project, but the interface
should stay boring and memorable so humans and coding agents share the same
workflow.

Recommended portable script map:

```text
scripts/check-dev.sh       fast cargo check loop while source is forming
scripts/check-test.sh      cargo test plus coverage for red-team testing
scripts/check.sh           strict closure gate before merge/release
scripts/coverage-report.sh llvm-cov reports written to local ignored files
scripts/stress-mutants.sh  explicit mutation testing, never in the fast loop
scripts/stress-loom.sh     explicit concurrency model checks where relevant
scripts/clean-target.sh    optional disk cleanup after all gates are complete
scripts/read-source-lines.sh source-only orientation without test noise
scripts/read-rust-slice.sh precise item, pattern, or line-range source reads
scripts/count-lines.sh     source/test/dependency size awareness
```

The normal loop should be:

```text
small source slice
  -> scripts/check-dev.sh
  -> repeat until coherent
  -> write adversarial tests
  -> scripts/check-test.sh
  -> inspect coverage report
  -> scripts/check.sh
  -> relevant stress scripts
```

The scripts should wrap commands equivalent to:

```text
dev check:
  cargo check --workspace --all-targets --all-features

test check:
  cargo test --workspace --all-features
  cargo llvm-cov --workspace --all-features

phase/release gate:
  cargo fmt --all --check
  cargo check --workspace --all-targets --all-features
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
  cargo test --workspace --all-features
  coverage gate
  dependency audit
  semver check when publishing libraries
  stress tools relevant to the changed code
```

Keep the fast loop fast. Keep the closure gate strict.

Use `scripts/read-source-lines.sh` whenever the task needs source-level
architecture understanding but not test inspection. Large Rust workspaces often
become mostly tests; source-only orientation preserves attention for module
boundaries, dependency direction, API shape, and duplicated production logic.

Use `scripts/read-rust-slice.sh` after the architecture is understood, usually
after `scripts/read-source-lines.sh` or a crate README has supplied the map, and
the task needs an exact API item, error type, constructor, impl, grep pattern,
or line range. Prefer it over rereading a whole crate when the next decision
hinges on a narrow source contract. Keep the default source-only behavior unless
tests, examples, or benches are explicitly relevant.

## Code Size And Complexity

Track size because growth hides design drift.

Watch:

- source lines by crate;
- test lines by crate;
- dependency count;
- public item count;
- number of feature flags;
- compile time;
- binary size;
- coverage by implementation crate;
- mutation survivors;
- slowest tests.

Large code is not automatically bad, but unexplained growth usually means one
of these:

- repeated validation logic;
- too many public surfaces;
- weak crate boundaries;
- tests compensating for unclear types;
- abstractions introduced before the domain stabilized;
- compatibility behavior scattered instead of centralized.

When code grows, draw the map. If the map is hard to draw, the boundaries are
probably unclear.

## Practical Rust Patterns

Use:

- builders for complex construction;
- newtypes for domain values;
- enums for modes and states;
- RAII guards for cleanup and commit/rollback obligations;
- sealed traits for internal extension points;
- `Cow` only when borrowed-or-owned behavior is truly useful;
- `Arc` only when shared ownership is real;
- `Mutex` only when shared mutable state is unavoidable;
- `OnceLock` or `LazyLock` for global initialization where appropriate;
- `SmallVec`, arenas, or specialized allocators only after measuring and
  documenting the need.

Avoid:

- global mutable state;
- boolean mode parameters;
- accidental cloning;
- catch-all error variants;
- hidden I/O;
- unbounded queues;
- public fields that bypass validation;
- "temporary" compatibility hacks without tests;
- macros where functions or traits are clear enough.

## Feature Flags

Feature flags are part of the public contract for libraries.

- Keep features additive.
- Avoid mutually exclusive features unless absolutely necessary.
- Document every feature.
- Test default features, no default features, and all features.
- Avoid feature leakage from dependencies.
- Do not let features silently change persistence formats or public API
  semantics without clear naming and tests.

## Compatibility And SemVer

For libraries:

- Treat public APIs as SemVer contracts.
- Use `cargo semver-checks` before releases when the crate is public.
- Avoid exposing internal dependency types in public APIs.
- Use private fields and `#[non_exhaustive]` to preserve evolution room.
- Add compatibility fixtures before changing formats.
- Document migration behavior.

For applications:

- Treat config, CLI flags, environment variables, data files, and network
  protocols as compatibility contracts.
- Keep deprecations explicit and tested.

## Final Merge Checklist

Before considering work complete:

- The design has been reread against the original goal.
- The changed source has been reread after edits.
- The public API is documented and minimal.
- Invariants are enforced in types or validation.
- Every external input has limits.
- Every fallible path has a typed or contextual error.
- Tests cover happy, invalid, boundary, and relevant recovery paths.
- Coverage meets the floor for touched implementation crates.
- Formatting, linting, documentation, and tests pass.
- Stress tools have run where relevant.
- Dependencies and feature flags are justified.
- Documentation explains what future maintainers need to know.

## Grounding References

This advice is grounded in current Rust and Rust ecosystem references:

- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/checklist.html
- Rust API Guidelines future proofing:
  https://rust-lang.github.io/api-guidelines/future-proofing.html
- Cargo workspaces: https://doc.rust-lang.org/cargo/reference/workspaces.html
- Cargo profiles: https://doc.rust-lang.org/cargo/reference/profiles.html
- Cargo tests: https://doc.rust-lang.org/cargo/guide/tests.html
- Clippy lint groups: https://doc.rust-lang.org/clippy/lints.html
- rustdoc lints: https://doc.rust-lang.org/rustdoc/lints.html
- Rust error handling:
  https://doc.rust-lang.org/book/ch09-00-error-handling.html
- Rust unsafe keyword:
  https://doc.rust-lang.org/stable/reference/unsafe-keyword.html
- Proptest: https://proptest-rs.github.io/proptest/intro.html
- cargo-nextest: https://www.nexte.st/
- Rustonomicon Send and Sync:
  https://doc.rust-lang.org/nomicon/send-and-sync.html
- Cargo bench:
  https://doc.rust-lang.org/nightly/cargo/commands/cargo-bench.html
