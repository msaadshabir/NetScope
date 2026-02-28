# Contributing to NetScope

Thanks for considering contributing to NetScope. This document covers the basics of getting set up and submitting changes.

## Getting Started

1. Fork and clone the repository.
2. Install prerequisites (see [Getting Started](docs/getting-started.md)):
   - Rust 1.85+ (edition 2024)
   - libpcap development headers
3. Build and run tests:
   ```bash
   cargo build
   cargo test
   ```

## Development Workflow

1. Create a branch for your change.
2. Make your changes. See the [Development Guide](docs/development.md) for repo layout and code patterns.
3. Run tests: `cargo test`
4. Run benchmarks if your change touches the hot path: `cargo bench`
5. Run `cargo clippy` and `cargo fmt` to catch lint issues and formatting.
6. Submit a pull request with a clear description of what and why.

## What to Contribute

- **Bug fixes** -- always welcome. Include a test case if possible.
- **New protocol parsers** -- follow the zero-copy pattern in `src/protocol/`. See [Development Guide](docs/development.md#adding-a-new-protocol).
- **New anomaly detectors** -- follow the pattern in `src/analysis/anomaly.rs`. See [Development Guide](docs/development.md#adding-a-new-anomaly-detector).
- **Documentation improvements** -- fix errors, add examples, improve clarity.
- **Performance improvements** -- include benchmark comparisons (before/after `cargo bench` output).

## Code Style

- Protocol parsers are zero-copy: `struct FooHeader<'a> { data: &'a [u8] }`.
- Accessor methods are `#[inline]` and read from fixed byte offsets.
- Error types implement `Display` and `std::error::Error`.
- Serialization uses `serde` with `#[serde(rename_all = "snake_case")]`.
- Use `ahash::AHashMap` instead of `std::collections::HashMap` on hot paths.
- Run `cargo fmt` before submitting.

## Testing

- Unit tests live alongside the source code in `#[cfg(test)]` modules.
- Tests should cover: valid parsing, truncated/malformed input, edge cases.
- For protocol parsers, test the minimum valid input and one byte shorter than minimum.

## Pull Request Guidelines

- Keep PRs focused. One feature or fix per PR.
- Include a description of what changed and why.
- If the change is user-facing, update the relevant docs in `docs/`.
- If the change affects performance, include benchmark numbers.

## Reporting Issues

When reporting a bug, include:

- NetScope version (`netscope --version`).
- Operating system and architecture.
- The command you ran.
- Expected vs. actual behavior.
- Relevant log output (run with `-vvv` for full trace logs).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
