# Contributing

Keep changes focused and explain the behavior they fix. Use stable Rust and run:

```sh
cargo fmt --check
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Use synthetic HOME directories and config fixtures in tests. Never commit real
tokens, personal configs, or private project paths.

For vulnerabilities, follow [SECURITY.md](SECURITY.md).
