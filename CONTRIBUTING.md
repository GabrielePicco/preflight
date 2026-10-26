# Contributing

Keep changes focused and explain the behavior they fix. Use stable Rust and run:

```sh
cargo fmt --check
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
./demo/demo.sh
```

Use synthetic HOME directories and config fixtures in tests. Never commit real
tokens, personal configs, project paths, or screenshots of a real setup. Use
`demo/demo.sh` for screenshots and recordings. The only demo payload is the
display-only canary already in that script; never execute it.

Open a focused PR and leave merging to the maintainer. For vulnerabilities,
follow [SECURITY.md](SECURITY.md). Repository visibility, release tags, package
publishing, and public announcements require explicit maintainer approval.
