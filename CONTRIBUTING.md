# Contributing

Umbra follows specification-driven development. Do not implement a capability until
there is an approved OpenSpec change under `openspec/changes/`.

Before opening a PR, run the relevant local checks:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo xtask coverage
npx @fission-ai/openspec@latest validate --all --strict
```

## AI-Assisted Contributions

AI-assisted contributions are allowed only when a human contributor fully
understands, reviews, tests, and takes responsibility for the change.

Substantial AI-generated changes must disclose the tool and model used, plus the
scope of generation, in the PR description or commit trailer. Use `Assisted-by:`
for assisted edits and `Generated-by:` for substantial generated artifacts.

Do not submit AI-generated code that you cannot explain, debug, license-check, or
maintain. Do not include secrets, live infrastructure details, unpublished
vulnerabilities, or operational anti-censorship intelligence in prompts, commits,
issues, or PRs.

All contributions must satisfy the project license, dependency policy, test
coverage gate, and security requirements in `AGENTS.md`.
