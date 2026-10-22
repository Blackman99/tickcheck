# Contributing

Thanks for helping. Two rules shape every change:

1. **tickcheck never starts Python.** No `exec.Command("python", …)`, no `pip`, `uv`, `conda` subprocesses, no importing anything. If a feature seems to need it, open an issue first.
2. **It reads, it doesn't send.** No network code. The IOC feed is embedded; users extend it with `--ioc`.

## Build and test

```sh
go test ./...                 # unit tests, including the demo home
go run ./cmd/tickcheck --demo
bash scripts/real-python.sh   # needs python3 with venv: builds real envs and a poisoned wheel,
                              # checks tickcheck flags it and that no hook ran
```

CI runs all three on Linux, macOS and Windows, plus a census of the runner itself.

## Adding a known pattern

A legitimate hook that keys out REVIEW belongs in `knownHooks` in `internal/census/verdict.go`: a file-name regex, a body regex, and which packages may own it. Add a test with the real file contents (they are short) and a link to where the package ships it.

## Adding an incident

Add it to `internal/census/ioc.json` with `sources` that anyone can check. Hashes must come from those sources or from a file you hashed yourself; say which in the PR. Never commit live malware: the demo and tests use inert stand-ins, except for files that are harmless on their own (like the 12-byte `cook.pth`).

## Style

`gofmt`, no new dependencies without a reason in the PR. Output text is part of the interface: keep it short, say what was checked and what to do next.
