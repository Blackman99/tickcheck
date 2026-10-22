# What runs every time Python starts, and why pip is the wrong first check

LiteLLM 1.107.0, published to PyPI and Docker Hub on 2026-10-21, dropped three files into the root of site-packages: a 12-byte `cook.pth` containing `import cook`, a `cook.py`, and a `sitecustomize.py`. None of them needs to be imported by your code. Python runs them on its own, on every interpreter start in that environment. This article explains the mechanism, why the usual first response makes things worse, and how tickcheck sorts what it finds into BAD, SUSPECT, REVIEW and OK.

## How `.pth` startup hooks work

When the interpreter starts, the `site` module walks each site-packages directory and reads every file ending in `.pth`, in alphabetical order. For each line:

- blank lines and lines starting with `#` are skipped;
- a line that starts with `import` followed by a space or a tab is executed as Python code;
- any other line is treated as a directory and appended to `sys.path` if it exists.

The executable-line rule exists for legitimate reasons. setuptools ships `distutils-precedence.pth` to install its distutils shim, editable installs (PEP 660) use `__editable__.*.pth`, old namespace packages use `-nspkg.pth`, and virtualenv and uv write `_virtualenv.pth`. Because the line only has to *start* with `import`, it can import a module and then run arbitrary statements after a semicolon.

Two more files are loaded the same way: `sitecustomize` (from anywhere on `sys.path`) and `usercustomize` (from the user site, when enabled). They can be a `.py` module, a package, a compiled extension or a sourceless `.pyc`. Debian/Ubuntu and Homebrew both ship a `sitecustomize.py` of their own.

All of this happens before `-c`, before your script, before any console entry point. `python -S` disables it, but almost nothing you run day to day passes `-S`.

## Why pip is the wrong first check

`pip` is a Python program. `pip show litellm`, `pip list`, `pip uninstall litellm`, and any scanner written in Python all start that interpreter, and the interpreter runs the startup hooks before doing what you asked. In an environment with the LiteLLM drop, the step that is supposed to confirm the infection runs the payload once more.

The published advisories say the same thing in practice: they tell you to look through site-packages with shell tools like `find` rather than with pip, and they warn that some `.pth` and `sitecustomize.py` files are legitimate, so a hit is not automatically bad. That leaves two problems: there are many site-packages directories on a typical developer machine (every venv, conda env, pipx and uv tool, pyenv and uv-managed Python, the user site, the system install, project `.venv`s in agent worktrees), and deciding which hooks belong needs more than a file listing.

tickcheck is a single Go binary with no dependencies outside the Go standard library. It never starts a Python interpreter. It finds environments by their files (`pyvenv.cfg`, known install layouts) and reads hook files and package metadata as text.

## How tickcheck decides a verdict

For every executable hook (a `.pth` file with at least one `import` line, or a `sitecustomize`/`usercustomize`), tickcheck also resolves the modules that line imports, finds which installed distribution lists each file in its `*.dist-info/RECORD`, and checks the file's sha256 against the RECORD entry. Then it assigns the worst verdict that applies.

**BAD**: the sha256 of the hook, or of a module it loads, is in the IOC feed; or the owning package name and version is listed there (for example `litellm 1.107.0`). Host markers from the feed (such as `/tmp/remote_code_loader.lock`) and a live Linux process holding that lock also count as BAD. The built-in feed covers the LiteLLM 1.107.0 drop, and `--ioc FILE` adds a new incident without a new release.

**SUSPECT**: any of
- payload signals in the hook or a module it imports: an encoded blob (base64, zlib, marshal and similar) passed to `exec`/`eval`/`compile`, a very long encoded literal, process spawning, network calls, `fork`/`setsid`, or references to credential paths such as `~/.aws/credentials`;
- the file no longer matches the sha256 recorded in its package's RECORD;
- the hook's name has nothing to do with the package that installed it, as with litellm installing `cook.pth`.

A poisoned entry in a pip or uv cache is at least SUSPECT.

**REVIEW**: the hook runs at startup and tickcheck cannot vouch for it, but there are no payload signals. Either the file is in no installed package's RECORD, or it is plain code from a package that does not match a known pattern.

**OK**: a known pattern from its own package with a matching RECORD hash: the setuptools distutils shim, editable installs, `-nspkg.pth`, the virtualenv/uv venv patch, pywin32, coverage, and the Debian apport and Homebrew `sitecustomize.py`.

The signals are regular-expression matches over the file text. Nothing is decoded, imported or executed. The signal check runs before the known-pattern check, so a file with a familiar name that carries a payload, for example a `_virtualenv.py` that calls `subprocess`, still comes out SUSPECT. An environment takes the worst verdict among its hooks, and the worst overall sets the exit code: 4 for BAD, 3 for SUSPECT, 0 otherwise.

When a hook is BAD, tickcheck also looks for the command that installed the package in local Claude Code, Codex, OpenCode and Gemini CLI transcripts and in shell history, and lists which credential files the stealer would have found on that machine (by existence only, never read). `tickcheck pull` then moves the BAD hooks and their `__pycache__` copies into a quarantine directory with a manifest, again without starting Python, and `tickcheck restore` puts them back.

## What this was tested on

tickcheck has not been run on a machine actually infected by LiteLLM 1.107.0. It was tested on a defanged replica: `tickcheck --demo` generates a home directory with seven environments and a LiteLLM 1.107.0 drop whose `cook.pth` is byte-identical to the real 12-byte file, while `cook.py` is a harmless stand-in. The CI suite also builds real venvs and installs a real wheel that drops `cook.pth` and another `.pth` hook, puts decoy `python` and `pip` executables on `PATH` that fail the test if anything calls them, and checks the verdicts, the exit code and the pull/restore round trip. The Go tests run on Linux, macOS and Windows; the real-Python checks run on Linux and macOS with Python 3.10 and 3.13.

If you have an affected environment, the file hashes in the built-in feed will match the real `cook.pth`; detection of the other dropped files depends on their hashes, which you can add with `--ioc`.

- Repository: https://github.com/Blackman99/tickcheck
- Docs: https://blackman99.github.io/tickcheck/docs/
