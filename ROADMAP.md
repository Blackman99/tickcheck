# Roadmap

Each step has to serve [GOAL.md](GOAL.md): show every piece of code that runs when Python starts, everywhere on the machine, without starting Python.

## v0.1 (now)

- Census of `.pth` / `sitecustomize` / `usercustomize` hooks in venvs, agent worktrees, pipx, uv tools and caches, pyenv, uv pythons, conda, pre-commit, user site and system installs.
- Verdicts from the file alone (IOC hashes and dists, RECORD hash, payload signals, known patterns).
- Package caches, host markers, Linux processes holding the loader lock.
- Who installed it, from Claude Code / Codex / OpenCode / Gemini CLI transcripts and shell history.
- `pull` / `restore` with a manifest. `--json`, exit codes, `--root` for rootfs and CI.

## v0.2: images without running them

`tickcheck image <ref|file.tar>` reads OCI image layers (whiteouts included) and runs the census on the merged filesystem. No `docker run`, no export step.

## v0.3: after every install

A post-install check for pip and uv (a shell shim or a uv hook) so a new startup hook is reported the moment an agent installs the package that drops it, not the next time someone looks.

## v0.4: cooldown guard for agents

A Claude Code / Codex `PreToolUse` hook that holds `pip install` / `uv add` of a release younger than N hours and says why. Most poisoned releases are pulled within a day.

## v0.5: more startup surfaces

`PYTHONSTARTUP`, extra `PYTHONPATH` dirs, IPython and Jupyter kernel startup files, `.pth` files in other users' sites (with permission), entry-point console scripts that wrap `python`.

Not planned: scanning package code for vulnerabilities (pip-audit, OSV and Socket do that), running Python in a sandbox, rotating credentials.
