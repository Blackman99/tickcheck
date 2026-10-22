# Goal

**Show every piece of code that runs automatically when Python starts, in every Python environment on your machine, with who put it there and whether it belongs, without ever starting Python.**

Every feature has to serve this sentence. Things that don't:

- Scanning package code for vulnerabilities (that's pip-audit, OSV, Socket).
- Running or sandboxing Python (it would trigger the very hooks we look for).
- Rotating credentials (tickcheck lists what *could* have been read and hands off to keyroll / your provider consoles).
