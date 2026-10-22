# Python 每次启动都会运行什么，以及为什么第一步不该用 pip 检查

2026-10-21 发布到 PyPI 和 Docker Hub 的 LiteLLM 1.107.0 往 site-packages 根目录放了三个文件：一个 12 字节、内容为 `import cook` 的 `cook.pth`，一个 `cook.py`，以及一个 `sitecustomize.py`。你的代码不需要导入它们，Python 会在这个环境里每次启动解释器时自动运行它们。本文说明这个机制，为什么常见的第一反应会让情况更糟，以及 tickcheck 如何把发现的启动钩子分为 BAD、SUSPECT、REVIEW 和 OK。

## `.pth` 启动钩子如何工作

解释器启动时，`site` 模块会遍历每个 site-packages 目录，按字母顺序读取所有 `.pth` 文件。对每一行：

- 空行和以 `#` 开头的行被跳过；
- 以 `import` 加空格或制表符开头的行会被当作 Python 代码执行；
- 其他行被当作目录，存在时追加到 `sys.path`。

可执行行的规则有正当用途：setuptools 用 `distutils-precedence.pth` 安装 distutils 垫片，可编辑安装（PEP 660）用 `__editable__.*.pth`，旧式命名空间包用 `-nspkg.pth`，virtualenv 和 uv 会写入 `_virtualenv.pth`。由于这一行只需要以 `import` 开头，它可以先导入一个模块，再在分号后面执行任意语句。

另外两个文件也以同样方式加载：`sitecustomize`（`sys.path` 上任意位置）和 `usercustomize`（用户 site，启用时）。它们可以是 `.py` 模块、包、编译扩展或无源码的 `.pyc`。Debian/Ubuntu 和 Homebrew 都自带 `sitecustomize.py`。

这一切发生在 `-c`、你的脚本和任何命令行入口之前。`python -S` 可以关闭它，但日常运行的东西几乎都不带 `-S`。

## 为什么第一步不该用 pip 检查

`pip` 本身是 Python 程序。`pip show litellm`、`pip list`、`pip uninstall litellm`，以及任何用 Python 写的扫描器，都会启动这个解释器，而解释器在执行你的请求之前先运行启动钩子。在带有 LiteLLM 投放文件的环境里，本应用来确认感染的那一步会再运行一次恶意载荷。

已发布的安全通告实际上也这样建议：用 `find` 这类 shell 工具检查 site-packages，而不是用 pip；同时提醒部分 `.pth` 和 `sitecustomize.py` 是正当的，命中不等于有害。这留下两个问题：一台典型的开发机上有很多 site-packages 目录（每个 venv、conda 环境、pipx 和 uv 工具、pyenv 和 uv 管理的 Python、用户 site、系统安装、智能体工作树里的项目 `.venv`）；而判断哪些钩子属于正常情况，仅靠文件列表是不够的。

tickcheck 是一个单文件 Go 程序，除 Go 标准库外没有任何依赖，从不启动 Python 解释器。它通过文件（`pyvenv.cfg`、已知安装布局）发现环境，并把钩子文件和包元数据当作文本读取。

## tickcheck 如何给出判定

对每个可执行钩子（至少含一行 `import` 的 `.pth`，或 `sitecustomize`/`usercustomize`），tickcheck 还会解析该行导入的模块，找出哪个已安装的发行包在其 `*.dist-info/RECORD` 中列出了每个文件，并将文件的 sha256 与 RECORD 记录比对，然后取适用的最严重判定。

**BAD**：钩子或其加载模块的 sha256 在 IOC 情报中；或所属包的名称和版本被列出（例如 `litellm 1.107.0`）。情报中的主机标记（如 `/tmp/remote_code_loader.lock`）以及 Linux 上持有该锁的存活进程也算 BAD。内置情报覆盖 LiteLLM 1.107.0 投放，`--ioc FILE` 可以在不发新版的情况下加入新事件。

**SUSPECT**：满足以下任一条件
- 钩子或其导入模块中有载荷特征：经编码的数据（base64、zlib、marshal 等）被传给 `exec`/`eval`/`compile`，超长编码字面量，启动子进程，网络调用，`fork`/`setsid`，或引用凭据路径（如 `~/.aws/credentials`）；
- 文件与所属包 RECORD 中记录的 sha256 不一致；
- 钩子名称与安装它的包毫无关系，例如 litellm 安装了 `cook.pth`。

pip 或 uv 缓存中被投毒的条目至少为 SUSPECT。

**REVIEW**：钩子会在启动时运行，tickcheck 无法为它担保，但没有载荷特征。要么文件不在任何已安装包的 RECORD 里，要么是来自某个包的普通代码，且不符合已知模式。

**OK**：来自其自身所属包、RECORD 哈希一致的已知模式：setuptools distutils 垫片、可编辑安装、`-nspkg.pth`、virtualenv/uv 的 venv 补丁、pywin32、coverage，以及 Debian apport 和 Homebrew 的 `sitecustomize.py`。

这些特征是对文件文本的正则匹配，不解码、不导入、不执行。特征检查先于已知模式检查，因此名字眼熟却携带载荷的文件（例如调用 `subprocess` 的 `_virtualenv.py`）仍然是 SUSPECT。环境取其中钩子的最严重判定，全局最严重判定决定退出码：BAD 为 4，SUSPECT 为 3，否则为 0。

钩子为 BAD 时，tickcheck 还会在本地 Claude Code、Codex、OpenCode、Gemini CLI 的会话记录和 shell 历史中查找安装该包的命令，并列出窃密程序在这台机器上可能找到的凭据文件（只检查是否存在，从不读取）。`tickcheck pull` 随后把 BAD 钩子及其 `__pycache__` 副本移入带清单的隔离目录，同样不启动 Python；`tickcheck restore` 可以放回。

## 测试基于什么

tickcheck 没有在真正被 LiteLLM 1.107.0 感染的机器上运行过。它是在去除危害的复现环境上测试的：`tickcheck --demo` 生成一个包含七个环境的家目录，其中 LiteLLM 1.107.0 投放的 `cook.pth` 与真实的 12 字节文件逐字节相同，而 `cook.py` 是无害的替身。CI 还会创建真实的 venv，安装一个会投放 `cook.pth` 和另一个 `.pth` 钩子的真实 wheel，在 `PATH` 上放置诱饵 `python` 和 `pip`（一旦被调用测试即失败），并校验判定、退出码和 pull/restore 往返。Go 测试在 Linux、macOS 和 Windows 上运行；真实 Python 检查在 Linux 和 macOS 上用 Python 3.10 和 3.13 运行。

如果你有受影响的环境，内置情报中的哈希会匹配真实的 `cook.pth`；其他投放文件能否精确识别取决于它们的哈希，可以用 `--ioc` 补充。

- 仓库：https://github.com/Blackman99/tickcheck
- 文档：https://blackman99.github.io/tickcheck/docs/
