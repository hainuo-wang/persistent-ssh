# persistent-ssh

**人工完成一次 SSH 认证，然后让不同会话复用连接执行任务、传输文件。**

[English](README.md) · [Skill 入口](SKILL.md) · [认证配置](docs/authentication.md) · [兼容范围](docs/platforms.md) · [类似项目](docs/related-work.md)

这是一个完整的 **skill + Python CLI**，仓库本身就是 skill：安装后无需另外
寻找后台工具。系统 OpenSSH 负责密码、OTP、扫码或推送认证，本地后台管理器
持有连接，短命令客户端通过私有 IPC 使用它。没有额外 pip 运行依赖，也不是 MCP 服务。

## 安装与使用

本地需要 Python 3.10+ 和 OpenSSH。在仓库目录执行：

```console
python scripts/install_skill.py
```

默认安装到 `$CODEX_HOME/skills/persistent-ssh`，未设置 `CODEX_HOME` 时为
`~/.codex/skills/persistent-ssh`。其他 agent 可使用 `--destination` 指定 skill
目录。之后可在支持 skill 的聊天中使用 `$persistent-ssh`。

假设已经通过常规方式配置并验证了 SSH 别名 `lab-host`：

```console
python scripts/ssh_manager.py --profile lab init --host lab-host
python scripts/ssh_manager.py --profile lab start
python scripts/ssh_manager.py --profile lab connect
python scripts/ssh_manager.py --profile lab auth-info
```

`--profile` 等全局参数放在子命令前面。以上命令既可在仓库运行，也可把脚本路径
换成安装后的绝对路径。`init` 创建独立 profile，`start` 只启动后台程序，
`connect` 才发起登录，避免查询状态时意外创建认证请求。

需要密码或 OTP 时，**由本人在自己的交互式终端运行**：

```console
python scripts/ssh_manager.py --profile lab auth
```

输入不会回显，不要把密码放进聊天、命令参数、环境变量或配置文件。
扫码链接会出现在 `auth-info` 的临时输出中。扫码确认后，需要一次回车时使用
`auth --empty`。对于“扫码确认后按特定提示提交多次空回车”的流程，可在初始化时
使用 `--settings examples/scan-confirm.json` 并调整匹配规则，人工确认后再执行
`confirm`。默认不会自动填任何认证答案。

连接 `ready` 后：

```console
python scripts/ssh_manager.py --profile lab ping
python scripts/ssh_manager.py --profile lab exec --cwd /srv/project --command "git status --short"
python scripts/ssh_manager.py --profile lab upload ./work/fix.patch /tmp/fix.patch
python scripts/ssh_manager.py --profile lab download /tmp/results.json ./outputs/results.json
```

命令、上传和下载使用同一条已认证连接，不另开 SCP/SFTP 登录。文件支持分块、
续传、SHA-256 校验和完整文件的原子提交；覆盖需要明确添加 `--overwrite`。
多行脚本建议使用 `exec --script <本地 UTF-8 脚本>`，避免本地 shell 展开远端变量。

命令返回任务 ID；`--wait` 只是等待观察，不会超时杀掉任务。用 `job ID` 查看后续
输出，`--timeout` 才是实际执行期限。关闭客户端不取消远端任务。多个聊天修改同一
项目并不自动隔离，应使用不同 worktree，并在覆盖前核对远端版本。

## 适用范围

- Windows：ConPTY + 任务计划程序，已验证独立后台启动和原始数据通道。
- Linux：PTY + systemd 用户服务或 tmux；已有离线密码/OTP 完整链路测试。
- macOS：核心及 PTY 离线测试已通过 GitHub CI；**launchd 后台生命周期尚未验证**。
- 远端：目前要求 Linux、可用 shell、Python 3.8+、Bash、`/proc` 和可写临时目录。

“无法配置密钥”本身不是障碍，但不能据此覆盖所有设备。禁止 shell/Python 的堡垒机、
网络设备或 Windows 远端还不在当前支持范围。没有绕过 MFA、恢复失效认证或保证永不
断线的机制；断网、注销、重启、策略到期等仍可能要求重新认证。

后台连接由同 profile 的客户端共享，聊天结束时不要关闭它。需要明确断开时使用
`disconnect --yes`，停止后台管理器使用 `shutdown --yes`。具体状态目录和边界见
[安全说明](SECURITY.md)。不要把运行目录、`auth.key` 或真实认证信息上传 GitHub。

## 开发与发布

```console
python -m unittest discover -s tests -v
```

测试使用隔离文件和模拟认证入口，不需要公开真实服务器配置。GitHub CI 已通过
Windows/Linux/macOS × Python 3.10/3.12/3.14 的全部九种组合。仓库同时包含
GitHub Actions、英文/中文说明、认证示例和 MIT 许可证。上传这个仓库目录即可；
不要上传父工作目录。已有相似开源工具及本项目的定位见
[相关项目对比](docs/related-work.md)，本项目不宣称首创。
