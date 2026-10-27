# Related work

Reviewed on **2026-10-27** using the projects' own documentation. This is a scoped
comparison, not an exhaustive search or a claim that persistent SSH is novel.
No third-party implementation code was copied into this repository.

| Project | Documented overlap | Relevance to this package |
| --- | --- | --- |
| [fryjustinc/ssh-mcp-sessions](https://github.com/fryjustinc/ssh-mcp-sessions) | Persistent SSH sessions and remote development operations; password, private-key and agent authentication | A close existing MCP-oriented approach. Its documented host storage can contain a password; this package instead makes the human supply each login challenge without storing SSH credentials. |
| [overklassniy/ssh-mcp](https://github.com/overklassniy/ssh-mcp) | Commands, SFTP transfers, directory sync, forwarding and keyboard-interactive 2FA through an environment value | Broader MCP tooling. This package focuses on native interactive authentication and file transport over the already-open shell. |
| [wijzeu/ssh-mcp-server](https://github.com/wijzeu/ssh-mcp-server) | MFA and a persistent shell transport for bastions | Its documented shell mode does not provide upload/download because SFTP is unavailable in that mode. Shell-based transfers are a useful distinction here; both projects have environmental limits. |
| [shashikanth-gs/mcp-ssh-bridge](https://github.com/shashikanth-gs/mcp-ssh-bridge) | Multi-host SSH tools and persistent shell sessions with MCP transports | Another comparable system. Its documentation distinguishes shared persistent shells from stateless HTTP operations; this package explicitly shares each local profile between trusted clients. |

OpenSSH already provides connection sharing through `ControlMaster`, `ControlPath`
and `ControlPersist`; see the [official ssh_config manual](https://man.openbsd.org/ssh_config).
Where that workflow fits the platform and gateway, it may be simpler than another
broker. A skill that wraps those options is a valid alternative.

`persistent-ssh` packages a particular combination: native human authentication,
an independently hosted local broker, short-lived agent-friendly JSON clients,
shell-based verified transfers, and a self-contained skill. These are engineering
choices, not evidence of a first-of-its-kind tool. The other projects were reviewed
from their documentation, not installed or benchmarked in this comparison.
