# Platform support and verification

This matrix records observations as of **2026-10-27**, not universal compatibility.

| Component | Implementation | Verification |
| --- | --- | --- |
| Windows local host | ConPTY for authentication; raw pipes for data; on-demand Task Scheduler | Native raw-data tests and system-task startup tested; task has no trigger or runtime limit and is parented by the system service |
| Linux local host | Controlling PTY plus raw pipes; user systemd or tmux | Core suite and offline password→OTP→helper→jobs/transfers integration tested on Linux; tmux hosting exercised |
| Linux systemd hosting | `systemd-run --user` when a user manager is available | Implemented; actual service launch not exercised in the available container |
| macOS local host | POSIX PTY and per-user launchd | Implemented, not yet verified on a real Mac; CI configuration is not proof of execution |
| Linux remote helper | Python 3.8+, Bash, `/proc`, writable temp; optional tmux | Real remote job/file behavior exercised by the preceding provider-specific implementation; generalized helper also exercised in the Linux offline fixture |
| Authentication | Manual password/OTP; configurable scan/push empty-response sequence | Generic state-machine tests and Linux synthetic password/OTP fixture; not a claim that every MFA provider has been tested |
| Native interactive gateway | System OpenSSH, human scan approval | Verified in the predecessor on a real gateway; generic profile login remains provider-dependent |

Local Python 3.10+ is the supported baseline. The local checks used Python 3.14
on Windows and Python 3.12 on Linux; CI is configured to exercise additional
supported Python versions. The runtime has no pip dependencies.

Final local verification collected 26 tests: **25 passed and one Linux-only test
was skipped on Windows; all 26 passed on Linux**. This includes installing the
complete skill into an isolated directory and creating a source archive from
that installation. The skill manifest validator also passed. The GitHub Actions
matrix has been provided but was not run on GitHub as part of this verification.

## Persistence boundaries

Windows tasks run on demand as the signed-in user with limited privileges and no
stored Windows password. There are no time/login triggers. Task runtime is
unlimited and battery transitions do not deliberately stop it. User sign-out and
machine shutdown remain boundaries.

Linux uses an available systemd user manager, otherwise a separate tmux server.
It does not fall back to an unverified `nohup` child inside an agent process group.
macOS uses launchd in the current GUI user domain. Headless systems without a
usable service manager/tmux need explicit setup; the tool reports the limitation.

Remote commands run in tmux when installed, otherwise in a detached process session.
They write job records and output to the helper's private temporary directory.
Loss of local IPC does not cancel them. Remote reboot, temp cleanup, OOM or an
administrator can still end tasks or remove records. A full Codex application
shutdown and physical network outage were not part of the recorded tests.

## Unsupported or conditional environments

- Windows/BSD/macOS remote helper targets are not implemented; `/proc` validation
  is Linux-specific.
- Shell/Python-prohibited gateways and network appliances are not supported.
- Non-POSIX login shells, customized prompts and multi-stage gateway menus may
  require provider settings; arbitrary terminal applications are not automated.
- Filesystems must support atomic rename and hard links for no-clobber publication.
  A filesystem without those primitives can reject transfers; the tool does not
  silently weaken overwrite protection.
- Directory sync, interactive remote editors, GUI forwarding, rsync acceleration
  and atomic multi-writer version checks are not provided.
- Large dataset throughput has not been comprehensively benchmarked. The original
  real transfer sample was about 2 MiB, and the Linux fixture uses a smaller sample.
