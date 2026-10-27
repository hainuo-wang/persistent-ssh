# Contributing

The runtime uses only Python's standard library and the system OpenSSH client.
Keep provider assumptions in optional non-secret profile settings. Do not add
password/OTP storage, skip host-key verification, or auto-retry authentication.

Run the offline suite from the repository root:

```console
python -m unittest discover -s tests -v
```

The Linux/tmux fixture is skipped elsewhere. It exercises the actual broker and
PTY with a local synthetic authentication program, not an external SSH host.
Never make CI depend on a personal server, MFA code, SSH key or account token.

When changing authentication, cover split prompts, manual response gating and
the transition to machine protocol. Redact only human-facing diagnostics, never
the encoded wire protocol. When changing transfers, check resume, checksum
failures, empty/binary/Unicode files and no-clobber publication. Platform lifecycle
changes need observations on the affected OS; don't relabel an untested backend.

The default CLI observation limit must not become an implicit command-kill
deadline. Preserve job IDs across uncertain replies and don't replay mutations
automatically. Shared profiles must not allow one routine client exit to stop
the broker or another client's jobs.

Before a release, run `python scripts/package_release.py`, inspect the file list
and archive, and review `docs/platforms.md`. The packaging allowlist excludes
runtime state and compiled caches. It supplements review; it is not a general
secret scanner. Set the repository's private vulnerability reporting/contact
details before inviting reports. Changes are distributed under the MIT license.
