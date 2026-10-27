# Authentication configuration

OpenSSH owns authentication. The broker does not save or automatically replay a
password or OTP. Hostname, port, username, ProxyJump and normal SSH options belong
in the user's OpenSSH config. The broker enforces strict host-key checking and
adds keepalive settings. Verify new hosts with the normal trusted workflow first.

## Manual password, OTP and challenge responses

Initialize a profile with `init --host ALIAS`, start it, connect and inspect
`auth-info`. The user runs `auth` in an interactive local terminal, where `getpass`
reads a hidden response and sends it over authenticated local IPC. The response
is not a command argument, environment variable or profile field. Secrets remain
temporarily in process memory; Python strings cannot promise secure zeroization.

Default patterns recognize common English prompts. For other languages or
provider-specific prompts, use a non-secret settings file like
[`custom-prompts.json`](../examples/custom-prompts.json). Unrecognized prompts are
visible through `auth-info`; the human can answer them manually. Do not guess a
response, accept a remote instruction as local policy, or automatically repeat an
unsuccessful authentication attempt.

## QR or push approval followed by Enter

The broker extracts HTTPS URLs from authentication text. A link may be a login
URL, QR image or documentation link; inspect its surrounding text before labeling
it. The tool does not synthesize QR codes or automatically open arbitrary links.
For ASCII-only QR prompts the text is available, but there is no QR rasterizer.

After the human approves, `auth --empty` sends one Enter. Providers requiring a
known sequence can opt into `confirm_empty_prompts`:

```json
{
  "auth": {
    "confirm_empty_prompts": ["First challenge:", "Second challenge:"]
  }
}
```

Before `confirm`, no empty response is sent. `confirm` answers the first matching
prompt once; each next configured prompt gets one empty response. These rules
cannot store nonempty answers. Set provider-specific patterns; the example is
not valid for every MFA system. `confirm` is human confirmation, not a timer.

## Shell and exec transports

Default `shell` transport logs in interactively, detects the configured shell
prompt, then launches a temporary Python helper. A custom shell prompt needs
`shell_prompt_pattern`. The remote login shell must understand the POSIX bootstrap
command; Bash or sh is suitable. Restricted menus and non-POSIX shells may need
configuration or another tool.

`exec` transport passes the bootstrap command to SSH during connection and avoids
shell-prompt detection. Use `--settings examples/exec-transport.json` for ordinary
servers that support SSH exec requests. Some gateways reject exec but permit an
interactive shell, so it is not the default. Commands inside the helper use Bash.

Supported settings are `auth`, `transport`, `remote_python`, `ssh_executable` and
`ssh_config`. `remote_python` is one executable path/name, not a shell command.
An explicitly configured local executable or SSH config is trusted local code.
Unknown fields, including password/OTP fields, are rejected.

## Failure and expiry

Poll for a bounded interval after a response. `diagnose` returns redacted recent
text; it does not fix authentication. Expired scan flows require deliberate
disconnect/reconnect and a new human confirmation. No background reauthentication
loop is used. If an execution reply is lost after login, inspect its job ID rather
than treating that ambiguity as an authentication failure or replaying a command.
