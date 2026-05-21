<h1 align="center">Coocon</h1>
<p align="center">
  <strong>Hardened local code runner</strong> with predictable limits, clean UX, and an agent‑friendly JSON API.
</p>

> **⚠️ Security Expectations**
> - Coocon reduces risk but does **not** provide VM‑grade isolation.
> - Strongest protections on Linux with `bubblewrap` + `seccomp`. Best‑effort only on Windows, macOS, and WSL.
> - Do not run hostile, multi‑tenant, or high‑risk code without an external sandbox (container or microVM).

---

## Contents

- [Why Coocon](#why-coocon)
- [Platform Support](#platform-support)
- [Install](#install)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [Profiles & Security Modes](#profiles--security-modes)
- [Policy JSON](#policy-json)
- [Transport & Protocol](#transport--protocol)
- [Security Model](#security-model)
- [Limitations](#limitations)
- [Development](#development)

---

## Why Coocon

- **Limit‑enforced** code execution without heavy infrastructure
- **Predictable resource caps** (CPU, memory, output size, file descriptors)
- **Dual interface:** intuitive CLI for humans, JSON line protocol for agents
- **Per‑sandbox policies:** restrict languages, network, and resource ceilings

---

## Platform Support

| Platform | Isolation Level | Requirements |
|----------|----------------|--------------|
| **Linux (native)** | Strong | `bubblewrap`, `libseccomp` (runtime); `libseccomp-dev` (build) |
| **WSL** | Best effort | Namespace isolation is disabled by design |
| **macOS** | Best effort | `rlimit` + isolated workspace; no namespace sandbox |
| **Windows** | Best effort | Job Objects + isolated workspace |

---

## Install

```bash
# Rust daemon
cargo build --release

# Python CLI
python3 -m pip install -e .
```

### Linux (strict/balanced mode)

```bash
sudo apt install bubblewrap libseccomp-dev   # Debian/Ubuntu
```

---

## Quick Start

```bash
# Start the daemon
coocon start

# Ephemeral execution
coocon run "print('hello from ephemeral sandbox')"

# Check server capabilities
coocon info

# Stop
coocon stop
```

### Full walkthrough

```bash
coocon start

# Ephemeral run
coocon run "print('hello')"

# Persistent sandbox
coocon create mybox --memory 256 --timeout 30 --profile fast
coocon run mybox "print('hello from persistent sandbox')"

# Cleanup
coocon destroy mybox
coocon stop
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `start` | Start the Rust daemon |
| `stop` | Stop the daemon |
| `status` | Daemon health check |
| `list` | List active sandboxes |
| `info` | Server version, platform, and capabilities |
| `doctor` | Verify dependencies and configuration |
| `examples` | Show usage examples |
| `create <name> [opts]` | Create a persistent sandbox |
| `destroy <name>` | Remove a sandbox and its workspace |
| `run <code> [opts]` | Ephemeral execution |
| `run <name> <code>` | Execute in a persistent sandbox |
| `exec <name> <file>` | Run a file inside a sandbox |
| `shell <name>` | Interactive shell (if supported) |
| `quick <code> [opts]` | One‑shot ephemeral with inline limits |
| `history <name>` | Show execution history for a sandbox |
| `reset <name>` | Reset sandbox state |
| `api-exec --json '{...}'` | Raw JSON API call |

### Create / Run options

```text
-m, --memory MEMORY_MB        Memory limit (default: 256)
-t, --timeout TIMEOUT_SECS    Timeout in seconds (default: 30)
--network                     Allow network access (requires OS support)
--profile {safe,fast,dev}     Select a preset
--mode {strict,balanced,dev}  Security mode override
--policy FILE.json            Attach a custom execution policy
-l, --language {python,bash}  Interpreter selection
```

---

## Profiles & Security Modes

### Profiles (convenient presets)

| Profile | Memory | Timeout | Security Mode | Use case |
|---------|--------|---------|---------------|----------|
| `safe` | 128 MB | 10 s | `strict` | Untrusted or risky snippets |
| `fast` (default) | 256 MB | 30 s | `balanced` | Daily automation and agents |
| `dev` | 1024 MB | 300 s | `dev` | Local debugging |

### Security Modes (enforced by daemon)

| Mode | Behavior |
|------|----------|
| `strict` | Requires `bubblewrap` + `libseccomp`. Fails if OS protections are unavailable. Network requires namespace isolation. |
| `balanced` (default) | Uses all available hardening. Blocks unsupported risky options (e.g., `--network` without isolation). |
| `dev` | `rlimit` only. No namespace sandbox. For local experimentation only. |

---

## Policy JSON

Optional per‑sandbox or per‑execution policy enforced server‑side.

```json
{
  "allowed_languages": ["python", "bash"],
  "max_code_bytes": 131072,
  "max_output_bytes": 32768,
  "max_memory_mb": 512,
  "max_timeout_secs": 120,
  "allow_network": false
}
```

Usage:

```bash
coocon create mybox --mode strict --policy policy.json
coocon run "print('hello')" --profile safe --policy policy.json
```

---

## Transport & Protocol

- **Linux / macOS:** Unix domain socket at `/tmp/coocon.sock` (permissions `0600`)
- **Windows:** TCP `127.0.0.1:19999` (localhost only)

### Protocol

Line‑delimited JSON. Each request is one JSON object terminated by `\n`. Each response is one JSON object terminated by `\n`.

**Example request:**
```json
{"Execute":{"name":"mybox","code":"print(2+2)","language":"python"}}
```

**Example response:**
```json
{"Executed":{"success":true,"output":"4\n","error":null,"exit_code":0,"execution_time_ms":15}}
```

### Raw client examples

**Unix (with `socat`):**
```bash
echo '{"Ping":{}}' | socat - UNIX-CONNECT:/tmp/coocon.sock
```

**Windows (with `ncat`):**
```powershell
'{"Ping":{}}' | ncat 127.0.0.1 19999
```

**Python:**
```python
import json, socket

def rpc(req: dict) -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 19999))
        s.sendall((json.dumps(req) + "\n").encode())
        return json.loads(s.recv(4096).decode().strip())

print(rpc({"Create": {"config": {"name": "demo", "memory_mb": 256, "timeout_secs": 10}}}))
print(rpc({"Execute": {"name": "demo", "code": "print('hello')", "language": "python"}}))
```

---

## Security Model

- **No shell interpolation:** user code is written to a file and invoked directly by the interpreter (`python3`, `bash`, etc.).
- **Ephemeral workspace:** each sandbox receives a unique directory under `/tmp/coocon` (or `%TEMP%\coocon`) with restricted permissions (`0700` on Unix).
- **Environment sanitization:** on Unix, all environment variables are cleared and only `PATH`, `HOME`, `LANG`, and `LC_ALL` are set. On Windows the environment is inherited to preserve interpreter discoverability.
- **Resource limits:**
  - **Unix:** `RLIMIT_AS` (memory), `RLIMIT_CPU` (CPU time), `RLIMIT_NOFILE` (file descriptors), `RLIMIT_NPROC` (process count, best effort).
  - **Windows:** Job Object with kill‑on‑close, memory limit, and active process limit.
- **Linux hardening (strict/balanced):**
  - `seccomp‑bpf` denylist: blocks `ptrace`, `mount`, `bpf`, `reboot`, and other dangerous syscalls.
  - `bubblewrap` namespace sandbox: unshared filesystem, IPC, PID, UTS, cgroup, and optionally network.
- **Output bounding:** stdout/stderr are truncated to `max_output_bytes` to prevent response‑size DoS.
- **Request bounding:** single JSON lines are capped at 1 MiB.

---

## Limitations

- **Not a VM boundary.** A determined process may escape process‑level restrictions on Windows, macOS, and WSL.
- **Windows / macOS:** no kernel namespace sandbox. Isolation is best effort via OS job control and resource limits.
- **WSL:** namespace isolation is intentionally disabled due to incomplete compatibility.
- **Network:** true network isolation requires Linux + `bubblewrap`. On other platforms, `network: false` is a policy flag, not a kernel guarantee.
- **Do not expose the daemon to untrusted networks.** The socket/TCP bind is localhost‑only by design.

---

## Development

```bash
# Python syntax check
python3 -m py_compile coocon/__init__.py src/coocon_cli.py

# Rust check
cargo check

# Build release
cargo build --release
```

---

## License

MIT
