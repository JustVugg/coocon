<p align="center">
  <img src="coocon.png" alt="PolyMCP Logo" width="500"/>
</p>

Coocon is a **hardened local code runner** for executing snippets with predictable limits, clean UX, and an agent‑friendly API.

**Security expectations**
- Coocon reduces risk but does not provide VM‑grade isolation.
- Best‑effort isolation on Windows/macOS; strongest isolation on Linux with `bubblewrap`.
- Do not run hostile, multi‑tenant, or high‑risk code without an external sandbox (container or microVM).

It ships as:
- **Rust daemon** (execution engine)
- **Python CLI** (human + agent interface)

## Why Coocon

- You need **limit‑enforced** code execution without spinning up heavy infra
- You want **predictable limits** (CPU/memory/output)
- You need a **simple CLI** for humans *and* a JSON API for agents

## Quick start

```bash
coocon start
coocon run "print('hello from ephemeral sandbox')"
coocon stop
```

Expected output (approx):

```text
hello from ephemeral sandbox
```

Check capabilities:

```bash
coocon info
```

## Install

```bash
cargo build --release
python3 -m pip install -e .
```

## Quick start (full)

```bash
coocon start
coocon run "print('hello from ephemeral sandbox')"
coocon create mybox --memory 256 --timeout 30 --profile fast
coocon run mybox "print('hello from persistent sandbox')"
coocon destroy mybox
coocon stop
```

## Requirements

- Python 3.9+
- Rust (for building the daemon)
- Linux strict mode: `bubblewrap` + `libseccomp` (runtime); `libseccomp-dev` (build)

## 30‑second demo

```bash
coocon start
coocon run "print('2+2=', 2+2)"
coocon run "import sys; print(sys.version.split()[0])" --profile fast
coocon stop
```

## CLI commands

```text
start | stop | status | list | info | doctor | examples
create <name> [-m MEMORY_MB] [-t TIMEOUT_SECS] [--network] [--profile safe|fast|dev] [--mode ...] [--policy policy.json]
destroy <name>
run <code> [-l python|bash] [--profile safe|fast|dev] [--mode ...] [--policy policy.json]  # ephemeral
run <name> <code> [-l python|bash]              # persistent
exec <name> <file>
shell <name>
quick <code> [-m MEMORY_MB] [-t TIMEOUT_SECS] [--profile safe|fast|dev] [--mode ...] [--policy policy.json]
history <name>
reset <name>
api-exec --json '{"code":"print(1)","profile":"safe"}'
```

## Profiles (easy defaults)

- `safe`: tighter limits, strict mode
- `fast` (default): balanced limits for normal usage
- `dev`: permissive for local debugging

## Security modes

- `strict`: blocks execution if required OS protections are unavailable
- `balanced` (default): secure defaults, blocks risky unsupported options (like `--network`)
- `dev`: permissive mode for local experimentation

## Policy JSON (optional, enforced by daemon)

```json
{
  "allowed_languages": ["python"],
  "max_code_bytes": 131072,
  "max_output_bytes": 32768,
  "max_memory_mb": 512,
  "max_timeout_secs": 120,
  "allow_network": false
}
```

Use it with:

```bash
coocon create mybox --mode strict --policy policy.json
coocon run "print('hello')" --profile safe --policy policy.json
```

## Transport

- Linux/macOS: Unix socket `/tmp/coocon.sock`
- Windows: TCP `127.0.0.1:19999`

## Security model (current)

- No shell interpolation for user code
- Ephemeral per-sandbox workspace under `/tmp/coocon`
- Cleared environment for child processes (Unix). On Windows, the environment is inherited to keep interpreters discoverable.
- Per-execution limits on Unix:
  - memory (`RLIMIT_AS`)
  - CPU time (`RLIMIT_CPU`)
  - open file descriptors (`RLIMIT_NOFILE`)
  - process count best-effort (`RLIMIT_NPROC`)
- Output truncation to bound response size
- Linux: if `bubblewrap` is available, strict/balanced use a Linux namespace sandbox
- Linux: seccomp denylist (strict/balanced)
- Windows: Job Object limits (best effort)

## Important limitation

Coocon is a hardened local runner, **not a VM‑grade isolation boundary**.
Strict mode requires Linux + `bubblewrap`. On WSL/macOS/Windows, only best‑effort isolation is available.
For hostile multi‑tenant workloads, combine with container or microVM isolation.

## Platform hardening matrix

- Linux (native): `strict` uses bubblewrap + seccomp + rlimits; requires `bwrap`, `libseccomp` (runtime), `libseccomp-dev` (build)
- WSL: best effort only (no reliable namespace isolation); consider disabling automount and interop at the WSL level
- macOS: best effort only for CLI (rlimits + isolated dir); strong isolation requires a signed, sandboxed app wrapper
- Windows: best effort with Job Objects + isolated dir; strong isolation requires AppContainer/Windows Sandbox (not yet integrated)

## Development checks

```bash
python3 -m py_compile coocon/__init__.py src/coocon_cli.py
cargo check
```
