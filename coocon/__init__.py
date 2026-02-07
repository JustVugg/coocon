#!/usr/bin/env python3
"""Coocon CLI and Python client for the secure execution daemon."""

from __future__ import annotations

import argparse
import json
import os
import socket
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

__version__ = "1.0.0"
IS_WIN = sys.platform == "win32"
TCP_ADDR = ("127.0.0.1", 19999)
UNIX_SOCKET = "/tmp/coocon.sock"
REQUEST_TIMEOUT = 30
SECURITY_MODES = ("strict", "balanced", "dev")
PROFILES = ("safe", "fast", "dev")
PROFILE_PRESETS: Dict[str, Dict[str, Any]] = {
    "safe": {
        "mode": "strict",
        "policy": {
            "allowed_languages": ["python", "bash"],
            "max_code_bytes": 131072,
            "max_output_bytes": 32768,
            "max_memory_mb": 512,
            "max_timeout_secs": 120,
            "allow_network": False,
        },
    },
    "fast": {
        "mode": "balanced",
        "policy": {
            "allowed_languages": ["python", "bash"],
            "max_code_bytes": 524288,
            "max_output_bytes": 131072,
            "max_memory_mb": 1024,
            "max_timeout_secs": 300,
            "allow_network": False,
        },
    },
    "dev": {
        "mode": "dev",
        "policy": None,
    },
}


def _init_history_dir() -> Path:
    preferred = Path.home() / ".coocon"
    fallback = Path("/tmp/coocon-history")
    for candidate in (preferred, fallback):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except Exception:
            continue
    raise RuntimeError("Cannot initialize history directory")


HISTORY_DIR = _init_history_dir()


class Colors:
    if sys.stdout.isatty():
        G = "\033[92m"
        R = "\033[91m"
        Y = "\033[93m"
        B = "\033[94m"
        E = "\033[0m"
    else:
        G = R = Y = B = E = ""


@dataclass
class Result:
    success: bool
    output: str
    error: Optional[str]
    exit_code: int
    time_ms: int


class CooconError(RuntimeError):
    pass


def _hist_file(name: str) -> Path:
    return HISTORY_DIR / f"{name}.py"


def get_history(name: str) -> str:
    path = _hist_file(name)
    return path.read_text(encoding="utf-8") if path.exists() else ""


def save_history(name: str, code: str) -> None:
    _hist_file(name).write_text(code, encoding="utf-8")


def clear_history(name: str) -> None:
    path = _hist_file(name)
    if path.exists():
        path.unlink()


def load_policy(path: str) -> Dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.exists() or not policy_path.is_file():
        raise CooconError(f"Policy file not found: {policy_path}")
    try:
        content = policy_path.read_text(encoding="utf-8")
        value = json.loads(content)
    except Exception as exc:
        raise CooconError(f"Invalid policy JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CooconError("Policy JSON must be an object")
    return value


def resolve_mode_policy(
    mode: Optional[str], profile: Optional[str], policy_path: Optional[str]
) -> tuple[str, Optional[Dict[str, Any]]]:
    if profile and profile not in PROFILE_PRESETS:
        raise CooconError(f"Unknown profile: {profile}")
    base_mode = PROFILE_PRESETS.get(profile, {}).get("mode", "balanced")
    base_policy = PROFILE_PRESETS.get(profile, {}).get("policy")
    final_mode = mode or base_mode
    final_policy = load_policy(policy_path) if policy_path else base_policy
    return final_mode, final_policy


def print_user_error(exc: Exception, fallback_hint: Optional[str] = None) -> None:
    msg = str(exc)
    hint = fallback_hint
    if "not found" in msg and "sandbox" in msg:
        hint = "Create it first: coocon create <name>"
    elif "Daemon not found" in msg:
        hint = "Build it first: cargo build --release"
    elif "strict mode" in msg and "requires hard resource limits" in msg:
        hint = "Use --profile fast (or --mode balanced) on this OS."
    elif "--network" in msg or "network isolation" in msg:
        hint = "Drop --network or use a backend with network isolation."
    elif "policy" in msg and "Invalid" in msg:
        hint = "Validate your policy JSON with: python3 -m json.tool policy.json"

    print(f"{Colors.R}{msg}{Colors.E}", file=sys.stderr)
    if hint:
        print(f"{Colors.Y}Hint: {hint}{Colors.E}", file=sys.stderr)


class Client:
    def _send(self, request: Dict[str, Any]) -> Any:
        payload = (json.dumps(request) + "\n").encode("utf-8")

        if IS_WIN:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(REQUEST_TIMEOUT)
            sock.connect(TCP_ADDR)
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(REQUEST_TIMEOUT)
            sock.connect(UNIX_SOCKET)

        try:
            sock.sendall(payload)
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            if not data:
                raise CooconError("Empty response from daemon")
            return json.loads(data.decode("utf-8"))
        finally:
            sock.close()

    def ping(self) -> bool:
        try:
            return self._send({"Ping": None}) == "Pong"
        except Exception:
            return False

    def create(
        self,
        name: str,
        memory_mb: int = 256,
        timeout_secs: int = 30,
        network: bool = False,
        security_mode: str = "balanced",
        policy: Optional[Dict[str, Any]] = None,
    ) -> str:
        config: Dict[str, Any] = {
            "name": name,
            "memory_mb": memory_mb,
            "timeout_secs": timeout_secs,
            "network": network,
            "security_mode": security_mode,
        }
        if policy is not None:
            config["policy"] = policy
        response = self._send(
            {
                "Create": {
                    "config": config
                }
            }
        )
        if "Created" in response:
            return response["Created"]["name"]
        if "Error" in response:
            raise CooconError(response["Error"]["message"])
        raise CooconError(str(response))

    def execute(self, name: str, code: str, language: str = "python") -> Result:
        response = self._send({"Execute": {"name": name, "code": code, "language": language}})
        if "Executed" in response:
            item = response["Executed"]
            return Result(
                success=item["success"],
                output=item.get("output", ""),
                error=item.get("error"),
                exit_code=item.get("exit_code", 1),
                time_ms=item.get("execution_time_ms", 0),
            )
        if "Error" in response:
            raise CooconError(response["Error"]["message"])
        raise CooconError(str(response))

    def destroy(self, name: str) -> None:
        response = self._send({"Destroy": {"name": name}})
        if "Error" in response:
            raise CooconError(response["Error"]["message"])

    def list(self) -> list[dict]:
        response = self._send({"List": None})
        return response.get("List", {}).get("sandboxes", [])

    def info(self) -> dict:
        response = self._send({"Info": None})
        return response.get("Info", {})

    def shutdown(self) -> None:
        try:
            self._send({"Shutdown": None})
        except Exception:
            pass


def _find_daemon_executable() -> Optional[Path]:
    binary = "coocon.exe" if IS_WIN else "coocon"
    candidates = [
        Path.cwd() / "target" / "release" / binary,
        Path(__file__).resolve().parent.parent / "target" / "release" / binary,
        Path(__file__).resolve().parent / binary,
    ]
    for path in candidates:
        if path.exists() and path.is_file():
            return path
    return None


def _is_running() -> bool:
    return Client().ping()


def start_daemon() -> bool:
    if _is_running():
        print(f"{Colors.Y}Daemon already running{Colors.E}")
        return True

    daemon = _find_daemon_executable()
    if daemon is None:
        print(f"{Colors.R}Daemon not found. Build first: cargo build --release{Colors.E}")
        return False

    print(f"{Colors.B}Starting daemon...{Colors.E}")
    if IS_WIN:
        subprocess.Popen([str(daemon)], creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        subprocess.Popen(
            [str(daemon)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    for _ in range(80):
        time.sleep(0.1)
        if _is_running():
            print(f"{Colors.G}Daemon started{Colors.E}")
            return True

    print(f"{Colors.R}Failed to start daemon{Colors.E}")
    return False


def stop_daemon() -> None:
    if not _is_running():
        print(f"{Colors.Y}Daemon not running{Colors.E}")
        return
    Client().shutdown()
    time.sleep(0.2)
    print(f"{Colors.G}Daemon stopped{Colors.E}")


def ensure_daemon() -> bool:
    return _is_running() or start_daemon()


def run_doctor() -> int:
    daemon = _find_daemon_executable()
    daemon_running = _is_running()
    print("Coocon Doctor")
    print(f"- platform: {sys.platform}")
    print(f"- python: {sys.version.split()[0]}")
    print(f"- history_dir: {HISTORY_DIR}")
    print(f"- daemon_binary: {'ok' if daemon else 'missing'}")
    if daemon:
        print(f"  path: {daemon}")
    print(f"- daemon_running: {'yes' if daemon_running else 'no'}")
    if not IS_WIN:
        sock = Path(UNIX_SOCKET)
        print(f"- unix_socket: {'present' if sock.exists() else 'missing'} ({UNIX_SOCKET})")
    if daemon_running:
        info = Client().info()
        caps = {}
        print("- capabilities:")
        for item in info.get("capabilities", []):
            print(f"  - {item}")
            if "=" in item:
                k, v = item.split("=", 1)
                caps[k.strip()] = v.strip()

        strong = caps.get("strong_isolation", "false") == "true"
        is_wsl = caps.get("is_wsl", "false") == "true"
        if sys.platform.startswith("linux"):
            if is_wsl:
                print(f"{Colors.Y}Strict mode unavailable: WSL detected (no strong isolation){Colors.E}")
            elif not strong:
                print(f"{Colors.Y}Strict mode unavailable: install bubblewrap (bwrap){Colors.E}")
        elif sys.platform == "darwin":
            print(f"{Colors.Y}Strict mode unavailable: macOS has no namespace sandbox for CLI{Colors.E}")
        elif IS_WIN:
            print(f"{Colors.Y}Strict mode unavailable: Windows has no namespace sandbox backend{Colors.E}")

        print(f"{Colors.G}Doctor OK{Colors.E}")
        return 0
    if sys.platform.startswith("linux"):
        if _is_wsl():
            print(f"{Colors.Y}Strict mode unavailable: WSL detected (no strong isolation){Colors.E}")
        elif shutil.which("bwrap") is None:
            print(f"{Colors.Y}Strict mode unavailable: install bubblewrap (bwrap){Colors.E}")
    elif sys.platform == "darwin":
        print(f"{Colors.Y}Strict mode unavailable: macOS has no namespace sandbox for CLI{Colors.E}")
    elif IS_WIN:
        print(f"{Colors.Y}Strict mode unavailable: Windows has no namespace sandbox backend{Colors.E}")

    print(f"{Colors.Y}Daemon is stopped. Run: coocon start{Colors.E}")
    return 1


def _is_wsl() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    for path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            data = Path(path).read_text().lower()
        except Exception:
            continue
        if "microsoft" in data:
            return True
    return False


def print_examples() -> None:
    print("Common commands:")
    print("  coocon run \"print('hello')\"")
    print("  coocon run \"import sys; print(sys.version)\" --profile fast")
    print("  coocon create teambox --profile safe")
    print("  coocon run teambox \"print(2**64)\"")
    print("  coocon api-exec --json '{\"code\":\"print(1)\",\"profile\":\"safe\"}'")


def _print_result(result: Result) -> int:
    if result.success:
        if result.output:
            print(result.output.rstrip("\n"))
        return 0
    if result.output:
        print(result.output.rstrip("\n"))
    msg = result.error or "execution failed"
    print(f"{Colors.R}Error: {msg}{Colors.E}", file=sys.stderr)
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="coocon", description="Secure execution platform CLI")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("status")
    sub.add_parser("list")
    sub.add_parser("info")
    sub.add_parser("doctor", help="Environment and daemon health check")
    sub.add_parser("examples", help="Show copy-paste examples")

    create = sub.add_parser("create")
    create.add_argument("name")
    create.add_argument("-m", "--memory", type=int, default=256)
    create.add_argument("-t", "--timeout", type=int, default=30)
    create.add_argument("--network", action="store_true", help="Allow network access")
    create.add_argument("--mode", choices=SECURITY_MODES)
    create.add_argument("--profile", choices=PROFILES, default="fast")
    create.add_argument("--policy", help="Path to JSON execution policy")

    destroy = sub.add_parser("destroy")
    destroy.add_argument("name")

    reset = sub.add_parser("reset")
    reset.add_argument("name")

    run = sub.add_parser("run")
    run.add_argument("target")
    run.add_argument("code", nargs="?")
    run.add_argument("-l", "--language", default="python")
    run.add_argument("--mode", choices=SECURITY_MODES)
    run.add_argument("--profile", choices=PROFILES, default="fast")
    run.add_argument("--policy", help="Path to JSON execution policy (ephemeral run)")

    execute = sub.add_parser("exec")
    execute.add_argument("name")
    execute.add_argument("file")

    shell = sub.add_parser("shell")
    shell.add_argument("name")

    quick = sub.add_parser("quick")
    quick.add_argument("code")
    quick.add_argument("-t", "--timeout", type=int, default=30)
    quick.add_argument("-m", "--memory", type=int, default=256)
    quick.add_argument("--mode", choices=SECURITY_MODES)
    quick.add_argument("--profile", choices=PROFILES, default="fast")
    quick.add_argument("--policy", help="Path to JSON execution policy")

    history = sub.add_parser("history")
    history.add_argument("name")

    api_exec = sub.add_parser("api-exec", help="Machine-friendly JSON execution")
    api_exec.add_argument("--json", required=True, dest="payload")

    args = parser.parse_args()

    if args.cmd == "start":
        start_daemon()
        return

    if args.cmd == "stop":
        stop_daemon()
        return

    if args.cmd == "status":
        if _is_running():
            print(f"{Colors.G}RUNNING{Colors.E}")
            info = Client().info()
            print(f"  version: {info.get('version', '?')}")
        else:
            print(f"{Colors.R}STOPPED{Colors.E}")
        return

    if args.cmd == "doctor":
        raise SystemExit(run_doctor())

    if args.cmd == "examples":
        print_examples()
        return

    if args.cmd == "list":
        if not _is_running():
            print(f"{Colors.Y}Daemon not running{Colors.E}")
            return
        entries = Client().list()
        if not entries:
            print("No sandboxes")
            return
        for item in entries:
            state = item.get("state", "?")
            if isinstance(state, dict):
                state = next(iter(state.keys()), "?")
            print(f"{item.get('name', '?')}: {state}")
        return

    if args.cmd == "info":
        print(f"coocon {__version__}")
        if _is_running():
            info = Client().info()
            print("status: running")
            for line in info.get("security", []):
                print(f"- {line}")
            for line in info.get("capabilities", []):
                print(f"- {line}")
        else:
            print("status: stopped")
        return

    if args.cmd == "history":
        content = get_history(args.name)
        print(content if content else "No history")
        return

    if args.cmd == "reset":
        clear_history(args.name)
        print(f"{Colors.G}History reset for '{args.name}'{Colors.E}")
        return

    if args.cmd == "create":
        if not ensure_daemon():
            raise SystemExit(1)
        try:
            mode, policy = resolve_mode_policy(args.mode, args.profile, args.policy)
            name = Client().create(args.name, args.memory, args.timeout, args.network, mode, policy)
            clear_history(name)
            print(f"{Colors.G}Created '{name}' ({mode}){Colors.E}")
        except Exception as exc:
            print_user_error(exc, "Try: coocon create mybox --profile fast")
            raise SystemExit(1)
        return

    if args.cmd == "destroy":
        if not ensure_daemon():
            raise SystemExit(1)
        try:
            Client().destroy(args.name)
            clear_history(args.name)
            print(f"{Colors.G}Destroyed '{args.name}'{Colors.E}")
        except Exception as exc:
            print_user_error(exc)
            raise SystemExit(1)
        return

    if args.cmd == "run":
        if not ensure_daemon():
            raise SystemExit(1)
        # ergonomic mode: `coocon run "<code>"` runs in ephemeral sandbox
        if args.code is None:
            quick_name = f"_run_{os.getpid()}"
            client = Client()
            try:
                mode, policy = resolve_mode_policy(args.mode, args.profile, args.policy)
                client.create(quick_name, 256, 30, False, mode, policy)
                result = client.execute(quick_name, args.target, args.language)
                raise SystemExit(_print_result(result))
            except CooconError as exc:
                print_user_error(exc, "Try: coocon run \"print('hello')\" --profile fast")
                raise SystemExit(1)
            finally:
                try:
                    client.destroy(quick_name)
                except Exception:
                    pass

        merged = "\n".join(filter(None, [get_history(args.target), args.code]))
        try:
            result = Client().execute(args.target, merged, args.language)
            exit_code = _print_result(result)
            if result.success:
                save_history(args.target, merged)
            raise SystemExit(exit_code)
        except CooconError as exc:
            print_user_error(exc)
            raise SystemExit(1)

    if args.cmd == "exec":
        if not ensure_daemon():
            raise SystemExit(1)
        path = Path(args.file)
        if not path.exists() or not path.is_file():
            print_user_error(
                CooconError(f"File not found: {path}"),
                "Use an existing file path, e.g. coocon exec mybox script.py",
            )
            raise SystemExit(1)
        code = path.read_text(encoding="utf-8")
        merged = "\n".join(filter(None, [get_history(args.name), code]))
        try:
            result = Client().execute(args.name, merged, "python")
            exit_code = _print_result(result)
            if result.success:
                save_history(args.name, merged)
            raise SystemExit(exit_code)
        except CooconError as exc:
            print_user_error(exc)
            raise SystemExit(1)

    if args.cmd == "shell":
        if not ensure_daemon():
            raise SystemExit(1)
        print(f"{Colors.B}Interactive shell for '{args.name}' (Ctrl+D to exit){Colors.E}")
        while True:
            try:
                code = input(f"{Colors.G}>>> {Colors.E}")
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue

            if not code.strip():
                continue

            merged = "\n".join(filter(None, [get_history(args.name), code]))
            try:
                result = Client().execute(args.name, merged, "python")
            except CooconError as exc:
                print_user_error(exc)
                continue

            if result.success:
                save_history(args.name, merged)
                if result.output:
                    print(result.output.rstrip("\n"))
            else:
                print(f"{Colors.R}{result.error or 'execution failed'}{Colors.E}")
        return

    if args.cmd == "quick":
        if not ensure_daemon():
            raise SystemExit(1)
        name = f"_quick_{os.getpid()}"
        client = Client()
        try:
            mode, policy = resolve_mode_policy(args.mode, args.profile, args.policy)
            client.create(name, args.memory, args.timeout, False, mode, policy)
            result = client.execute(name, args.code, "python")
            raise SystemExit(_print_result(result))
        except CooconError as exc:
            print_user_error(exc, "Try: coocon quick \"print('ok')\" --profile fast")
            raise SystemExit(1)
        finally:
            try:
                client.destroy(name)
            except Exception:
                pass

    if args.cmd == "api-exec":
        if not ensure_daemon():
            raise SystemExit(1)
        try:
            payload = json.loads(args.payload)
            code = payload["code"]
            language = payload.get("language", "python")
            name = payload.get("name")
            profile = payload.get("profile")
            mode = payload.get("mode")
            memory_mb = int(payload.get("memory_mb", 256))
            timeout_secs = int(payload.get("timeout_secs", 30))
            policy = payload.get("policy")
            client = Client()
            if profile:
                mode, preset_policy = resolve_mode_policy(mode, profile, None)
                if policy is None:
                    policy = preset_policy
            else:
                mode = mode or "balanced"

            ephemeral = name is None
            sandbox = name or f"_api_{os.getpid()}"
            if ephemeral:
                client.create(sandbox, memory_mb, timeout_secs, False, mode, policy)

            result = client.execute(sandbox, code, language)
            print(
                json.dumps(
                    {
                        "success": result.success,
                        "output": result.output,
                        "error": result.error,
                        "exit_code": result.exit_code,
                        "execution_time_ms": result.time_ms,
                        "sandbox": sandbox,
                        "ephemeral": ephemeral,
                    }
                )
            )
            raise SystemExit(0 if result.success else 1)
        except Exception as exc:
            print(json.dumps({"success": False, "error": str(exc)}))
            raise SystemExit(1)
        finally:
            try:
                if "ephemeral" in locals() and ephemeral:
                    client.destroy(sandbox)
            except Exception:
                pass

    parser.print_help()


if __name__ == "__main__":
    main()
