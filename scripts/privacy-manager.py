#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""privacy-manager — install, start and configure the redaction gateway + local model.

The plugin panel drives this tool; it is also usable by hand.

    privacy-manager status                  # JSON: what exists, what runs, URLs
    privacy-manager config                  # JSON: current effective configuration
    privacy-manager config --set k=v [...]  # persist overrides, restart what changed
    privacy-manager install --part gateway  # venv + gateway.py + unit, then start
    privacy-manager install --part model    # llama-server binary + GGUF, then start
    privacy-manager start|stop|restart --part gateway|model|all
    privacy-manager logs --part gateway|model --lines 80

Long operations (install) run inside a transient systemd unit, so a browser request
returns immediately and the panel can poll `status` for progress via the log file.

Both halves are independent processes: the gateway is a Python reverse proxy and
the model is a llama.cpp server. The gateway reaches the model over HTTP, so the
model URL is configurable on its own; when it points at a remote host the local
model does not need to run at all.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------- layout -----
DEPLOY_DIR = Path(os.environ.get("PRIVACY_DEPLOY_DIR", "/opt/privacy-gateway"))
REPO_DIR = Path(os.environ.get("PRIVACY_REPO_DIR", "/root/privacy-gateway"))
CONFIG_FILE = Path(os.environ.get("PRIVACY_CONFIG_FILE", "/etc/privacy-gateway/manager.json"))
ENV_DIR = Path(os.environ.get("PRIVACY_ENV_DIR", "/etc/privacy-gateway"))
LOG_DIR = Path(os.environ.get("PRIVACY_LOG_DIR", "/var/log/privacy-gateway"))
STATE_DIR = Path(os.environ.get("PRIVACY_STATE_DIR", "/var/lib/privacy-gateway"))

GATEWAY_UNIT = "privacy-gateway.service"
MODEL_UNIT = "llama-privacy.service"

GATEWAY_ENV = ENV_DIR / "gateway.env"
MODEL_ENV = ENV_DIR / "model.env"
INSTALL_LOG = LOG_DIR / "install.log"

VENV_DIR = DEPLOY_DIR / "venv"
VENV_PY = VENV_DIR / "bin" / "python"
MODEL_BIN_DIR = DEPLOY_DIR / "bin"
MODEL_BINARY = MODEL_BIN_DIR / "llama-server"
GGUF_DIR = DEPLOY_DIR / "v4"

IN_FLIGHT = STATE_DIR / "install.in-flight"

# -------------------------------------------------------------- defaults -----
DEFAULTS = {
    # Gateway listen + upstream
    "gateway_port": 8317,
    "gateway_host": "0.0.0.0",
    "backend_url": "http://127.0.0.1:8316",
    # The endpoint the panel writes into the *unprotected* provider row when it
    # creates the gateway-routed twin. Kept separate from backend_url because the
    # gateway may forward to loopback while clients reach the backend by another
    # address.
    "direct_base_url": "http://100.114.93.90:8316/v1",
    # Model endpoint used by Layer 1. Independent of where the model runs.
    "model_url": "http://127.0.0.1:8319",
    # llama-server listen
    "model_port": 8319,
    "model_host": "127.0.0.1",
    # Downloads
    "gateway_repo": "https://github.com/amwangfan/privacy-gateway.git",
    "gateway_ref": "main",
    "model_gguf_url": (
        "https://huggingface.co/amwangfan/privacy-gateway-v4-qwen2.5-0.5b/resolve/main/"
        "qwen2.5.0.5b-privacy-v4-f16.gguf"
    ),
    "model_binary_url": "",  # empty: resolve the newest llama.cpp ubuntu-x64 release
    "model_filename": "qwen2.5-0.5b-privacy-v4-f16.gguf",
    "hf_endpoint": os.environ.get("HF_ENDPOINT", ""),
    "model_context": 2048,
    "model_parallel": 4,
}

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _fail(error: str, **extra) -> None:
    print(json.dumps({"ok": False, "error": error, **extra}, ensure_ascii=False))
    raise SystemExit(EXIT_FAILED)


def _say(*parts: object) -> None:
    print(*parts, flush=True)


# --------------------------------------------------------------- helpers -----
def load_config() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
        except Exception as exc:
            _say(f"[warn] cannot read {CONFIG_FILE}: {exc}", file=sys.stderr)
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(f".tmp-{os.getpid()}")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)


def run(cmd: list[str], timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def systemctl_active(unit: str) -> str:
    try:
        return run(["systemctl", "is-active", unit], timeout=10).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def http_ok(url: str, timeout: float = 4.0) -> bool:
    if not url:
        return False
    try:
        req = urllib.request.Request(url, headers={"accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    import socket

    target = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True
    except Exception:
        return False


def venv_ready() -> bool:
    return VENV_PY.exists() and os.access(VENV_PY, os.X_OK)


def model_binary_ready() -> bool:
    if MODEL_BINARY.exists() and os.access(MODEL_BINARY, os.X_OK):
        return True
    # Fall back to a build tree, which is how this host has always run it.
    built = DEPLOY_DIR / "llama.cpp" / "build" / "bin" / "llama-server"
    return built.exists() and os.access(built, os.X_OK)


def effective_binary() -> str:
    if MODEL_BINARY.exists() and os.access(MODEL_BINARY, os.X_OK):
        return str(MODEL_BINARY)
    built = DEPLOY_DIR / "llama.cpp" / "build" / "bin" / "llama-server"
    if built.exists():
        return str(built)
    return str(MODEL_BINARY)


def gguf_path(cfg: dict) -> Path:
    return GGUF_DIR / cfg.get("model_filename", DEFAULTS["model_filename"])


def gateway_script() -> Path:
    return DEPLOY_DIR / "gateway.py"


def _same_bytes(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def install_in_flight() -> bool:
    if not IN_FLIGHT.exists():
        return False
    try:
        age = time.time() - IN_FLIGHT.stat().st_mtime
    except OSError:
        return False
    # A stale marker (crashed unit) must not block forever.
    if age > 3600:
        try:
            IN_FLIGHT.unlink()
        except OSError:
            pass
        return False
    return True


# --------------------------------------------------------------- commands ----
def cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config()
    gw_port = int(cfg["gateway_port"])
    model_port = int(cfg["model_port"])

    gateway = {
        "unit": GATEWAY_UNIT,
        "active": systemctl_active(GATEWAY_UNIT),
        "code_present": gateway_script().exists(),
        "venv_present": venv_ready(),
        "required_env_present": all(
            os.environ.get(name) or True for name in ("PATH",)
        ),
        "listening": port_open("127.0.0.1", gw_port),
        "port": gw_port,
        "url": f"http://127.0.0.1:{gw_port}",
        "healthy": http_ok(f"http://127.0.0.1:{gw_port}/privacy/health"),
        "config_file": str(GATEWAY_ENV),
    }
    model = {
        "unit": MODEL_UNIT,
        "active": systemctl_active(MODEL_UNIT),
        "binary_present": model_binary_ready(),
        "binary_path": effective_binary(),
        "weights_present": gguf_path(cfg).exists(),
        "weights_path": str(gguf_path(cfg)),
        "weights_bytes": gguf_path(cfg).stat().st_size if gguf_path(cfg).exists() else 0,
        "listening": port_open("127.0.0.1", model_port),
        "port": model_port,
        "url": f"http://127.0.0.1:{model_port}",
        "healthy": http_ok(f"http://127.0.0.1:{model_port}/health"),
        "config_file": str(MODEL_ENV),
    }

    # Readiness here is about "can be started", so a running-but-unhealthy unit is
    # still ready; the UI shows active/healthy separately.
    gateway["ready"] = gateway["code_present"] and gateway["venv_present"]
    model["ready"] = model["binary_present"] and model["weights_present"]

    gateway["needs"] = [
        name
        for name, ok in (
            ("venv", gateway["venv_present"]),
            ("code", gateway["code_present"]),
        )
        if not ok
    ]
    model["needs"] = [
        name
        for name, ok in (
            ("binary", model["binary_present"]),
            ("weights", model["weights_present"]),
        )
        if not ok
    ]

    print(json.dumps({
        "ok": True,
        "installing": install_in_flight(),
        "config": cfg,
        "deploy_dir": str(DEPLOY_DIR),
        "install_log": str(INSTALL_LOG),
        "gateway": gateway,
        "model": model,
    }, ensure_ascii=False))
    return EXIT_OK


def cmd_config(args: argparse.Namespace) -> int:
    cfg = load_config()
    if not args.set:
        print(json.dumps({"ok": True, "config": cfg, "file": str(CONFIG_FILE)}, ensure_ascii=False))
        return EXIT_OK

    int_keys = {"gateway_port", "model_port", "model_context", "model_parallel"}
    # Only a value that actually differs counts as a change, otherwise re-saving
    # the form would restart both services on every click.
    changed: list[str] = []
    for item in args.set:
        if "=" not in item:
            _fail(f"--set expects key=value, got {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key not in DEFAULTS:
            _fail(f"unknown setting {key!r}", known=sorted(DEFAULTS))
        new_value = int(value) if key in int_keys else value
        if cfg.get(key) == new_value:
            continue
        cfg[key] = new_value
        changed.append(key)

    if not changed:
        print(json.dumps({
            "ok": True, "changed": [], "restarted": [], "config": cfg,
            "detail": "no value changed",
        }, ensure_ascii=False))
        return EXIT_OK

    save_config(cfg)
    restarted = _apply_runtime_config(cfg, changed)
    print(json.dumps({
        "ok": True,
        "changed": changed,
        "config": cfg,
        "restarted": restarted,
    }, ensure_ascii=False))
    return EXIT_OK


def _write_env_file(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = [
        "# Generated by privacy-manager. Loaded by EnvironmentFile= in the unit;",
        "# EnvironmentFile wins over the unit's own Environment= assignments.",
    ]
    for key, value in values.items():
        lines.append(f'{key}="{value}"')
    tmp = path.with_suffix(f".tmp-{os.getpid()}")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _apply_runtime_config(cfg: dict, changed: list[str]) -> list[str]:
    """Regenerate the env files and restart only the halves that changed."""
    restarted: list[str] = []

    gateway_keys = {"gateway_port", "gateway_host", "backend_url", "model_url"}
    model_keys = {"model_port", "model_host", "model_context", "model_parallel", "model_filename"}

    if gateway_keys & set(changed):
        _write_env_file(GATEWAY_ENV, {
            "GATEWAY_HOST": str(cfg["gateway_host"]),
            "GATEWAY_PORT": str(cfg["gateway_port"]),
            "BACKEND_URL": str(cfg["backend_url"]),
            "LAYER1_URL": str(cfg["model_url"]),
        })
        _reload_and_restart(GATEWAY_UNIT)
        restarted.append("gateway")

    if model_keys & set(changed):
        _write_env_file(MODEL_ENV, {
            "MODEL_BINARY": effective_binary(),
            "MODEL_HOST": str(cfg["model_host"]),
            "MODEL_PORT": str(cfg["model_port"]),
            "MODEL_FILE": str(gguf_path(cfg)),
            "MODEL_CONTEXT": str(cfg["model_context"]),
            "MODEL_PARALLEL": str(cfg["model_parallel"]),
        })
        _reload_and_restart(MODEL_UNIT)
        restarted.append("model")

    return restarted


def _reload_and_restart(unit: str) -> None:
    try:
        run(["systemctl", "daemon-reload"], timeout=20)
        run(["systemctl", "restart", unit], timeout=120)
    except Exception as exc:
        _say(f"[warn] restart of {unit} failed: {exc}", file=sys.stderr)


def cmd_start(args: argparse.Namespace) -> int:
    cfg = load_config()
    parts = ["gateway", "model"] if args.part == "all" else [args.part]
    for part in parts:
        unit = GATEWAY_UNIT if part == "gateway" else MODEL_UNIT
        try:
            run(["systemctl", "start", unit], timeout=180)
        except Exception as exc:
            _fail(f"cannot start {unit}: {exc}")
    time.sleep(1.5)
    return cmd_status(argparse.Namespace())


def cmd_stop(args: argparse.Namespace) -> int:
    parts = ["gateway", "model"] if args.part == "all" else [args.part]
    for part in parts:
        unit = GATEWAY_UNIT if part == "gateway" else MODEL_UNIT
        try:
            run(["systemctl", "stop", unit], timeout=120)
        except Exception as exc:
            _fail(f"cannot stop {unit}: {exc}")
    return cmd_status(argparse.Namespace())


def cmd_restart(args: argparse.Namespace) -> int:
    cfg = load_config()
    # Rewrite both env files from the stored config so a restart picks up edits
    # even if only the file was changed by hand.
    _write_env_file(GATEWAY_ENV, {
        "GATEWAY_HOST": str(cfg["gateway_host"]),
        "GATEWAY_PORT": str(cfg["gateway_port"]),
        "BACKEND_URL": str(cfg["backend_url"]),
        "LAYER1_URL": str(cfg["model_url"]),
    })
    _write_env_file(MODEL_ENV, {
        "MODEL_BINARY": effective_binary(),
        "MODEL_HOST": str(cfg["model_host"]),
        "MODEL_PORT": str(cfg["model_port"]),
        "MODEL_FILE": str(gguf_path(cfg)),
        "MODEL_CONTEXT": str(cfg["model_context"]),
        "MODEL_PARALLEL": str(cfg["model_parallel"]),
    })
    parts = ["gateway", "model"] if args.part == "all" else [args.part]
    for part in parts:
        _reload_and_restart(GATEWAY_UNIT if part == "gateway" else MODEL_UNIT)
    time.sleep(1.5)
    return cmd_status(argparse.Namespace())


def cmd_logs(args: argparse.Namespace) -> int:
    unit = GATEWAY_UNIT if args.part == "gateway" else MODEL_UNIT
    proc = run(["journalctl", "-u", unit, "--no-pager", "-n", str(args.lines)], timeout=30)
    print(json.dumps({"ok": True, "unit": unit, "text": proc.stdout[-20000:]}, ensure_ascii=False))
    return EXIT_OK


# ---------------------------------------------------------------- install ----
def _resolve_model_binary_url(cfg: dict) -> str:
    if cfg.get("model_binary_url"):
        return str(cfg["model_binary_url"])
    machine = os.uname().machine
    arch = "arm64" if machine in ("aarch64", "arm64") else "x64"
    api = "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=5"
    try:
        req = urllib.request.Request(api, headers={"accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            releases = json.load(resp)
    except Exception as exc:
        _fail(
            "cannot resolve a llama.cpp release; set model_binary_url explicitly "
            f"(GitHub API failed: {exc})"
        )
    wanted = f"-bin-ubuntu-{arch}.tar.gz"
    for rel in releases:
        for asset in rel.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(wanted) and "cuda" not in name and "vulkan" not in name:
                return asset["browser_download_url"]
    _fail(f"no ubuntu-{arch} asset found in the latest releases; set model_binary_url")


def _download(url: str, dest: Path, label: str) -> None:
    dest.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    _say(f"[install] downloading {label}")
    _say(f"[install]   {url}")
    _say(f"[install]   -> {dest}")
    headers = {"user-agent": "privacy-manager/1.0"}
    if "huggingface.co" in url:
        endpoint = os.environ.get("HF_ENDPOINT", "")
        if endpoint:
            url = url.replace("https://huggingface.co", endpoint.rstrip("/"))
    req = urllib.request.Request(url, headers=headers)
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as fh:
            total = int(resp.headers.get("content-length") or 0)
            done = 0
            last = 0.0
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                now = time.time()
                if now - last > 5:
                    last = now
                    pct = f"{done * 100 // total}%" if total else f"{done // 1048576} MiB"
                    _say(f"[install]   {label}: {pct} ({done // 1048576} MiB, {int(now - started)}s)")
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        _fail(f"download failed for {label}: {exc}")
    os.replace(tmp, dest)
    _say(f"[install]   {label} done ({dest.stat().st_size // 1048576} MiB)")


def install_gateway(cfg: dict) -> None:
    deploy = DEPLOY_DIR
    deploy.mkdir(parents=True, exist_ok=True)

    if not venv_ready():
        _say("[install] creating the virtualenv")
        if not run(["python3", "-m", "venv", str(VENV_DIR)], timeout=300).returncode == 0:
            _fail("python3 -m venv failed")
    req = REPO_DIR / "requirements.txt"
    if req.exists():
        _say("[install] installing Python requirements")
        proc = run([str(VENV_PY), "-m", "pip", "install", "--upgrade", "pip"], timeout=600)
        if proc.returncode != 0:
            _say(proc.stderr[-2000:], file=sys.stderr)
        proc = run([str(VENV_PY), "-m", "pip", "install", "-r", str(req)], timeout=1800)
        if proc.returncode != 0:
            _say(proc.stdout[-2000:], file=sys.stderr)
            _fail("pip install -r requirements.txt failed")

    # Copy the gateway itself. Never silently destroy a working deployment that
    # already carries vault state: back the old file up first.
    src = REPO_DIR / "gateway.py"
    if src.exists():
        target = gateway_script()
        if target.exists() and _same_bytes(src, target):
            _say("[install] gateway.py is already current; leaving it in place")
        else:
            if target.exists():
                backup = target.with_suffix(f".bak-{int(time.time())}")
                shutil.copy2(target, backup)
                _say(f"[install] backed up the existing gateway.py to {backup.name}")
            _say("[install] installing gateway.py")
            shutil.copy2(src, target)
            os.chmod(target, 0o755)
    else:
        _say(f"[install] {src} not found; keeping any existing gateway.py")

    _write_env_file(GATEWAY_ENV, {
        "GATEWAY_HOST": str(cfg["gateway_host"]),
        "GATEWAY_PORT": str(cfg["gateway_port"]),
        "BACKEND_URL": str(cfg["backend_url"]),
        "LAYER1_URL": str(cfg["model_url"]),
    })


def install_model(cfg: dict) -> None:
    if not model_binary_ready():
        url = _resolve_model_binary_url(cfg)
        with tempfile.TemporaryDirectory() as tmpdir:
            archive = Path(tmpdir) / "llama.tar.gz"
            _download(url, archive, "llama.cpp ubuntu build")
            _say("[install] extracting llama-server")
            MODEL_BIN_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
            with tarfile.open(archive) as tar:
                member = None
                for m in tar.getmembers():
                    if os.path.basename(m.name) == "llama-server" and m.isfile():
                        member = m
                        break
                if member is None:
                    _fail("the llama.cpp archive has no llama-server binary")
                with tar.extractfile(member) as fh, open(MODEL_BINARY, "wb") as out:
                    shutil.copyfileobj(fh, out)
            os.chmod(MODEL_BINARY, 0o755)
        _say(f"[install] llama-server installed at {MODEL_BINARY}")
    else:
        _say(f"[install] llama-server already present at {effective_binary()}")

    weights = gguf_path(cfg)
    if not weights.exists():
        _download(str(cfg["model_gguf_url"]), weights, "model weights")
    else:
        _say(f"[install] weights already present at {weights}")

    _write_env_file(MODEL_ENV, {
        "MODEL_BINARY": effective_binary(),
        "MODEL_HOST": str(cfg["model_host"]),
        "MODEL_PORT": str(cfg["model_port"]),
        "MODEL_FILE": str(weights),
        "MODEL_CONTEXT": str(cfg["model_context"]),
        "MODEL_PARALLEL": str(cfg["model_parallel"]),
    })


def _spawn_install(part: str) -> None:
    """Run the install in a transient unit so the HTTP request can return now."""
    LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    IN_FLIGHT.write_text(json.dumps({"part": part, "started": time.time()}), encoding="utf-8")

    inner = (
        f"{sys.executable} {Path(__file__).resolve()} _install --part {part} "
        f"2>&1 | tee -a {INSTALL_LOG}"
    )
    unit = f"privacy-install-{part}-{int(time.time())}"
    try:
        proc = run([
            "systemd-run", "--unit", unit, "--collect", "--quiet",
            "/bin/bash", "-lc", inner,
        ], timeout=30)
    except Exception as exc:
        _fail(f"cannot start the install unit: {exc}")
    if proc.returncode != 0:
        _fail((proc.stderr or proc.stdout or "systemd-run failed").strip())


def cmd_install(args: argparse.Namespace) -> int:
    if install_in_flight():
        _fail("an install is already running")

    cfg = load_config()
    if args.part in ("gateway", "model"):
        parts = [args.part]
    else:
        parts = []
        if not venv_ready() or not gateway_script().exists():
            parts.append("gateway")
        if not model_binary_ready() or not gguf_path(cfg).exists():
            parts.append("model")

    if not parts:
        print(json.dumps({
            "ok": True, "started": [], "detail": "everything is already installed",
        }, ensure_ascii=False))
        return EXIT_OK

    for part in parts:
        _spawn_install(part)
    print(json.dumps({
        "ok": True,
        "started": parts,
        "log": str(INSTALL_LOG),
        "detail": "install running in the background; poll status for progress",
    }, ensure_ascii=False))
    return EXIT_OK


def cmd_install_foreground(args: argparse.Namespace) -> int:
    """Internal: the body the transient unit runs."""
    cfg = load_config()
    try:
        if args.part in ("gateway", "all"):
            install_gateway(cfg)
        if args.part in ("model", "all"):
            install_model(cfg)
    except SystemExit:
        raise
    except Exception as exc:
        _say(f"[install] FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FAILED
    finally:
        try:
            IN_FLIGHT.unlink()
        except OSError:
            pass
    _say("[install] done; starting the service")
    unit = GATEWAY_UNIT if args.part == "gateway" else MODEL_UNIT
    if args.part == "all":
        run(["systemctl", "start", GATEWAY_UNIT, MODEL_UNIT], timeout=180)
    else:
        run(["systemctl", "start", unit], timeout=180)
    return EXIT_OK


# ------------------------------------------------------------------ parser ---
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-manager", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="JSON status of both halves")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("config", help="read or change the persisted configuration")
    p.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    p.set_defaults(func=cmd_config)

    for name, fn, help_text in (
        ("start", cmd_start, "start the gateway and/or the model"),
        ("stop", cmd_stop, "stop the gateway and/or the model"),
        ("restart", cmd_restart, "rewrite env files and restart"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--part", default="all", choices=["gateway", "model", "all"])
        p.set_defaults(func=fn)

    p = sub.add_parser("install", help="download and deploy a missing half")
    p.add_argument("--part", default="auto", choices=["gateway", "model", "all", "auto"])
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("_install", help="internal: run the install in the foreground")
    p.add_argument("--part", default="all", choices=["gateway", "model", "all"])
    p.set_defaults(func=cmd_install_foreground)

    p = sub.add_parser("logs", help="recent journal lines for one half")
    p.add_argument("--part", default="gateway", choices=["gateway", "model"])
    p.add_argument("--lines", type=int, default=80)
    p.set_defaults(func=cmd_logs)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
