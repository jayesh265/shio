"""HAR-2: a sandboxed executor. Python is not a sandbox, so commands an agent runs go through one of these.

    sb = Sandbox.best(Limits(scope="work/", network="none", cpu_seconds=5, wall_seconds=10))
    r = sb.run(["python3", "script.py"])       # -> Result(exit, stdout, stderr, killed, refused, backend, ...)

Backends (the first available is chosen by best()):
  macos    sandbox-exec with a generated profile: file writes only inside the scope (and a private temp dir),
           network denied, or allowed only to a local filtering proxy that admits the allowlisted hosts
  bwrap    Linux bubblewrap: read-only root, the scope bound writable, a new network namespace (no network)
  docker   docker run --network none, the scope mounted at /work, --cpus and --memory limits
Every backend also applies: a CPU-seconds limit (RLIMIT_CPU), a wall-clock limit that kills the whole process group,
an output cap, and a scrubbed environment (only PATH, HOME=scope, LANG, and what you pass in `env`).

Fail closed: if no backend can confine the process, Sandbox.best() raises instead of running unconfined; tests and
the CPU/time limits alone can use Unconfined explicitly, which says so in every result. A network allowlist is
enforced only by the macos backend (bwrap and docker give none or full network; they refuse an allowlist). Each run
is recorded (a SignedChain "sandbox" when `log` is given): the command, the limits, exit, kill, refusals, timing.

Limits, plainly: sandbox-exec is deprecated by Apple though still shipped; profiles confine files and network, not
every syscall; bwrap needs unprivileged user namespaces; an allowlist names hosts, so a compromised allowed host is
still reachable.
"""
import dataclasses
import os
import platform
import resource
import select
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class SandboxUnavailable(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Limits:
    scope: str
    network: object = "none"            # "none" or a tuple of allowlisted host names
    cpu_seconds: int = 10
    wall_seconds: float = 30
    max_output: int = 200_000
    env: tuple = ()                     # ((name, value), ...)


@dataclasses.dataclass
class Result:
    command: list
    exit: int
    stdout: str
    stderr: str
    killed: bool
    seconds: float
    backend: str
    refused: list = dataclasses.field(default_factory=list)

    @property
    def ok(self):
        return self.exit == 0 and not self.killed


class _Base:
    name = "base"

    def __init__(self, limits, log=None, signer=None):
        self.limits, self.log, self.signer = limits, log, signer
        self.scope = Path(limits.scope).resolve()
        self.scope.mkdir(parents=True, exist_ok=True)

    @classmethod
    def available(cls):
        return False

    def _env(self, extra=None):
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin", "HOME": str(self.scope),
               "LANG": "C.UTF-8", "TMPDIR": str(self.scope / ".tmp")}
        env.update(dict(self.limits.env))
        env.update(extra or {})
        (self.scope / ".tmp").mkdir(exist_ok=True)
        return env

    def _preexec(self):
        cpu = int(self.limits.cpu_seconds)

        def fn():
            os.setsid()
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        return fn

    def wrap(self, argv):
        return argv, {}

    def run(self, argv, stdin=None):
        argv = [str(a) for a in argv]
        wrapped, extra_env = self.wrap(argv)
        t0 = time.monotonic()
        proc = subprocess.Popen(wrapped, cwd=self.scope, env=self._env(extra_env), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=self._preexec())
        killed = False
        try:
            out, err = proc.communicate(stdin.encode() if stdin else None, timeout=self.limits.wall_seconds)
        except subprocess.TimeoutExpired:
            killed = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = proc.communicate()
        code = proc.returncode
        if code is not None and code < 0 and -code in (signal.SIGXCPU, signal.SIGKILL):
            killed = True
        cap = self.limits.max_output
        res = Result(argv, code, out.decode(errors="replace")[:cap], err.decode(errors="replace")[:cap], killed,
                     round(time.monotonic() - t0, 3), self.name, self._refusals(err.decode(errors="replace")))
        self._record(res)
        return res

    def _refusals(self, stderr):
        hits = [ln for ln in stderr.splitlines() if "Operation not permitted" in ln or "Permission denied" in ln
                or "Read-only file system" in ln or "nodename nor servname" in ln or "Could not resolve" in ln
                or "Network is unreachable" in ln or "Failed to connect" in ln
                or "Couldn't connect" in ln or "Operation not permitted" in ln]
        return hits[:20]

    def _record(self, r):
        if not self.log:
            return
        from ..governance.chain import SignedChain
        SignedChain(self.log, "sandbox").append("sandbox_run", {
            "backend": r.backend, "command": r.command[:20], "exit": r.exit, "killed": r.killed, "seconds": r.seconds,
            "refused": r.refused, "scope": str(self.scope), "network": list(self.limits.network)
            if isinstance(self.limits.network, (list, tuple)) else self.limits.network,
            "cpu_seconds": self.limits.cpu_seconds, "wall_seconds": self.limits.wall_seconds}, self.signer)


class Unconfined(_Base):
    """CPU, time and output limits only. Files and network are NOT confined; every result says backend 'unconfined'."""
    name = "unconfined"

    @classmethod
    def available(cls):
        return True


class AllowlistProxy:
    """A local HTTP(S) proxy admitting only allowlisted hosts (CONNECT for https, absolute URLs for http)."""

    def __init__(self, hosts):
        self.hosts = {h.lower().rstrip(".") for h in hosts}
        self.refused, self.allowed = [], []
        proxy = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _ok(self, host):
                host = (host or "").split(":")[0].lower().rstrip(".")
                return host in proxy.hosts or any(host.endswith("." + h) for h in proxy.hosts)

            def do_CONNECT(self):
                host, _, port = self.path.partition(":")
                if not self._ok(host):
                    proxy.refused.append(host)
                    self.send_error(403, "host not on the sandbox allowlist")
                    return
                proxy.allowed.append(host)
                try:
                    up = socket.create_connection((host, int(port or 443)), timeout=10)
                except OSError:
                    self.send_error(502)
                    return
                self.send_response(200, "Connection established")
                self.end_headers()
                conns = [self.connection, up]
                while True:
                    r, _, _ = select.select(conns, [], [], 30)
                    if not r:
                        break
                    for s in r:
                        data = s.recv(65536)
                        if not data:
                            up.close()
                            return
                        (up if s is self.connection else self.connection).sendall(data)

            def do_GET(self):
                from urllib.parse import urlparse
                host = urlparse(self.path).hostname
                if not self._ok(host):
                    proxy.refused.append(host)
                    self.send_error(403, "host not on the sandbox allowlist")
                    return
                self.send_error(501, "plain http through the sandbox proxy is not supported; use https")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


class MacSandbox(_Base):
    name = "macos"

    @classmethod
    def available(cls):
        return platform.system() == "Darwin" and shutil.which("sandbox-exec") is not None

    def profile(self, proxy_port=None):
        scope = str(self.scope).replace('"', "")
        net = '(allow network-outbound (remote ip "localhost:{}"))'.format(proxy_port) if proxy_port else ""
        return ("(version 1)(allow default)"
                "(deny network*)" + net +
                '(allow network* (local unix-socket))'
                "(deny file-write*)"
                f'(allow file-write* (subpath "{scope}") (literal "/dev/null") (literal "/dev/stdout") '
                f'(literal "/dev/stderr") (regex #"^/dev/tty") (regex #"^/dev/fd/"))')

    def run(self, argv, stdin=None):
        self._proxy = AllowlistProxy(self.limits.network) if isinstance(self.limits.network, (list, tuple)) else None
        try:
            r = super().run(argv, stdin)
            if self._proxy:
                r.refused += [f"network: {h} is not on the allowlist" for h in self._proxy.refused]
                if self._proxy.refused:
                    self._record(r)
            return r
        finally:
            if self._proxy:
                self._proxy.close()

    def wrap(self, argv):
        port = self._proxy.port if getattr(self, "_proxy", None) else None
        env = {"HTTPS_PROXY": f"http://127.0.0.1:{port}", "HTTP_PROXY": f"http://127.0.0.1:{port}",
               "https_proxy": f"http://127.0.0.1:{port}", "http_proxy": f"http://127.0.0.1:{port}"} if port else {}
        return ["sandbox-exec", "-p", self.profile(port)] + argv, env


class BwrapSandbox(_Base):
    name = "bwrap"

    @classmethod
    def available(cls):
        if platform.system() != "Linux" or not shutil.which("bwrap"):
            return False
        return subprocess.run(["bwrap", "--ro-bind", "/", "/", "--unshare-net", "true"], capture_output=True).returncode == 0

    def wrap(self, argv):
        if isinstance(self.limits.network, (list, tuple)):
            raise SandboxUnavailable("bwrap gives no network or all of it: a host allowlist needs the macos backend")
        return ["bwrap", "--ro-bind", "/", "/", "--bind", str(self.scope), str(self.scope), "--dev", "/dev",
                "--proc", "/proc", "--tmpfs", "/tmp", "--unshare-net", "--unshare-pid", "--die-with-parent",
                "--chdir", str(self.scope)] + argv, {}


class DockerSandbox(_Base):
    name = "docker"
    image = "python:3.12-slim"

    @classmethod
    def available(cls):
        return shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0

    def wrap(self, argv):
        if isinstance(self.limits.network, (list, tuple)):
            raise SandboxUnavailable("docker --network none or full network: a host allowlist needs the macos backend")
        return ["docker", "run", "--rm", "-i", "--network", "none", "--cpus", "1", "--memory", "512m",
                "--pids-limit", "128", "-v", f"{self.scope}:/work", "-w", "/work", "--read-only", "--tmpfs", "/tmp",
                self.image] + argv, {}


BACKENDS = (MacSandbox, BwrapSandbox, DockerSandbox)


class Sandbox:
    @staticmethod
    def best(limits, log=None, signer=None, allow_unconfined=False):
        for b in BACKENDS:
            if b.available():
                return b(limits, log, signer)
        if allow_unconfined:
            return Unconfined(limits, log, signer)
        raise SandboxUnavailable("no sandbox backend can confine processes here (sandbox-exec, bwrap or docker): "
                                 "refusing to run commands unconfined")
