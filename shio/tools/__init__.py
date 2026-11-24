"""HAR-9: a small vetted tool library for the agent loop. Each tool declares reads or acts and confines itself.

  file_tools(root)          file_read (reads, untrusted output) and file_write (acts); both resolve paths inside root
                            and refuse anything outside it, including through symlinks and ".."
  http_fetch(allow)         reads a URL on an allowlisted host (https only, size and time capped); its output is
                            untrusted, and its URL is a Guard control value, so an injected address is denied
  shell(sandbox)            acts; runs a command only through a shio.sandbox backend (never a bare subprocess)
  git_read(repo)            reads: status, log, diff and show with fixed arguments, no shell, no write commands
  sql_read(db)              reads: SQLite opened read-only (mode=ro) with an authorizer that refuses anything but SELECT
"""
import json
import sqlite3
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from ..harness.loop import ToolSpec


class ToolRefused(PermissionError):
    pass


def _inside(root, rel):
    root = Path(root).resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise ToolRefused(f"{rel} is outside the tool's scope")
    return p


def file_tools(root, max_bytes=200_000):
    def file_read(path):
        p = _inside(root, path)
        return p.read_text(errors="replace")[:max_bytes]

    def file_write(path, text):
        p = _inside(root, path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return {"written": str(p.relative_to(Path(root).resolve())), "bytes": len(text.encode())}

    return [ToolSpec("file_read", file_read, "reads", "read a file in the workspace"),
            ToolSpec("file_write", file_write, "acts", "write a file in the workspace", content=("text",))]


def http_fetch(allow, timeout=10, max_bytes=500_000, opener=None):
    hosts = {h.lower() for h in allow}

    def fetch(url):
        u = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        if u.scheme != "https":
            raise ToolRefused("https only")
        host = (u.hostname or "").lower()
        if host not in hosts and not any(host.endswith("." + h) for h in hosts):
            raise ToolRefused(f"{host} is not on the fetch allowlist")
        with (opener or urllib.request.urlopen)(u.geturl(), timeout=timeout) as r:
            return r.read(max_bytes).decode(errors="replace")

    return ToolSpec("http_fetch", fetch, "reads", "fetch a web page (untrusted)", control={"url": "url"},
                    opens_address=True)


def shell(sandbox):
    def run(command):
        if not isinstance(command, list) or not all(isinstance(c, str) for c in command):
            raise ToolRefused("command must be a list of strings (no shell string)")
        r = sandbox.run(command)
        return {"exit": r.exit, "stdout": r.stdout[-20000:], "stderr": r.stderr[-5000:], "killed": r.killed,
                "refused": r.refused, "backend": r.backend}
    return ToolSpec("shell", run, "acts", "run a command in the sandbox")


GIT_READ = {"status": ["status", "--porcelain=v1"], "log": ["log", "--oneline", "-n", "50"], "diff": ["diff", "--stat"],
            "show": ["show", "--stat", "HEAD"]}


def git_read(repo):
    def git(what):
        if what not in GIT_READ:
            raise ToolRefused(f"git {what} is not one of the read-only commands ({', '.join(GIT_READ)})")
        r = subprocess.run(["git", "-C", str(repo), "--no-pager", *GIT_READ[what]], capture_output=True, text=True,
                           timeout=20, env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                                            "GIT_CONFIG_NOSYSTEM": "1", "HOME": "/nonexistent"})
        return r.stdout[-20000:] if r.returncode == 0 else f"git error: {r.stderr[-500:]}"
    return ToolSpec("git_read", git, "reads", "read-only git: status, log, diff, show")


def sql_read(db, max_rows=500):
    def query(sql):
        con = sqlite3.connect(f"file:{Path(db).resolve()}?mode=ro", uri=True)

        def auth(action, *a):
            return sqlite3.SQLITE_OK if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                                                   sqlite3.SQLITE_FUNCTION) else sqlite3.SQLITE_DENY
        con.set_authorizer(auth)
        try:
            cur = con.execute(sql)
            cols = [d[0] for d in cur.description or []]
            return {"columns": cols, "rows": [list(r) for r in cur.fetchmany(max_rows)]}
        except sqlite3.DatabaseError as e:
            raise ToolRefused(f"query refused: {e}") from None
        finally:
            con.close()
    return ToolSpec("sql_read", query, "reads", "read-only SQL (SELECT only)")
