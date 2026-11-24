"""HAR-11: credential handles. The agent (and the model) only ever see a handle such as secret://payments_api; the tool
resolves it inside its own call, and nothing the tool returns can carry the secret back out.

    vault = Secrets({"payments_api": os.environ["PAYMENTS_KEY"]})      # or Secrets.from_env("SHIO_SECRET_")
    pay = vault.bind(pay_fn)                     # args may contain "secret://payments_api"; resolved for the call only
    vault.handle("payments_api")                 # -> "secret://payments_api": what goes in prompts and plans

bind() replaces handles in arguments just before calling, then scrubs every secret value out of the result (and out of
any exception message) before it returns, so the journal, the trace, the record and the vault only ever hold the
handle. An unknown handle is an error, never a pass-through. Secrets are never logged, repr'd or serialised.
"""
import functools
import os
import re

HANDLE = re.compile(r"secret://([A-Za-z0-9_.-]+)")


class SecretError(KeyError):
    pass


class Secrets:
    def __init__(self, values):
        self._v = dict(values)

    @classmethod
    def from_env(cls, prefix="SHIO_SECRET_"):
        return cls({k[len(prefix):].lower(): v for k, v in os.environ.items() if k.startswith(prefix)})

    def __repr__(self):
        return f"<Secrets {sorted(self._v)}>"

    @staticmethod
    def handle(name):
        return f"secret://{name}"

    def _resolve(self, x):
        if isinstance(x, str):
            def sub(m):
                if m.group(1) not in self._v:
                    raise SecretError(f"unknown secret handle {m.group(0)}")
                return self._v[m.group(1)]
            return HANDLE.sub(sub, x)
        if isinstance(x, dict):
            return {k: self._resolve(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return type(x)(self._resolve(v) for v in x)
        return x

    def scrub(self, x):
        if isinstance(x, str):
            for name, v in sorted(self._v.items(), key=lambda kv: -len(kv[1])):
                if v:
                    x = x.replace(v, self.handle(name))
            return x
        if isinstance(x, dict):
            return {self.scrub(k): self.scrub(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return type(x)(self.scrub(v) for v in x)
        return x

    def bind(self, fn):
        @functools.wraps(fn)
        def call(*args, **kwargs):
            try:
                out = fn(*self._resolve(list(args)), **self._resolve(kwargs))
            except SecretError:
                raise
            except Exception as e:
                raise type(e)(self.scrub(str(e))) from None
            return self.scrub(out)
        return call
