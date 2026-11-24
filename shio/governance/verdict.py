"""Verdict: what a pack's check returns.

A check in a .shio program is compiled to `bool(expression)`, so a pack check must be truthy exactly when it passed.
A Verdict is: `bool(v)` is whether it passed, `str(v)` is why, and `v.evidence` holds what it found (the identifiers
left in a text, the figures with no source, ...). It is immutable, so nothing downstream can turn a failure into a
pass.
"""


class Verdict:
    __slots__ = ("_passed", "_detail", "_evidence")

    def __init__(self, passed, detail="", evidence=()):
        object.__setattr__(self, "_passed", bool(passed))
        object.__setattr__(self, "_detail", str(detail or ""))
        object.__setattr__(self, "_evidence", tuple(evidence))

    def __setattr__(self, *_):
        raise AttributeError("a Verdict cannot be changed")

    __delattr__ = __setattr__

    @property
    def passed(self):
        return self._passed

    @property
    def detail(self):
        return self._detail

    @property
    def evidence(self):
        return self._evidence

    def __bool__(self):
        return self._passed

    def __str__(self):
        return self._detail or ("passed" if self._passed else "failed")

    def __repr__(self):
        return f"Verdict({self._passed}, {self._detail!r})"

    def __eq__(self, other):
        if isinstance(other, Verdict):
            return (self._passed, self._detail, self._evidence) == (other._passed, other._detail, other._evidence)
        if isinstance(other, bool):
            return self._passed is other
        return NotImplemented

    def __hash__(self):
        return hash((self._passed, self._detail, self._evidence))

    @classmethod
    def ok(cls, detail="", evidence=()):
        return cls(True, detail, evidence)

    @classmethod
    def fail(cls, detail, evidence=()):
        return cls(False, detail, evidence)

    @classmethod
    def of(cls, value):
        """A check function's result as a Verdict: a Verdict, a bool, or (bool, detail)."""
        if isinstance(value, Verdict):
            return value
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bool):
            return cls(value[0], value[1])
        if isinstance(value, bool):
            return cls(value)
        raise TypeError(f"a pack check must return a Verdict, a bool or (bool, detail), not {type(value).__name__}")
