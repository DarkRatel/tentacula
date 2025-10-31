_no_default = object()


class DSDict(dict):
    """Case-insensitive dictionary that preserves original keys."""

    def __init__(self, seed=None, **kwargs):
        super().__init__()
        self._original_keys = {}
        # Defer work to the method .update
        self.update(seed)
        self.update(kwargs)

    def __getitem__(self, key):
        return dict.__getitem__(self, key.casefold())

    def __setitem__(self, key, value):
        lower_key = key.casefold()
        self._original_keys[lower_key] = key
        return dict.__setitem__(self, lower_key, value)

    def __delitem__(self, key):
        lower_key = key.casefold()
        dict.__delitem__(self, lower_key)
        self._original_keys.pop(lower_key, None)

    def __contains__(self, key):
        return dict.__contains__(self, key.casefold())

    def __or__(self, other):
        base = self.copy()
        base.update(other)
        return base

    def __ror__(self, other):
        base = DSDict(other)
        base.update(other)
        return base

    def copy(self):
        new_dict = DSDict()
        new_dict.update(self.items())
        return new_dict

    def get(self, key, default=None):
        return dict.get(self, key.casefold(), default)

    def pop(self, key, default=_no_default):
        lower_key = key.casefold()
        if default is _no_default:
            self._original_keys.pop(lower_key, None)
            return dict.pop(self, lower_key)
        else:
            self._original_keys.pop(lower_key, None)
            return dict.pop(self, lower_key, default)

    def setdefault(self, key, default=None):
        lower_key = key.casefold()
        if lower_key not in self:
            self._original_keys[lower_key] = key
        return dict.setdefault(self, lower_key, default)

    def update(self, seed=None, **kwargs):
        if seed is None:
            seed = {}

        if hasattr(seed, "items"):
            for key, value in seed.items():
                self[key] = value
        else:
            for key, value in seed:
                self[key] = value

        for key, value in kwargs.items():
            self[key] = value

    def keys(self):
        return list(self._original_keys[k] for k in dict.keys(self))

    def items(self):
        return [(self._original_keys[k], v) for k, v in dict.items(self)]

    def __iter__(self):
        return iter(self.keys())

    def __repr__(self):
        items = ", ".join(f"{k!r}: {v!r}" for k, v in self.items())
        return f"{self.__class__.__name__}({{{items}}})"