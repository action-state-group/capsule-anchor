"""An incremental RFC6962 tree over the transparency log (capsule-anchor#109).

The log is append-only and its entries are never pruned (``store.py``), so a
process can keep every leaf hash it has seen and read only the entries after
them. A complete power-of-two subtree never changes once full, so its hash is
kept too: a root or an audit path then costs about ``log2(N)`` stored hashes
plus at most a few hundred fresh ones, instead of re-reading and re-hashing
the whole log on every registration.

Results are identical to ``ct.merkle_tree_hash`` and
``ct.inclusion_audit_path`` over the same leaves (``tests/test_ct_cache.py``
checks every size up to 600).
"""

from __future__ import annotations

import hashlib

#: Complete subtrees at least this large keep their hash. Smaller ones are
#: rehashed on demand (at most 2 * MEMO_MIN - 1 hashes each), which keeps the
#: memo to about 2N / MEMO_MIN entries.
MEMO_MIN = 256

_EMPTY = hashlib.sha256(b"").digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n > 1), RFC6962 2.1."""
    return 1 << ((n - 1).bit_length() - 1)


class CachedTree:
    """Leaf hashes of the log's first ``size`` entries, as raw 32 bytes."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._memo: dict[tuple[int, int], bytes] = {}

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, leaf_hash_hex: str) -> None:
        self._leaves.append(bytes.fromhex(leaf_hash_hex))

    def leaf(self, index: int) -> str:
        return self._leaves[index].hex()

    def leaves_hex(self, size: int) -> list[str]:
        """The first ``size`` leaf hashes as hex, for the readers that use
        ``ct``'s whole-list algorithms (consistency proofs)."""
        return [h.hex() for h in self._leaves[:size]]

    def _mth(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 0:
            return _EMPTY
        if n == 1:
            return self._leaves[start]
        complete = n & (n - 1) == 0
        if complete and n >= MEMO_MIN:
            cached = self._memo.get((start, n))
            if cached is not None:
                return cached
        k = _split(n)
        value = _node(self._mth(start, start + k), self._mth(start + k, end))
        if complete and n >= MEMO_MIN:
            self._memo[(start, n)] = value
        return value

    def root(self, size: int) -> str:
        """The RFC6962 tree hash of the first ``size`` leaves, as hex."""
        if not 0 <= size <= len(self._leaves):
            raise ValueError("tree_size out of range")
        return self._mth(0, size).hex()

    def audit_path(self, index: int, size: int) -> list[str]:
        """The RFC6962 inclusion path of leaf ``index`` in the tree of the
        first ``size`` leaves, leaf to root, as hex (RFC6962 2.1.1)."""
        if not 0 <= index < size <= len(self._leaves):
            raise IndexError("leaf index out of range")
        path: list[bytes] = []
        start, end = 0, size
        while end - start > 1:
            k = _split(end - start)
            if index < start + k:
                path.append(self._mth(start + k, end))
                end = start + k
            else:
                path.append(self._mth(start, start + k))
                start = start + k
        return [h.hex() for h in reversed(path)]
