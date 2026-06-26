"""RFC6962 (Certificate Transparency) Merkle tree algorithms.

This is the real CT-style log machinery over the TRANSPARENCY LOG ENTRIES --
distinct from the tenant ledger Merkle trees (those use the compatible engine-compatible
``default_crypto.merkle_root`` semantics in ``crypto_shim``). Here we implement
the RFC6962 algorithms exactly so the authority's own log is auditable by any
external monitor / auditor (the DigiNotar mitigation, trust-model doc).

RFC6962 domain separation (this is what makes it a *real* CT tree, not the
engine odd-node-promotion tree):

  * leaf hash  : ``H(0x00 || leaf_bytes)``
  * inner node : ``H(0x01 || left_hash || right_hash)``
  * empty tree : ``H()`` (hash of the empty string)

and the *non-power-of-two split* rule (RFC6962 section 2.1): for an input of
``n`` leaves, let ``k`` be the largest power of two strictly less than ``n``;
the left subtree covers ``[0, k)`` and the right subtree covers ``[k, n)``.

Hashes here are hex strings (the project convention); the domain-separation
prefix bytes are prepended before hashing.

Implemented from RFC6962 sections 2.1 (tree hash), 2.1.1 (inclusion /
audit path), and 2.1.2 (consistency proof).
"""

from __future__ import annotations

import hashlib

# Domain-separation prefixes (RFC6962 section 2.1).
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def empty_root() -> str:
    """MTH({}) = SHA-256() -- the hash of the empty string (RFC6962 2.1)."""
    return _h(b"")


def leaf_hash(leaf_bytes: bytes) -> str:
    """MTH of a single leaf: ``H(0x00 || leaf_bytes)``."""
    return _h(_LEAF_PREFIX + leaf_bytes)


def _node_hash(left: str, right: str) -> str:
    """Inner node hash ``H(0x01 || left || right)`` over hex child hashes."""
    return _h(_NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


def _largest_power_of_two_below(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n > 1)."""
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def merkle_tree_hash(leaves: list[str]) -> str:
    """RFC6962 Merkle Tree Hash (MTH) over a list of *leaf hashes*.

    ``leaves`` are already-computed leaf hashes (``leaf_hash(...)``).
    """
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return _node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_audit_path(index: int, leaves: list[str]) -> list[str]:
    """RFC6962 inclusion (audit) path for ``leaves[index]`` (section 2.1.1).

    Returns the ordered list of sibling hashes from the leaf up to the root.
    The verifier reconstructs left/right ordering from ``index`` and tree size.
    """
    n = len(leaves)
    if not (0 <= index < n):
        raise IndexError("leaf index out of range")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        # leaf in left subtree; sibling is MTH of the right subtree
        return inclusion_audit_path(index, leaves[:k]) + [merkle_tree_hash(leaves[k:])]
    # leaf in right subtree; sibling is MTH of the left subtree
    return inclusion_audit_path(index - k, leaves[k:]) + [merkle_tree_hash(leaves[:k])]


def verify_inclusion_path(
    leaf_hash_value: str,
    index: int,
    tree_size: int,
    audit_path: list[str],
    root_hash: str,
) -> bool:
    """Verify an RFC6962 inclusion proof (section 2.1.1 verification).

    Recompute the root from ``leaf_hash_value`` at ``index`` in a tree of
    ``tree_size`` leaves using ``audit_path``; compare to ``root_hash``.
    """
    if not (0 <= index < tree_size):
        return False
    if tree_size == 1:
        return len(audit_path) == 0 and leaf_hash_value == root_hash

    fn = index  # node index within the current (sub)layer
    sn = tree_size - 1  # last node index within the current (sub)layer
    acc = leaf_hash_value
    path = list(audit_path)
    while sn > 0:
        if not path:
            return False
        if fn & 1 or fn == sn:
            # current node is a right child, OR is the rightmost (no right sib)
            sib = path.pop(0)
            acc = _node_hash(sib, acc)
            # ascend until we are no longer a right child / rightmost edge
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sib = path.pop(0)
            acc = _node_hash(acc, sib)
        fn >>= 1
        sn >>= 1
    return len(path) == 0 and acc == root_hash


def consistency_proof(first: int, second: int, leaves: list[str]) -> list[str]:
    """RFC6962 consistency proof between sizes ``first`` and ``second``.

    Proves the tree of size ``second`` (hashes in ``leaves``) is an append-only
    superset of the tree of size ``first`` (section 2.1.2).
    """
    if not (0 < first <= second <= len(leaves)):
        raise ValueError("require 0 < first <= second <= len(leaves)")
    if first == second:
        return []
    return _subproof(first, leaves[:second], True)


def _subproof(m: int, leaves: list[str], start_from_old_root: bool) -> list[str]:
    """RFC6962 SUBPROOF(m, D[0:n], b) (section 2.1.2)."""
    n = len(leaves)
    if m == n:
        # The old tree is exactly this subtree.
        return [] if start_from_old_root else [merkle_tree_hash(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], start_from_old_root) + [
            merkle_tree_hash(leaves[k:])
        ]
    return _subproof(m - k, leaves[k:], False) + [merkle_tree_hash(leaves[:k])]


def verify_consistency_proof(
    first: int,
    second: int,
    first_root: str,
    second_root: str,
    proof: list[str],
) -> bool:
    """Verify an RFC6962 consistency proof (section 2.1.2 verification).

    Confirms ``first_root`` (size ``first``) is a prefix of ``second_root``
    (size ``second``) using ``proof``.
    """
    if first > second or first < 0 or second < 0:
        return False
    if first == second:
        return first_root == second_root and proof == []
    if first == 0:
        # An empty tree is consistent with any tree; no proof needed.
        return proof == []

    proof = list(proof)
    # RFC6962 consistency verification.
    if _is_power_of_two(first):
        proof = [first_root] + proof

    fn = first - 1
    sn = second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    if not proof:
        return False
    fr = sr = proof[0]
    idx = 1
    while sn > 0:
        if idx >= len(proof):
            return False
        c = proof[idx]
        idx += 1
        if fn & 1 or fn == sn:
            fr = _node_hash(c, fr)
            sr = _node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return idx == len(proof) and fr == first_root and sr == second_root


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0
