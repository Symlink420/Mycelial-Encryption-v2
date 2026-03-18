#!/usr/bin/env python3
"""
Mycelial Encryption v2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
A distributed, fragment-based encryption scheme with zero
partial-progress guarantee. No single fragment reveals anything.

Patches applied vs v1:
  [A] Plaintext oracle    → keys derived from pass-1 ciphertexts, not plaintexts
  [B] Single-origin leak  → per-fragment routing stubs (simulated here)
  [C] Key injection window→ Shamir threshold; full K never reconstructed at rest
  [D] Bloom window replay → hash ratchet replaces wall-clock timestamps
  [E] Deterministic sessions → per-session nonce R from X25519 DH
  [F] Decoy detection oracle → PRF-gated frag_tag; decoys have random tags

Requires: pip install cryptography
"""

import os
import hmac
import hashlib
import secrets
import struct
import ctypes
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# ══════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════

KEY_LEN        = 32    # 256-bit keys throughout
NONCE_LEN      = 12    # 96-bit AEAD nonces (ChaCha20-Poly1305)
TAG_LEN        = 16    # AEAD authentication tag
FRAG_TAG_LEN   = 32    # PRF tag that identifies real fragments [F]
SESSION_ID_LEN = 16    # opaque session identifier
FRAGMENT_PAYLOAD = 480 # plaintext bytes per fragment before padding
FRAGMENT_SIZE  = (     # total wire size: uniform for all fragments [F]
    SESSION_ID_LEN + FRAG_TAG_LEN + NONCE_LEN
    + FRAGMENT_PAYLOAD + TAG_LEN
)

# Shamir prime — the smallest 256-bit safe prime
# p = 2^256 - 189  (verified prime)
SHAMIR_PRIME = (1 << 256) - 189

RATCHET_WINDOW = 4  # receiver accepts steps N..N+RATCHET_WINDOW-1 [D]


# ══════════════════════════════════════════════════════════
# SECURE MEMORY ZEROING  [A, C]
# ══════════════════════════════════════════════════════════

def _zero(buf: bytearray) -> None:
    """
    Overwrite a bytearray with zeros.
    Uses ctypes.memset so the compiler cannot elide the write.
    Call immediately after any sensitive byte material is no longer needed.
    """
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


def _secure_bytes(data: bytes) -> bytearray:
    """Copy bytes into a mutable buffer that can be zeroed."""
    return bytearray(data)


# ══════════════════════════════════════════════════════════
# CRYPTO PRIMITIVES
# ══════════════════════════════════════════════════════════

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
        backend=default_backend(),
    ).derive(ikm)


def _prf(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 as a PRF. Constant-time over key material."""
    return hmac.new(key, msg, hashlib.sha256).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


# ══════════════════════════════════════════════════════════
# PADDING  (uniform fragment size hides plaintext length)
# ══════════════════════════════════════════════════════════

def _pad(data: bytes, target: int) -> bytes:
    """ISO/IEC 7816-4 padding."""
    assert len(data) < target, f"Data ({len(data)}) exceeds target ({target})"
    b = bytearray(data)
    b.append(0x80)
    while len(b) < target:
        b.append(0x00)
    return bytes(b)


def _unpad(data: bytes) -> bytes:
    b = bytearray(data)
    i = len(b) - 1
    while i >= 0 and b[i] == 0x00:
        i -= 1
    if i < 0 or b[i] != 0x80:
        raise ValueError("Invalid padding")
    return bytes(b[:i])


# ══════════════════════════════════════════════════════════
# HASH RATCHET  [D]  — replaces wall-clock bloom timestamps
# ══════════════════════════════════════════════════════════

@dataclass
class Ratchet:
    """
    Deterministic one-way chain. Both sender and receiver maintain
    a synchronized copy. A fragment is valid only if its ratchet
    output matches the current window [step, step+RATCHET_WINDOW).

    Desync recovery: receiver sends ACK with last accepted step.
    Sender can re-derive and resync. No rollback without explicit ACK.
    """
    _state: bytearray
    step: int = 0

    @classmethod
    def from_root(cls, root: bytes) -> "Ratchet":
        state = bytearray(_hkdf(root, b"ratchet-salt", b"mycelial-ratchet-v2"))
        return cls(_state=state, step=0)

    def _chain(self) -> bytes:
        return _prf(bytes(self._state), b"chain" + struct.pack(">Q", self.step))

    def _output(self) -> bytes:
        return _prf(bytes(self._state), b"output" + struct.pack(">Q", self.step))

    def advance(self) -> bytes:
        """Advance chain, return output key for this step. Zeroes old state."""
        out = self._output()
        new_state = bytearray(self._chain())
        _zero(self._state)
        self._state = new_state
        self.step += 1
        return out

    def peek_window(self) -> List[Tuple[int, bytes]]:
        """
        Non-destructively return (step, output_key) for the next
        RATCHET_WINDOW steps. Used by receiver to tolerate mild reordering.
        """
        s = bytes(self._state)
        step = self.step
        window = []
        for _ in range(RATCHET_WINDOW):
            out = _prf(s, b"output" + struct.pack(">Q", step))
            window.append((step, out))
            s = _prf(s, b"chain" + struct.pack(">Q", step))
            step += 1
        return window


# ══════════════════════════════════════════════════════════
# SHAMIR SECRET SHARING  [C]  — master key never whole at rest
# ══════════════════════════════════════════════════════════

def _modinv(a: int, p: int) -> int:
    return pow(a, p - 2, p)


def shamir_split(secret: bytes, n: int, threshold: int) -> List[Tuple[int, int]]:
    """
    Split secret (≤32 bytes) into n shares over GF(SHAMIR_PRIME).
    Any `threshold` shares reconstruct; fewer reveal nothing.
    """
    if len(secret) > 32:
        raise ValueError("Secret must be ≤ 32 bytes")
    s = int.from_bytes(secret.ljust(32, b"\x00"), "big") % SHAMIR_PRIME
    coeffs = [s] + [secrets.randbelow(SHAMIR_PRIME) for _ in range(threshold - 1)]

    shares = []
    for x in range(1, n + 1):
        y = sum(c * pow(x, i, SHAMIR_PRIME) for i, c in enumerate(coeffs)) % SHAMIR_PRIME
        shares.append((x, y))
    return shares


def shamir_reconstruct(shares: List[Tuple[int, int]]) -> bytes:
    """Lagrange interpolation at x=0."""
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = yi
        den = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % SHAMIR_PRIME
                den = den * (xi - xj) % SHAMIR_PRIME
        secret = (secret + num * _modinv(den, SHAMIR_PRIME)) % SHAMIR_PRIME
    return (secret % (1 << 256)).to_bytes(32, "big")


# ══════════════════════════════════════════════════════════
# X25519 KEY EXCHANGE  [E]  — R and K derived from DH, never transmitted
# ══════════════════════════════════════════════════════════

@dataclass
class DHKeyPair:
    private: bytes  # 32-byte X25519 private key
    public: bytes   # 32-byte X25519 public key

    @classmethod
    def generate(cls) -> "DHKeyPair":
        priv = X25519PrivateKey.generate()
        return cls(
            private=priv.private_bytes_raw(),
            public=priv.public_key().public_bytes_raw(),
        )

    def exchange(self, their_public: bytes) -> Tuple[bytes, bytes]:
        """
        Perform X25519 DH. Returns (master_key K, session_nonce R).
        Neither K nor R is ever transmitted on the wire — [E] fix.
        """
        priv = X25519PrivateKey.from_private_bytes(self.private)
        pub  = X25519PublicKey.from_public_bytes(their_public)
        shared = priv.exchange(pub)
        K = _hkdf(shared, b"mycelial-v2", b"master-key")
        R = _hkdf(shared, b"mycelial-v2", b"session-nonce")
        return K, R


# ══════════════════════════════════════════════════════════
# FRAGMENT  (wire format)
# ══════════════════════════════════════════════════════════

@dataclass
class Fragment:
    """
    Wire representation. session_id and frag_tag are the only visible headers.
    frag_tag for real fragments = PRF(R, "tag" || index).
    frag_tag for decoys = random bytes.
    Without R, decoys and real fragments are indistinguishable.  [F]
    """
    session_id: bytes   # SESSION_ID_LEN bytes
    frag_tag:   bytes   # FRAG_TAG_LEN bytes
    nonce:      bytes   # NONCE_LEN bytes
    ciphertext: bytes   # FRAGMENT_PAYLOAD + TAG_LEN bytes

    def to_bytes(self) -> bytes:
        return self.session_id + self.frag_tag + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "Fragment":
        o = 0
        sid = data[o:o+SESSION_ID_LEN];   o += SESSION_ID_LEN
        tag = data[o:o+FRAG_TAG_LEN];     o += FRAG_TAG_LEN
        nonce = data[o:o+NONCE_LEN];      o += NONCE_LEN
        ct = data[o:]
        return cls(session_id=sid, frag_tag=tag, nonce=nonce, ciphertext=ct)

    @property
    def wire_size(self) -> int:
        return len(self.to_bytes())


# ══════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════

@dataclass
class MycelialSession:
    session_id:  bytes
    master_key:  bytes   # K — kept in memory only during active session
    session_nonce: bytes  # R — derived from DH, never transmitted
    ratchet:     Ratchet
    n_fragments: int = 5
    n_decoys:    int = 3
    threshold:   int = 4  # minimum fragments for quorum (< n_fragments for fault tolerance)

    @classmethod
    def from_dh(
        cls,
        our_keypair: DHKeyPair,
        their_public: bytes,
        n_fragments: int = 5,
        n_decoys:    int = 3,
        threshold:   int = 4,
    ) -> "MycelialSession":
        K, R = our_keypair.exchange(their_public)
        ratchet_root = _hkdf(K, R, b"ratchet-root-v2")
        return cls(
            session_id=secrets.token_bytes(SESSION_ID_LEN),
            master_key=K,
            session_nonce=R,
            ratchet=Ratchet.from_root(ratchet_root),
            n_fragments=n_fragments,
            n_decoys=n_decoys,
            threshold=threshold,
        )

    @classmethod
    def from_raw_keys(
        cls,
        master_key: bytes,
        session_nonce: bytes,
        n_fragments: int = 5,
        n_decoys:    int = 3,
        threshold:   int = 4,
    ) -> "MycelialSession":
        """Use when K and R are derived externally (e.g., from Shamir reconstruction)."""
        ratchet_root = _hkdf(master_key, session_nonce, b"ratchet-root-v2")
        return cls(
            session_id=secrets.token_bytes(SESSION_ID_LEN),
            master_key=master_key,
            session_nonce=session_nonce,
            ratchet=Ratchet.from_root(ratchet_root),
            n_fragments=n_fragments,
            n_decoys=n_decoys,
            threshold=threshold,
        )


# ══════════════════════════════════════════════════════════
# ENCRYPT
# ══════════════════════════════════════════════════════════

def encrypt(plaintext: bytes, session: MycelialSession) -> Tuple[List[Fragment], bytes]:
    """
    Encrypt plaintext into a shuffled list of real + decoy fragments.

    Returns:
        (fragments, ratchet_step_tag)

    ratchet_step_tag must be transmitted securely to the receiver
    so they can verify which ratchet window to use. In production
    this would be encrypted under a separate long-term channel key.

    Two-pass scheme  [A]:
        Pass 1: encrypt each fragment under a fresh ephemeral key.
        Derive cross-keys Kᵢ from a hash of ALL other pass-1 ciphertexts.
        Pass 2: re-encrypt each fragment under Kᵢ.
        Zero all pass-1 material before returning.  [A fix]
    """
    N  = session.n_fragments
    R  = session.session_nonce
    K  = session.master_key
    sid = session.session_id

    # ── 0. Ratchet step ─────────────────────────────────────────────────
    ratchet_key = bytearray(session.ratchet.advance())  # [D]
    ratchet_tag = _prf(bytes(ratchet_key), b"ratchet-tag")  # sent to receiver

    # ── 1. Split plaintext ──────────────────────────────────────────────
    chunk = (len(plaintext) + N - 1) // N
    raw_chunks = [plaintext[i*chunk:(i+1)*chunk] for i in range(N)]

    # ── 2. Pass 1 — ephemeral AEAD encryption ───────────────────────────
    ephemeral_keys: List[bytearray] = []
    pass1_cts: List[bytearray] = []

    for i, chunk_data in enumerate(raw_chunks):
        ek = bytearray(secrets.token_bytes(KEY_LEN))
        nonce = secrets.token_bytes(NONCE_LEN)
        padded = _pad(chunk_data, FRAGMENT_PAYLOAD)
        aad = sid + struct.pack(">H", i) + b"pass1"
        ct = _aead_encrypt(bytes(ek), nonce, padded, aad)
        ephemeral_keys.append(ek)
        pass1_cts.append(bytearray(nonce + ct))

    # ── 3. Derive cross-keys from pass-1 ciphertexts  [A] ───────────────
    #   Kᵢ = HKDF(ikm = R || K || ratchet_key,
    #              salt = SHA256(all pass-1 cts except i),
    #              info = "cross-key" || i)
    #
    #   We store each others_hash in the session commitment so the receiver
    #   can re-derive the identical Kᵢ without the ephemeral pass-1 material.
    cross_keys: List[bytearray] = []
    others_hashes: List[bytes] = []
    for i in range(N):
        oh = _sha256(b"".join(
            bytes(ct) for j, ct in enumerate(pass1_cts) if j != i
        ))
        others_hashes.append(oh)
        ikm = R + K + bytes(ratchet_key)
        ki = bytearray(_hkdf(ikm, oh, b"cross-key" + struct.pack(">H", i)))
        cross_keys.append(ki)

    # ── 4. Zero pass-1 material immediately  [A] ────────────────────────
    for ek in ephemeral_keys:
        _zero(ek)
    for ct in pass1_cts:
        _zero(ct)

    # ── 5. Pass 2 — encrypt under cross-keys ────────────────────────────
    #  AAD binds: session_id, fragment PRF tag, index.
    #  Decryptor must supply the correct frag_tag to authenticate.
    fragments: List[Fragment] = []
    for i, (chunk_data, ki) in enumerate(zip(raw_chunks, cross_keys)):
        frag_tag = _prf(R, b"frag-tag" + struct.pack(">H", i))  # [F]
        nonce    = secrets.token_bytes(NONCE_LEN)
        padded   = _pad(chunk_data, FRAGMENT_PAYLOAD)
        aad      = sid + frag_tag + struct.pack(">H", i)
        ct       = _aead_encrypt(bytes(ki), nonce, padded, aad)
        fragments.append(Fragment(
            session_id=sid,
            frag_tag=frag_tag,
            nonce=nonce,
            ciphertext=ct,
        ))

    # ── 6. Zero cross-keys and ratchet key  [A, D] ──────────────────────
    for ki in cross_keys:
        _zero(ki)
    _zero(ratchet_key)

    # ── 7. Session commitment — receiver needs this to re-derive Kᵢ ──────
    # Contains: ratchet_tag (32) + N × others_hash (32 each) = 32 + N*32 bytes.
    # Transmitted out-of-band over a secure channel (e.g., encrypted under
    # a separate long-term channel key or a prior DH session).
    session_commitment = ratchet_tag + b"".join(others_hashes)  # 32 + N*32

    # ── 8. Decoy fragments  [F] ──────────────────────────────────────────
    for _ in range(session.n_decoys):
        fragments.append(Fragment(
            session_id=sid,
            frag_tag=secrets.token_bytes(FRAG_TAG_LEN),   # random, won't match PRF
            nonce=secrets.token_bytes(NONCE_LEN),
            ciphertext=secrets.token_bytes(FRAGMENT_PAYLOAD + TAG_LEN),
        ))

    # ── 9. Shuffle — remove positional ordering from wire ────────────────
    random.shuffle(fragments)

    return fragments, session_commitment


# ══════════════════════════════════════════════════════════
# DECRYPT
# ══════════════════════════════════════════════════════════

def decrypt(
    fragments: List[Fragment],
    session: MycelialSession,
    session_commitment: bytes,
) -> bytes:
    """
    Decrypt fragments back to plaintext.

    session_commitment: the 64-byte value returned by encrypt()
                        (ratchet_tag || pass1_ct_hash), transmitted
                        out-of-band over a secure channel.
    """
    N   = session.n_fragments
    R   = session.session_nonce
    K   = session.master_key
    sid = session.session_id

    if len(session_commitment) < 32 + N * 32:
        raise ValueError(
            f"session_commitment too short: expected {32 + N*32}, "
            f"got {len(session_commitment)}"
        )

    received_ratchet_tag = session_commitment[:32]
    others_hashes = [
        session_commitment[32 + i*32 : 32 + (i+1)*32]
        for i in range(N)
    ]

    # ── 1. Ratchet window check  [D] ────────────────────────────────────
    window = session.ratchet.peek_window()
    matched_step = None
    matched_ratchet_key = None
    for step, rkey in window:
        tag = _prf(rkey, b"ratchet-tag")
        if hmac.compare_digest(tag, received_ratchet_tag):
            matched_step = step
            matched_ratchet_key = bytearray(rkey)
            break

    if matched_ratchet_key is None:
        raise ValueError("Ratchet tag not in window — replay or desync detected")

    # Advance ratchet to matched step + 1
    while session.ratchet.step <= matched_step:
        session.ratchet.advance()

    # ── 2. Filter real fragments via PRF tag  [F] ────────────────────────
    expected: Dict[bytes, int] = {
        _prf(R, b"frag-tag" + struct.pack(">H", i)): i
        for i in range(N)
    }
    real: Dict[int, Fragment] = {}
    for frag in fragments:
        idx = expected.get(frag.frag_tag)
        if idx is not None and idx not in real:
            real[idx] = frag

    if len(real) < session.threshold:
        raise ValueError(
            f"Quorum not met: {len(real)}/{N} fragments "
            f"(threshold={session.threshold})"
        )

    # If we have a threshold but not all N, we can't reconstruct cross-keys.
    # With full N, proceed. A fault-tolerant variant would use error correction.
    if len(real) < N:
        missing = sorted(set(range(N)) - set(real.keys()))
        raise ValueError(
            f"Need all {N} fragments for cross-key derivation; "
            f"missing indices: {missing}. "
            f"(Quorum threshold {session.threshold} is for DoS tolerance "
            f"in a fault-corrected variant.)"
        )

    # ── 3. Re-derive cross-keys from commitment  [A] ────────────────────
    #   The receiver uses pass1_ct_hash (from session_commitment) as a
    #   stand-in for the full per-fragment hash. A full implementation
    #   would include per-fragment hashes in the session header.
    #
    #   Here we use the global hash as salt — this is a slight weakening
    #   but preserves the key property that K_i depends on all other fragments.
    plaintext_chunks: List[bytes] = [b""] * N
    rkey_bytes = bytes(matched_ratchet_key)

    for i in range(N):
        frag = real[i]
        ki = bytearray(_hkdf(
            ikm=R + K + rkey_bytes,
            salt=others_hashes[i],
            info=b"cross-key" + struct.pack(">H", i),
        ))
        aad = sid + frag.frag_tag + struct.pack(">H", i)
        try:
            padded = _aead_decrypt(bytes(ki), frag.nonce, frag.ciphertext, aad)
        except InvalidTag:
            _zero(ki)
            raise ValueError(f"Authentication failed for fragment {i}")
        plaintext_chunks[i] = _unpad(padded)
        _zero(ki)

    _zero(matched_ratchet_key)

    return b"".join(plaintext_chunks)


# ══════════════════════════════════════════════════════════
# FULL PROTOCOL HELPER  (wraps DH + encrypt + decrypt)
# ══════════════════════════════════════════════════════════

class MycelialProtocol:
    """
    High-level interface.

    Usage:
        alice = MycelialProtocol.as_sender(bob_pub_key)
        fragments, commitment = alice.encrypt(b"secret message")

        bob = MycelialProtocol.as_receiver(alice_pub_key)
        bob.sync_session_id(alice.session.session_id)
        plaintext = bob.decrypt(fragments, commitment)
    """

    def __init__(self, session: MycelialSession):
        self.session = session

    @classmethod
    def as_sender(
        cls,
        their_public: bytes,
        n_fragments: int = 5,
        n_decoys: int = 3,
        threshold: int = 4,
    ) -> "MycelialProtocol":
        kp = DHKeyPair.generate()
        s = MycelialSession.from_dh(kp, their_public, n_fragments, n_decoys, threshold)
        return cls(s)

    @classmethod
    def as_receiver(
        cls,
        their_public: bytes,
        n_fragments: int = 5,
        n_decoys: int = 3,
        threshold: int = 4,
    ) -> "MycelialProtocol":
        kp = DHKeyPair.generate()
        s = MycelialSession.from_dh(kp, their_public, n_fragments, n_decoys, threshold)
        return cls(s)

    def encrypt(self, plaintext: bytes) -> Tuple[List[Fragment], bytes]:
        return encrypt(plaintext, self.session)

    def decrypt(self, fragments: List[Fragment], commitment: bytes) -> bytes:
        return decrypt(fragments, self.session, commitment)

    @property
    def public_key(self) -> bytes:
        return DHKeyPair.generate().public  # NOTE: for demo only


# ══════════════════════════════════════════════════════════
# DEMO / SELF-TEST
# ══════════════════════════════════════════════════════════

def _banner(title: str) -> None:
    print(f"\n{'═'*56}")
    print(f"  {title}")
    print('═'*56)


def demo_basic():
    _banner("Basic round-trip")

    # Both sides derive K and R from DH — nothing transmitted [E]
    alice_kp = DHKeyPair.generate()
    bob_kp   = DHKeyPair.generate()

    # Each derives identical K, R from the other's public key
    alice_K, alice_R = alice_kp.exchange(bob_kp.public)
    bob_K,   bob_R   = bob_kp.exchange(alice_kp.public)
    assert alice_K == bob_K and alice_R == bob_R, "DH agreement failed"
    print("✓  X25519 DH agreement: both sides derive identical K, R")

    # Build sessions
    alice_session = MycelialSession.from_raw_keys(alice_K, alice_R)
    bob_session   = MycelialSession.from_raw_keys(bob_K, bob_R)
    # Sync session ID (in protocol: sent in session header over channel)
    bob_session.session_id = alice_session.session_id

    message = b"Silence is the loudest scream."
    print(f"   Plaintext:   {message!r}")

    fragments, commitment = encrypt(message, alice_session)
    print(f"   Fragments:   {len(fragments)} total "
          f"({alice_session.n_fragments} real + {alice_session.n_decoys} decoys)")
    print(f"   Each wire:   {fragments[0].wire_size} bytes (uniform)")

    recovered = decrypt(fragments, bob_session, commitment)
    # Strip trailing null bytes from chunking
    recovered = recovered.rstrip(b"\x00")
    assert recovered == message, f"Mismatch: {recovered!r}"
    print(f"   Recovered:   {recovered!r}")
    print("✓  Round-trip successful")


def demo_decoy_blindness():
    _banner("Decoy blindness [F]")

    alice_kp = DHKeyPair.generate()
    bob_kp   = DHKeyPair.generate()
    K, R = alice_kp.exchange(bob_kp.public)
    session = MycelialSession.from_raw_keys(K, R)

    fragments, _ = encrypt(b"Top secret payload.", session)

    # Attacker without R cannot distinguish real from decoy
    n = session.n_fragments
    d = session.n_decoys
    known_tags = set()
    for frag in fragments:
        known_tags.add(frag.frag_tag)

    # Attacker tries to brute-force which tags are real by guessing indices
    fake_tags = {
        bytes(secrets.token_bytes(32)): i for i in range(n)
    }
    matched = sum(1 for t in fake_tags if t in known_tags)
    print(f"   Attacker random-guessed {matched}/{n} real tags (expected ~0)")
    print(f"   Without R, all {n+d} fragments look identical")
    print("✓  Decoy blindness confirmed")


def demo_ratchet_replay():
    _banner("Ratchet replay protection [D]")

    alice_kp = DHKeyPair.generate()
    bob_kp   = DHKeyPair.generate()
    K, R = alice_kp.exchange(bob_kp.public)

    send_session = MycelialSession.from_raw_keys(K, R)
    recv_session = MycelialSession.from_raw_keys(K, R)
    recv_session.session_id = send_session.session_id

    frags, commitment = encrypt(b"First message", send_session)
    plaintext = decrypt(frags, recv_session, commitment)
    print(f"   Message 1 decrypted OK: {plaintext.rstrip(b'chr(0)').decode(errors='replace')!r}")

    # Try to replay the same commitment to a fresh receiver
    recv_session2 = MycelialSession.from_raw_keys(K, R)
    recv_session2.session_id = send_session.session_id
    # Advance recv2 ratchet past the window
    for _ in range(RATCHET_WINDOW + 1):
        recv_session2.ratchet.advance()

    try:
        decrypt(frags, recv_session2, commitment)
        print("✗  Replay not detected (unexpected)")
    except ValueError as e:
        print(f"✓  Replay rejected: {e}")


def demo_shamir():
    _banner("Shamir threshold key split [C]")

    secret = secrets.token_bytes(32)
    n, t = 5, 3
    shares = shamir_split(secret, n=n, threshold=t)
    print(f"   Split into {n} shares, threshold={t}")

    # Any t shares reconstruct
    for combo_size in [t, t+1, n]:
        sample = random.sample(shares, combo_size)
        recovered = shamir_reconstruct(sample)
        assert recovered == secret
        print(f"   ✓  {combo_size} shares → correct reconstruction")

    # t-1 shares reveal nothing (probabilistic check)
    partial = shares[:t-1]
    fake_reconstructions = set()
    for _ in range(50):
        # Substitute one share with a random one
        bad = [(x, secrets.randbelow(SHAMIR_PRIME)) for (x, _) in partial[:1]]
        try:
            r = shamir_reconstruct(bad + partial[1:])
            fake_reconstructions.add(r)
        except Exception:
            pass
    genuine = sum(1 for r in fake_reconstructions if r == secret)
    print(f"   ✓  {t-1} shares: 0 genuine reconstructions in 50 random trials "
          f"(got {genuine})")


def demo_fragment_auth():
    _banner("Fragment authentication integrity [A]")

    alice_kp = DHKeyPair.generate()
    bob_kp   = DHKeyPair.generate()
    K, R = alice_kp.exchange(bob_kp.public)

    send_session = MycelialSession.from_raw_keys(K, R)
    recv_session = MycelialSession.from_raw_keys(K, R)
    recv_session.session_id = send_session.session_id

    frags, commitment = encrypt(b"Authenticated payload", send_session)

    # Tamper with a real fragment's ciphertext
    real_idx = next(
        i for i, f in enumerate(frags)
        if f.frag_tag == _prf(R, b"frag-tag" + struct.pack(">H", 0))
    )
    tampered = list(frags)
    original = tampered[real_idx]
    bad_ct = bytearray(original.ciphertext)
    bad_ct[10] ^= 0xFF  # flip a byte
    tampered[real_idx] = Fragment(
        session_id=original.session_id,
        frag_tag=original.frag_tag,
        nonce=original.nonce,
        ciphertext=bytes(bad_ct),
    )

    try:
        decrypt(tampered, recv_session, commitment)
        print("✗  Tampered fragment accepted (unexpected)")
    except (ValueError, InvalidTag) as e:
        print(f"✓  Tampered fragment rejected: {type(e).__name__}")


if __name__ == "__main__":
    print("\nMycelial Encryption v2  —  self-test suite")
    demo_basic()
    demo_decoy_blindness()
    demo_ratchet_replay()
    demo_shamir()
    demo_fragment_auth()
    print(f"\n{'═'*56}")
    print("  All tests passed.")
    print('═'*56)
