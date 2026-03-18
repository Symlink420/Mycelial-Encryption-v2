# Mycelial Encryption v2

> **No single fragment. No partial progress. No single point of failure.**

A distributed fragment-based encryption scheme inspired by mycelial networks — the underground fungal meshes that have no center, no critical node, and no path that carries the whole message. Intercept one strand and you learn nothing. You need everything to decrypt anything.

---

## Concept

Classical encryption is a locked box. Break the lock, read the contents.

Mycelial encryption is a shredded map scattered across five couriers taking five different roads. The map pieces are meaningless alone — and each piece's decryption key is *derived from the other pieces*. There is no key to steal because the key doesn't exist until all the fragments arrive.

```
Plaintext M
    │
    ├─ Fragment M₁  ──[path A]──►
    ├─ Fragment M₂  ──[path B]──►  [ Quorum gate ]──► Rederive keys ──► Plaintext M′
    ├─ Fragment M₃  ──[path C]──►
    ├─ Decoy        ──[path D]──►       ↑
    └─ Decoy        ──[path E]──►   indistinguishable
                                    from real fragments
```

---

## Security properties

| Property | Guarantee |
|---|---|
| **Zero partial progress** | An attacker with N−1 of N fragments gains zero bits of plaintext |
| **No plaintext oracle** | Keys are derived from pass-1 *ciphertexts*, not plaintexts — guessing fragments doesn't help |
| **No key injection window** | Master key K is never reconstructed whole; Shamir threshold signatures only |
| **Replay resistance** | Hash ratchet replaces wall-clock timestamps; NTP manipulation doesn't open a replay window |
| **Decoy blindness** | Real and decoy fragments are cryptographically indistinguishable without session nonce R |
| **Session unlinkability** | R derived from X25519 DH; never transmitted on the wire |

---

## How it works

### Two-pass encryption

The naive approach derives each fragment's key from the other *plaintexts* — which creates a brute-force oracle. Mycelial v2 fixes this with a two-pass scheme:

**Pass 1** — encrypt each fragment under a fresh ephemeral key. Immediately zero all ephemeral key material.

**Pass 2** — derive cross-keys from the pass-1 *ciphertexts*:

```
Kᵢ = HKDF(
    ikm  = R || K || ratchet_key,
    salt = SHA256(E°₁ ‖ … ‖ E°ₙ  excluding E°ᵢ),
    info = "cross-key" || i
)
```

Now the only way to derive Kᵢ is to already have all other ciphertexts — the mutual hostage property is preserved, and there's no plaintext to guess against.

### Hash ratchet

Instead of timestamping fragments with wall-clock time (NTP-manipulable, replay window exploitable), both sides maintain a synchronized one-way hash chain:

```
state[n+1] = HMAC-SHA256(state[n], "chain" || n)
output[n]  = HMAC-SHA256(state[n], "output" || n)
```

A fragment is valid only if its ratchet tag matches one of the next `RATCHET_WINDOW` (default: 4) steps. Once accepted, the chain advances and that step is permanently closed.

### Shamir key distribution

The master key K is never stored anywhere whole. It is split across N custodians using Shamir's Secret Sharing over GF(2²⁵⁶ − 189). Any threshold T of custodians can reconstruct K for a session; below T, the shares are information-theoretically independent.

### Decoy fragments

Every transmission includes a configurable number of decoy fragments with random frag_tags. Real fragments use `frag_tag = PRF(R, "frag-tag" || index)`. Without session nonce R (never transmitted), an observer cannot distinguish real from decoy — all wire packets are the same size and structurally identical.

---

## Installation

```bash
pip install cryptography
```

Python 3.9+ required.

---

## Usage

```python
from mycelial import DHKeyPair, MycelialSession, encrypt, decrypt

# Both parties perform X25519 key exchange out-of-band.
# K and R are derived locally — nothing sensitive is transmitted.
alice_kp = DHKeyPair.generate()
bob_kp   = DHKeyPair.generate()

K, R = alice_kp.exchange(bob_kp.public)

# Sender
send_session = MycelialSession.from_raw_keys(K, R, n_fragments=5, n_decoys=3)
fragments, commitment = encrypt(b"Eyes only.", send_session)
# → 8 uniform-size wire packets, shuffled

# Receiver (commitment transmitted over a separate secure channel)
recv_session = MycelialSession.from_raw_keys(K, R)
recv_session.session_id = send_session.session_id
plaintext = decrypt(fragments, recv_session, commitment)
# → b"Eyes only."
```

### Shamir key split

```python
from mycelial import shamir_split, shamir_reconstruct
import secrets

master_key = secrets.token_bytes(32)

# Split across 5 custodians, any 3 can reconstruct
shares = shamir_split(master_key, n=5, threshold=3)

# Later — collect any 3 shares
recovered = shamir_reconstruct(shares[:3])
assert recovered == master_key
```

---

## Running the test suite

```bash
python mycelial.py
```

```
════════════════════════════════════════════════════════
  Basic round-trip
════════════════════════════════════════════════════════
✓  X25519 DH agreement: both sides derive identical K, R
   Fragments:   8 total (5 real + 3 decoys)
   Each wire:   556 bytes (uniform)
✓  Round-trip successful

✓  Decoy blindness confirmed
✓  Replay rejected: Ratchet tag not in window
✓  Shamir: 3/4/5 shares → correct reconstruction
✓  Tampered fragment rejected
```

---

## Parameters

| Parameter | Default | Effect |
|---|---|---|
| `n_fragments` | 5 | Real fragments. Higher = more paths, more latency |
| `n_decoys` | 3 | Decoy packets added to transmission |
| `threshold` | 4 | Minimum fragments to attempt decryption |
| `RATCHET_WINDOW` | 4 | Steps receiver will accept (replay tolerance) |

---

## Threat model and known limitations

**What this does not protect against:**

- **Quorum DoS** — An attacker who can selectively drop packets on >(N − threshold) paths prevents quorum from ever forming. This is structural; the only mitigation is more paths and redundant fragments.
- **Quorum timing fingerprinting** — Inter-fragment arrival deltas can fingerprint which circuits are fast, potentially correlating routing back to the sender. Accepted risk; mitigated in practice by artificial jitter.
- **Compromised DH** — If the X25519 key exchange is performed over an insecure channel, R and K can be derived by a passive observer, collapsing all security properties.

**Best suited for:** High-value, low-frequency transmissions where latency is irrelevant — sealed diplomatic messages, long-term data escrow, multi-party signing ceremonies.

**Not suited for:** Real-time communication, high-throughput data, or scenarios requiring sub-second delivery.

---

## Cryptographic primitives

| Primitive | Usage |
|---|---|
| X25519 | Key exchange |
| ChaCha20-Poly1305 | Authenticated encryption (both passes) |
| HKDF-SHA256 | Key derivation |
| HMAC-SHA256 | PRF (ratchet, frag tags) |
| Shamir over GF(2²⁵⁶ − 189) | Threshold key distribution |

All from the [Python `cryptography`](https://cryptography.io) library (BoringSSL/OpenSSL backend).

---

## Design lineage

v1 → v2 patches:

| Vulnerability | Fix |
|---|---|
| Plaintext oracle | Keys derived from pass-1 ciphertexts |
| Single-origin correlation | Per-fragment routing (Tor-circuit stub) |
| Key injection window | Shamir threshold; K never whole at rest |
| Bloom window replay | Hash ratchet replaces wall-clock stamps |
| Deterministic sessions | Session nonce R from X25519 DH |
| Decoy detection oracle | PRF-gated `frag_tag`; decoys have random tags |
| Pass-1 memory exposure | Immediate zeroing via `ctypes.memset` |

---

## License

MIT
