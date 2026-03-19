# ML-KEM OT Protocol

Based on MR19 (Masny-Rindal, ePrint 2019/706), Figure 8, instantiated with ML-KEM instead of Crystals-Kyber, as per Section D.3.

Reference implementation: [libOTe KyberOT](https://github.com/osu-crypto/libOTe/blob/d0e499206d1d4d16c6b4ca6c0e712490e0632f80/thirdparty/KyberOT/KyberOT.c#L40-L41).

ML-KEM implementation: [ML-KEM](https://github.com/RustCrypto/KEMs/blob/5a7f3ab7af5420cacca9befc9212532e4c7f6ca1/ml-kem/src/).

## Notation

### Field and Ring

- `q = 3329` (ML-KEM prime)
- `Z_q = {0, 1, ..., 3328}` (integers mod q)
- `R_q = Z_q[X] / (X^256 + 1)` (polynomial ring; each element has 256 coefficients in Z_q)
- `T_q`: the NTT domain representation of `R_q` (256 elements of Z_q, stored as `NttPolynomial`)

### Vectors and Keys

- `k`: determines the module dimension (k=2 for ML-KEM-512, k=3 for ML-KEM-768, k=4 for ML-KEM-1024)
- `NttVector`: a vector of `k` `NttPolynomial`s, i.e `T_q^k`

An ML-KEM encapsulation key is represented as `EncapsulationKey(t_hat, rho)` where:
- `t_hat` is in `T_q^k`, i.e. an `NttVector` — the public key vector in NTT domain (`t_hat = A_hat * s + e` in NTT form)
- `rho` is a 32-byte seed used to derive the public matrix `A_hat`

We write `ek.t_hat` and `ek.rho` to refer to the two components.

Note that the ML-KEM encapsulation key is the same as the K-PKE encryption key (FIPS 203, Section 5).

The serialized form is:

```
ek_bytes = ByteEncode_12(t_hat) || rho
```

where `ByteEncode_12` encodes each of the `256*k` coefficients using 12 bits (FIPS 203, Algorithm 5 ByteEncode_d).

A decapsulation key `dk` contains the secret vector `s` and some additional data (FIPS 203, Algorithm 16 KeyGen_internal).

### Operations

- `+` and `-` on `NttVector`: component-wise addition and subtraction in `T_q^k`
- `EncapsulationKey +/- NttVector -> EncapsulationKey`: operates on the `t_hat` component only, `rho` is preserved from the `EncapsulationKey`

### Helper Functions

**`sample_ntt_poly(xof) -> NttPolynomial`**

Algorithm 7 from FIPS 203. Reads bytes from a XOF and produces a pseudorandom element in `T_q`.

**`sample_ntt_vector(seed) -> NttVector`**

Our helper (not from FIPS 203 or MR19). Produces a pseudorandom `NttVector` from a 32-byte
`seed` by calling `sample_ntt_poly` (FIPS 203, Algorithm 7) `k` times, once per polynomial. Each
`sample_ntt_poly` call produces a pseudorandom element of `T_q`. The resulting `NttVector`
is indistinguishable from a real `t_hat`, since a real `t_hat = A_hat * s + e` is computationally
indistinguishable from a pseudorandom vector in `T_q^k`.

```
for j in 0..k:
    x = xof(seed || 0 || j)             // 34 bytes: 32-byte seed + 2 index bytes
    t_hat[j] = sample_ntt_poly(x)
```

Each call uses different index bytes `(0, j)` for different XOF stream.
In libOTe, this corresponds to `randomPK`, where it instead generates `A_hat` and takes the first row from it.

**`hash_ek(ek) -> NttVector`**

Corresponds to libOTe's `pkHash`. Hashes `ek.t_hat` to a 32-byte seed and then samples a new `NttVector` from it.

Given an `EncapsulationKey` `ek`:

```
seed = sha3_256(ByteEncode_12(ek.t_hat))     // hash only the t_hat bytes, not rho
h    = sample_ntt_vector(seed)               // sample a new NttVector from the seed
```

Output: `h`.

**`random_ek(rng, rho) -> EncapsulationKey`**

Generate a random encapsulation key. A 32-byte random `seed` is sampled from a cryptographically secure random number generator `rng`:

Output: `EncapsulationKey(sample_ntt_vector(seed), rho)`

Sampling is identical to the one on `hash_ek`, except that the seed is random rather than derived from a hash.

## Protocol

### Receiver (choice bit `b`)

1. **Generate real keypair:**
   ```
   (dk, ek) = ML-KEM.KeyGen()
   ```
   where `ek` is an `EncapsulationKey`.

2. **Sample random key for position `1-b`:**
   ```
   r_{1-b} = random_ek(rng, ek.rho)
   ```
   where `rng` is a cryptographically secure random number generator.

3. **Compute the real key for position `b`:**
   ```
   r_b = ek - hash_ek(r_{1-b})
   ```

4. **Send to sender:**
   ```
   Receiver -> Sender: (r_0, r_1)
   ```
   Each serialized as `ByteEncode_12(r_j.t_hat) || rho`.

### Sender

5. **Receive `(r_0, r_1)` from the receiver**

6. **For each `j in {0, 1}`, reconstruct the encapsulation key:**
   ```
   ek_j = r_j + hash_ek(r_{1-j})
   ```

7. **Encapsulate to both reconstructed keys:**
   ```
   (ct_0, ss_0) = ML-KEM.Encaps(ek_0)
   (ct_1, ss_1) = ML-KEM.Encaps(ek_1)
   ```
   Each `ss_j` is a 32-byte ML-KEM shared secret. Each `ct_j` is an ML-KEM ciphertext.

8. **Derive OT output keys**

   Hashing each shared secret down to a 128-bit `Block`:
   ```
   key_j = RO(domain_sep || ss_j || i)
   ```
   `RO` is a random oracle (instantiated as a hash function), `domain_sep` is a fixed
   byte string for domain separation, and `i` is a tweak (the OT batch index) ensuring
   that different OTs in a batch produce independent keys.

   The sender stores `ots[i] = [key_0, key_1]` — both OT output keys.

9. **Send to receiver:**
   ```
   Sender -> Receiver: (ct_0, ct_1)
   ```

### Receiver (continued)

10. **Decapsulate the chosen ciphertext:**
    ```
    ss_b = ML-KEM.Decaps(dk, ct_b)
    ```

11. **Derive OT key:**
    ```
    key_b = RO(domain_sep || ss_b || i)
    ```
    The receiver stores `ots[i] = key_b` — one OT output key for the `i`-th OT in the batch.

## Why This Works

**Correctness:**

For the chosen side `b`, the sender reconstructs in step 6 by expanding `r_b`:
```
ek_b = r_b + hash_ek(r_{1-b})
     = (ek - hash_ek(r_{1-b})) + hash_ek(r_{1-b})
     = ek
```
So `ek_b = ek`, the real encapsulation key. In step 10, the receiver calls `ML-KEM.Decaps(dk, ct_b)` and
recovers the same shared secret `ss_b` that the sender computed via `ML-KEM.Encaps(ek_b)` in step 7.

**Security:**

For the other side `1-b`, the sender reconstructs in step 6:
```
ek_{1-b} = r_{1-b} + hash_ek(r_b)
```

Expanding `r_b` (from step 3):
```
ek_{1-b} = r_{1-b} + hash_ek(ek - hash_ek(r_{1-b}))
```

This does not simplify — `hash_ek` is a hash function, so the nested `hash_ek(ek - hash_ek(r_{1-b}))`
cannot be reduced. The result `ek_{1-b}` is an unrelated key for which the receiver does not
have a decapsulation key `dk`, so they cannot decapsulate `ct_{1-b}`.

The choice bit `b` is hidden from the sender. The sender reconstructs both `ek_0` and `ek_1` in
step 6, but under the MLWE assumption, a real encapsulation key is indistinguishable from a random
one. Since both reconstructed keys appear as valid encapsulation keys, the sender cannot determine
which one has a corresponding decapsulation key `dk`.
