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
- `NttVector<k>`: a vector of `k` `NttPolynomial`s in `T_q^k`

An ML-KEM encapsulation key (public key) consists of two parts:

```
ek = (t_hat, rho)
```

where:
- `t_hat` is an `NttVector<k>`: the public key vector in NTT domain (`t_hat = A_hat * s + e` in NTT form)
- `rho` is a 32-byte seed used to derive the public matrix `A_hat`

Note that the ML-KEM encapsulation key is the same as the K-PKE encryption key (FIPS 203, Section 5).

The serialized form is:

```
ek_bytes = ByteEncode_12(t_hat) || rho
```

where `ByteEncode_12` encodes each of the `256*k` coefficients using 12 bits (FIPS 203, Algorithm 5 ByteEncode_d).

We write `ek.t_hat` and `ek.rho` to refer to the two components of an encapsulation key.

A decapsulation key `dk` contains the secret vector `s` and some additional data (FIPS 203, Algorithm 16 KeyGen_internal).

### Operations

- `+` and `-` on `NttVector<k>`: component-wise addition and subtraction in `T_q^k`
- `SampleNTT(B)`: Algorithm 7 from FIPS 203. Reads from a byte stream `B` and produces a pseudorandom element in `T_q`, i.e. an `NttPolynomial`

### Helper Functions

**`SampleNTTVector(seed, rho) -> (t_hat, rho)`**

Our helper (not from FIPS 203 or MR19). Produces a pseudorandom `NttVector<k>` from a 32-byte
`seed` by calling `SampleNTT` (FIPS 203, Algorithm 7) `k` times, once per polynomial. Each
`SampleNTT` call produces a pseudorandom element of `T_q`. The resulting `NttVector<k>`
is indistinguishable from a real `t_hat`, since a real `t_hat = A_hat * s + e` is computationally
indistinguishable from a pseudorandom vector in `T_q^k`.

```
for j in 0..k:
    t_hat[j] = SampleNTT(seed || j || 0)     // 34 bytes: 32-byte seed + 2 index bytes
```

Each call uses different index bytes `(j, 0)` in FIPS 203 Algorithm 7 for domain separation.
In libOTe, this corresponds to `randomPK`, where it instead generates `A_hat` and takes the first row from it.

Output: `(t_hat, rho)`. The `rho` is passed through unchanged.

**`H(ek) -> (h, ek.rho)`**

Hash-to-key (corresponds to libOTe's `pkHash`). Maps an encapsulation key to another
encapsulation key. Takes an element of `T_q^k`, hashes it to a 32-byte seed, and uses that seed to sample a new element of `T_q^k`.

Given an encapsulation key `ek = (t_hat, rho)`:

```
seed = SHA3-256(ByteEncode_12(ek.t_hat))     // hash only the t_hat bytes, not rho
h    = SampleNTTVector(seed, ek.rho)         // sample a new NttVector<k> from the seed
```

Output: `(h, ek.rho)` where `h` is an `NttVector<k>` in `T_q^k`.

**`RandomEK(seed, rho) -> (t_hat, rho)`**

Generate a random encapsulation key from the given random 32 byte `seed` and `rho`:

Output: `SampleNTTVector(seed, rho)`

This is identical to `H` except the seed is random rather than derived from a hash.

## Protocol

**Convention:** All arithmetic (`+`, `-`) in the protocol steps operates on the `t_hat`
component only. The `rho` component is always the same across all keys in a single OT
(taken from the real key generated in step 1) and is carried along unchanged.

### Receiver (choice bit `b`)

1. **Generate real keypair:**
   ```
   (dk, ek) = ML-KEM.KeyGen()
   ```
   where `ek = (t_hat, rho)`.

2. **Sample random key for position `1-b`:**
   ```
   seed = 32 random bytes
   r_{1-b} = RandomEK(seed, ek.rho)
   ```

3. **Compute the correlated key for position `b`:**
   ```
   r_b = ek - H(r_{1-b})
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
   ek_j = r_j + H(r_{1-j})
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

For the chosen side `b`, the sender reconstructs in step 6:
```
ek_b = r_b + H(r_{1-b})
     = (ek - H(r_{1-b})) + H(r_{1-b})
     = ek
```
So `ek_b = ek`, the real public key. In step 10, the receiver calls `ML-KEM.Decaps(dk, ct_b)` and recovers the same shared secret `ss_b` that the sender computed via `ML-KEM.Encaps(ek_b)` in step 7.

**Security:**

For the other side `1-b`, the sender reconstructs in step 6:
```
ek_{1-b} = r_{1-b} + H(r_b)
```

Expanding `r_b` (from step 3):
```
ek_{1-b} = r_{1-b} + H(ek - H(r_{1-b}))
```

This does NOT simplify — `H` is a hash function, so `H(ek - H(r_{1-b}))` does not
cancel with `H(r_{1-b})`. The result `ek_{1-b}` is an unrelated key for which the
receiver does not have a decapsulation key `dk`, so they cannot decapsulate `ct_{1-b}`.

The choice bit `b` is hidden because `r_b = ek - H(r_{1-b})`. Since `ek` is
indistinguishable from uniform under the MLWE assumption, and `H(r_{1-b})` is determined by the
already-public `r_{1-b}`, subtracting it from a uniform value still yields a uniform
value. So both `r_0` and `r_1` appear uniform to the sender — neither reveals which
is the real key.
