# 01 · Crypto

**Job:** Fix the STARK field, the Poseidon2 hash instance, and the domain-separation scheme that every other layer shares.

## Field

The field is **BabyBear**, `p = 2^31 - 2^27 + 1 = 0x78000001`. All in-circuit
values are BabyBear elements. The STARK challenge field is the degree-4
binomial extension `BabyBear^4`.

Digests are **8 field elements** (~124-bit collision resistance). External
256-bit objects (secp256k1 x-only keys, Bitcoin txids) are carried as **16
little-endian 16-bit limbs**, and 64-bit amounts as **3 limbs** split
`31 + 31 + 2` bits.

## Hash

The hash is **Poseidon2** over BabyBear at width 16 (rate 8, capacity 8), using
the round constants and layers shipped by `p3-poseidon2`/`p3-baby-bear` so that
native and in-circuit evaluations are identical. Two modes:

- `h_sponge(domain, inputs)` — absorb a variable-length field slice, squeeze one
  8-element digest. Used for leaves, records, genesis, state commitments.
- `h_compress(domain, left, right)` — a single permutation compressing two
  digests to one. Used for every Merkle tree level.

## Domain separation

A `Domain` tag is folded into the capacity so that hashes computed for different
purposes can never collide or be repurposed. Every distinct structure (state
commitment, account id, address, coin leaf, output leaf, the spent/frozen/
balances tree nodes, record, genesis, link tuple, public-input binding) has its
own tag.

The exact constants and the reference `h_sponge`/`h_compress` implementations
live in `scsv-core::hash`; committed test vectors pin them so any accidental
change to the instance is loud.
