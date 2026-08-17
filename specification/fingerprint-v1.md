# Crash Capsule fingerprints, version `ccfp/1` (normative)

Two hashes answer two different questions, and conflating them is the classic way crash
deduplication goes wrong:

| Fingerprint | Question | Consequence of a match |
| --- | --- | --- |
| **strict** | Is this the same crash in the same build? | Exact deduplication; occurrence counting |
| **family** | Is this probably the same underlying bug across builds? | Candidate grouping, shown as a suggestion |

Both are `SHA-256` over deterministic CBOR of an explicitly ordered array. The array always
starts with a domain string, so material for one fingerprint kind can never be reinterpreted as
material for another.

## Excluded by construction

The following are never hashed, because they change between boots or between identical
machines and would defeat deduplication:

- absolute virtual addresses and any pointer value;
- ASLR and KASLR bases or slides;
- process, thread and CPU numbers;
- timestamps, uptimes and sequence numbers;
- the capsule id.

Frames can only express a *module-relative* offset, so an implementation cannot accidentally
include an address.

## Symbol normalisation

Applied in this order, to `frame.symbol`, before hashing:

1. strip a versioned-symbol suffix: `memcpy@@GLIBC_2.14` → `memcpy`;
2. strip a trailing offset: `foo_submit+0x1f/0x40` → `foo_submit`;
3. cut at the first `(` or `<`, removing argument and template lists:
   `ns::render<Pixel>(int, int)` → `ns::render`;
4. strip compiler-generated local suffixes: `.cold`, `.part`, `.isra`, `.constprop`,
   `.localalias`;
5. strip a Rust legacy-mangling disambiguator: a trailing `::h` followed by exactly sixteen
   hexadecimal digits.

## Material

`top_frames(n)` is the first `n = 5` frames, most recent first. Deeper frames are dominated by
generic entry points and add noise rather than identity. `null` is used for an absent optional,
so position is always meaningful.

### Userspace strict — domain `ccfp/1/strict`

```cddl
[ "ccfp/1/strict", source_kind: uint, failure_class: uint, component: tstr,
  build_id: bstr, signal: int,
  [ * [ build_id: bstr / null, symbol: tstr / null, offset: uint / null ] ] ]
```

### Kernel strict — domain `ccfp/1/kernel-strict`

```cddl
[ "ccfp/1/kernel-strict", failure_class: uint, kernel_build_id: bstr,
  architecture: tstr, module: tstr / null,
  [ * [ build_id: bstr / null, symbol: tstr / null, offset: uint / null ] ],
  taint: uint ]
```

The kernel variant keys on the kernel build id rather than a component build id, and includes
the taint mask: a crash on a tainted kernel is not the same incident as the same trace on a
clean one.

### Family — domain `ccfp/1/family`

```cddl
[ "ccfp/1/family", source_kind: uint, component: tstr, failure_class: uint,
  [ * [ module: tstr / null, symbol: tstr / null ] ] ]
```

The family material deliberately omits every build-local value: build ids, offsets and the
signal. Rebuilding the same source, or shipping a new package version, preserves the family
fingerprint while changing the strict one.

## Display

`signature()` renders `CCFP1-` followed by the first sixteen bytes in lowercase hex. This is a
display convenience only; the full 256-bit value is authoritative and is what gets stored,
compared and transmitted.

## Fuzzy matching

Anything beyond these two hashes — edit distance over frames, clustering, model-assisted
similarity — is **advisory**. It may suggest a merge to a human; it must never silently merge
two reports, and it must never be recorded as the reason two capsules are the same incident.

## Test vectors

`specification/test-vectors/fingerprint/` contains the exact material bytes and the resulting
fingerprint for each variant. A second implementation is conformant when hashing the committed
material reproduces the committed fingerprint *and* it independently produces the same material
from the same inputs.
