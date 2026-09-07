# Bundled SipHash reference implementation

Upstream: https://github.com/veorq/SipHash
Pinned revision: `32d067603b93b47828700880649198e0bfbbcffa`
Retrieved: 2026-09-07

The upstream repository identifies this as the reference C implementation by
Jean-Philippe Aumasson and Daniel J. Bernstein. rbldnsd uses SipHash-2-4 with a
16-byte operating-system-generated key and an 8-byte result for quota buckets.
The quota tests check all 64 upstream `vectors_sip64` vectors, including the
byte-order conversion used by rbldnsd.

All listed files are byte-for-byte upstream copies. `README.md` was renamed to
`README.upstream.md`; no contents were changed. Their upstream formatting is
preserved deliberately so future updates can be verified without a local style
diff. rbldnsd-owned wrapper and entropy code follows the project's C style.

Upstream offers CC0-1.0, MIT, or Apache-2.0 with LLVM exceptions. This bundled
copy includes all three original license texts and retains upstream copyright
and dedication notices. See `LICENSE_CC0`, `LICENSE_MIT`, `LICENSE_A2LLVM`, and
`README.upstream.md`. The rbldnsd integration may be used under the MIT option.

## SHA-256 checksums

- `siphash.c`: `94b6c1f3a24072a8a5afc4fea7fb9e95c5fc2e99657b6b712d991029ffdaa88c`
- `siphash.h`: `30d4269093e5886cb9e7ea826899ef02daddac682e73c335c53dd748b9e20bfb`
- `vectors.h`: `212c44114a63c6d84710b8627f3bc5ce155698accf2ea7bbff1c4b69c9f48d31`
- `LICENSE_MIT`: `f2e682acda10fead70f7a72918f5b229db02aaea32769a62c1378654e942bc98`
- `LICENSE_CC0`: `5537d4d10b76b81b6e8dfd8b644480a4b1efa332fbb0cdb61126c5be781ef7b4`
- `LICENSE_A2LLVM`: `acac485105b9aaac29d5ba5ac9de8a4a32800db356016d87417141a8a89db979`
- `README.upstream.md`: `8ece505c9a72eee0d9c2659f7d2c3477c6552658890e0d5889a5fa1433c66d11`

## Updating

Fetch the same files from one explicitly pinned upstream revision, retaining
all license notices. Update this revision and checksum list, then run
`python3 test/pyunit/test_ratelimit.py Accounting` and
`python3 test/pyunit/test_ratelimit_entropy.py` from the repository root before
running the daemon's quota integration tests.
