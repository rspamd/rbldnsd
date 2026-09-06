# Compiled domain snapshots

Compile a dnhash dataset using the ordinary parser, then serve the result:

```
rbldnsd -B domains.snap example.test:dnhash:domains.txt
rbldnsd -n -W 4 -b 127.0.0.1/5300 example.test:dnsnapshot:domains.snap
```

`-B` requires exactly one dnhash dataset (which may contain multiple source
files). It rejects parser warnings, unsupported excessive entry metadata (more
than 64 pairs), allocation failures and write errors. Existing output is retained
on failure. The output is written to a temporary file in the destination
directory, fsynced, and renamed into place. The containing directory is not
fsynced; rename durability across a machine crash is the publisher's responsibility.

A/ TXT values, defaults resolved at compilation, duplicate replacement order,
exact exclusions, wildcard exclusions, dot-prefix matching, per-entry metadata,
TXT substitutions, TTL, SOA, NS and absolute expiry are preserved. Absolute expiry
is not refreshed by compilation or loading. The DNS dataset origin remains a
runtime zone binding. `dnsnapshot` accepts exactly one uncompressed binary file;
use additional datasets for other inputs. The initial format limits a file to
1 GiB, 1024 nameservers and 64 metadata pairs per entry. It has no incremental
update hook; rebuild and reload to publish a new base.

Loaded entry keys, answers, metadata strings and substitutions live in a
`PROT_READ, MAP_PRIVATE` mapping. Small SOA/NS wrapper structures are allocated in
the ordinary dataset pool. Lookup does not allocate heap memory. Workers inherit
the same mapping. Replacing or unlinking the pathname does not invalidate the
old mapping; releasing a generation unmaps its old image without retaining hash
capacity. **Never modify or truncate an installed snapshot inode in place.**
The mapping assumes immutable published files, just as the text loader requires
atomic replacement. The checksum detects corruption at load time; it is not a
signature or protection against a writer changing a live inode.

## Version 1 layout

All integers are unsigned 32-bit big-endian values, including offsets; no native
pointers, alignment padding or host byte order are stored. Header is 128 bytes:

| Offset | Meaning |
| --- | --- |
| 0 | Eight ASCII bytes `RBLDNSNP` |
| 8 | Version, 1 |
| 12 | Exact total file size |
| 16 | Entry count |
| 20 | Dataset TTL |
| 24 | FNV-1a 32-bit checksum of entire file, treating bytes 24..27 as zero |
| 28 | Reserved, zero |
| 32..72 | Eleven substitution string offsets; zero means absent |
| 76 | Reserved, zero |
| 80 | SOA record offset, or zero |
| 84 | Nameserver offset-array offset, or zero |
| 88 | Nameserver count |
| 92 | Nameserver TTL |
| 96,100 | High and low halves of absolute expiry epoch seconds |
| 104,108 | High and low halves of source dataset timestamp (automatic SOA serial) |
| 112..124 | Reserved, zero |

The entry index immediately follows the header, with 24 bytes per entry:
`table, name_offset, name_length_without_root, rr_offset, params_offset,
params_count`. Table 0 is exact; tables 1..5 are wildcard suffix label counts.
Entries are strictly sorted by table, then lexicographically by the wire-name
bytes (length breaks equal prefixes). A zero RR offset means an explicit
exclusion, distinct from no index entry. Nonzero RR points to four IPv4 bytes
followed by a zero-terminated TXT template (at most 255 bytes). Name includes the
root terminator in the blob, but its indexed length excludes that terminator.
Parameters are an array of `(key_offset, value_offset)` pairs of zero-terminated
strings. Empty parameter lists must have offset zero.

SOA is 32 bytes: TTL, origin-name offset, person-name offset, serial, then the
16 network-order bytes for refresh/retry/expire/minimum TTL. Nameserver array
contains wire-name offsets. Names include their root terminator. All offsets
point into the blob after the complete entry index. Strings are at most 65535
bytes (TXT has the tighter limit above). Loader validates size, version, reserved
fields, checksum, every range, wire-name labels, wildcard label counts, string
termination, strict ordering, and metadata bounds before exposing the mapping.
FNV is an integrity checksum of compiled content, not a source-file identity.

## Extension interface

`rbldnsd_snapshot.h` exposes exact table lookup and callback enumeration for
snapshots, and callback enumeration for dnhash. A successful lookup with `rr ==
NULL` is an exclusion; return zero is a miss. `snapshot_entry` contains copied
parameter descriptors but borrowed name/RR/key/value pointers. Those pointers
remain valid only until the dataset is reset. Callers needing durable entries
must copy them. Enumeration may stop by returning zero from its callback.
`rbldnsd_snapshot_write_iter` accepts a metadata dataset and an entry producer
callback for compaction; the producer invokes the supplied visitor for each
entry and returns success. Its entries must have unique table/name keys and
borrowed pointers must stay valid until the writer returns. The writer sorts
them before serialization.

Tests: `RBLDNSD=/absolute/path/rbldnsd python3 test/pyunit/test_snapshot.py -v`.
They compare complete DNS packets against dnhash, including SOA/NS and negative
answers, reject malformed offsets even with a recomputed checksum, and exercise
atomic replacement, multiworker reload and unlink. Linux also checks that the
supervisor's mapping permissions are `r--p`.
