# Incremental domain updates

`-O N -M /path/to/control.sock` enables at most N distinct exact-domain
updates **per eligible dataset**, with N from 1 through 65536. Every
configured `dnhash` and `dnsnapshot` dataset gets an independent overlay,
initially empty. Other dataset types can coexist and retain their ordinary
query behavior; they are not overlay targets. Subdatasets created dynamically
by `combined` are not eligible. Wildcard updates and ACL-key updates are not
supported.

An overlay belongs to a dataset, not a zone name. Two zone aliases using the
same dataset share its updates, revision, and capacity. A zone with multiple
eligible datasets has a separate target for each dataset. Use discovery below
to select the intended one. Each target's names are relative to the zone
through which that dataset is queried.

Use `dnsnapshot` for a read-only mapped base and online compaction. Memory is
fixed at startup **for every eligible dataset**: N value slots plus a khash
index with at least twice N buckets (rounded to a power of two, minimum four).
The index reuses the existing DNS hash function. Total overlay memory
therefore scales with both N and the number of distinct eligible datasets;
aliases of the same dataset do not allocate another overlay. On 64-bit
platforms each value slot is approximately 532 bytes, with another 8.25 bytes
per index bucket. Its flags and slot pointers use atomic accesses; all arrays
are allocated in shared mappings before workers fork and never resize. Only
the controller changes the index, and readers validate its publication
sequence before accepting a result. Compaction rebuilds the same index storage
after reclamation, clearing khash's deleted buckets. Mutable overlay storage
is shared between all workers and generations, separate from the base's CoW
pages.

## Selecting a dataset

Send `overlay-list` to the Unix datagram control socket. A discovery reply has
this shape:

```json
{
  "targets": [
    {
      "id": 1,
      "spec": "dnsnapshot:/srv/alpha.snapshot",
      "spec_truncated": false,
      "zones": [
        "alpha.test",
        "alias.test"
      ],
      "zone_count": 2,
      "zones_truncated": false
    }
  ],
  "target_count": 1,
  "next_offset": -1
}
```

Target IDs are 1-based and assigned by eligible-dataset traversal at startup.
They remain stable across zone reloads and compactions. Discover IDs again
after a daemon restart or configuration change instead of assuming a previous
ID still names the same dataset. Specifications are JSON-escaped strings.

Discovery returns at most eight targets per reply. If `next_offset` is
nonnegative, send `overlay-list OFFSET` with that value and continue until it
is -1. Offsets are zero-based target positions, not target IDs. Each entry
includes at most 512 specification bytes and four zone aliases.
`spec_truncated` and `zones_truncated` disclose omissions; `zone_count` is the
full alias count. A truncated specification is descriptive metadata, not a
complete source path.

Use the `@ID` prefix to address a target explicitly:

```
overlay-status @1
overlay-put @1 0 spam.example 127.0.0.2 listed
overlay-del @1 1 old.example
overlay-compact @1 2
overlay-status @2
```

`overlay-status @ID` includes the selected target's `id`, revision, capacity
usage, and export/compaction state. Each target has its own revision sequence
and capacity. Updating or filling one target does not change another target's
revision or use its slots. Unknown or malformed IDs return an error.

The original commands without `@ID` remain valid only when there is exactly
one eligible dataset, even if that dataset has several zone aliases or
unrelated dataset types coexist. With multiple targets, unqualified status,
put, delete, and compact commands are rejected as ambiguous.

`overlay-put @ID EXPECTED_REVISION NAME IPV4 TXT` replaces an exact answer.
Names are relative to the configured zone, as in the source dataset. TXT is at
most 255 bytes and uses the normal dataset substitutions; an empty TXT is
allowed with the trailing space after IPV4. Entry parameters are not accepted:
an override replaces the entire original entry including its entry parameters.
Existing zone/global ACL checks still run. Do not replace per-entry protected
data unless removing that entry policy is intended.

`overlay-del @ID EXPECTED_REVISION NAME` installs an exact **exclusion**. It
masks both the exact base entry and any matching base wildcard. It does not
merely remove an override and reveal the base. `overlay-put` can replace an
exclusion. Names and output paths cannot contain spaces; commands cannot
contain NUL.

Only the controller mutates the mapping. Every accepted put/delete increments
that target's revision; a stale expected revision returns an error and its
current revision. Validation or capacity errors leave the revision unchanged.
After an acknowledgement, new queries on every worker see the updated mapping;
queries already in progress may complete with their previous result. A reader
that cannot obtain a stable entry within 64 attempts returns SERVFAIL, keeping
the UDP loop responsive even if the writer is stopped during publication. A
missing acknowledgement is ambiguous: inspect `overlay-status @ID` before
retrying. Replacing an existing name uses no additional capacity.

## Compaction and persistence

For a `dnsnapshot` dataset, `overlay-compact @ID REVISION` captures the
selected overlay at that revision, starts an isolated compiler, and atomically
replaces the configured snapshot with the merged result. The compiler loads
the current **on-disk** base, not a stale supervisor image. Its 60-second
deadline bounds an unsuccessful job; queries and new overlay mutations
continue meanwhile. Success requests a normal reload. Poll `overlay-status
@ID`: `export_state` is `running`, `success`, or `failed`;
`compaction_pending` remains true until the new base is active and every
worker using an older base has exited.

The controller verifies the new base's device/inode identity, captured from
the compiled file descriptor and from the candidate loader's validated file
descriptor. Only then does it reclaim that target's overlay entries through
the captured revision. Other targets retain their own entries and checkpoints.
Newer mutations remain in shared memory. Explicit exclusions are included in
the compiled base, so delisted names cannot reappear through a wildcard. A
failed reload retains the overlay; retry the normal reload after resolving the
failure. Only one compaction/export may be outstanding per target. Independent
targets can have separate jobs outstanding. At most eight compiler jobs may run
across all targets. If that global limit prevents a job from starting, retry
after another job finishes.

`overlay-compact @ID REVISION /separate/output.snapshot` works with either
supported dataset type and exports a merged snapshot without activating it or
clearing the overlay. The output must not be any configured dataset's current
source file, including a different target or an unrelated dataset type. Online
replacement is also rejected when distinct dataset objects use the same source
path; aliases of one shared dataset remain supported. The compiler uses atomic
rename and never writes an existing mapped inode. Use atomic replacement for
external updates too; never modify snapshot files in place. Avoid external
publications while compacting: the exported base is the version opened by the
compiler, and its final rename is the publication point.

**Acknowledged updates are ephemeral until compacted.** There is no journal. A
daemon restart starts at revision zero and retains only changes already
included in its configured on-disk snapshot. Updates newer than a completed
compaction's revision still need another compaction before restart. Snapshot
publication fsyncs the file but does not promise directory-entry persistence
across machine power loss. Keep the latest source and snapshot backups.
