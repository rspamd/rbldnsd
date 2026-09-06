# Incremental domain updates

`-O N -M /path/to/control.sock` enables at most N distinct exact-domain
updates, 1 through 65536. Initially the overlay is empty. This mode requires
exactly one `dnhash` or `dnsnapshot` dataset; IP lists, combined datasets,
ACL keys, and wildcard updates are not supported. Use `dnsnapshot` for a
read-only mapped base and online compaction. Memory is fixed at startup:
a hash table with twice the next power of two of N slots, approximately
536 bytes per slot. Mutable overlay storage is shared between all workers
and generations, separate from the base's CoW pages.

Send these commands to the Unix datagram control socket:

```
overlay-status
overlay-put 0 spam.example 127.0.0.2 listed
overlay-del 1 old.example
overlay-compact 2
```

Names are relative to the configured zone, as in the source dataset.
`overlay-put EXPECTED_REVISION NAME IPV4 TXT` replaces an exact answer.
TXT is at most 255 bytes and uses the normal dataset substitutions; an empty
TXT is allowed with the trailing space after IPV4. Entry parameters are not
accepted: an override replaces the entire original entry including its entry
parameters. Existing zone/global ACL checks still run. Do not replace
per-entry protected data unless removing that entry policy is intended.

`overlay-del EXPECTED_REVISION NAME` installs an exact **exclusion**. It masks
both the exact base entry and any matching base wildcard. It does not merely
remove an override and reveal the base. `overlay-put` can replace an exclusion.
Names and output paths cannot contain spaces; commands cannot contain NUL.

Only the controller mutates the mapping. Every accepted put/delete increments
the revision; a stale expected revision returns an error and the current
revision. Validation or capacity errors leave the revision unchanged. After
an acknowledgement, new queries on every worker see the updated mapping;
queries already in progress may complete with their previous result. A
missing acknowledgement is ambiguous: inspect `overlay-status` before
retrying. Replacing an existing name uses no additional capacity.

## Compaction and persistence

For a `dnsnapshot` dataset, `overlay-compact REVISION` captures the overlay at
that revision, starts an isolated compiler, and atomically replaces the
configured snapshot with the merged result. The compiler loads the current
**on-disk** base, not a stale supervisor image. Its 60-second deadline bounds
an unsuccessful job; queries and new overlay mutations continue meanwhile.
Success requests a normal reload. Poll `overlay-status`: `export_state` is
`running`, `success`, or `failed`; `compaction_pending` remains true until the
new base is active and every worker using an older base has exited.

The controller verifies the new base's device/inode identity, captured from
the compiled file descriptor and from the candidate loader's validated file
descriptor. Only then does it reclaim overlay entries through the captured
revision. Newer mutations remain in shared memory. Explicit exclusions are
included in the compiled base, so delisted names cannot reappear through a
wildcard. A failed reload retains the overlay; retry the normal reload after
resolving the failure. Only one compaction/export may be outstanding.

`overlay-compact REVISION /separate/output.snapshot` works with either
supported dataset type and exports a merged snapshot without activating it
or clearing the overlay. The output must not be a current source file.
The compiler uses atomic rename and never writes an existing mapped inode.
Use atomic replacement for external updates too; never modify snapshot
files in place. Avoid external publications while compacting: the exported
base is the version opened by the compiler, and its final rename is the
publication point.

**Acknowledged updates are ephemeral until compacted.** There is no journal.
A daemon restart starts at revision zero and retains only changes already
included in its configured on-disk snapshot. Updates newer than a completed
compaction's revision still need another compaction before restart. Snapshot
publication fsyncs the file but does not promise directory-entry persistence
across machine power loss. Keep the latest source and snapshot backups.
