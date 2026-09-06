This is a fork of rbldnsd developped to improve the performance and add some new features to this DNS server.

Main changes from the original source:

* **Modernized Build System with CMake**: We've integrated a sophisticated CMake build system to streamline the development process.
* **Optimized Compilation with LTO Support**: With the inclusion of Link Time Optimization (LTO) support during compilation, we've fine-tuned the performance for a more efficient DNS server.
* **Introducing Hashed Backend** - `dnhash`: a hashed backend that not only conserves CPU resources but also encompasses all the functionalities of the existing dnset (e.g. wildcard elements).
* **Expanded IP Address Support with iptrie**:` ip4trie` now allows seamless integration of both IPv6 and IPv4 addresses, enhancing the versatility of the server.
* **Vectorized Datagram Processing**: vectorized processing of incoming datagrams allows a single CPU core to handle around 300,000 RPS (Requests Per Second).
* **Embedded jemalloc**: The addition of embedded jemalloc support brings along insightful memory usage statistics, ensuring you have a comprehensive overview of resource utilization.
* **ACL Zone - aclkey**: Added the `aclkey` zone-helper that allows key-based access to your DNS data, enabling resolution of addresses like 1.0.0.127.<KEY>.zone.com, where key corresponds to a designated DNS label.

This project has been supported by [Abusix](https://abusix.com/).

TODO:

1. Rate limits using leaky bucket model
2. Hyperscan based regexp backend
3. eBPF filters to optimise UDP worker flows
4. Better documentation

The current source tree has been forked from https://github.com/spamhaus/rbldnsd and is now maintained by Vsevolod Stakhov.
The original source was written originally by Michael Tokarev <mjt+rbldnsd@corpit.ru>


The original, unmantained source and debian packages can always be found at:
  http://www.corpit.ru/mjt/rbldnsd.html


Copyright (C) 2023 Vsevolod Stakhov
Copyright (C) 2016-2018 The Spamhaus Project Ltd.
Copyright (C) 2002 Michael Tokarev

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

### Multiple UDP workers

Use `-W 4` to run four query workers and a stable supervisor. Workers have
separate `SO_REUSEPORT` sockets and share loaded zone pages through fork/CoW.
Send SIGHUP to the supervisor to reload. An isolated candidate process loads
all input files, then forks replacements sharing its new image. The controller
activates the complete generation and retires the previous one only after every
worker is ready. File-change reloads use the same path; unchanged files do not
rotate workers.

Each generation keeps an immutable owner process that can replace crashed
workers even after a failed reload. A small guardian observes controller death
and bounds cleanup of blocked loaders and stopped workers. The controller
keeps configuration and file metadata, not zone contents, so retired images
are reclaimed completely. Reload memory is approximately the old image plus
the new image, without inherited hash-table capacity from larger old zones.
`-T seconds` bounds candidate loading and worker startup (default 60 seconds).
A failed, crashed, or timed-out candidate leaves the active generation intact.

The default `-W 1` keeps the existing single-process behavior. Multiple-worker
mode currently excludes `-U` dynamic updates and `-s` statistics files; SIGUSR1
reports individual worker counters in the log. Kernel UDP distribution varies
by platform. See the manual for lifecycle and memory details.

Run the process lifecycle tests with:

```sh
RBLDNSD=/path/to/built/rbldnsd python3 test/pyunit/test_workers.py
```

### Local control and worker accounting

`-M /run/rbldnsd/control.sock` enables an owner-only (0600), nonblocking Unix
**datagram** socket. The directory must already exist and be writable by the
runtime user, within the chroot when used. Existing paths are never removed at
startup. Normal shutdown removes only the socket inode created by this process;
after a crash, remove the stale socket manually after verifying the daemon stopped.

Commands are `status`, `stats`, `reload`, and `shutdown`, optionally followed by
a newline. Replies are JSON datagrams. The client must bind its own private Unix
socket path and receive a datagram up to 16 KiB. For example:

```python
import json, socket, tempfile
with tempfile.TemporaryDirectory() as directory:
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        client.bind(directory + '/client')
        client.sendto(b'stats', '/run/rbldnsd/control.sock')
        print(json.loads(client.recv(16384)))
```

`status` and `stats` return the controller PID, published generation, last reload
result/time, live worker identities and states, and per-worker and lifetime
aggregate counters. At most eight workers appear per response; when `next_slot`
is nonnegative, request `stats N` (or `status N`) using that slot number to
continue. Totals cover all slots on every page. Totals survive worker replacement and crashes. Counters cover
received datagrams/bytes, generated responses/bytes, response codes and unanswered
queries. Generated responses are not proof of successful transmission. Delayed
reply count/bytes are instantaneous gauges. `receive_drop_accounting` and
`send_error_accounting` indicate whether their corresponding transport counters
are available; unsupported counters must not be interpreted as measured zero.
Rates can be calculated from successive samples. Samples are approximate across
concurrent worker updates, not an atomic snapshot of all counters.

Accounting lives in a fixed, separate shared mapping, with slots reused after
workers are reaped. `-s` retains its existing single-process per-zone format and
is still incompatible with `-W` greater than one; use JSON accounting instead.
`-M` with `-W 1` uses in-process reloads. Reload/shutdown acknowledge command
acceptance, not completion: poll status to observe the resulting generation or
reload failure. Commands and responses never wait for a client to become writable;
if a client loses a reply, it must inspect status before retrying a mutation.
Compiled read-only domain datasets: see [README.snapshot.md](README.snapshot.md).

UDP sends are bounded: a partial `sendmmsg()` continues from its unsent tail;
`EAGAIN`, `ENOBUFS`, other send failures, or exhaustion of four `EINTR` retries
cause remaining replies to be dropped and counted in `send_errors`. This also
applies to delayed replies. No unbounded send queue or busy retry loop is used.
`send_errors` counts discarded datagrams, not failed system calls; response and
byte totals still count generated responses. Oversized truncated input datagrams
are counted as unanswered and never parsed as complete DNS queries.

On Linux, `receive_drops` uses `SO_RXQ_OVFL` ancillary reports. Counters and their
per-socket baselines survive worker replacement in shared memory. Duplicate and
out-of-order observations are ignored and 32-bit wraparound is handled, assuming
fewer than 2^31 drops between observations. These are socket receive-queue drops,
not all network loss. The kernel reports them only with a later received packet;
loss after the last delivered packet remains unobserved. Truncated ancillary
reports are ignored and a later complete report catches up. Other platforms
report receive-drop accounting as unavailable.
Bounded shared domain updates and online snapshot compaction: see
[README.overlay.md](README.overlay.md).
