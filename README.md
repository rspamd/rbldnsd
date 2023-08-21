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
3. Multiprocessing using SO_REUSEPORT and eBPF filters to optimise UDP flows
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
