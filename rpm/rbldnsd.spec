%global srcname rbldnsd
%global rbldnsuser rbldns
%global rbldnshome %{_localstatedir}/lib/rbldns

Name:           rbldnsd
Version:        1.0.0
Release:        1%{?dist}
Summary:        Small fast daemon to serve DNSBLs
License:        GPL-2.0-or-later
URL:            https://github.com/rspamd/rbldnsd
Source0:        https://github.com/rspamd/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        rbldnsd.service
Source2:        rbldnsd.sysconfig

BuildRequires:  cmake >= 3.9
BuildRequires:  gcc
BuildRequires:  gawk
BuildRequires:  make
BuildRequires:  jemalloc-devel
BuildRequires:  libev-devel
BuildRequires:  zlib-devel
BuildRequires:  systemd-rpm-macros

Requires(pre):  shadow-utils

%description
Rbldnsd is a small authoritative-only DNS nameserver
designed to serve DNS-based blocklists (DNSBLs).
It may handle IP-based and name-based blocklists.

This is a high-performance fork with modern build system,
LTO support, and optimized datagram processing.

%prep
%autosetup -n %{name}-%{version}

%build
%cmake \
    -DENABLE_JEMALLOC=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
%cmake_build

%install
%cmake_install

# Install systemd service
install -D -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/rbldnsd.service
install -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/sysconfig/rbldnsd

# Install man page
install -D -m 0644 rbldnsd.8 %{buildroot}%{_mandir}/man8/rbldnsd.8

# Create data directory
mkdir -p %{buildroot}%{rbldnshome}

%pre
getent group %{rbldnsuser} >/dev/null || groupadd -r %{rbldnsuser}
getent passwd %{rbldnsuser} >/dev/null || \
    useradd -r -g %{rbldnsuser} -d %{rbldnshome} -s /sbin/nologin \
    -c "rbldns Daemon" %{rbldnsuser}
exit 0

%post
%systemd_post rbldnsd.service

%preun
%systemd_preun rbldnsd.service

%postun
%systemd_postun_with_restart rbldnsd.service

%files
%license LICENSE.txt
%doc README.md NEWS TODO CHANGES-0.81 README.user
%{_sbindir}/rbldnsd*
%{_mandir}/man8/rbldnsd.8*
%{_unitdir}/rbldnsd.service
%config(noreplace) %{_sysconfdir}/sysconfig/rbldnsd
%attr(0755, root, root) %dir %{rbldnshome}

%changelog
* Mon Dec 16 2024 rbldnsd maintainers <vsevolod@rspamd.com> - 1.0.0-1
 - Initial RPM spec for EL8+
