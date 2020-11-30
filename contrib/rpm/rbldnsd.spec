# RPM spec file for rbldnsd

Summary: Small fast daemon to serve DNSBLs
Name: rbldnsd
Version: 1.0.0
Release: 1
License: GPL
Group: System Environment/Daemons
BuildRoot: %_tmppath/%name-%version
BuildRequires: cmake, jemalloc-devel, libev-devel, zlib-devel
Requires: /sbin/chkconfig, /sbin/nologin, shadow-utils

Source: http://www.github.com/rspamd/%name/%{name}-%version.tar.gz

%define home /var/lib/rbldns

%description
Rbldnsd is a small authoritate-only DNS nameserver
designed to serve DNS-based blocklists (DNSBLs).
It may handle IP-based and name-based blocklists.

%prep
%setup -q -n %name-%version

%build
%{__cmake} -DENABLE_JEMALLOC=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=%{_prefix}
%{__make} %{?jobs:-j%jobs}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT{%_sbindir,%_mandir/man8,/etc/init.d,/etc/sysconfig}
cp rbldnsd $RPM_BUILD_ROOT%_sbindir/
cp -p rbldnsd.8 $RPM_BUILD_ROOT%_mandir/man8/
cp -p contrib/debian/rbldnsd.default $RPM_BUILD_ROOT/etc/sysconfig/rbldnsd
cp -p contrib/debian/rbldnsd.init $RPM_BUILD_ROOT/etc/init.d/rbldnsd
chmod +x $RPM_BUILD_ROOT/etc/init.d/rbldnsd

%clean
rm -rf $RPM_BUILD_ROOT

%post
if ! getent passwd rbldns ; then
   mkdir -p -m 0755 %home	# ensure it is owned by root
   useradd -r -d %home -M -c "rbldns Daemon" -s /sbin/nologin rbldns
fi
/sbin/chkconfig --add rbldnsd
/etc/init.d/rbldnsd restart

%preun
if [ $1 -eq 0 ]; then
   /etc/init.d/rbldnsd stop || :
   /sbin/chkconfig --del rbldnsd
fi

%files
%defattr (-,root,root)
%doc README.user NEWS TODO contrib/debian/changelog CHANGES-0.81
%_sbindir/rbldnsd
%_mandir/man8/rbldnsd.8*
%config(noreplace) /etc/sysconfig/rbldnsd
/etc/init.d/rbldnsd
