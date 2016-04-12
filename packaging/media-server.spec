Name:       media-server
Summary:    File manager service server.
Version: 0.2.90
Release:    1
Group:      utils
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    media-server.service.wearable
Source2:    media-scanner.service.wearable
Source3:    media-server.service.mobile

Requires(post): /usr/bin/vconftool
Requires: deviced

BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(deviced)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  pkgconfig(notification)


%description
Description: File manager service server

%package -n libmedia-utils
Summary:   media server runtime library.
Group:     TO_BE/FILLED_IN

%description -n libmedia-utils
Description : media server runtime library.


%package -n libmedia-utils-devel
Summary:   media server development library.
Group:     Development/Libraries
Requires:  libmedia-utils = %{version}-%{release}

%description -n libmedia-utils-devel
Description: media server development library.

%prep
%setup -q

%build

export GC_SECTIONS_FLAGS="-fdata-sections -ffunction-sections -Wl,--gc-sections"
export CFLAGS+=" ${GC_SECTIONS_FLAGS}"
export CXXFLAGS+=" ${GC_SECTIONS_FLAGS}"

%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

%autogen

%configure --prefix=%{_prefix} --disable-static

make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
install -m 644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/media-server.service
ln -s ../media-server.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/media-server.service

install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/media-scanner.service
#ln -s ../media-scanner.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/media-scanner.service

mkdir -p %{buildroot}/usr/etc
cp -rf %{_builddir}/%{name}-%{version}/media-server-plugin %{buildroot}/usr/etc/media-server-plugin

#License
mkdir -p %{buildroot}/%{_datadir}/license
cp -rf %{_builddir}/%{name}-%{version}/LICENSE.APLv2.0 %{buildroot}/%{_datadir}/license/%{name}
cp -rf %{_builddir}/%{name}-%{version}/LICENSE.APLv2.0 %{buildroot}/%{_datadir}/license/libmedia-utils

%post
vconftool set -t int db/filemanager/dbupdate "1" -f -s system::vconf_inhouse
vconftool set -t int memory/filemanager/Mmc "0" -i -f -s system::vconf_inhouse
vconftool set -t string db/private/mediaserver/mmc_info "" -f -s media-server::vconf

%files
%manifest media-server.manifest
%defattr(-,root,root,-)
%{_bindir}/media-server
%{_bindir}/media-scanner
%{_bindir}/mediadb-update
/usr/lib/systemd/system/media-server.service
/usr/lib/systemd/system/multi-user.target.wants/media-server.service
/usr/lib/systemd/system/media-scanner.service
#/usr/lib/systemd/system/multi-user.target.wants/media-scanner.service
/usr/etc/media-server-plugin
#License
%{_datadir}/license/%{name}
%{_datadir}/license/libmedia-utils

%files -n libmedia-utils
%manifest libmedia-utils.manifest
%defattr(-,root,root,-)
%{_libdir}/libmedia-utils.so
%{_libdir}/libmedia-utils.so.0
%{_libdir}/libmedia-utils.so.0.0.0

%files -n libmedia-utils-devel
%defattr(-,root,root,-)
%{_libdir}/pkgconfig/libmedia-utils.pc
%{_includedir}/media-utils/*.h

