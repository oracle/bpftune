# BPF-based auto-tuning SPEC file

%define name        bpftune
%define rel	    1
%define release     %{rel}%{?dist}
%define version     0.2
%global _unitdir    /usr/lib/systemd/system/	
%global pcpdir	    /var/lib/pcp/pmdas

License:        GPLv2 WITH Linux-syscall-note
Name:           %{name}
Summary:        BPF/tracing tools for auto-tuning Linux
Group:          Development/Tools
Requires:       libbpf >= 0.6
Requires:       libnl3
Requires:       libcap
BuildRequires:  libbpf-devel >= 0.6
BuildRequires:  libcap-devel
BuildRequires:	bpftool >= 4.18
BuildRequires:  libnl3-devel
BuildRequires:  clang >= 11
BuildRequires:  clang-libs >= 11
BuildRequires:  llvm >= 11
BuildRequires:  llvm-libs >= 11
BuildRequires:	python3-docutils
Version:        %{version}
Release:        %{release}
Source:         bpftune-%{version}.tar.bz2
Prefix:         %{_prefix}

%description
Service consisting of daemon (bpftune) and plugins which
support auto-tuning of Linux via BPF observability.

%package devel
Summary:        Development files for %{name}
Requires:       %{name} = %{version}-%{release}
Requires:       libbpf-devel >= 0.6
Requires:       libcap-devel
Requires:       bpftool
Requires:       libnl3-devel

%description devel
The %{name}-devel package contains libraries and header files for
developing BPF shared object tuners that use %{name}

%package pcp-pmda
Summary:	Performance Co-Pilot PMDA for bpftune
Requires:       %{name} = %{version}-%{release}
Requires:	pcp
Requires:       python3-pcp 

%description pcp-pmda
The %{name}-pcp-pmda exports tunables and metrics from bpftune
to Performance Co-Pilot (PCP)

%prep
%setup -q -n bpftune-%{version}

%build
make

%install
rm -Rf %{buildroot}
%make_install

%files
%defattr(-,root,root)
%{_sysconfdir}/ld.so.conf.d/libbpftune.conf
%{_sbindir}/bpftune
%{_unitdir}/bpftune.service
%{_libdir}/libbpftune.so.%{version}.%{rel}
%{_libdir}/bpftune/*
%{_mandir}/*/*

%license LICENSE.txt

%files devel
%{_libdir}/libbpftune.so
%{_includedir}/bpftune

%license LICENSE.txt

%files pcp-pmda
%{pcpdir}/%{name}/*

%license LICENSE.txt

%changelog
* Wed Mar 26 2025 Alan Maguire <alan.maguire@oracle.com> - 0.2-1
- Add support for PCP PMDA package
* Tue May 30 2023 Alan Maguire <alan.maguire@oracle.com> - 0.1-3
- Fix timeout retry logic in libbpftune. [Orabug: 35385703]
* Wed May 24 2023 Alan Maguire <alan.maguire@oracle.com> - 0.1-2
- Spec file reviewed.
* Mon May 30 2022 Alan Maguire <alan.maguire@oracle.com> - 0.1-1
- Initial packaging support
