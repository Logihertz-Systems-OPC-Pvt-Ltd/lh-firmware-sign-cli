Name:           lh-firmware-sign-cli
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-fw-sign - Hybrid Dual-Algorithm Signature Verification Invariant
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-firmware-sign-cli
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Zero-dependency Go PKCS#11 v3.0 HSM-compatible binary firmware signer implementing hybrid Ed25519 + RSA-PSS-SHA384 signatures, LHFWSIG1 anti-rollback trailers, X.509 code-signing chains, and RFC 3161 TSA tokens.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-fw-sign ]; then
    install -m 0755 bin/lh-fw-sign %{buildroot}%{_bindir}/lh-fw-sign
elif [ -f lh-fw-sign ]; then
    install -m 0755 lh-fw-sign %{buildroot}%{_bindir}/lh-fw-sign
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-firmware-sign-cli.
