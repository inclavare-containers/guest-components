%define release 3
%global config_dir /etc/trustiflux
%global libdir /usr/lib

Name:		trustiflux
Version:	1.2.1
Release:	%{release}%{?dist}
Summary:	A daemon service running inside TEE (Trusted Execution Environment) to confidential resource related APIs

License:	Apache-2.0
URL:		https://github.com/inclavare-containers/guest-components
Source0:	https://github.com/inclavare-containers/guest-components/archive/refs/tags/v%{version}.tar.gz
Source1:	https://github.com/inclavare-containers/guest-components/releases/download/v%{version}/guest-components-v%{version}-vendor.tar.gz
BuildRoot:  %{_tmppath}/%{name}-%{version}-build

ExclusiveArch:	x86_64

BuildRequires:	cargo clang perl protobuf-devel git libtdx-attest-devel libgudev-devel tpm2-tss-devel
Requires: tpm2-tss libtdx-attest tee-primitives

%description
A daemon service running inside TEE (Trusted Execution Environment) to confidential resource related APIs

%package -n attestation-agent
Summary:	Attestation Agent is a daemon service running inside TEE (Trusted Execution Environment) to provide attestation related APIs.

%description -n attestation-agent
Attestation Agent is a daemon service running inside TEE (Trusted Execution Environment) to provide attestation related APIs.

%package -n confidential-data-hub
Summary:	Confidential Data Hub is a daemon service running inside TEE (Trusted Execution Environment) to provide confidential resource related APIs.

%description -n confidential-data-hub
Confidential Data Hub is a daemon service running inside TEE (Trusted Execution Environment) to provide confidential resource related APIs.


%prep
%autosetup -n guest-components-%{version}
tar -xvf %{SOURCE1} 

%build
# building the attestation-agent
cargo build -p attestation-agent --bin ttrpc-aa --release --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,tdx-attester,system-attester,tpm-attester,instance_info --target x86_64-unknown-linux-gnu
cargo build -p attestation-agent --bin ttrpc-aa-client --release --no-default-features --features bin,ttrpc --target x86_64-unknown-linux-gnu

# building the confidential-data-hub
cargo build -p confidential-data-hub --release --bin cdh-oneshot --no-default-features --features "bin,aliyun,kbs" --target x86_64-unknown-linux-gnu


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

# installing the attestation-agent
install -d -p %{buildroot}%{libdir}/systemd/system
install -m 644 dist/rpm/attestation-agent.service %{buildroot}%{libdir}/systemd/system/attestation-agent.service
install -d -p %{buildroot}/etc/trustiflux
install -m 644 dist/rpm/attestation-agent.toml %{buildroot}%{config_dir}/attestation-agent.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa %{buildroot}%{_prefix}/bin/attestation-agent
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-aa-client %{buildroot}%{_prefix}/bin/attestation-agent-client

# install dracut modules
install -d -p %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent
install -m 755 dist/dracut/modules.d/99attestation-agent/module-setup.sh %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent
install -m 644 dist/dracut/modules.d/99attestation-agent/attestation-agent.service %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent
install -m 644 dist/dracut/modules.d/99attestation-agent/attestation-agent.toml %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent
install -m 644 dist/dracut/modules.d/99attestation-agent/attestation-agent-platform-detect.sh %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent
install -m 644 dist/dracut/modules.d/99attestation-agent/attestation-agent-platform-detect.service %{buildroot}%{libdir}/dracut/modules.d/99attestation-agent

# installing the confidential-data-hub
install -d -p %{buildroot}/etc/trustiflux
install -m 644 dist/rpm/confidential-data-hub.toml %{buildroot}%{config_dir}/confidential-data-hub.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/cdh-oneshot %{buildroot}%{_prefix}/bin/confidential-data-hub

# install dracut modules
install -d -p %{buildroot}%{libdir}/dracut/modules.d/99confidential-data-hub
install -m 755 dist/dracut/modules.d/99confidential-data-hub/module-setup.sh %{buildroot}%{libdir}/dracut/modules.d/99confidential-data-hub
install -m 644 dist/dracut/modules.d/99confidential-data-hub/confidential-data-hub.toml %{buildroot}%{libdir}/dracut/modules.d/99confidential-data-hub

%clean
rm -rf %{buildroot}

%files -n attestation-agent
%{_bindir}/attestation-agent
%{_bindir}/attestation-agent-client
%dir %{config_dir}
%{config_dir}/attestation-agent.toml
%{libdir}/systemd/system/attestation-agent.service
%dir %{libdir}/dracut/modules.d/99attestation-agent
%{libdir}/dracut/modules.d/99attestation-agent/module-setup.sh
%{libdir}/dracut/modules.d/99attestation-agent/attestation-agent.service
%{libdir}/dracut/modules.d/99attestation-agent/attestation-agent.toml
%{libdir}/dracut/modules.d/99attestation-agent/attestation-agent-platform-detect.sh
%{libdir}/dracut/modules.d/99attestation-agent/attestation-agent-platform-detect.service

%files -n confidential-data-hub
%{_bindir}/confidential-data-hub
%{config_dir}/confidential-data-hub.toml
%dir %{libdir}/dracut/modules.d/99confidential-data-hub
%{libdir}/dracut/modules.d/99confidential-data-hub/confidential-data-hub.toml
%{libdir}/dracut/modules.d/99confidential-data-hub/module-setup.sh

%changelog
* Fri Jun 13 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.2.1-4
- Spec: use config files in source code

* Wed Jun 11 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.2.1-3
- Spec: fix dracut path to lib dir

* Mon May 26 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.2.1-2
- Spec: use upstream source tar ball for RPM build

* Thu May 22 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.2.1-1
- AA: fix dracut bugs
- AA: fix tpm parsed evidence bugs

* Tue May 20 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.2.0-1
- AA: add TPM attestation key and quote in evidence

* Wed Feb 19 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.1.0-1
- CDH: Add support for OIDC RAM
- Dracut: Fix wrong path

* Thu Jan 9 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.0.0-1
- First release