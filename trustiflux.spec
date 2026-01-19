%define release 1
%global config_dir /etc/trustiflux
%global libdir /usr/lib

Name:		trustiflux
Version:	1.4.9
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

%package -n trustiflux-api-server
Summary:	REST API server exporting attestation and confidential data hub endpoints.
Requires: attestation-agent = %{version}-%{release}
Requires: confidential-data-hub = %{version}-%{release}

%description -n trustiflux-api-server
trustiflux-api-server exposes attestation-agent and confidential-data-hub ttRPC services over HTTP.

%package -n confidential-data-hub
Summary:	Confidential Data Hub is a daemon service running inside TEE (Trusted Execution Environment) to provide confidential resource related APIs.

%description -n confidential-data-hub
Confidential Data Hub is a daemon service running inside TEE (Trusted Execution Environment) to provide confidential resource related APIs.


%prep
%autosetup -n guest-components-%{version}
tar -xvf %{SOURCE1} 

%build
# building the attestation-agent
OPENSSL_NO_VENDOR=1 cargo build -p attestation-agent --bin ttrpc-aa --release --no-default-features --features bin,ttrpc,rust-crypto,coco_as,kbs,tdx-attester,system-attester,tpm-attester,instance_info,csv-attester,hygon-dcu-attester --target x86_64-unknown-linux-gnu
cargo build -p attestation-agent --bin ttrpc-aa-client --release --no-default-features --features bin,ttrpc,eventlog --target x86_64-unknown-linux-gnu

# building the confidential-data-hub
cargo build -p confidential-data-hub --release --bin cdh-oneshot --no-default-features --features "bin,aliyun,kbs" --target x86_64-unknown-linux-gnu
cargo build -p confidential-data-hub --release --bin ttrpc-cdh --no-default-features --features "bin,aliyun,kbs,ttrpc" --target x86_64-unknown-linux-gnu
cargo build -p confidential-data-hub --release --bin ttrpc-cdh-tool --no-default-features --features "bin,ttrpc" --target x86_64-unknown-linux-gnu

# building the api-server-rest
cargo build -p api-server-rest --release --target x86_64-unknown-linux-gnu


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
install -d -p %{buildroot}%{libdir}/systemd/system
install -m 644 dist/rpm/confidential-data-hub-daemon.service %{buildroot}%{libdir}/systemd/system/confidential-data-hub-daemon.service
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/cdh-oneshot %{buildroot}%{_prefix}/bin/confidential-data-hub
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-cdh %{buildroot}%{_prefix}/bin/confidential-data-hub-daemon
install -m 755 target/x86_64-unknown-linux-gnu/release/ttrpc-cdh-tool %{buildroot}%{_prefix}/bin/confidential-data-hub-client

# installing the api-server-rest
install -d -p %{buildroot}%{libdir}/systemd/system
install -m 644 dist/rpm/trustiflux-api-server.service %{buildroot}%{libdir}/systemd/system/trustiflux-api-server.service
install -d -p %{buildroot}%{config_dir}
install -m 644 dist/rpm/trustiflux-api-server.toml %{buildroot}%{config_dir}/trustiflux-api-server.toml
install -d -p %{buildroot}%{_prefix}/bin
install -m 755 target/x86_64-unknown-linux-gnu/release/api-server-rest %{buildroot}%{_prefix}/bin/trustiflux-api-server

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

%files -n trustiflux-api-server
%dir %{config_dir}
%config(noreplace) %{config_dir}/trustiflux-api-server.toml
%{_bindir}/trustiflux-api-server
%{libdir}/systemd/system/trustiflux-api-server.service

%files -n confidential-data-hub
%{_bindir}/confidential-data-hub
%{_bindir}/confidential-data-hub-daemon
%{_bindir}/confidential-data-hub-client
%{config_dir}/confidential-data-hub.toml
%{libdir}/systemd/system/confidential-data-hub-daemon.service
%dir %{libdir}/dracut/modules.d/99confidential-data-hub
%{libdir}/dracut/modules.d/99confidential-data-hub/confidential-data-hub.toml
%{libdir}/dracut/modules.d/99confidential-data-hub/module-setup.sh

%changelog
* Mon Jan 19 2026 Jiale Zhang <zhangjiale@linux.alibaba.com> - 1.4.9-1
- Attestation: system attester supports AAEL runtime measurements
- Attestation agent: get_token supports additional_data (optional)
- AA instance info: add EAS model id and instance id
- Release: add GuanFu workflow for AnolisOS23 and update RPM packaging

* Mon Dec 29 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 1.4.8-1
- kbs protocol: support carry attest token via Attestation header
- Release CI: support push event to RVDS
- RPM spec: add api-server-rest as trustiflux-api-server
- Sample attester: Support dummy measurement register
- Support trustee API key
- slsa provenance: use absolute path as file measurement name
- Add CDH daemon and fix timeout nits
- API Server: support /aa/aael API
- Update CI: use script for long shell operations

* Mon Dec 1 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 1.4.6-1
- CI: Add SLSA provenance generation logic
- AA instance info: aliyun ecs type support fqdn as instance name

* Thu Nov 12 2025 Jiale Zhang <zhangjiale@linux.alibaba.com> - 1.4.5-1
- TPM attester: Support TCG format AAEL
- TPM attester: support keylime agent AK

* Sat Oct 11 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.4.4-1
- TDX Attester: fix CCEL generation

* Wed Sep 17 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.4.3-1
- Dracut: fix dracut module

* Tue Sep 16 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.4.2-1
- TDX Attester: fix GPU attester error

* Fri Sep 5 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.4.1-1
- TDX Attester: fix CCEL algorithm

* Thu Aug 28 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.4.0-1
- Kbs Protocol: update to v0.4.0
- Hardware: add Hygon csv and hygon dcu support

* Thu Jul 3 2025 Xynnn007 <mading.ma@alibaba-inc.com> -1.3.1-1
- Dracut: remove dependency on sysinit.target for AA
- AA: Support configuring CoCoAS and KBS URL via ENV
- AA: get as token support config policy id via ENV
- AA: support instance information reporting to trustee
- AA: add AAInstanceInfo HTTP header when access /attest and /attestation API of trustee
- TDX attester: Add GPU attestation support

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