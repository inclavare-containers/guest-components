TEE_PLATFORM ?= fs
ARCH ?= $(shell uname -m)

DESTDIR ?= /usr/local/bin

LIBC ?= musl

ATTESTER ?=

NO_RESOURCE_PROVIDER ?=

ifeq ($(NO_RESOURCE_PROVIDER), true)
  RESOURCE_PROVIDER :=
else
  RESOURCE_PROVIDER ?= kbs
endif

ifeq ($(TEE_PLATFORM), none)
  ATTESTER = none
else ifeq ($(TEE_PLATFORM), fs)
  ATTESTER = none
else ifeq ($(TEE_PLATFORM), tdx)
  ATTESTER = tdx-attester
else ifeq ($(TEE_PLATFORM), az-cvm-vtpm)
  ATTESTER = az-snp-vtpm-attester,az-tdx-vtpm-attester
else ifeq ($(TEE_PLATFORM), sev)
  ATTESTER = none
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev
  endif
else ifeq ($(TEE_PLATFORM), snp)
  ATTESTER = snp-attester
else ifeq ($(TEE_PLATFORM), se)
  ATTESTER = se-attester
else ifeq ($(TEE_PLATFORM), all)
  ATTESTER = all-attesters
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev,kbs
  endif
else ifeq ($(TEE_PLATFORM), amd)
  ATTESTER = snp-attester
  ifeq ($(NO_RESOURCE_PROVIDER), true)
    RESOURCE_PROVIDER :=
  else
    RESOURCE_PROVIDER = sev,kbs
  endif
else ifeq ($(TEE_PLATFORM), cca)
  ATTESTER = cca-attester
endif
# TODO: Add support for CSV

ifeq ($(ARCH), $(filter $(ARCH), s390x powerpc64le))
  $(info s390x/powerpc64le only supports gnu)
  LIBC = gnu
endif

CDH := confidential-data-hub
AA := attestation-agent
ASR := api-server-rest

BUILD_DIR := target/$(ARCH)-unknown-linux-$(LIBC)/release

CDH_BINARY := $(BUILD_DIR)/$(CDH)
AA_BINARY := $(BUILD_DIR)/$(AA)
ASR_BINARY := $(BUILD_DIR)/$(ASR)

VERSION := $(shell grep "Version:"  trustiflux.spec | sed 's/Version:[[:space:]]*//')

build: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	@echo guest components built for $(TEE_PLATFORM) succeeded!

$(CDH_BINARY):
	@echo build $(CDH) for $(TEE_PLATFORM)
	cd $(CDH) && $(MAKE) RESOURCE_PROVIDER=$(RESOURCE_PROVIDER) LIBC=$(LIBC)

$(AA_BINARY):
	@echo build $(AA) for $(TEE_PLATFORM)
	cd $(AA) && $(MAKE) ttrpc=true ARCH=$(ARCH) LIBC=$(LIBC) ATTESTER=$(ATTESTER)

$(ASR_BINARY):
	@echo build $(ASR) for $(TEE_PLATFORM)
	cd $(ASR) && $(MAKE) ARCH=$(ARCH) LIBC=$(LIBC)

install: $(CDH_BINARY) $(ASR_BINARY) $(AA_BINARY)
	install -D -m0755 $(CDH_BINARY) $(DESTDIR)/$(CDH)
	install -D -m0755 $(AA_BINARY) $(DESTDIR)/$(AA)
	install -D -m0755 $(ASR_BINARY) $(DESTDIR)/$(ASR)

/tmp/v${VERSION}.tar.gz:
	rm -rf /tmp/guest-components-tarball/guest-components-${VERSION}/ && mkdir -p /tmp/guest-components-tarball/guest-components-${VERSION}/

	rsync -a --exclude target --exclude .git ./ /tmp/guest-components-tarball/guest-components-${VERSION}/

	tar -czf /tmp/v${VERSION}.tar.gz -C /tmp/guest-components-tarball/ guest-components-${VERSION}

	@echo "Tarball generated:" /tmp/v${VERSION}.tar.gz

/tmp/guest-components-v${VERSION}-vendor.tar.gz:
	@echo "Generating vendor tarball..."
	rm -rf /tmp/guest-components-tarball/guest-components-${VERSION}/ && mkdir -p /tmp/guest-components-tarball/guest-components-${VERSION}/vendor
	mkdir -p /tmp/guest-components-tarball/guest-components-${VERSION}/.cargo/
	cargo vendor --locked --manifest-path ./Cargo.toml --no-delete --versioned-dirs --respect-source-config /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/ | tee /tmp/guest-components-tarball/guest-components-${VERSION}/.cargo/config.toml

	sed -i 's;^.*directory = .*/vendor/.*$$;directory = "vendor";g' /tmp/guest-components-tarball/guest-components-${VERSION}/.cargo/config.toml

	# sanity check on cargo vendor
	@grep "source.crates-io" /tmp/guest-components-tarball/guest-components-${VERSION}/.cargo/config.toml >/dev/null || (echo "cargo vendor failed, please check /tmp/guest-components-tarball/guest-components-${VERSION}/.cargo/config.toml"; exit 1)

	# remove unused files
	find /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/windows*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	find /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/winapi*/src/ ! -name 'lib.rs' -type f -exec rm -f {} +
	rm -fr /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/windows*/lib/*.a
	rm -fr /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/winapi*/lib/*.a
	rm -fr /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/winapi*/lib/*.lib
	rm -fr /tmp/guest-components-tarball/guest-components-${VERSION}/vendor/windows*/lib/*.lib

	tar -czf /tmp/guest-components-v${VERSION}-vendor.tar.gz -C /tmp/guest-components-tarball/guest-components-${VERSION}/ vendor
	@echo "Vendor tarball generated:" /tmp/guest-components-v${VERSION}-vendor.tar.gz

.PHONE: create-tarball
create-tarball: /tmp/v${VERSION}.tar.gz /tmp/guest-components-v${VERSION}-vendor.tar.gz

.PHONE: rpm-build
rpm-build: create-tarball
# setup build tree
	which rpmdev-setuptree || { yum install -y rpmdevtools ; }
	rpmdev-setuptree

	# copy sources
	cp /tmp/v${VERSION}.tar.gz ~/rpmbuild/SOURCES/
	cp /tmp/guest-components-v${VERSION}-vendor.tar.gz ~/rpmbuild/SOURCES/

	# install build dependencies
	which yum-builddep || { yum install -y yum-utils ; }
	yum-builddep -y ./trustiflux.spec

	# build
	rpmbuild -ba ./trustiflux.spec
	@echo "RPM package is:" ~/rpmbuild/RPMS/*/trustiflux-*

.PHONE: rpm-build-in-docker
rpm-build-in-docker:
# copy sources
	mkdir -p ~/rpmbuild/SOURCES/
	cp /tmp/v${VERSION}.tar.gz ~/rpmbuild/SOURCES/

	docker run --rm -v ~/rpmbuild:/root/rpmbuild \
		-v /tmp:/tmp \
		-v .:/code --workdir=/code \
		alibaba-cloud-linux-3-registry.cn-hangzhou.cr.aliyuncs.com/alinux3/alinux3:latest \
		bash -x -c \
		"yum makecache -y && yum install make cargo clang perl protobuf-devel git libtdx-attest-devel libgudev-devel tpm2-tss-devel rsync tar which -y && make rpm-build"

clean:
	rm -rf target
